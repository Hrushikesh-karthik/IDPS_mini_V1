# =============================================================================
# proxy/proxy_server.py — AI-Powered Zero Trust Reverse Proxy
# =============================================================================
# This is the CORE of the entire system.
#
# It is a FastAPI application that:
#   1. Accepts every HTTP request on PROXY_PORT (default: 8000)
#   2. Runs it through a 3-layer security pipeline:
#        Layer 1: Deep Packet Inspection (rule-based, instant)
#        Layer 2: ML Attack Classification (Random Forest)
#        Layer 3: Anomaly Detection (Isolation Forest / Zero-Day)
#   3. Blocks malicious requests with a 403 response
#   4. Forwards clean requests to the backend application
#   5. Logs everything to SQLite and sends email alerts on blocks
#
# Start the proxy:
#   python app.py
#   — or —
#   uvicorn proxy.proxy_server:app --host 0.0.0.0 --port 8000
# =============================================================================

import time
import logging
import sys
import os
import json  # for traffic log serialization

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Project imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import (
    BACKEND_URL, BACKEND_TIMEOUT,
    CONFIDENCE_THRESHOLD, INSTANT_REBLOCK_KNOWN_ATTACKERS,
    TRAFFIC_LOG_PATH
)
from database.db import (
    init_db, log_visitor, is_ip_blocked,
    block_ip, log_alert
)
from proxy.packet_inspector import inspect as dpi_inspect
from ml.attack_detector import detector, extract_features_from_request
from ml.anomaly_detector import anomaly_detector
from ml.explain import explainer

# Set up logging — all proxy events use the [proxy] prefix
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
logger = logging.getLogger("proxy")


# =============================================================================
# FASTAPI APP SETUP
# =============================================================================

app = FastAPI(
    title="Zero Trust AI Security Proxy",
    description="AI-powered reverse proxy with deep packet inspection and ML-based attack detection.",
    version="1.0.0",
    # Hide docs in production — the proxy shouldn't expose its own API docs
    docs_url="/proxy-status",   # Internal status page only
    redoc_url=None
)

# Allow CORS for the dashboard (Streamlit runs on a different port)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Tighten this in production
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# STARTUP EVENT
# Runs once when the server starts — initializes DB and ML models.
# =============================================================================

@app.on_event("startup")
async def startup():
    """
    Initializes all system components when the proxy starts.

    Order matters:
    1. Database must be ready before we log anything
    2. ML models are loaded (already done at import time via singletons)
    3. SHAP explainer is initialized with the loaded model
    """
    logger.info("=" * 60)
    logger.info("Zero Trust AI Security Proxy — Starting Up")
    logger.info("=" * 60)

    # Initialize SQLite database (creates tables if they don't exist)
    init_db()
    logger.info("✓ Database initialized")

    # Initialize SHAP explainer with the loaded classifier
    # This is done here (not at import time) because the detector
    # must be fully loaded before we can attach SHAP to it
    if detector.loaded:
        explainer.initialize(detector.model, detector.feature_names)
        logger.info("✓ ML classifier loaded")
        logger.info("✓ SHAP explainer initialized")
    else:
        logger.warning(
            "⚠ ML model not loaded. "
            "Run 'python ml/train_model.py' to train first. "
            "DPI and anomaly detection will still work."
        )

    if anomaly_detector.available:
        logger.info("✓ Anomaly detector loaded")
    else:
        logger.warning(
            "⚠ Anomaly model not loaded. "
            "Run 'python ml/anomaly_detector.py' to train."
        )

    logger.info(f"✓ Proxy listening — forwarding safe traffic to {BACKEND_URL}")
    logger.info("=" * 60)


# =============================================================================
# HELPER: EXTRACT CLIENT IP
# =============================================================================

def get_client_ip(request: Request) -> str:
    """
    Extracts the real client IP from the request.

    Why not just use request.client.host?
    When the proxy sits behind a load balancer or another proxy,
    the real client IP is in the X-Forwarded-For header, not client.host.

    We check X-Forwarded-For first, then fall back to the direct connection IP.

    Args:
        request: The FastAPI Request object

    Returns:
        IP address string (e.g. "203.0.113.42")
    """
    # X-Forwarded-For can be a comma-separated list when multiple proxies
    # are chained: "client_ip, proxy1_ip, proxy2_ip"
    # The real client is always the FIRST one.
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    # X-Real-IP is simpler — set by nginx and similar
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()

    # Fall back to the direct TCP connection IP
    if request.client:
        return request.client.host

    return "unknown"


# =============================================================================
# HELPER: BUILD BLOCK RESPONSE
# =============================================================================

def block_response(ip: str, attack_type: str, reason: str) -> JSONResponse:
    """
    Returns a standardized 403 Forbidden response for blocked requests.

    We deliberately don't tell the attacker WHY they were blocked —
    only that access was denied. The full details go to the database and
    the admin email.

    Args:
        ip:          Source IP (for logging only, not in response)
        attack_type: Detected attack class
        reason:      Human-readable reason (logged, not returned)

    Returns:
        JSONResponse with status 403
    """
    logger.warning(
        f"BLOCKED | IP: {ip} | Type: {attack_type} | Reason: {reason[:80]}"
    )

    return JSONResponse(
        status_code=403,
        content={
            "error":   "Access Denied",
            "message": "Your request has been blocked by the security proxy.",
            "code":    "ZERO_TRUST_BLOCK"
            # Intentionally vague — don't leak security details to attackers
        }
    )


# =============================================================================
# HELPER: HANDLE A DETECTED ATTACK
# =============================================================================

async def handle_attack(
    ip:          str,
    attack_type: str,
    reason:      str,
    confidence:  float,
    features:    dict,
    anomaly_score: float = None,
    anomaly_reason: str  = None
) -> JSONResponse:
    """
    Called whenever a request is determined to be malicious.

    Responsibilities:
    1. Add IP to the block list in the database
    2. Generate a SHAP explanation
    3. Send admin email alert
    4. Log the alert record
    5. Return a 403 response

    This function is async because sending email (in a real impl) would
    be an async I/O operation. We import mailer lazily to avoid circular imports.

    Args:
        ip:             Source IP address
        attack_type:    Detected attack class
        reason:         Human-readable block reason
        confidence:     ML confidence score (0.0–1.0)
        features:       Raw feature dict (for SHAP)
        anomaly_score:  Isolation Forest score (if zero-day)
        anomaly_reason: Pre-built anomaly explanation string

    Returns:
        JSONResponse 403
    """
    # --- 1. Block the IP in the database ---
    block_ip(ip, attack_type, reason)

    # --- 2. Generate explanation (SHAP or template) ---
    feature_vector = []
    if detector.loaded and features:
        try:
            feature_vector = detector._build_feature_vector(features)
        except Exception:
            pass

    explanation = explainer.explain(
        attack_type    = attack_type,
        confidence     = confidence,
        feature_vector = feature_vector,
        anomaly_score  = anomaly_score,
        anomaly_reason = anomaly_reason
    )

    # --- 3. Send admin email alert ---
    email_status = "disabled"
    try:
        from alerts.mailer import send_alert
        from datetime import datetime, timezone
        timestamp = datetime.now(timezone.utc).isoformat()

        email_body = explainer.build_email_body(
            ip                = ip,
            attack_type       = attack_type,
            timestamp         = timestamp,
            explanation_result = explanation
        )

        success = send_alert(
            ip          = ip,
            attack_type = attack_type,
            timestamp   = timestamp,
            confidence  = confidence,
            subject     = explanation["summary"],
            body        = email_body
        )
        email_status = "sent" if success else "failed"

    except Exception as e:
        logger.error(f"Email alert error: {e}")
        email_status = "failed"

    # --- 4. Log the alert record ---
    log_alert(attack_type, ip, email_status)

    # --- 5. Return 403 ---
    return block_response(ip, attack_type, reason)


# =============================================================================
# HELPER: FORWARD REQUEST TO BACKEND
# =============================================================================

async def forward_to_backend(request: Request, body: bytes) -> Response:
    """
    Forwards a clean, verified request to the protected backend application.

    Preserves:
    - HTTP method (GET, POST, PUT, etc.)
    - All original headers (minus hop-by-hop headers)
    - Request body
    - Query parameters (already part of the URL)

    Adds:
    - X-Forwarded-For: tells the backend the real client IP
    - X-Proxy-Verified: signals the request passed security checks

    Args:
        request: Original FastAPI request object
        body:    Raw request body bytes

    Returns:
        FastAPI Response object with the backend's response
    """
    # Build the target URL: backend base + the original path + query string
    target_url = f"{BACKEND_URL}{request.url.path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    # Copy headers — exclude hop-by-hop headers that shouldn't be forwarded
    # These are connection-level headers, not application-level
    hop_by_hop = {
        "connection", "keep-alive", "transfer-encoding",
        "te", "trailers", "upgrade", "proxy-authorization",
        "proxy-authenticate"
    }

    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in hop_by_hop
    }

    # Add proxy identification headers
    client_ip = get_client_ip(request)
    forward_headers["x-forwarded-for"]  = client_ip
    forward_headers["x-proxy-verified"] = "zero-trust-proxy-v1"

    try:
        async with httpx.AsyncClient(timeout=BACKEND_TIMEOUT) as client:
            response = await client.request(
                method  = request.method,
                url     = target_url,
                headers = forward_headers,
                content = body,
            )

        # Return the backend's response back to the original client
        # Strip hop-by-hop headers from the response too
        response_headers = {
            k: v for k, v in response.headers.items()
            if k.lower() not in hop_by_hop
        }

        return Response(
            content    = response.content,
            status_code = response.status_code,
            headers    = response_headers,
            media_type = response.headers.get("content-type")
        )

    except httpx.ConnectError:
        logger.error(f"Backend unreachable at {BACKEND_URL}")
        return JSONResponse(
            status_code=502,
            content={
                "error":   "Bad Gateway",
                "message": "The backend application is currently unavailable.",
                "code":    "BACKEND_UNREACHABLE"
            }
        )
    except httpx.TimeoutException:
        logger.error(f"Backend timed out after {BACKEND_TIMEOUT}s")
        return JSONResponse(
            status_code=504,
            content={
                "error":   "Gateway Timeout",
                "message": "The backend application did not respond in time.",
                "code":    "BACKEND_TIMEOUT"
            }
        )


def log_traffic(
    ip: str, method: str, url: str,
    status: str, attack_type: str,
    body_size: int, elapsed_ms: float,
    user_agent: str
):
    """
    Appends one JSON line to the traffic log file for the live dashboard feed.

    Each line is a self-contained JSON object so the dashboard can parse
    individual lines without loading the entire file.

    Args:
        ip:          Source IP address
        method:      HTTP method (GET, POST, etc.)
        url:         Request URL (truncated to 120 chars)
        status:      "ALLOWED" or "BLOCKED"
        attack_type: Attack class if blocked, "None" if allowed
        body_size:   Request body size in bytes
        elapsed_ms:  Total pipeline processing time
        user_agent:  User-Agent header value (truncated)
    """
    from datetime import datetime, timezone
    entry = {
        "ts":          datetime.now(timezone.utc).isoformat(),
        "ip":          ip,
        "method":      method,
        "url":         url[:120],
        "status":      status,
        "attack_type": attack_type,
        "body_size":   body_size,
        "elapsed_ms":  round(elapsed_ms, 1),
        "user_agent":  user_agent[:80] if user_agent else "",
    }
    try:
        with open(TRAFFIC_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.error(f"Traffic log write error: {e}")


# =============================================================================
# MAIN CATCH-ALL ROUTE
# This single route handles EVERY incoming request to the proxy.
# =============================================================================

@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
)
async def proxy_handler(request: Request, full_path: str) -> Response:
    """
    The main proxy handler — intercepts every HTTP request.

    Runs the full Zero Trust security pipeline:
      Layer 0: Known bad IP check (instant DB lookup)
      Layer 1: Deep Packet Inspection (regex patterns)
      Layer 2: ML Attack Classification (Random Forest)
      Layer 3: Anomaly Detection (Isolation Forest)
      Layer 4: Forward to backend (if all clear)

    Args:
        request:   FastAPI Request object (headers, method, URL, etc.)
        full_path: The URL path being requested (e.g. "api/users/1")

    Returns:
        Either a 403 block response or the backend's response
    """
    # Record request start time (used for ML feature: request duration)
    start_time = time.time()

    # -------------------------------------------------------------------------
    # Extract request components
    # -------------------------------------------------------------------------
    ip           = get_client_ip(request)
    method       = request.method
    url          = str(request.url)
    query_string = request.url.query or ""
    headers      = dict(request.headers)

    # Read body — must be awaited (async I/O)
    # We read it once here and pass it around (can't re-read a stream)
    body = await request.body()

    logger.info(f"REQUEST | {method} {url[:80]} | IP: {ip} | Body: {len(body)}B")

    # =========================================================================
    # LAYER 0: KNOWN BAD IP CHECK
    # Fastest possible check — just a DB lookup.
    # Known attackers are blocked before any computation runs.
    # =========================================================================

    if INSTANT_REBLOCK_KNOWN_ATTACKERS and is_ip_blocked(ip):
        logger.warning(f"INSTANT BLOCK | Known bad IP: {ip}")
        log_visitor(ip)
        log_traffic(ip, method, url, "BLOCKED", "Known Attacker", len(body),
                    (time.time() - start_time) * 1000,
                    headers.get("user-agent", ""))
        return block_response(ip, "Known Attacker", "IP is on the permanent block list.")

    # Log this visit in the visitors table (all IPs, good and bad)
    log_visitor(ip)

    # =========================================================================
    # LAYER 1: DEEP PACKET INSPECTION
    # Rule-based regex scanning. Fast, reliable for known signatures.
    # =========================================================================

    dpi_result = dpi_inspect(
        ip           = ip,
        method       = method,
        url          = url,
        query_string = query_string,
        headers      = headers,
        body         = body
    )

    if dpi_result["is_suspicious"]:
        log_traffic(ip, method, url, "BLOCKED", dpi_result["attack_type"],
                    len(body), (time.time() - start_time) * 1000,
                    headers.get("user-agent", ""))
        return await handle_attack(
            ip          = ip,
            attack_type = dpi_result["attack_type"],
            reason      = dpi_result["reason"],
            confidence  = 1.0,
            features    = {},
        )

    # =========================================================================
    # LAYER 2: ML ATTACK CLASSIFICATION
    # Random Forest classifier trained on UNSW-NB15.
    # Detects known attack categories with probability scores.
    # =========================================================================

    duration_ms = (time.time() - start_time) * 1000

    # Extract features from this HTTP request
    raw_features = extract_features_from_request(
        ip          = ip,
        method      = method,
        url         = url,
        headers     = headers,
        body        = body,
        duration_ms = duration_ms
    )

    # Run the classifier
    ml_result = detector.detect(raw_features)

    if ml_result["ml_available"] and ml_result["is_attack"]:
        attack_type = ml_result["prediction"]
        confidence  = ml_result["confidence"]
        reason = (
            f"ML classifier detected {attack_type} with "
            f"{confidence * 100:.1f}% confidence."
        )
        log_traffic(ip, method, url, "BLOCKED", attack_type,
                    len(body), (time.time() - start_time) * 1000,
                    headers.get("user-agent", ""))
        return await handle_attack(
            ip          = ip,
            attack_type = attack_type,
            reason      = reason,
            confidence  = confidence,
            features    = raw_features,
        )

    # =========================================================================
    # LAYER 3: ANOMALY DETECTION (ZERO-DAY)
    #
    # IMPORTANT — dual-signal requirement to prevent false positives:
    #
    # The anomaly detector is trained on UNSW-NB15 network-flow features
    # (packet counts, byte counts, TTL values, etc.). Our HTTP proxy can only
    # approximate these features — many fields are zero or minimal for a plain
    # browser GET request, which makes them look "anomalous" to a model trained
    # on rich network captures.
    #
    # To avoid blocking legitimate traffic, we only escalate to Zero-Day when
    # BOTH signals agree something is wrong:
    #   ① The anomaly detector flags the traffic as unusual, AND
    #   ② The ML classifier did NOT confidently predict "Normal"
    #      (i.e. its top prediction is not Normal, or Normal confidence < 0.85)
    #
    # A plain browser GET produces ML prediction="Normal" with high confidence
    # → anomaly flag alone is not enough → request is forwarded safely.
    # =========================================================================

    anomaly_result = anomaly_detector.score(raw_features)

    if anomaly_result["available"] and anomaly_result["is_anomaly"]:

        # Check whether ML also considers this non-normal
        ml_confident_normal = (
            ml_result.get("ml_available") and
            ml_result.get("prediction") == "Normal" and
            ml_result.get("confidence", 0.0) >= 0.85
        )

        if ml_confident_normal:
            # ML says Normal with high confidence — anomaly detector is likely
            # reacting to our approximated feature values, not a real attack.
            # Log the discrepancy for visibility but allow the request through.
            logger.info(
                f"Anomaly flagged but ML confident Normal "
                f"(score={anomaly_result['anomaly_score']:.3f}, "
                f"ML Normal conf={ml_result['confidence']:.2f}) — allowing | IP: {ip}"
            )
        else:
            # Both signals agree: anomalous pattern AND ML not confident it's Normal
            # → block as Zero-Day
            log_traffic(ip, method, url, "BLOCKED", "Zero-Day",
                        len(body), (time.time() - start_time) * 1000,
                        headers.get("user-agent", ""))
            return await handle_attack(
                ip             = ip,
                attack_type    = "Zero-Day",
                reason         = anomaly_result["reason"],
                confidence     = 0.0,
                features       = raw_features,
                anomaly_score  = anomaly_result["anomaly_score"],
                anomaly_reason = anomaly_result["reason"]
            )

    # =========================================================================
    # LAYER 4: FORWARD TO BACKEND
    # =========================================================================

    elapsed = (time.time() - start_time) * 1000
    log_traffic(ip, method, url, "ALLOWED", "None",
                len(body), elapsed, headers.get("user-agent", ""))
    logger.info(f"ALLOWED | IP: {ip} | Pipeline took {elapsed:.1f}ms — forwarding")

    return await forward_to_backend(request, body)


# =============================================================================
# HEALTH / STATUS ENDPOINT
# Accessible at /proxy-status — shows system state without exposing internals.
# =============================================================================

@app.get("/proxy-health")
async def health_check():
    """
    Simple health check endpoint for monitoring.

    Returns the status of each component so you can quickly see
    if models need to be trained or the DB is missing.

    Access at: http://localhost:8000/proxy-health
    """
    from database.db import get_stats

    try:
        stats = get_stats()
        db_ok = True
    except Exception:
        stats = {}
        db_ok = False

    return {
        "status":           "running",
        "backend_url":      BACKEND_URL,
        "components": {
            "database":         db_ok,
            "ml_classifier":    detector.loaded,
            "anomaly_detector": anomaly_detector.available,
            "shap_explainer":   explainer.shap_explainer is not None,
        },
        "stats": stats
    }