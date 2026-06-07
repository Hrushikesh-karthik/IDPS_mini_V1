# =============================================================================
# proxy/packet_inspector.py — Deep Packet Inspection Engine
# =============================================================================
# The FIRST layer of defense in the proxy pipeline.
#
# This module inspects every part of an incoming HTTP request using
# regex pattern matching to detect known attack signatures.
#
# It runs BEFORE any ML model, making it:
#   - Extremely fast (microseconds vs milliseconds for ML)
#   - 100% reliable for well-known attack patterns
#   - Zero false positives on classic signatures like "' OR 1=1"
#
# Inspection order (fastest/cheapest first):
#   1. HTTP Method      → is it an allowed verb?
#   2. Request Size     → is the payload abnormally large?
#   3. User-Agent       → known scanner/attack tool?
#   4. URL / Path       → path traversal, encoded attacks?
#   5. Query Parameters → SQLi, XSS, command injection?
#   6. Headers          → header injection?
#   7. Request Body     → SQLi, XSS, shellcode in POST body?
#   8. Rate Check       → too many requests from this IP?
# =============================================================================

import re
import time
import logging
from collections import defaultdict
from urllib.parse import unquote, unquote_plus

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import ALLOWED_METHODS, MAX_REQUEST_SIZE_BYTES

logger = logging.getLogger("packet_inspector")


# =============================================================================
# ATTACK SIGNATURE PATTERNS
# Each entry is a compiled regex. Compiling once at module load is efficient.
# =============================================================================

# --- SQL Injection ---
# Covers classic SQLi keywords, comment sequences, and common bypass tricks.
SQL_INJECTION_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
    r"(\bUNION\b.{0,20}\bSELECT\b)",           # UNION SELECT (most common)
    r"(\bOR\b.{0,10}['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",  # OR 1=1
    r"(--|#|/\*|\*/)",                           # SQL comment sequences
    r"(\bxp_cmdshell\b|\bsp_executesql\b)",      # SQL Server dangerous procs
    r"(\bSLEEP\s*\(|\bWAITFOR\s+DELAY\b)",      # Time-based blind SQLi
    r"(\bINFORMATION_SCHEMA\b|\bSYSCOLUMNS\b)", # Schema enumeration
    r"(\bCHAR\s*\(\d+\)|\bCONCAT\s*\()",        # Encoding tricks
    r"(';|';--|\";\s*--)",                       # Statement termination
    r"(\bCAST\s*\(|\bCONVERT\s*\()",            # Type conversion tricks
]]

# --- Cross-Site Scripting (XSS) ---
# Covers script tags, event handlers, and protocol handlers.
#
# IMPORTANT: The event handler pattern requires an HTML tag context (<...on...=)
# to avoid false positives on cookie values like "anonymous_id=" which contain
# common letter sequences that naively match "on\w+=".
XSS_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(<\s*script[\s>])",                            # <script> tag
    r"(javascript\s*:)",                             # javascript: protocol
    r"(<[^>]+\bon(error|load|click|mouseover|focus|blur|submit|change|keyup|keydown|input|mouseout|mousemove|dblclick|contextmenu|resize|scroll)\s*=)", # event handler INSIDE an HTML tag
    r"(<\s*iframe[\s>])",                            # <iframe> injection
    r"(<\s*img[^>]+src\s*=\s*['\"]?javascript)",    # <img src=javascript:
    r"(document\.(cookie|write|location))",          # DOM manipulation
    r"(window\.(location|open))",                    # Window manipulation
    r"(eval\s*\(|setTimeout\s*\(|setInterval\s*\()", # JS eval
    r"(<\s*svg[^>]*\bon\w+\s*=)",                   # SVG event handler injection
    r"(expression\s*\()",                            # CSS expression() (IE)
    r"(&#x[0-9a-fA-F]+;|&#\d+;)",                  # HTML entity encoding bypass
    r"(%3C\s*script|%3cscript)",                     # URL-encoded <script
]]

# --- Command Injection ---
# Shell metacharacters and common command patterns.
COMMAND_INJECTION_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(;\s*(ls|cat|pwd|whoami|id|uname|wget|curl|bash|sh|python|perl|php))",
    r"(\|\s*(ls|cat|pwd|whoami|id|uname|wget|curl|bash|sh))",
    r"(&&\s*(ls|cat|pwd|whoami|wget|curl|bash))",
    r"(`[^`]+`)",                                # Backtick execution
    r"(\$\([^)]+\))",                            # $(command) substitution
    r"(>\s*/dev/null|>>/etc/)",                  # Output redirection
    r"(/bin/(bash|sh|dash)|/usr/bin/(python|perl|nc|ncat))", # Shell paths
    r"(nc\s+-[el]|netcat\s+-[el])",              # Netcat reverse shell
    r"(\bchmod\s+[0-7]{3,4}\b|\bchown\s+\w+:)", # Permission changes
]]

# --- Path Traversal ---
# Attempts to access files outside the web root.
PATH_TRAVERSAL_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(\.\./|\.\.\\)",                           # Classic ../
    r"(%2e%2e%2f|%2e%2e/|\.\.%2f)",             # URL-encoded ../
    r"(%252e%252e|\.\.%255c)",                   # Double-encoded
    r"(/etc/(passwd|shadow|hosts|hostname|issue))", # Linux sensitive files
    r"(/proc/(self|version|cmdline))",           # Linux proc filesystem
    r"(C:\\(Windows|System32|Users|boot\.ini))", # Windows sensitive paths
    r"(\.\./\.\./\.\./)",                        # Deep traversal
    r"(file://|file:\\\\)",                      # File protocol handler
]]

# --- Suspicious User-Agents ---
# Known automated attack tools, vulnerability scanners, and exploit frameworks.
SUSPICIOUS_AGENT_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(sqlmap)",                                 # SQL injection tool
    r"(nikto)",                                  # Web vulnerability scanner
    r"(nmap|masscan|zmap)",                      # Port/network scanners
    r"(metasploit|msfconsole|msfvenom)",         # Exploit framework
    r"(burpsuite|burp\s*suite)",                 # Web proxy/attack tool
    r"(acunetix|nessus|openvas)",                # Vulnerability scanners
    r"(w3af|wfuzz|dirb|dirbuster|gobuster)",     # Web fuzzing tools
    r"(havij|pangolin)",                         # SQLi tools
    r"(hydra|medusa|john\s+the\s+ripper)",       # Password crackers
    r"(python-requests/|go-http-client/|java/\d)", # Scripted clients (suspicious)
    r"(zgrab|nuclei|jaeles)",                    # Modern scanning tools
]]

# --- Header Injection ---
# Carriage return / newline injection to split HTTP responses.
HEADER_INJECTION_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(\r\n|\r|\n)",                             # CRLF injection
    r"(%0d%0a|%0d|%0a)",                         # URL-encoded CRLF
    r"(%0D%0A|%0D|%0A)",                         # Uppercase encoded CRLF
]]

# --- Shellcode / Binary ---
# Patterns that indicate binary shellcode or encoded exploit payloads.
SHELLCODE_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(\\x[0-9a-fA-F]{2}){4,}",                 # \x41\x42\x43... sequences
    r"(%[0-9a-fA-F]{2}){8,}",                   # Long URL-encoded sequences
    r"(AAAA{10,}|A{20,})",                       # Buffer overflow padding
    r"(\x90{4,})",                               # NOP sled (\x90 bytes)
]]


# =============================================================================
# RATE LIMITER
# Tracks request counts per IP in memory to detect brute force.
# =============================================================================

class RateLimiter:
    """
    Simple in-memory rate limiter using a sliding time window.

    Tracks how many requests each IP has made in the last N seconds.
    If an IP exceeds the threshold, it's flagged as a brute force attempt.

    Note: This resets when the server restarts. For persistence across
    restarts, you'd use Redis — but SQLite is fine for this project.

    Attributes:
        window_seconds: Time window to count requests in
        max_requests:   Max allowed requests per window
        _counts:        Dict of {ip: [(timestamp, count), ...]}
    """

    def __init__(self, window_seconds: int = 60, max_requests: int = 100):
        self.window_seconds = window_seconds
        self.max_requests   = max_requests
        # {ip_address: [timestamp_of_each_request, ...]}
        self._history: dict = defaultdict(list)

    def is_rate_limited(self, ip: str) -> tuple[bool, int]:
        """
        Checks if an IP has exceeded the request rate limit.

        Args:
            ip: Source IP address string

        Returns:
            (is_limited, request_count_in_window)
            is_limited = True if the IP should be blocked for rate abuse
        """
        now = time.time()
        window_start = now - self.window_seconds

        # Add this request to history
        self._history[ip].append(now)

        # Remove timestamps outside the current window (sliding window)
        self._history[ip] = [
            ts for ts in self._history[ip]
            if ts >= window_start
        ]

        count = len(self._history[ip])
        return count > self.max_requests, count

    def get_request_count(self, ip: str) -> int:
        """Returns the current request count for an IP (without adding a new one)."""
        now = time.time()
        window_start = now - self.window_seconds
        return len([ts for ts in self._history.get(ip, []) if ts >= window_start])


# Global rate limiter instance (shared across all requests)
# 100 requests per 60 seconds per IP by default
rate_limiter = RateLimiter(window_seconds=60, max_requests=100)


# =============================================================================
# INSPECTION RESULT
# =============================================================================

def _make_result(
    is_suspicious: bool,
    attack_type:   str  = "None",
    reason:        str  = "",
    severity:      str  = "low",
    location:      str  = ""
) -> dict:
    """
    Helper to build a consistent inspection result dictionary.

    Args:
        is_suspicious: True if an attack pattern was found
        attack_type:   e.g. "SQL Injection", "XSS", "Path Traversal"
        reason:        Human-readable explanation of what was found
        severity:      "low" | "medium" | "high" | "critical"
        location:      Where in the request it was found

    Returns:
        Dict with consistent keys for all callers to use.
    """
    return {
        "is_suspicious": is_suspicious,
        "attack_type":   attack_type,
        "reason":        reason,
        "severity":      severity,
        "location":      location
    }


def _clean_result() -> dict:
    """Returns a result indicating no threat was found."""
    return _make_result(False, "None", "No suspicious patterns detected.", "low", "")


# =============================================================================
# INDIVIDUAL SCANNERS
# Each function inspects one specific part of the request.
# They return early (fast path) as soon as ONE match is found.
# =============================================================================

def check_method(method: str) -> dict:
    """
    Checks if the HTTP method is in the allowed list.

    Attackers sometimes use unusual methods (TRACE, CONNECT, PROPFIND)
    to probe server capabilities or exploit WebDAV vulnerabilities.

    Args:
        method: The HTTP method string (e.g. "GET", "POST")

    Returns:
        Inspection result dict
    """
    if method.upper() not in ALLOWED_METHODS:
        return _make_result(
            True,
            "Suspicious Method",
            f"HTTP method '{method}' is not in the allowed list: {ALLOWED_METHODS}",
            "medium",
            "http_method"
        )
    return _clean_result()


def check_request_size(body: bytes) -> dict:
    """
    Flags requests with abnormally large bodies.

    Oversized requests can indicate:
    - Buffer overflow attempts
    - DoS via resource exhaustion
    - Large payload injection

    Args:
        body: Raw request body bytes

    Returns:
        Inspection result dict
    """
    size = len(body) if body else 0

    if size > MAX_REQUEST_SIZE_BYTES:
        return _make_result(
            True,
            "Oversized Request",
            f"Request body size {size:,} bytes exceeds limit of "
            f"{MAX_REQUEST_SIZE_BYTES:,} bytes. Possible DoS or buffer overflow attempt.",
            "high",
            "request_body"
        )
    return _clean_result()


def check_user_agent(user_agent: str) -> dict:
    """
    Checks the User-Agent header against known attack tool signatures.

    Legitimate browsers have consistent, recognizable User-Agent strings.
    Attack tools like sqlmap, nikto, and nmap have distinctive signatures.

    Args:
        user_agent: The User-Agent header value

    Returns:
        Inspection result dict
    """
    if not user_agent:
        # Missing User-Agent is mildly suspicious (most browsers send one)
        return _make_result(
            True,
            "Missing User-Agent",
            "Request has no User-Agent header. Most legitimate browsers send this header.",
            "low",
            "headers"
        )

    for pattern in SUSPICIOUS_AGENT_PATTERNS:
        match = pattern.search(user_agent)
        if match:
            return _make_result(
                True,
                "Suspicious User-Agent",
                f"User-Agent matches known attack tool signature: '{match.group()}'",
                "high",
                "user_agent"
            )

    return _clean_result()


def check_url(url: str) -> dict:
    """
    Inspects the request URL for path traversal and other URL-based attacks.

    Decodes the URL first (handles both single and double encoding tricks).

    Args:
        url: Full request URL string

    Returns:
        Inspection result dict
    """
    # Decode URL encoding to catch evasion attempts like %2e%2e%2f
    decoded_url = unquote(unquote(url))  # Double decode catches double-encoding

    for pattern in PATH_TRAVERSAL_PATTERNS:
        match = pattern.search(decoded_url)
        if match:
            return _make_result(
                True,
                "Path Traversal",
                f"URL contains path traversal sequence: '{match.group()}'",
                "high",
                "url"
            )

    # Also run SQLi and XSS checks on the URL itself
    for pattern in SQL_INJECTION_PATTERNS:
        match = pattern.search(decoded_url)
        if match:
            return _make_result(
                True,
                "SQL Injection",
                f"SQL injection pattern detected in URL: '{match.group()}'",
                "critical",
                "url"
            )

    for pattern in XSS_PATTERNS:
        match = pattern.search(decoded_url)
        if match:
            return _make_result(
                True,
                "XSS",
                f"Cross-site scripting pattern detected in URL: '{match.group()}'",
                "high",
                "url"
            )

    return _clean_result()


def check_query_params(query_string: str) -> dict:
    """
    Inspects URL query parameters for injection attacks.

    Query parameters are the most common injection vector:
    e.g. /search?q=' UNION SELECT * FROM users--

    Decodes the query string before checking to catch encoding bypasses.

    Args:
        query_string: The raw query string (everything after '?')

    Returns:
        Inspection result dict
    """
    if not query_string:
        return _clean_result()

    # Decode URL encoding (handles + as space and %xx encoding)
    decoded = unquote_plus(query_string)

    # Check for all attack types in query parameters
    checks = [
        (SQL_INJECTION_PATTERNS,      "SQL Injection",      "critical"),
        (XSS_PATTERNS,                "XSS",                "high"),
        (COMMAND_INJECTION_PATTERNS,  "Command Injection",  "critical"),
        (PATH_TRAVERSAL_PATTERNS,     "Path Traversal",     "high"),
        (SHELLCODE_PATTERNS,          "Shellcode",          "critical"),
    ]

    for patterns, attack_type, severity in checks:
        for pattern in patterns:
            match = pattern.search(decoded)
            if match:
                return _make_result(
                    True,
                    attack_type,
                    f"{attack_type} pattern detected in query parameters: '{match.group()}'",
                    severity,
                    "query_params"
                )

    return _clean_result()


def check_headers(headers: dict) -> dict:
    """
    Inspects request headers for injection and manipulation attempts.

    Header injection (CRLF injection) can be used to:
    - Split HTTP responses (HTTP Response Splitting)
    - Inject arbitrary headers into responses
    - Bypass security controls

    Also checks Host header for suspicious values.

    Args:
        headers: Dict of header name → value

    Returns:
        Inspection result dict
    """
    # Headers where XSS payloads could realistically be injected and reflected.
    # We deliberately EXCLUDE "cookie" because cookie values are structured
    # key=value pairs that frequently contain word-like strings ("anonymous_id=",
    # "session_token=", etc.) which cause false positives with XSS patterns.
    XSS_SCAN_HEADERS = {"referer", "origin", "x-forwarded-host", "x-rewrite-url"}

    for header_name, header_value in headers.items():
        header_lower = header_name.lower()
        header_str   = str(header_value)

        # --- CRLF injection — check ALL headers ---
        # Any newline in a header = HTTP response splitting attempt
        for pattern in HEADER_INJECTION_PATTERNS:
            match = pattern.search(header_str)
            if match:
                return _make_result(
                    True,
                    "Header Injection",
                    f"CRLF injection detected in header '{header_name}': "
                    f"contains newline characters.",
                    "high",
                    f"header:{header_name}"
                )

        # --- XSS — only scan headers that carry reflected/rendered content ---
        # Skipping "cookie" prevents false positives on values like "anonymous_id="
        if header_lower in XSS_SCAN_HEADERS:
            for pattern in XSS_PATTERNS:
                match = pattern.search(header_str)
                if match:
                    return _make_result(
                        True,
                        "XSS",
                        f"XSS pattern detected in header '{header_name}': '{match.group()}'",
                        "high",
                        f"header:{header_name}"
                    )

    return _clean_result()


def check_body(body: bytes) -> dict:
    """
    Inspects the request body (POST/PUT payload) for attack content.

    The body is decoded from bytes → string before checking.
    Handles both UTF-8 and Latin-1 encoded bodies.

    Args:
        body: Raw request body as bytes

    Returns:
        Inspection result dict
    """
    if not body:
        return _clean_result()

    # Decode bytes → string (ignore errors to handle binary payloads)
    try:
        body_str = body.decode("utf-8", errors="ignore")
    except Exception:
        body_str = body.decode("latin-1", errors="ignore")

    # URL-decode the body too (form POST data is URL-encoded)
    decoded_body = unquote_plus(body_str)

    checks = [
        (SQL_INJECTION_PATTERNS,     "SQL Injection",     "critical"),
        (XSS_PATTERNS,               "XSS",               "high"),
        (COMMAND_INJECTION_PATTERNS, "Command Injection",  "critical"),
        (PATH_TRAVERSAL_PATTERNS,    "Path Traversal",    "high"),
        (SHELLCODE_PATTERNS,         "Shellcode",         "critical"),
    ]

    for patterns, attack_type, severity in checks:
        for pattern in patterns:
            match = pattern.search(decoded_body)
            if match:
                # Truncate the match for the log (avoid logging huge payloads)
                matched_text = match.group()[:100]
                return _make_result(
                    True,
                    attack_type,
                    f"{attack_type} pattern detected in request body: '{matched_text}'",
                    severity,
                    "request_body"
                )

    return _clean_result()


def check_rate_limit(ip: str) -> dict:
    """
    Checks if this IP is sending requests too fast (brute force / DoS).

    Uses the in-memory sliding window rate limiter.

    Args:
        ip: Source IP address

    Returns:
        Inspection result dict
    """
    is_limited, count = rate_limiter.is_rate_limited(ip)

    if is_limited:
        return _make_result(
            True,
            "Brute Force",
            f"IP {ip} sent {count} requests in the last "
            f"{rate_limiter.window_seconds} seconds "
            f"(limit: {rate_limiter.max_requests}). Possible brute force or DoS.",
            "critical",
            "rate_limiter"
        )

    return _clean_result()


# =============================================================================
# MAIN INSPECTION FUNCTION
# This is the only function the proxy_server.py needs to call.
# =============================================================================

def inspect(
    ip:           str,
    method:       str,
    url:          str,
    query_string: str,
    headers:      dict,
    body:         bytes
) -> dict:
    """
    Runs the full Deep Packet Inspection pipeline on an incoming request.

    Checks are ordered from cheapest to most expensive.
    Returns immediately (fast path) as soon as ONE attack is detected.

    Args:
        ip:           Source IP address (e.g. "203.0.113.42")
        method:       HTTP method (e.g. "GET", "POST")
        url:          Full request URL
        query_string: Query string portion of the URL (after '?')
        headers:      Dict of HTTP headers {name: value}
        body:         Raw request body bytes (may be empty)

    Returns:
        Dict with keys:
        {
            "is_suspicious": bool,
            "attack_type":   str,
            "reason":        str,
            "severity":      str,   # "low" | "medium" | "high" | "critical"
            "location":      str    # where in the request the pattern was found
        }

    Example (attack detected):
        {
            "is_suspicious": True,
            "attack_type":   "SQL Injection",
            "reason":        "SQL pattern detected in query params: 'UNION SELECT'",
            "severity":      "critical",
            "location":      "query_params"
        }

    Example (clean request):
        {
            "is_suspicious": False,
            "attack_type":   "None",
            "reason":        "No suspicious patterns detected.",
            "severity":      "low",
            "location":      ""
        }
    """

    # --- 1. Rate limit check (fastest — just a counter lookup) ---
    result = check_rate_limit(ip)
    if result["is_suspicious"]:
        logger.warning(f"[DPI] Rate limit exceeded | IP: {ip}")
        return result

    # --- 2. HTTP Method check ---
    result = check_method(method)
    if result["is_suspicious"]:
        logger.warning(f"[DPI] Suspicious method | IP: {ip} | Method: {method}")
        return result

    # --- 3. Request size check ---
    result = check_request_size(body)
    if result["is_suspicious"]:
        logger.warning(f"[DPI] Oversized request | IP: {ip} | Size: {len(body)}")
        return result

    # --- 4. User-Agent check ---
    user_agent = headers.get("user-agent", headers.get("User-Agent", ""))
    result = check_user_agent(user_agent)
    if result["is_suspicious"]:
        logger.warning(f"[DPI] Suspicious User-Agent | IP: {ip} | UA: {user_agent[:80]}")
        return result

    # --- 5. URL / Path check ---
    result = check_url(url)
    if result["is_suspicious"]:
        logger.warning(f"[DPI] Suspicious URL | IP: {ip} | URL: {url[:100]}")
        return result

    # --- 6. Query parameter check ---
    result = check_query_params(query_string)
    if result["is_suspicious"]:
        logger.warning(f"[DPI] Suspicious query params | IP: {ip}")
        return result

    # --- 7. Header check ---
    result = check_headers(headers)
    if result["is_suspicious"]:
        logger.warning(f"[DPI] Suspicious header | IP: {ip}")
        return result

    # --- 8. Body check (most expensive — last) ---
    result = check_body(body)
    if result["is_suspicious"]:
        logger.warning(f"[DPI] Suspicious body | IP: {ip}")
        return result

    # All checks passed — request appears clean
    return _clean_result()


# =============================================================================
# SELF-TEST
# Run directly to verify all patterns work:
#   python proxy/packet_inspector.py
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("=" * 60)
    print("Deep Packet Inspection — Self Test")
    print("=" * 60)

    # Each test: (description, call, expect_suspicious)
    tests = [

        # --- SQL Injection ---
        ("SQLi in query params",
         lambda: check_query_params("id=1' UNION SELECT username,password FROM users--"),
         True),

        ("SQLi SLEEP (blind)",
         lambda: check_query_params("id=1; SLEEP(5)--"),
         True),

        # --- XSS ---
        ("XSS script tag in body",
         lambda: check_body(b"name=<script>alert('xss')</script>"),
         True),

        ("XSS event handler",
         lambda: check_query_params("q=<img onerror=alert(1) src=x>"),
         True),

        # --- Command Injection ---
        ("Command injection in body",
         lambda: check_body(b"file=report.pdf; cat /etc/passwd"),
         True),

        ("Command substitution",
         lambda: check_query_params("cmd=$(whoami)"),
         True),

        # --- Path Traversal ---
        ("Path traversal in URL",
         lambda: check_url("/files/../../../../etc/passwd"),
         True),

        ("Encoded path traversal",
         lambda: check_url("/files/%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
         True),

        # --- Suspicious User-Agent ---
        ("sqlmap User-Agent",
         lambda: check_user_agent("sqlmap/1.7.8#stable (https://sqlmap.org)"),
         True),

        ("Nikto scanner",
         lambda: check_user_agent("Mozilla/5.0 (Nikto/2.1.6)"),
         True),

        # --- Header Injection ---
        ("CRLF header injection",
         lambda: check_headers({"X-Custom": "value\r\nSet-Cookie: admin=true"}),
         True),

        # --- Oversized request ---
        ("Oversized body",
         lambda: check_request_size(b"A" * (MAX_REQUEST_SIZE_BYTES + 1)),
         True),

        # --- Legitimate requests (should NOT be flagged) ---
        ("Normal GET search",
         lambda: check_query_params("q=how+to+bake+chocolate+cake"),
         False),

        ("Normal User-Agent",
         lambda: check_user_agent(
             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
             "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
         ),
         False),

        ("Normal POST body",
         lambda: check_body(b"username=alice&password=secret123"),
         False),
    ]

    passed = 0
    failed = 0

    for description, test_fn, expect_suspicious in tests:
        result = test_fn()
        actual = result["is_suspicious"]
        ok     = actual == expect_suspicious

        status = "✓ PASS" if ok else "✗ FAIL"
        flag   = "BLOCKED" if actual else "ALLOWED"
        print(f"  {status} | {flag} | {description}")

        if not ok:
            print(f"         Expected suspicious={expect_suspicious}, "
                  f"got suspicious={actual}")
            print(f"         Reason: {result['reason']}")

        if ok:
            passed += 1
        else:
            failed += 1

    print()
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("=" * 60)