# =============================================================================
# app.py — Main Entry Point
# =============================================================================
# Run this file to start the Zero Trust AI Security Proxy.
#
# Usage:
#   python app.py
#
# What it does:
#   - Starts the FastAPI proxy on PROXY_HOST:PROXY_PORT (default 0.0.0.0:8000)
#   - The proxy will inspect and forward/block all incoming HTTP requests
#
# Before running:
#   1. pip install -r requirements.txt
#   2. python ml/train_model.py         (needs UNSW-NB15 dataset in data/)
#   3. python ml/anomaly_detector.py    (trains on Normal traffic only)
#   4. python app.py                    (starts the proxy)
#
# In a separate terminal, start the dashboard:
#   streamlit run dashboard/dashboard.py
# =============================================================================

import uvicorn
from config import PROXY_HOST, PROXY_PORT

if __name__ == "__main__":
    print("=" * 60)
    print("  Zero Trust AI Security Proxy")
    print("=" * 60)
    print(f"  Proxy:     http://{PROXY_HOST}:{PROXY_PORT}")
    print(f"  Health:    http://localhost:{PROXY_PORT}/proxy-health")
    print(f"  Dashboard: streamlit run dashboard/dashboard.py")
    print("=" * 60)

    uvicorn.run(
        "proxy.proxy_server:app",
        host     = PROXY_HOST,
        port     = PROXY_PORT,
        reload   = False,   # Set True during development for auto-reload
        workers  = 1,       # Single worker keeps in-memory rate limiter consistent
        log_level = "info"
    )