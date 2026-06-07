# =============================================================================
# config.py — Central Configuration for Zero Trust Proxy
# =============================================================================
# All settings live here. No magic numbers buried in other files.
# To customize the system, only this file needs to change.
# =============================================================================

import os

# -----------------------------------------------------------------------------
# PROXY SETTINGS
# The proxy is the security gateway that sits in front of your app.
# -----------------------------------------------------------------------------

# Port the proxy listens on (users connect here)
PROXY_HOST = "0.0.0.0"
PROXY_PORT = 8000

# The real application the proxy protects (traffic is forwarded here if safe)
BACKEND_URL = "http://localhost:8001"

# How long (seconds) to wait for backend to respond before timing out
BACKEND_TIMEOUT = 10

# -----------------------------------------------------------------------------
# DATABASE SETTINGS
# SQLite is a single-file database — no server needed.
# -----------------------------------------------------------------------------

# Path to the SQLite database file (created automatically on first run)
DB_PATH = os.path.join(os.path.dirname(__file__), "database", "proxy.db")

# -----------------------------------------------------------------------------
# MACHINE LEARNING SETTINGS
# Controls how aggressively the ML model blocks traffic.
# -----------------------------------------------------------------------------

# Confidence threshold for the attack classifier (Random Forest)
# If model says "this is an attack" with confidence > this value → block
# Range: 0.0 to 1.0 | Higher = less sensitive | Lower = more sensitive
CONFIDENCE_THRESHOLD = 0.70

# Isolation Forest anomaly threshold
# Requests with anomaly score below this value are flagged as Zero-Day
# Range: typically -0.5 to 0.5 | More negative = stricter (fewer false positives)
# Set to -0.3 so only strongly anomalous traffic (not normal HTTP requests
# with sparse features) triggers a Zero-Day flag.
ANOMALY_THRESHOLD = -0.3

# Path to saved model files (populated after running ml/train_model.py)
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
CLASSIFIER_MODEL_PATH = os.path.join(MODELS_DIR, "attack_classifier.pkl")
ANOMALY_MODEL_PATH    = os.path.join(MODELS_DIR, "anomaly_detector.pkl")
SCALER_PATH           = os.path.join(MODELS_DIR, "scaler.pkl")
LABEL_ENCODER_PATH    = os.path.join(MODELS_DIR, "label_encoder.pkl")

# Path to the UNSW-NB15 dataset CSV files
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# -----------------------------------------------------------------------------
# EMAIL / ALERT SETTINGS
# Admin receives an email whenever the proxy blocks an attack.
# Use Gmail App Passwords or any SMTP provider.
# -----------------------------------------------------------------------------

SMTP_HOST     = "smtp.gmail.com"
SMTP_PORT     = 587
SMTP_USERNAME = "your_email@gmail.com"       # ← change this
SMTP_PASSWORD = "your_app_password_here"     # ← change this (use App Password)
ADMIN_EMAIL   = "admin@example.com"          # ← where alerts are sent
ALERT_FROM    = "ZeroTrustProxy <your_email@gmail.com>"  # ← sender display name

# Set to False to disable email alerts (useful during development/testing)
EMAIL_ALERTS_ENABLED = False

# -----------------------------------------------------------------------------
# ZERO TRUST POLICY
# These define what the proxy considers "safe" vs "dangerous".
# -----------------------------------------------------------------------------

# HTTP methods that are allowed through at all
ALLOWED_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# Maximum allowed request body size in bytes (10 KB default)
# Requests larger than this are flagged as suspicious
MAX_REQUEST_SIZE_BYTES = 10_000

# If an IP has been blocked before, instantly re-block without re-inspecting
INSTANT_REBLOCK_KNOWN_ATTACKERS = True

# -----------------------------------------------------------------------------
# DASHBOARD SETTINGS
# -----------------------------------------------------------------------------

# Number of recent alerts to show in the dashboard table
DASHBOARD_RECENT_ALERTS_LIMIT = 50

# Live traffic log file — proxy appends one JSON line per request
# Dashboard tail-reads this file for the live packet feed
TRAFFIC_LOG_PATH = os.path.join(os.path.dirname(__file__), "database", "traffic.log")

# Maximum lines to keep in the live traffic display
TRAFFIC_LOG_DISPLAY_LINES = 100