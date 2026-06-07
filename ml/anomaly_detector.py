# =============================================================================
# ml/anomaly_detector.py — Zero-Day Detection via Isolation Forest
# =============================================================================
# This module handles TWO responsibilities:
#
#   1. TRAINING (run once):
#      train_anomaly_detector() — trains Isolation Forest on Normal traffic
#      only, then saves the model to models/anomaly_detector.pkl
#
#   2. RUNTIME (called on every request):
#      AnomalyDetector.score(features) — returns anomaly score + verdict
#
# Why Isolation Forest?
#   - Unsupervised: no labels needed — only learns "what normal looks like"
#   - Efficient: O(n log n) training, O(log n) inference
#   - Interpretable score: -1.0 (extreme anomaly) to +1.0 (very normal)
#   - Specifically designed for high-dimensional anomaly detection
#
# Zero Trust principle applied here:
#   "If traffic doesn't look like anything we've seen before → block it."
# =============================================================================

import os
import sys
import pickle
import logging
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import (
    DATA_DIR, MODELS_DIR,
    ANOMALY_MODEL_PATH, SCALER_PATH,
    ANOMALY_THRESHOLD
)

logger = logging.getLogger("anomaly_detector")

# Path to save the anomaly scaler separately
# (we use a different scaler than the classifier — different training data)
ANOMALY_SCALER_PATH = os.path.join(MODELS_DIR, "anomaly_scaler.pkl")

# The features used for anomaly detection
# We use a focused subset — these are the most informative for detecting
# behavioral deviations in network traffic
ANOMALY_FEATURES = [
    "dur",          # Connection duration
    "spkts",        # Source packet count
    "dpkts",        # Destination packet count
    "sbytes",       # Source bytes
    "dbytes",       # Destination bytes
    "rate",         # Packets per second
    "sttl",         # Source TTL
    "dttl",         # Destination TTL
    "sload",        # Source load
    "dload",        # Destination load
    "sinpkt",       # Source inter-packet time
    "dinpkt",       # Destination inter-packet time
    "smean",        # Mean source packet size
    "dmean",        # Mean destination packet size
    "ct_srv_src",   # Same service/source connection count
    "ct_dst_ltm",   # Destination connection count
    "ct_src_ltm",   # Source connection count
]


# =============================================================================
# TRAINING FUNCTION (run once via train_model.py or standalone)
# =============================================================================

def train_anomaly_detector(df_path: str = None) -> None:
    """
    Trains an Isolation Forest on NORMAL traffic only.

    This teaches the model what legitimate traffic looks like.
    At runtime, any request that deviates significantly from this
    learned profile is flagged as a potential Zero-Day attack.

    Args:
        df_path: Optional path to a CSV file. If None, loads from data/.

    Saves:
        models/anomaly_detector.pkl  — the trained Isolation Forest
        models/anomaly_scaler.pkl    — the scaler fitted on Normal traffic
    """
    logger.info("=" * 60)
    logger.info("Training Anomaly Detector (Isolation Forest)")
    logger.info("=" * 60)

    # -------------------------------------------------------------------------
    # Step 1: Load the dataset
    # -------------------------------------------------------------------------
    if df_path is None:
        train_path = os.path.join(DATA_DIR, "UNSW_NB15_training-set.csv")
        test_path  = os.path.join(DATA_DIR, "UNSW_NB15_testing-set.csv")

        frames = []
        for p in [train_path, test_path]:
            if os.path.exists(p):
                frames.append(pd.read_csv(p, low_memory=False))
                logger.info(f"Loaded: {p}")

        if not frames:
            raise FileNotFoundError(
                "No CSV files found in data/. "
                "Download UNSW_NB15_training-set.csv first."
            )

        df = pd.concat(frames, ignore_index=True)
    else:
        df = pd.read_csv(df_path, low_memory=False)

    # Normalize column names
    df.columns = [c.strip().lower() for c in df.columns]

    logger.info(f"Total rows loaded: {len(df):,}")

    # -------------------------------------------------------------------------
    # Step 2: Filter to NORMAL traffic only
    # -------------------------------------------------------------------------
    # Find the label column (might be "attack_cat" or "label")
    label_col = None
    for candidate in ["attack_cat", "label", "category"]:
        if candidate in df.columns:
            label_col = candidate
            break

    if label_col is None:
        raise ValueError("Cannot find label column in dataset.")

    # Clean the label column
    df[label_col] = (
        df[label_col]
        .fillna("Normal")
        .astype(str)
        .str.strip()
        .str.capitalize()
    )

    # Keep only Normal rows for training
    normal_df = df[df[label_col] == "Normal"].copy()
    logger.info(f"Normal traffic rows: {len(normal_df):,} / {len(df):,} total")

    if len(normal_df) < 100:
        raise ValueError(
            f"Only {len(normal_df)} Normal rows found. "
            "Need at least 100 to train the anomaly detector."
        )

    # -------------------------------------------------------------------------
    # Step 3: Select and prepare features
    # -------------------------------------------------------------------------
    # Keep only feature columns that exist in the dataset
    available = [f for f in ANOMALY_FEATURES if f in normal_df.columns]
    missing   = [f for f in ANOMALY_FEATURES if f not in normal_df.columns]

    if missing:
        logger.warning(f"Missing features (skipped): {missing}")

    logger.info(f"Using {len(available)} features for anomaly detection.")

    X_normal = normal_df[available].copy()

    # Fill NaN values with the column median
    X_normal = X_normal.fillna(X_normal.median(numeric_only=True))
    X_normal = X_normal.values.astype(np.float32)

    # -------------------------------------------------------------------------
    # Step 4: Scale the features
    # -------------------------------------------------------------------------
    # Isolation Forest is distance-based internally, so scaling matters.
    # We fit the scaler on Normal traffic only — same data we train on.
    logger.info("Fitting scaler on Normal traffic...")
    anomaly_scaler = StandardScaler()
    X_scaled = anomaly_scaler.fit_transform(X_normal)

    # -------------------------------------------------------------------------
    # Step 5: Train Isolation Forest
    # -------------------------------------------------------------------------
    logger.info("Training Isolation Forest...")

    # contamination: expected fraction of anomalies in training data.
    # Since we filtered to Normal only, this should be very low.
    # "auto" lets sklearn decide based on the data.
    #
    # n_estimators=200: more trees = more stable anomaly scores
    # max_samples="auto": uses min(256, n_samples) sub-samples per tree
    # random_state=42: reproducible results

    iso_forest = IsolationForest(
        n_estimators=200,       # Number of isolation trees
        max_samples="auto",     # Samples per tree (auto = min(256, n))
        contamination=0.01,     # Expected anomaly rate in training data (~1%)
        random_state=42,
        n_jobs=-1,              # Use all CPU cores
        verbose=1
    )

    iso_forest.fit(X_scaled)
    logger.info("Isolation Forest training complete.")

    # -------------------------------------------------------------------------
    # Step 6: Validate — score some Normal samples
    # -------------------------------------------------------------------------
    # Sanity check: most Normal samples should score above ANOMALY_THRESHOLD
    sample_scores = iso_forest.score_samples(X_scaled[:1000])
    pct_above = np.mean(sample_scores > ANOMALY_THRESHOLD) * 100
    logger.info(
        f"Validation: {pct_above:.1f}% of Normal samples score above "
        f"threshold {ANOMALY_THRESHOLD} (expect >80%)"
    )

    # -------------------------------------------------------------------------
    # Step 7: Save model and scaler
    # -------------------------------------------------------------------------
    os.makedirs(MODELS_DIR, exist_ok=True)

    with open(ANOMALY_MODEL_PATH, "wb") as f:
        pickle.dump(iso_forest, f)
    logger.info(f"Saved anomaly model: {ANOMALY_MODEL_PATH}")

    with open(ANOMALY_SCALER_PATH, "wb") as f:
        pickle.dump(anomaly_scaler, f)
    logger.info(f"Saved anomaly scaler: {ANOMALY_SCALER_PATH}")

    # Also save the feature list so runtime knows which features to use
    feature_list_path = os.path.join(MODELS_DIR, "anomaly_features.pkl")
    with open(feature_list_path, "wb") as f:
        pickle.dump(available, f)
    logger.info(f"Saved anomaly feature list: {feature_list_path}")

    logger.info("Anomaly detector training complete!")


# =============================================================================
# RUNTIME CLASS
# =============================================================================

class AnomalyDetector:
    """
    Loads the trained Isolation Forest and scores live requests at runtime.

    Usage:
        from ml.anomaly_detector import anomaly_detector
        result = anomaly_detector.score(feature_dict)

    score() returns a dict like:
        {
            "is_anomaly":    True,
            "anomaly_score": -0.35,
            "verdict":       "Zero-Day",
            "reason":        "Traffic significantly deviates from...",
            "available":     True
        }
    """

    def __init__(self):
        self.model         = None
        self.scaler        = None
        self.feature_names = None
        self.available     = False

        self._load()

    def _load(self):
        """
        Loads the Isolation Forest model, scaler, and feature list from disk.
        Sets self.available = True only if ALL artifacts load successfully.
        """
        feature_list_path = os.path.join(MODELS_DIR, "anomaly_features.pkl")

        required = {
            "model":    ANOMALY_MODEL_PATH,
            "scaler":   ANOMALY_SCALER_PATH,
            "features": feature_list_path,
        }

        for name, path in required.items():
            if not os.path.exists(path):
                logger.warning(
                    f"Anomaly model artifact missing: {path}. "
                    "Run 'python ml/anomaly_detector.py' to train."
                )
                return

        try:
            with open(required["model"], "rb") as f:
                self.model = pickle.load(f)

            with open(required["scaler"], "rb") as f:
                self.scaler = pickle.load(f)

            with open(required["features"], "rb") as f:
                self.feature_names = pickle.load(f)

            self.available = True
            logger.info(
                f"Anomaly detector loaded. "
                f"Features: {len(self.feature_names)} | "
                f"Threshold: {ANOMALY_THRESHOLD}"
            )

        except Exception as e:
            logger.error(f"Failed to load anomaly model: {e}")

    def score(self, raw_features: dict) -> dict:
        """
        Scores a single request for anomalousness.

        The Isolation Forest returns a raw anomaly score per sample:
          - High positive score (e.g. +0.3): very normal-looking traffic
          - Score near 0:                    borderline
          - Negative score (e.g. -0.4):      anomalous — doesn't fit normal pattern

        We compare against ANOMALY_THRESHOLD from config.py.

        Args:
            raw_features: Dict of feature_name → value
                          (same format as attack_detector.extract_features_from_request)

        Returns:
            Dict:
            {
                "is_anomaly":    bool,   # True = block as Zero-Day
                "anomaly_score": float,  # Raw score from Isolation Forest
                "verdict":       str,    # "Normal" or "Zero-Day"
                "reason":        str,    # Human-readable explanation
                "available":     bool    # False if model not loaded
            }
        """
        # If model isn't loaded, don't block (let other layers decide)
        if not self.available:
            return {
                "is_anomaly":    False,
                "anomaly_score": 0.0,
                "verdict":       "Unknown",
                "reason":        "Anomaly model not available.",
                "available":     False
            }

        try:
            # Build the feature vector in the correct order
            vector = self._build_vector(raw_features)

            # Scale using the anomaly-specific scaler
            vector_scaled = self.scaler.transform([vector])

            # score_samples() returns the raw anomaly score
            # Lower = more anomalous
            raw_score = float(self.model.score_samples(vector_scaled)[0])

            # Decision: is this anomalous?
            is_anomaly = raw_score < ANOMALY_THRESHOLD

            if is_anomaly:
                verdict = "Zero-Day"
                reason  = self._build_zero_day_reason(raw_score, raw_features)
            else:
                verdict = "Normal"
                reason  = "Traffic pattern is consistent with normal behavior."

            return {
                "is_anomaly":    is_anomaly,
                "anomaly_score": raw_score,
                "verdict":       verdict,
                "reason":        reason,
                "available":     True
            }

        except Exception as e:
            logger.error(f"Anomaly scoring error: {e}")
            return {
                "is_anomaly":    False,
                "anomaly_score": 0.0,
                "verdict":       "Unknown",
                "reason":        f"Scoring error: {str(e)}",
                "available":     False
            }

    def _build_vector(self, raw_features: dict) -> list:
        """
        Converts raw feature dict to a numeric list in the exact order
        the anomaly model expects.

        Missing features are filled with 0.
        Non-numeric values are cast to float (defaulting to 0 on failure).
        """
        vector = []
        for feature in self.feature_names:
            val = raw_features.get(feature, 0)
            try:
                vector.append(float(val))
            except (TypeError, ValueError):
                vector.append(0.0)
        return vector

    def _build_zero_day_reason(self, score: float, features: dict) -> str:
        """
        Builds a human-readable explanation for a zero-day detection.

        The explanation mentions which specific measurements were unusual,
        making it easier to understand WHY the traffic was flagged.

        Args:
            score:    The raw Isolation Forest score (negative = anomalous)
            features: The raw feature dict for this request

        Returns:
            A sentence explaining the anomaly for the admin alert email.
        """
        # Severity label based on how anomalous the score is
        if score < -0.4:
            severity = "severely"
        elif score < -0.2:
            severity = "significantly"
        else:
            severity = "moderately"

        # Find which features look unusual by checking extreme values
        unusual_aspects = []

        sbytes = features.get("sbytes", 0)
        if sbytes > 50_000:
            unusual_aspects.append(f"unusually large payload ({int(sbytes):,} bytes)")

        rate = features.get("rate", 1)
        if rate > 100:
            unusual_aspects.append(f"very high request rate ({rate:.0f} req/s)")

        dur = features.get("dur", 0)
        if dur < 0.001 and dur > 0:
            unusual_aspects.append("extremely short connection duration")

        spkts = features.get("spkts", 0)
        if spkts > 500:
            unusual_aspects.append(f"abnormal packet count ({int(spkts):,})")

        # Build the explanation sentence
        base = (
            f"Traffic pattern {severity} deviates from normal behavior "
            f"(anomaly score: {score:.3f}, threshold: {ANOMALY_THRESHOLD})."
        )

        if unusual_aspects:
            detail = " Unusual signals: " + ", ".join(unusual_aspects) + "."
        else:
            detail = (
                " The overall traffic profile does not match any known "
                "normal user behavior pattern."
            )

        policy = (
            " Blocked according to Zero Trust policy: "
            "unknown suspicious traffic is denied by default."
        )

        return base + detail + policy


# =============================================================================
# SINGLETON
# Loaded once at import time. Used by proxy_server.py
# =============================================================================

anomaly_detector = AnomalyDetector()


# =============================================================================
# STANDALONE — Run this file directly to train the anomaly model:
#   python ml/anomaly_detector.py
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    train_anomaly_detector()