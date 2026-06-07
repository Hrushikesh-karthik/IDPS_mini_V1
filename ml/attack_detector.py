# =============================================================================
# ml/attack_detector.py — Runtime Attack Classifier
# =============================================================================
# This module loads the trained Random Forest model and uses it to classify
# live HTTP requests arriving at the proxy.
#
# It is NOT a training script — it just loads the saved .pkl files and
# exposes a single function: detect(features) → result dict
#
# Called by proxy_server.py on every incoming request.
# =============================================================================

import os
import sys
import pickle
import logging
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import (
    CLASSIFIER_MODEL_PATH, SCALER_PATH, LABEL_ENCODER_PATH,
    MODELS_DIR, CONFIDENCE_THRESHOLD
)

logger = logging.getLogger("attack_detector")


# =============================================================================
# MODEL LOADER
# =============================================================================

class AttackDetector:
    """
    Wraps the trained Random Forest classifier for runtime use.

    Loaded once at proxy startup (expensive operation).
    detect() called on every request (cheap — just matrix multiply).

    Attributes:
        model:         RandomForestClassifier
        scaler:        StandardScaler (same one used during training)
        label_encoder: LabelEncoder (maps integers back to class names)
        feature_names: Ordered list of feature columns expected by the model
        cat_encoders:  Dict of LabelEncoders for categorical features
        loaded:        True if all artifacts loaded successfully
    """

    def __init__(self):
        self.model         = None
        self.scaler        = None
        self.label_encoder = None
        self.feature_names = None
        self.cat_encoders  = {}
        self.loaded        = False

        self._load_artifacts()

    def _load_artifacts(self):
        """
        Loads all saved .pkl files from the models/ directory.
        Sets self.loaded = True only if ALL files load successfully.
        """
        required_files = {
            "model":         CLASSIFIER_MODEL_PATH,
            "scaler":        SCALER_PATH,
            "label_encoder": LABEL_ENCODER_PATH,
            "feature_names": os.path.join(MODELS_DIR, "feature_names.pkl"),
            "cat_encoders":  os.path.join(MODELS_DIR, "cat_encoders.pkl"),
        }

        # Check all files exist before loading
        for name, path in required_files.items():
            if not os.path.exists(path):
                logger.warning(
                    f"Model artifact not found: {path}\n"
                    f"Run 'python ml/train_model.py' first to train the model."
                )
                return

        # Load each artifact
        try:
            with open(required_files["model"], "rb") as f:
                self.model = pickle.load(f)

            with open(required_files["scaler"], "rb") as f:
                self.scaler = pickle.load(f)

            with open(required_files["label_encoder"], "rb") as f:
                self.label_encoder = pickle.load(f)

            with open(required_files["feature_names"], "rb") as f:
                self.feature_names = pickle.load(f)

            with open(required_files["cat_encoders"], "rb") as f:
                self.cat_encoders = pickle.load(f)

            self.loaded = True
            logger.info(
                f"Attack detector loaded. "
                f"Classes: {list(self.label_encoder.classes_)} | "
                f"Features: {len(self.feature_names)}"
            )

        except Exception as e:
            logger.error(f"Failed to load model artifacts: {e}")

    def detect(self, raw_features: dict) -> dict:
        """
        Classifies a single request using the trained Random Forest.

        Args:
            raw_features: Dict mapping feature names to their values.
                          Keys should match those in self.feature_names.
                          Missing keys are filled with 0.

                          Example:
                          {
                            "dur": 0.5,
                            "sbytes": 1200,
                            "proto": "tcp",
                            "service": "http",
                            ...
                          }

        Returns:
            Dict with keys:
            {
                "prediction":  "Normal" | "SQL Injection" | "DoS" | ...,
                "confidence":  0.0–1.0,    # probability of top class
                "is_attack":   True/False, # True if above threshold
                "all_probs":   {class: prob, ...}  # full probability vector
                "ml_available": True/False # False if model not loaded
            }
        """
        # If model failed to load, return safe default (let other checks handle it)
        if not self.loaded:
            return {
                "prediction":   "Unknown",
                "confidence":   0.0,
                "is_attack":    False,
                "all_probs":    {},
                "ml_available": False
            }

        try:
            # Build feature vector in the exact order the model expects
            feature_vector = self._build_feature_vector(raw_features)

            # Scale the features using the same scaler from training
            feature_vector_scaled = self.scaler.transform([feature_vector])

            # Get class probabilities from all 100 trees
            # Shape: (1, n_classes) — e.g. [[0.01, 0.02, 0.92, ...]]
            proba = self.model.predict_proba(feature_vector_scaled)[0]

            # Find the class with the highest probability
            top_class_idx  = np.argmax(proba)
            top_confidence = float(proba[top_class_idx])
            top_class_name = self.label_encoder.inverse_transform([top_class_idx])[0]

            # Build a readable probability dict for all classes
            all_probs = {
                self.label_encoder.inverse_transform([i])[0]: float(p)
                for i, p in enumerate(proba)
            }

            # Is this an attack?
            # Two conditions must both be true:
            # 1. The predicted class is not "Normal"
            # 2. Confidence is above the configured threshold
            is_attack = (
                top_class_name != "Normal" and
                top_confidence >= CONFIDENCE_THRESHOLD
            )

            return {
                "prediction":   top_class_name,
                "confidence":   top_confidence,
                "is_attack":    is_attack,
                "all_probs":    all_probs,
                "ml_available": True
            }

        except Exception as e:
            logger.error(f"Detection error: {e}")
            return {
                "prediction":   "Unknown",
                "confidence":   0.0,
                "is_attack":    False,
                "all_probs":    {},
                "ml_available": False
            }

    def _build_feature_vector(self, raw_features: dict) -> list:
        """
        Converts a raw feature dict into a numeric vector in the correct order.

        Handles:
        - Categorical features (proto, service, state) → encoded integers
        - Missing features → filled with 0
        - Unknown categorical values → encoded as 0 (unseen label)

        Args:
            raw_features: Dict of feature name → value

        Returns:
            List of floats in the same order as self.feature_names
        """
        vector = []

        for feature in self.feature_names:
            value = raw_features.get(feature, 0)

            # If this is a categorical feature, encode it as the model expects
            if feature in self.cat_encoders:
                encoder = self.cat_encoders[feature]
                str_value = str(value).lower().strip()

                # Handle unseen labels gracefully (don't crash on new protocols)
                if str_value in encoder.classes_:
                    encoded = encoder.transform([str_value])[0]
                else:
                    encoded = 0  # Default for unknown categories

                vector.append(float(encoded))
            else:
                # Numeric feature — just cast to float
                try:
                    vector.append(float(value))
                except (TypeError, ValueError):
                    vector.append(0.0)

        return vector

    def get_feature_names(self) -> list:
        """Returns the list of features the model was trained on."""
        return self.feature_names or []


# =============================================================================
# FEATURE EXTRACTOR
# Converts a raw HTTP request object into the feature dict the model expects.
# =============================================================================

def extract_features_from_request(
    ip: str,
    method: str,
    url: str,
    headers: dict,
    body: bytes,
    duration_ms: float = 0.0
) -> dict:
    """
    Maps properties of an HTTP request to the numeric features the ML model
    was trained on (UNSW-NB15 network flow features).

    This is an approximation — the UNSW-NB15 dataset captures raw network
    packets, but we only have HTTP-layer data at the proxy. We do our best
    to extract equivalent signals.

    Args:
        ip:          Source IP address string
        method:      HTTP method ("GET", "POST", etc.)
        url:         Full request URL
        headers:     Dict of HTTP headers
        body:        Raw request body bytes
        duration_ms: Request processing time in milliseconds (optional)

    Returns:
        Dict mapping feature names to numeric values
    """
    body_size   = len(body) if body else 0
    header_size = sum(len(k) + len(v) for k, v in headers.items())
    url_length  = len(url)
    num_params  = url.count("&") + (1 if "?" in url else 0)

    # Map HTTP method to a numeric code
    method_code = {
        "GET": 0, "POST": 1, "PUT": 2, "DELETE": 3,
        "PATCH": 4, "HEAD": 5, "OPTIONS": 6
    }.get(method.upper(), 7)

    # Try to extract protocol from URL scheme
    proto = "tcp"  # HTTP always uses TCP

    # Infer service from port or URL scheme
    if url.startswith("https"):
        service = "ssl"
    else:
        service = "http"

    return {
        # Connection properties
        "dur":     duration_ms / 1000.0,  # Convert ms to seconds
        "proto":   proto,
        "service": service,
        "state":   "CON",                  # Active connection

        # Traffic volume
        "spkts":   1,                      # 1 packet per HTTP request
        "dpkts":   0,                      # Response not measured yet
        "sbytes":  body_size + header_size + url_length,
        "dbytes":  0,

        # Rate signals
        "rate":    1.0,                    # 1 request in this window
        "sttl":    64,                     # Default TTL for most OS
        "dttl":    64,

        # Load
        "sload":   float(body_size * 8),  # Approximate bits sent
        "dload":   0.0,

        # Timing
        "sinpkt":  float(duration_ms),
        "dinpkt":  0.0,

        # Packet size averages
        "smean":   float(body_size + header_size),
        "dmean":   0.0,

        # Connection count features (approximated from request characteristics)
        # These are normally tracked over time windows — we use request signals
        "ct_srv_src":        num_params,    # Params ~ distinct service calls
        "ct_dst_ltm":        1,
        "ct_src_ltm":        1,
        "ct_src_dport_ltm":  method_code,  # Encode HTTP method
        "ct_dst_sport_ltm":  0,
        "ct_dst_src_ltm":    1,
    }


# =============================================================================
# SINGLETON INSTANCE
# Loaded once at module import time.
# All other modules just do: from ml.attack_detector import detector
# =============================================================================

detector = AttackDetector()