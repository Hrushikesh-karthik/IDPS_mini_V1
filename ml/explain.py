# =============================================================================
# ml/explain.py — Explainable AI with SHAP
# =============================================================================
# This module answers the question:
#   "WHY did the model block this request?"
#
# It uses SHAP (SHapley Additive exPlanations) to calculate how much each
# feature contributed to the model's decision, then converts those numbers
# into plain English for the admin alert email.
#
# SHAP works by asking:
#   "If we remove this feature, how much does the prediction change?"
#   Features that change it a lot → high importance → mentioned in explanation
#
# Example output:
#   "Blocked as DoS attack (confidence: 94%).
#    Top signals: high packet rate (rate=847), large source bytes (sbytes=98234),
#    short connection duration (dur=0.001)."
# =============================================================================

import os
import sys
import logging
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

logger = logging.getLogger("explain")

# Human-readable descriptions for each feature
# Used to build natural language explanations
FEATURE_DESCRIPTIONS = {
    "dur":               "connection duration",
    "proto":             "network protocol",
    "service":           "service type",
    "state":             "connection state",
    "spkts":             "packets sent by source",
    "dpkts":             "packets sent by destination",
    "sbytes":            "bytes sent by source",
    "dbytes":            "bytes sent by destination",
    "rate":              "packet rate (packets/sec)",
    "sttl":              "source time-to-live",
    "dttl":              "destination time-to-live",
    "sload":             "source traffic load",
    "dload":             "destination traffic load",
    "sinpkt":            "source inter-packet time",
    "dinpkt":            "destination inter-packet time",
    "smean":             "mean source packet size",
    "dmean":             "mean destination packet size",
    "ct_srv_src":        "connection count (same service/source)",
    "ct_dst_ltm":        "recent connections to destination",
    "ct_src_ltm":        "recent connections from source",
    "ct_src_dport_ltm":  "source-to-dest port connections",
    "ct_dst_sport_ltm":  "dest-from-source port connections",
    "ct_dst_src_ltm":    "source-destination pair connections",
}

# Per-attack-type human-readable explanation templates
# Used when SHAP is not available or as a fallback
ATTACK_EXPLANATIONS = {
    "Normal": (
        "Traffic appears legitimate and matches normal behavior patterns."
    ),
    "Analysis": (
        "The request pattern matches analysis or scanning behavior — "
        "systematically probing ports or files to gather system information."
    ),
    "Backdoor": (
        "Traffic characteristics match backdoor communication patterns — "
        "covert channels used to maintain unauthorized remote access."
    ),
    "DoS": (
        "The traffic pattern matches a Denial of Service attack — "
        "abnormally high volume designed to overwhelm the server."
    ),
    "Exploits": (
        "The request appears to exploit a known vulnerability — "
        "crafted payloads targeting specific software weaknesses."
    ),
    "Fuzzers": (
        "The request contains random or malformed input consistent with fuzzing — "
        "automated probing to discover unknown vulnerabilities."
    ),
    "Generic": (
        "Traffic matches a generic attack pattern targeting cipher suites "
        "or protocol weaknesses without targeting a specific application."
    ),
    "Reconnaissance": (
        "The traffic pattern is consistent with network reconnaissance — "
        "scanning to map the network topology and discover open services."
    ),
    "Shellcode": (
        "The payload contains patterns associated with shellcode — "
        "binary instructions designed to execute arbitrary commands on the server."
    ),
    "Worms": (
        "Traffic behavior matches self-propagating worm activity — "
        "automated attempts to spread to other systems in the network."
    ),
    "Zero-Day": (
        "The traffic pattern significantly deviates from normal user behavior "
        "and does not match any known attack signature. Blocked according to "
        "Zero Trust policy: unknown suspicious traffic is denied by default."
    ),
}


# =============================================================================
# EXPLAINER CLASS
# =============================================================================

class Explainer:
    """
    Generates human-readable explanations for blocked requests.

    Two modes:
    1. SHAP mode (preferred): Calculates exact feature contributions.
       Requires the trained model to be loaded. More accurate.

    2. Fallback mode: Uses pre-written template explanations per attack type.
       Used when SHAP is unavailable or errors out.
    """

    def __init__(self):
        self.shap_explainer = None   # Loaded lazily on first use
        self.model          = None   # Reference to the Random Forest
        self.feature_names  = None   # Feature column names

    def initialize(self, model, feature_names: list):
        """
        Connects the explainer to the trained Random Forest model.

        Call this after the AttackDetector loads its model.
        We use a TreeExplainer — optimized for tree-based models like
        Random Forest, much faster than the generic KernelExplainer.

        Args:
            model:         Trained RandomForestClassifier
            feature_names: List of feature column names (in order)
        """
        self.model         = model
        self.feature_names = feature_names

        try:
            import shap

            # TreeExplainer is specifically optimized for Random Forest.
            # It uses the tree structure to compute SHAP values exactly
            # (no approximation needed), making it fast enough for real-time use.
            self.shap_explainer = shap.TreeExplainer(model)
            logger.info("SHAP TreeExplainer initialized successfully.")

        except ImportError:
            logger.warning(
                "SHAP library not installed. "
                "Install with: pip install shap\n"
                "Falling back to template-based explanations."
            )
        except Exception as e:
            logger.warning(f"SHAP initialization failed: {e}. Using fallback.")

    def explain(
        self,
        attack_type: str,
        confidence: float,
        feature_vector: list,
        anomaly_score: float = None,
        anomaly_reason: str = None
    ) -> dict:
        """
        Generates a full explanation for a blocked request.

        Args:
            attack_type:    The predicted attack class (e.g. "SQL Injection")
            confidence:     Model confidence (0.0 to 1.0)
            feature_vector: The numeric feature values used for prediction
            anomaly_score:  Isolation Forest score (if zero-day, else None)
            anomaly_reason: Pre-built anomaly reason string (if zero-day)

        Returns:
            Dict:
            {
                "summary":        str,   # One-sentence summary for email subject
                "explanation":    str,   # Full paragraph for email body
                "top_features":   list,  # [{"feature": ..., "importance": ...}]
                "confidence_pct": str,   # "94.2%"
                "shap_used":      bool   # Whether SHAP was used
            }
        """
        confidence_pct = f"{confidence * 100:.1f}%"

        # --- Zero-Day: use anomaly-specific explanation ---
        if attack_type == "Zero-Day":
            explanation = anomaly_reason or ATTACK_EXPLANATIONS["Zero-Day"]
            return {
                "summary":        f"Zero-Day Attack Detected (anomaly score: {anomaly_score:.3f})",
                "explanation":    explanation,
                "top_features":   [],
                "confidence_pct": confidence_pct,
                "shap_used":      False
            }

        # --- Known attack: try SHAP first, then fallback ---
        top_features = []
        shap_used    = False
        shap_detail  = ""

        if self.shap_explainer is not None and feature_vector:
            try:
                top_features, shap_detail, shap_used = self._shap_explain(
                    feature_vector, attack_type
                )
            except Exception as e:
                logger.warning(f"SHAP explanation failed: {e}. Using fallback.")

        # Build the full explanation text
        base_explanation = ATTACK_EXPLANATIONS.get(
            attack_type,
            f"The request was classified as {attack_type} by the ML model."
        )

        if shap_detail:
            explanation = (
                f"{base_explanation}\n\n"
                f"Key contributing signals: {shap_detail}"
            )
        else:
            explanation = base_explanation

        summary = (
            f"{attack_type} attack detected with {confidence_pct} confidence."
        )

        return {
            "summary":        summary,
            "explanation":    explanation,
            "top_features":   top_features,
            "confidence_pct": confidence_pct,
            "shap_used":      shap_used
        }

    def _shap_explain(
        self,
        feature_vector: list,
        attack_type: str,
        top_n: int = 5
    ):
        """
        Uses SHAP to identify which features most influenced the prediction.

        SHAP values tell us: "How much did this feature push the prediction
        toward 'attack' vs. 'normal'?"

        Args:
            feature_vector: The numeric feature values (as a list)
            attack_type:    The predicted class name
            top_n:          How many top features to return

        Returns:
            top_features: List of dicts [{"feature": ..., "value": ..., "importance": ...}]
            detail_str:   Comma-separated string for embedding in explanation text
            shap_used:    Always True if this function succeeds
        """
        import shap

        x = np.array(feature_vector).reshape(1, -1)

        # shap_values shape: (n_classes, n_samples, n_features) for multi-class
        # or (n_samples, n_features) for binary
        shap_values = self.shap_explainer.shap_values(x)

        # For multi-class Random Forest, shap_values is a list (one per class)
        # Find the index of the predicted attack class
        if isinstance(shap_values, list):
            # Get class index from the model's label encoder
            # We need to find which class index corresponds to attack_type
            try:
                from ml.attack_detector import detector
                classes = list(detector.label_encoder.classes_)
                if attack_type in classes:
                    class_idx = classes.index(attack_type)
                else:
                    class_idx = 0
                values = shap_values[class_idx][0]
            except Exception:
                # Fall back to averaging absolute values across all classes
                values = np.mean([np.abs(sv[0]) for sv in shap_values], axis=0)
        else:
            values = shap_values[0]

        # Get absolute SHAP values (direction doesn't matter — magnitude does)
        abs_values = np.abs(values)

        # Get top N feature indices by importance
        top_indices = np.argsort(abs_values)[::-1][:top_n]

        top_features = []
        detail_parts = []

        for idx in top_indices:
            if idx >= len(self.feature_names):
                continue

            fname      = self.feature_names[idx]
            fvalue     = feature_vector[idx]
            importance = float(abs_values[idx])

            # Get human-readable name
            readable = FEATURE_DESCRIPTIONS.get(fname, fname)

            top_features.append({
                "feature":    fname,
                "readable":   readable,
                "value":      round(fvalue, 4),
                "importance": round(importance, 4)
            })

            # Format value for display
            if isinstance(fvalue, float) and fvalue != int(fvalue):
                val_str = f"{fvalue:.3f}"
            else:
                val_str = str(int(fvalue)) if fvalue == int(fvalue) else str(fvalue)

            detail_parts.append(f"{readable} ({val_str})")

        detail_str = ", ".join(detail_parts)

        return top_features, detail_str, True

    def build_email_body(
        self,
        ip: str,
        attack_type: str,
        timestamp: str,
        explanation_result: dict
    ) -> str:
        """
        Formats a complete email body for the admin alert.

        Args:
            ip:                 Source IP that was blocked
            attack_type:        Detected attack class
            timestamp:          When the block occurred (ISO string)
            explanation_result: Dict returned by explain()

        Returns:
            A multi-line string formatted as the email body.
        """
        top_features_section = ""
        if explanation_result.get("top_features"):
            lines = []
            for feat in explanation_result["top_features"]:
                lines.append(
                    f"  • {feat['readable']}: {feat['value']} "
                    f"(SHAP importance: {feat['importance']:.4f})"
                )
            top_features_section = "\nTop Contributing Signals:\n" + "\n".join(lines)

        shap_note = (
            "✓ SHAP analysis used for feature attribution."
            if explanation_result.get("shap_used")
            else "ℹ Template explanation used (SHAP not available)."
        )

        body = f"""
╔══════════════════════════════════════════════════╗
║         ZERO TRUST PROXY — SECURITY ALERT        ║
╚══════════════════════════════════════════════════╝

An incoming request has been blocked by the AI Security Proxy.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INCIDENT SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Attack Type  : {attack_type}
  Source IP    : {ip}
  Timestamp    : {timestamp}
  Confidence   : {explanation_result['confidence_pct']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EXPLANATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{explanation_result['explanation']}
{top_features_section}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ACTION TAKEN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ✗ Request was BLOCKED and not forwarded to the backend.
  ✗ Source IP {ip} has been added to the block list.
  ✗ All future requests from this IP will be instantly rejected.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{shap_note}
This alert was generated automatically by the Zero Trust Proxy.
        """.strip()

        return body


# =============================================================================
# SINGLETON
# =============================================================================

explainer = Explainer()