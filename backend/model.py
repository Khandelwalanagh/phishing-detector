"""
ML Model wrapper for phishing URL detection.
Uses a RandomForestClassifier trained on synthetic data.
Falls back to heuristic score if model is not available.
"""
import os
import joblib
import numpy as np
from typing import Dict, Any, Optional

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

# Feature names must match url_analyzer.extract_features() output order
FEATURE_NAMES = [
    "url_length", "domain_length", "path_length",
    "dots_count", "hyphens_count", "underscores_count",
    "at_count", "question_count", "equals_count",
    "ampersand_count", "slash_count", "percent_count",
    "digit_count", "special_char_count",
    "subdomain_count", "has_ip_address", "is_https",
    "is_url_shortener", "high_risk_tld", "domain_has_digit",
    "domain_has_hyphen", "path_depth", "has_query_string",
    "query_param_count", "suspicious_keywords", "domain_entropy",
    "is_brand_impersonation",
]


def _features_to_array(features: Dict[str, Any]) -> np.ndarray:
    return np.array([[features.get(f, 0) for f in FEATURE_NAMES]], dtype=float)


def load_model():
    if os.path.exists(MODEL_PATH):
        bundle = joblib.load(MODEL_PATH)
        # Bundle is a dict {"clf": classifier, "scaler": ..., "feature_names": ...}
        if isinstance(bundle, dict):
            return bundle["clf"]
        return bundle  # backwards-compat if saved as raw clf
    return None


def predict(features: Dict[str, Any], heuristic_score: float) -> Dict[str, Any]:
    """
    Predict whether a URL is phishing or legitimate.

    Returns:
        {
          "label":       "phishing" | "legitimate",
          "confidence":  float 0-1,
          "ml_score":    float 0-100  (phishing probability * 100)
        }
    """
    model = load_model()

    if model is not None:
        X = _features_to_array(features)
        proba = model.predict_proba(X)[0]
        # proba[1] = probability of class 1 (phishing)
        phishing_prob = float(proba[1])
        label = "phishing" if phishing_prob >= 0.5 else "legitimate"
        return {
            "label":      label,
            "confidence": round(phishing_prob if label == "phishing" else 1 - phishing_prob, 3),
            "ml_score":   round(phishing_prob * 100, 2),
            "source":     "ml_model",
        }
    else:
        # Fallback to heuristic
        label = "phishing" if heuristic_score >= 40 else "legitimate"
        confidence = heuristic_score / 100 if label == "phishing" else 1 - heuristic_score / 100
        return {
            "label":      label,
            "confidence": round(confidence, 3),
            "ml_score":   None,
            "source":     "heuristic_fallback",
        }


def save_model(clf, scaler=None) -> None:
    bundle = {"clf": clf, "scaler": scaler, "feature_names": FEATURE_NAMES}
    joblib.dump(bundle, MODEL_PATH)
