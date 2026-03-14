"""
Training script: generates a synthetic phishing dataset and trains a
RandomForestClassifier, then saves the model to model.pkl.

Run once: python train_model.py
"""
import numpy as np
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import joblib

# ─────────────────────────────────────────────────────────────────────────────
# Import the feature names from model.py so they stay in sync
# ─────────────────────────────────────────────────────────────────────────────
from model import FEATURE_NAMES, MODEL_PATH

SEED = 42
rng  = np.random.default_rng(SEED)

N_PHISHING    = 2000
N_LEGITIMATE  = 2000


def make_phishing_samples(n: int) -> np.ndarray:
    """Simulate feature vectors for phishing URLs."""
    samples = np.zeros((n, len(FEATURE_NAMES)))
    idx = {f: i for i, f in enumerate(FEATURE_NAMES)}

    samples[:, idx["url_length"]]         = rng.integers(60, 200,  n)
    samples[:, idx["domain_length"]]      = rng.integers(15,  60,  n)
    samples[:, idx["path_length"]]        = rng.integers(10,  80,  n)
    samples[:, idx["dots_count"]]         = rng.integers( 4,  10,  n)
    samples[:, idx["hyphens_count"]]      = rng.integers( 2,   8,  n)
    samples[:, idx["underscores_count"]]  = rng.integers( 0,   4,  n)
    samples[:, idx["at_count"]]           = rng.integers( 0,   2,  n)
    samples[:, idx["question_count"]]     = rng.integers( 0,   3,  n)
    samples[:, idx["equals_count"]]       = rng.integers( 1,   6,  n)
    samples[:, idx["ampersand_count"]]    = rng.integers( 0,   5,  n)
    samples[:, idx["slash_count"]]        = rng.integers( 4,  12,  n)
    samples[:, idx["percent_count"]]      = rng.integers( 0,   5,  n)
    samples[:, idx["digit_count"]]        = rng.integers( 5,  20,  n)
    samples[:, idx["special_char_count"]] = rng.integers(10,  30,  n)
    samples[:, idx["subdomain_count"]]    = rng.integers( 2,   5,  n)
    samples[:, idx["has_ip_address"]]     = rng.choice([0, 1], n, p=[0.3, 0.7])
    samples[:, idx["is_https"]]           = rng.choice([0, 1], n, p=[0.7, 0.3])
    samples[:, idx["is_url_shortener"]]   = rng.choice([0, 1], n, p=[0.6, 0.4])
    samples[:, idx["high_risk_tld"]]      = rng.choice([0, 1], n, p=[0.2, 0.8])
    samples[:, idx["domain_has_digit"]]   = rng.choice([0, 1], n, p=[0.3, 0.7])
    samples[:, idx["domain_has_hyphen"]]  = rng.choice([0, 1], n, p=[0.3, 0.7])
    samples[:, idx["path_depth"]]         = rng.integers( 3,   8,  n)
    samples[:, idx["has_query_string"]]   = rng.choice([0, 1], n, p=[0.2, 0.8])
    samples[:, idx["query_param_count"]]  = rng.integers( 2,   8,  n)
    samples[:, idx["suspicious_keywords"]] = rng.integers(1,   5,  n)
    samples[:, idx["domain_entropy"]]     = rng.uniform(3.5, 5.0,  n)
    samples[:, idx["is_brand_impersonation"]] = rng.choice([0, 1], n, p=[0.7, 0.3])

    return samples


def make_legitimate_samples(n: int) -> np.ndarray:
    """Simulate feature vectors for legitimate URLs."""
    samples = np.zeros((n, len(FEATURE_NAMES)))
    idx = {f: i for i, f in enumerate(FEATURE_NAMES)}

    samples[:, idx["url_length"]]         = rng.integers(10,  60,  n)
    samples[:, idx["domain_length"]]      = rng.integers( 3,  20,  n)
    samples[:, idx["path_length"]]        = rng.integers( 0,  30,  n)
    samples[:, idx["dots_count"]]         = rng.integers( 1,   4,  n)
    samples[:, idx["hyphens_count"]]      = rng.integers( 0,   2,  n)
    samples[:, idx["underscores_count"]]  = rng.integers( 0,   1,  n)
    samples[:, idx["at_count"]]           = np.zeros(n)
    samples[:, idx["question_count"]]     = rng.integers( 0,   2,  n)
    samples[:, idx["equals_count"]]       = rng.integers( 0,   2,  n)
    samples[:, idx["ampersand_count"]]    = rng.integers( 0,   2,  n)
    samples[:, idx["slash_count"]]        = rng.integers( 1,   5,  n)
    samples[:, idx["percent_count"]]      = rng.integers( 0,   1,  n)
    samples[:, idx["digit_count"]]        = rng.integers( 0,   5,  n)
    samples[:, idx["special_char_count"]] = rng.integers( 1,   8,  n)
    samples[:, idx["subdomain_count"]]    = rng.integers( 0,   2,  n)
    samples[:, idx["has_ip_address"]]     = rng.choice([0, 1], n, p=[0.98, 0.02])
    samples[:, idx["is_https"]]           = rng.choice([0, 1], n, p=[0.1,  0.9])
    samples[:, idx["is_url_shortener"]]   = rng.choice([0, 1], n, p=[0.95, 0.05])
    samples[:, idx["high_risk_tld"]]      = rng.choice([0, 1], n, p=[0.97, 0.03])
    samples[:, idx["domain_has_digit"]]   = rng.choice([0, 1], n, p=[0.85, 0.15])
    samples[:, idx["domain_has_hyphen"]]  = rng.choice([0, 1], n, p=[0.85, 0.15])
    samples[:, idx["path_depth"]]         = rng.integers( 0,   4,  n)
    samples[:, idx["has_query_string"]]   = rng.choice([0, 1], n, p=[0.6,  0.4])
    samples[:, idx["query_param_count"]]  = rng.integers( 0,   3,  n)
    samples[:, idx["suspicious_keywords"]] = rng.integers(0,   2,  n)
    samples[:, idx["domain_entropy"]]     = rng.uniform(1.5, 3.5,  n)
    samples[:, idx["is_brand_impersonation"]] = np.zeros(n)

    return samples


def train() -> None:
    print("Generating synthetic training data …")
    X_phish = make_phishing_samples(N_PHISHING)
    X_legit  = make_legitimate_samples(N_LEGITIMATE)

    X = np.vstack([X_phish, X_legit])
    y = np.array([1] * N_PHISHING + [0] * N_LEGITIMATE)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=SEED, stratify=y
    )

    print(f"Training on {len(X_train)} samples …")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=3,
        random_state=SEED,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    print("\n── Evaluation on hold-out test set ──")
    print(classification_report(y_test, clf.predict(X_test),
                                target_names=["legitimate", "phishing"]))

    bundle = {"clf": clf, "scaler": None, "feature_names": FEATURE_NAMES}
    joblib.dump(bundle, MODEL_PATH)
    print(f"Model saved → {MODEL_PATH}")


if __name__ == "__main__":
    train()
