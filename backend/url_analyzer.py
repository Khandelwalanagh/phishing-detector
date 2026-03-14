"""
URL Feature Extractor and Heuristic Analyzer for Phishing Detection.
"""
import re
import math
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "banking", "paypal", "ebay", "amazon", "apple", "microsoft", "google",
    "webscr", "password", "credential", "wallet", "suspend", "unusual",
    "locked", "validate", "recover", "alert", "support", "helpdesk",
]

TARGET_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "facebook",
    "instagram", "netflix", "bankofamerica", "chase", "wellsfargo",
    "yahoo", "dhl", "fedex", "ups", "linkedin", "whatsapp", "steam",
    "binance", "coinbase"
]

HIGH_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".loan", ".win", ".download", ".stream", ".gdn", ".racing",
    ".review", ".country", ".science", ".work", ".party",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "tiny.cc", "rebrand.ly", "cutt.ly",
    "shorte.st", "cli.re", "rb.gy",
}

IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


# ─────────────────────────────────────────────────────────────────────────────
# Feature Extraction
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(url: str) -> Dict[str, Any]:
    """Extract numeric features from a URL for ML and heuristic scoring."""
    parsed = urlparse(url if url.startswith(("http", "ftp")) else "http://" + url)

    scheme      = parsed.scheme.lower()
    netloc      = parsed.netloc.lower()
    path        = parsed.path
    query       = parsed.query
    full_url    = url

    # Strip port from netloc for domain checks
    domain_part = netloc.split(":")[0]

    # TLD extraction
    if TLDEXTRACT_AVAILABLE:
        ext = tldextract.extract(url)
        subdomain   = ext.subdomain
        domain      = ext.domain
        suffix      = ext.suffix
        registered  = ext.registered_domain
    else:
        parts = domain_part.rsplit(".", 2)
        subdomain   = ".".join(parts[:-2]) if len(parts) > 2 else ""
        domain      = parts[-2] if len(parts) >= 2 else domain_part
        suffix      = parts[-1] if len(parts) >= 1 else ""
        registered  = f"{domain}.{suffix}"

    tld = f".{suffix}" if suffix else ""

    features: Dict[str, Any] = {
        # Length-based
        "url_length":           len(full_url),
        "domain_length":        len(domain_part),
        "path_length":          len(path),

        # Character counts in full URL
        "dots_count":           full_url.count("."),
        "hyphens_count":        full_url.count("-"),
        "underscores_count":    full_url.count("_"),
        "at_count":             full_url.count("@"),
        "question_count":       full_url.count("?"),
        "equals_count":         full_url.count("="),
        "ampersand_count":      full_url.count("&"),
        "slash_count":          full_url.count("/"),
        "percent_count":        full_url.count("%"),
        "digit_count":          sum(c.isdigit() for c in full_url),
        "special_char_count":   sum(not c.isalnum() for c in full_url),

        # Domain-level
        "subdomain_count":      len(subdomain.split(".")) if subdomain else 0,
        "has_ip_address":       int(bool(IP_PATTERN.match(domain_part))),
        "is_https":             int(scheme == "https"),
        "is_url_shortener":     int(registered in URL_SHORTENERS or domain_part in URL_SHORTENERS),
        "high_risk_tld":        int(tld.lower() in HIGH_RISK_TLDS),
        "domain_has_digit":     int(any(c.isdigit() for c in domain)),
        "domain_has_hyphen":    int("-" in domain),

        # Path / query
        "path_depth":           len([p for p in path.split("/") if p]),
        "has_query_string":     int(len(query) > 0),
        "query_param_count":    len(parse_qs(query)),

        # Keyword signals
        "suspicious_keywords":  sum(kw in full_url.lower() for kw in SUSPICIOUS_KEYWORDS),

        # Entropy (randomness) of domain — high entropy ≈ DGA domain
        "domain_entropy":       _entropy(domain),
        
        # Brand impersonation check
        "is_brand_impersonation": 0,  # Calculated below
    }

    # Brand Impersonation logic
    # Check if a target brand name is explicitly in the URL, but the domain isn't exactly brand.com
    for brand in TARGET_BRANDS:
        if brand in full_url.lower():
            # If the brand is in the URL, but the actual domain part isn't exactly the brand
            if domain != brand:
                features["is_brand_impersonation"] = 1
                break

    return features


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


# ─────────────────────────────────────────────────────────────────────────────
# Heuristic Scorer
# ─────────────────────────────────────────────────────────────────────────────

def heuristic_score(features: Dict[str, Any]) -> tuple[float, List[str]]:
    """
    Compute a 0-100 heuristic risk score and return a list of triggered reasons.
    Higher = more suspicious.
    """
    score   = 0.0
    reasons: List[str] = []

    def add(points: float, reason: str, condition: bool) -> None:
        nonlocal score
        if condition:
            score += points
            reasons.append(reason)

    add(30, "IP address used instead of domain name",
        features["has_ip_address"] == 1)

    add(35, "Brand Impersonation (Fake Login Warning) — URL mimics a popular brand",
        features["is_brand_impersonation"] == 1)

    add(5, "No HTTPS — plain HTTP connection",
        features["is_https"] == 0)

    add(20, "High-risk free TLD (e.g. .tk, .ml, .xyz)",
        features["high_risk_tld"] == 1)

    add(15, "Known URL shortener — destination hidden",
        features["is_url_shortener"] == 1)

    add(10, "Suspicious keywords in URL (e.g. login, verify, paypal)",
        features["suspicious_keywords"] >= 2)

    add(5, "Suspicious keyword present in URL",
        features["suspicious_keywords"] == 1)

    add(10, "@-symbol detected — may redirect to different host",
        features["at_count"] >= 1)

    add(8, "Excessive subdomains (≥ 3 levels)",
        features["subdomain_count"] >= 3)

    add(5, "Two or more subdomains",
        features["subdomain_count"] == 2)

    add(8, "Unusually long URL (> 75 chars)",
        features["url_length"] > 75)

    add(5, "Long URL (> 54 chars)",
        54 < features["url_length"] <= 75)

    add(7, "Domain contains digits — often used in imitation attacks",
        features["domain_has_digit"] == 1)

    add(5, "Domain contains hyphens — common in phishing",
        features["domain_has_hyphen"] == 1)

    add(6, "High domain entropy — possible DGA/random domain",
        features["domain_entropy"] > 3.8)

    add(5, "Many special characters in URL",
        features["special_char_count"] > 10)

    add(4, "Deep path structure",
        features["path_depth"] >= 5)

    add(3, "Many URL query parameters",
        features["query_param_count"] >= 4)

    # Cap at 100
    return min(score, 100.0), reasons


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def analyze_url(url: str) -> Dict[str, Any]:
    """
    Full URL analysis: feature extraction + heuristic scoring.
    Returns a dict ready for the API response.
    """
    features        = extract_features(url)
    h_score, reasons = heuristic_score(features)

    return {
        "heuristic_score": round(h_score, 2),
        "features":        features,
        "reasons":         reasons,
    }
