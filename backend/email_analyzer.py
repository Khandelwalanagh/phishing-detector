"""
Email Content Analyzer for Phishing Detection.
Supports both plain email body text and raw RFC-2822 email source.
"""
import re
from typing import Dict, Any, List

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

URGENCY_PATTERNS = [
    r"act now",
    r"immediate(ly)?",
    r"urgent(ly)?",
    r"as soon as possible",
    r"within 24 hours?",
    r"within 48 hours?",
    r"account (has been )?suspended",
    r"account (has been )?locked",
    r"unusual (sign-?in|activity|login)",
    r"verify (your )?account",
    r"confirm (your )?(identity|account|email|details)",
    r"update (your )?(payment|billing|account|information|details)",
    r"your (account|password|card) (will be |has been )?",
    r"click (here|the link|below)",
    r"limited time",
    r"expire[sd]?",
    r"re-?validation",
    r"security (alert|notice|warning)",
    r"failed (payment|delivery|attempt)",
]

SENSITIVE_KEYWORDS = [
    "password", "credit card", "social security", "ssn", "bank account",
    "routing number", "pin", "billing", "login credentials", "username",
    "wire transfer", "western union", "moneygram",
]

DANGEROUS_EXTENSIONS = {
    ".exe", ".vbs", ".bat", ".cmd", ".scr", ".js", ".jar", ".ps1",
    ".msi", ".com", ".pif", ".hta", ".reg", ".wsf",
}

URL_REGEX = re.compile(
    r"https?://[^\s\"'<>)]+", re.IGNORECASE
)

EMAIL_HEADER_REGEX = re.compile(
    r"^(From|To|Subject|Date|Return-Path|Reply-To|X-Originating-IP)\s*:",
    re.IGNORECASE | re.MULTILINE,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _detect_raw_email(content: str) -> bool:
    """Heuristic: does this look like raw RFC-2822 email source?"""
    return bool(EMAIL_HEADER_REGEX.search(content[:2000]))


def _extract_links(text: str) -> List[str]:
    return URL_REGEX.findall(text)


def _parse_sender_domain(content: str) -> str:
    """Extract the sender domain from a From: header if present."""
    m = re.search(r"^From:.*?@([\w.\-]+)", content[:2000],
                  re.IGNORECASE | re.MULTILINE)
    return m.group(1).lower() if m else ""


def _parse_reply_to_domain(content: str) -> str:
    m = re.search(r"^Reply-To:.*?@([\w.\-]+)", content[:2000],
                  re.IGNORECASE | re.MULTILINE)
    return m.group(1).lower() if m else ""


def _check_mismatched_domains(from_domain: str, reply_domain: str) -> bool:
    """True if from and reply-to domains differ (common phishing tactic)."""
    if not from_domain or not reply_domain:
        return False
    return from_domain != reply_domain


def _check_attachment_risk(content: str) -> List[str]:
    """Find mentions of dangerous attachment extensions."""
    found = []
    for ext in DANGEROUS_EXTENSIONS:
        if ext in content.lower():
            found.append(ext)
    return found


# ─────────────────────────────────────────────────────────────────────────────
# Core Analyzer
# ─────────────────────────────────────────────────────────────────────────────

def analyze_email(content: str) -> Dict[str, Any]:
    """
    Analyze email content (body or raw source) for phishing indicators.
    Returns a structured dict with risk_score, label, reasons.
    """
    score   = 0.0
    reasons: List[str] = []
    content_lower = content.lower()

    is_raw = _detect_raw_email(content)

    # ── Link analysis ────────────────────────────────────────────────────────
    links = _extract_links(content)
    link_count = len(links)

    # Count unique domains in links
    link_domains = set()
    for link in links:
        m = re.search(r"https?://([^/\s]+)", link, re.IGNORECASE)
        if m:
            link_domains.add(m.group(1).lower())

    word_count = max(len(content.split()), 1)
    link_density = link_count / word_count

    if link_count == 0 and not is_raw:
        pass  # neutral for plain body with no links
    elif link_count >= 5:
        score += 15
        reasons.append(f"High number of links ({link_count}) — excessive linking is a phishing signal")
    elif link_count >= 2:
        score += 7
        reasons.append(f"Multiple links ({link_count}) detected")

    if link_density > 0.05:
        score += 10
        reasons.append("High link-to-text ratio — email body is mostly links")

    if len(link_domains) >= 3:
        score += 8
        reasons.append(f"Links point to {len(link_domains)} different domains — scatter pattern")

    # ── Urgency / threat language ────────────────────────────────────────────
    urgency_hits = []
    for pat in URGENCY_PATTERNS:
        if re.search(pat, content_lower):
            urgency_hits.append(pat.replace(r"(ly)?", "ly").replace(r"\b", "").replace("\\", ""))

    if urgency_hits:
        score += min(len(urgency_hits) * 8, 30)
        reasons.append(
            f"Urgency/threat language detected ({len(urgency_hits)} pattern{'s' if len(urgency_hits)>1 else ''}): "
            + ", ".join(f'"{h}"' for h in urgency_hits[:3])
        )

    # ── Sensitive information requests ───────────────────────────────────────
    sensitive_hits = [kw for kw in SENSITIVE_KEYWORDS if kw in content_lower]
    if sensitive_hits:
        score += min(len(sensitive_hits) * 7, 20)
        reasons.append(
            f"Requests sensitive information: {', '.join(sensitive_hits[:4])}"
        )

    # ── Dangerous attachments ────────────────────────────────────────────────
    dangerous_ext = _check_attachment_risk(content)
    if dangerous_ext:
        score += 20
        reasons.append(
            f"Potentially dangerous file extension(s) mentioned: {', '.join(dangerous_ext)}"
        )

    # ── Header analysis (only for raw email) ────────────────────────────────
    if is_raw:
        from_domain    = _parse_sender_domain(content)
        reply_domain   = _parse_reply_to_domain(content)

        if _check_mismatched_domains(from_domain, reply_domain):
            score += 20
            reasons.append(
                f"Sender/Reply-To domain mismatch: FROM={from_domain} vs REPLY-TO={reply_domain}"
            )

        # Check if any link domain differs from declared sender domain
        if from_domain and link_domains:
            mismatched = [d for d in link_domains if from_domain not in d and d not in from_domain]
            if len(mismatched) >= 2:
                score += 10
                reasons.append(
                    f"Links point to domains unrelated to sender ({from_domain}): "
                    + ", ".join(list(mismatched)[:3])
                )

    # ── Generic suspicious patterns ──────────────────────────────────────────
    if re.search(r"dear (customer|user|client|member|valued)", content_lower):
        score += 5
        reasons.append('Generic greeting ("Dear Customer/User") instead of your real name')

    if re.search(r"do not (reply|respond) to this (email|message)", content_lower):
        score += 3
        reasons.append("Do-not-reply disclaimer — common in phishing to avoid responses")

    if re.search(r"(lottery|you('ve)? won|winner|prize|jackpot|million dollar)", content_lower):
        score += 25
        reasons.append("Lottery/prize scam indicators detected")

    score = min(score, 100.0)

    # ── Build feature summary ────────────────────────────────────────────────
    features = {
        "is_raw_email":      is_raw,
        "link_count":        link_count,
        "unique_domains":    len(link_domains),
        "link_density":      round(link_density, 4),
        "urgency_hits":      len(urgency_hits),
        "sensitive_keywords": len(sensitive_hits),
        "dangerous_attachments": len(dangerous_ext),
        "word_count":        word_count,
    }

    return {
        "risk_score": round(score, 2),
        "features":   features,
        "reasons":    reasons,
        "links_found": links[:20],  # cap to 20 for response size
    }
