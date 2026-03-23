"""
PhishGuard — API Key Authentication
Generates and validates HMAC-signed API keys using itsdangerous.
No database required: keys are cryptographically self-verifying.
"""
import os
import secrets
from itsdangerous import URLSafeSerializer, BadSignature, SignatureExpired

from fastapi import Header, HTTPException, Depends
from typing import Optional

# ── Load secrets from env ─────────────────────────────────────
_SESSION_SECRET: str = os.environ.get("SESSION_SECRET", "change-me-please-use-a-real-secret")
_API_KEY_SALT:   str = os.environ.get("API_KEY_SALT",   "phishguard-api-salt-2026")

_serializer = URLSafeSerializer(_SESSION_SECRET, salt=_API_KEY_SALT)


# ── Key Generation ────────────────────────────────────────────

def generate_api_key() -> str:
    """
    Creates a cryptographically signed API key.
    Format: <signed_token>  (URL-safe, no padding issues)
    """
    token = secrets.token_urlsafe(24)           # 24 bytes → 32 char token
    return _serializer.dumps(token)             # HMAC-signed


# ── Key Validation ────────────────────────────────────────────

def validate_api_key(key: str) -> bool:
    """Returns True if the key is a valid PhishGuard-issued token."""
    try:
        _serializer.loads(key)
        return True
    except (BadSignature, SignatureExpired, Exception):
        return False


# ── FastAPI Dependency ────────────────────────────────────────

def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> str:
    """
    FastAPI dependency — inject via Depends(require_api_key).
    Raises HTTP 401 if the header is missing or the key is invalid.
    """
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Add X-API-Key header. Visit /api/keys/generate to obtain one.",
        )
    if not validate_api_key(x_api_key):
        raise HTTPException(
            status_code=401,
            detail="Invalid or tampered API key. Visit /api/keys/generate to obtain a new one.",
        )
    return x_api_key
