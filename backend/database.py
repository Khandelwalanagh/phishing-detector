"""
database.py — Async SQLAlchemy setup for PhishGuard.

Stores every URL scan result for deduplication and history.
Uses SQLite locally (DATABASE_URL=sqlite+aiosqlite:///./phishguard.db).
Easily swappable to PostgreSQL by changing DATABASE_URL.
"""
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Column, Integer, Text, Float, DateTime, String, select, update
)
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase

# ── Engine & Session ──
DATABASE_URL: str = os.environ.get(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./phishguard.db"
)

engine = create_async_engine(DATABASE_URL, echo=False, future=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


# ── ORM Base ──
class Base(DeclarativeBase):
    pass


# ── URL Scan Table ──
class UrlScan(Base):
    __tablename__ = "url_scans"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    url         = Column(Text, nullable=False, unique=True)
    url_hash    = Column(String(64), nullable=False, unique=True, index=True)
    label       = Column(String(32))           # 'phishing' | 'legitimate'
    risk_score  = Column(Float)
    reasons     = Column(Text)                 # JSON array
    features    = Column(Text)                 # JSON object
    model_src   = Column(String(32))           # 'ml_model' | 'heuristics'
    confidence  = Column(Float)
    scan_count  = Column(Integer, default=1)
    first_seen  = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen   = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                         onupdate=lambda: datetime.now(timezone.utc))


# ── Init (called on app startup) ──
async def init_db() -> None:
    """Create all tables if they don't exist."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# ── Helpers ──
def _hash_url(url: str) -> str:
    return hashlib.sha256(url.strip().lower().encode()).hexdigest()


async def get_cached_scan(url: str) -> Optional[dict]:
    """Return cached scan result dict if URL was scanned before, else None."""
    h = _hash_url(url)
    async with AsyncSessionLocal() as session:
        row = await session.scalar(select(UrlScan).where(UrlScan.url_hash == h))
        if row is None:
            return None
        # Increment hit counter
        await session.execute(
            update(UrlScan)
            .where(UrlScan.url_hash == h)
            .values(
                scan_count=row.scan_count + 1,
                last_seen=datetime.now(timezone.utc),
            )
        )
        await session.commit()
        return _row_to_dict(row, cached=True)


async def save_scan(
    url: str,
    label: str,
    risk_score: float,
    reasons: list,
    features: dict,
    model_src: str,
    confidence: float,
) -> None:
    """Persist a new scan result. Silently skips if URL already exists."""
    h = _hash_url(url)
    async with AsyncSessionLocal() as session:
        existing = await session.scalar(select(UrlScan).where(UrlScan.url_hash == h))
        if existing:
            return  # already stored (shouldn't normally happen, but be safe)
        scan = UrlScan(
            url=url,
            url_hash=h,
            label=label,
            risk_score=risk_score,
            reasons=json.dumps(reasons),
            features=json.dumps(features),
            model_src=model_src,
            confidence=confidence,
        )
        session.add(scan)
        await session.commit()


async def get_scan_history(limit: int = 50, offset: int = 0) -> list[dict]:
    """Return most-recently scanned URLs, newest first."""
    async with AsyncSessionLocal() as session:
        rows = await session.scalars(
            select(UrlScan)
            .order_by(UrlScan.last_seen.desc())
            .limit(limit)
            .offset(offset)
        )
        return [_row_to_dict(r) for r in rows]


async def get_db_stats() -> dict:
    """Return aggregate statistics from the DB."""
    from sqlalchemy import func
    async with AsyncSessionLocal() as session:
        total = await session.scalar(select(func.count(UrlScan.id))) or 0
        phishing = await session.scalar(
            select(func.count(UrlScan.id)).where(UrlScan.label == "phishing")
        ) or 0
        return {"total_stored": total, "phishing_stored": phishing}


# ── Internal serialiser ──
def _row_to_dict(row: UrlScan, cached: bool = False) -> dict:
    def _try_json(v):
        try:
            return json.loads(v) if v else []
        except Exception:
            return v

    return {
        "id":          row.id,
        "url":         row.url,
        "label":       row.label,
        "risk_score":  row.risk_score,
        "confidence":  row.confidence,
        "model_source": row.model_src,
        "reasons":     _try_json(row.reasons),
        "features":    _try_json(row.features),
        "scan_count":  row.scan_count,
        "first_seen":  row.first_seen.isoformat() if row.first_seen else None,
        "last_seen":   row.last_seen.isoformat() if row.last_seen else None,
        "cached":      cached,
    }
