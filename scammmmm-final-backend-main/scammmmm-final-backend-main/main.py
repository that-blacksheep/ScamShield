"""
ScamShield — FastAPI Entry Point (v4.0)
Fixes: lifespan API, thread-safe DB pool, unified scoring, phone field added,
       env-based CORS, /api/history endpoint, structured error responses,
       Pydantic V2 SettingsConfigDict migration.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from contextlib import asynccontextmanager
from queue import Empty, Queue
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from checks.cyber import analyze as run_cyber_analyze
from checks.ml import run_ml_checks

# ─────────────────────────────────────────────────────────────
#  Settings (reads from .env or environment variables)
# ─────────────────────────────────────────────────────────────
class Settings(BaseSettings):
    cors_origins: str = "*"          # comma-separated list in production
    db_path: str = "scamshield.db"
    db_pool_size: int = 5
    log_level: str = "INFO"

    # Modern Pydantic V2 Config
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger("scamshield.main")


# ─────────────────────────────────────────────────────────────
#  Thread-safe SQLite connection pool
# ─────────────────────────────────────────────────────────────
class ConnectionPool:
    def __init__(self, db_path: str, size: int = 5):
        self._pool: Queue[sqlite3.Connection] = Queue(maxsize=size)
        for _ in range(size):
            con = sqlite3.connect(db_path, check_same_thread=False)
            con.row_factory = sqlite3.Row
            self._pool.put(con)

    def acquire(self, timeout: float = 5.0) -> sqlite3.Connection:
        try:
            return self._pool.get(timeout=timeout)
        except Empty:
            raise HTTPException(503, "Database pool exhausted — try again shortly")

    def release(self, con: sqlite3.Connection) -> None:
        self._pool.put(con)

    def close_all(self) -> None:
        while not self._pool.empty():
            try:
                self._pool.get_nowait().close()
            except Empty:
                break


_pool: Optional[ConnectionPool] = None


def get_pool() -> ConnectionPool:
    if _pool is None:
        raise RuntimeError("DB pool not initialised")
    return _pool


# ─────────────────────────────────────────────────────────────
#  Database bootstrap
# ─────────────────────────────────────────────────────────────
def init_db(con: sqlite3.Connection) -> None:
    con.executescript("""
        CREATE TABLE IF NOT EXISTS checks (
            id       TEXT    PRIMARY KEY,
            url      TEXT,
            company  TEXT,
            email    TEXT,
            score    INTEGER,
            verdict  TEXT,
            signals  TEXT,
            ts       DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_checks_ts ON checks(ts);
        CREATE INDEX IF NOT EXISTS idx_checks_verdict ON checks(verdict);
    """)
    con.commit()


# ─────────────────────────────────────────────────────────────
#  Lifespan (startup + shutdown)
# ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _pool
    _pool = ConnectionPool(settings.db_path, settings.db_pool_size)
    con = _pool.acquire()
    try:
        init_db(con)
    finally:
        _pool.release(con)
    logger.info("ScamShield v4.0 started — DB pool ready (%d conns)", settings.db_pool_size)
    yield
    _pool.close_all()
    logger.info("ScamShield shut down cleanly")


# ─────────────────────────────────────────────────────────────
#  App
# ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="ScamShield API",
    version="4.0.0",
    description="Forensic job-offer fraud detection engine",
    lifespan=lifespan,
)

origins = [o.strip() for o in settings.cors_origins.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────
#  Request / Response models
# ─────────────────────────────────────────────────────────────
class CheckRequest(BaseModel):
    job_url:          str   = Field(default="N/A",     description="Job posting URL")
    company_claimed:  str   = Field(default="Unknown", description="Company name as stated in offer")
    recruiter_email:  str   = Field(default="",        description="Recruiter's email address")
    phone_number:     str   = Field(default="",        description="Recruiter/HR phone number")
    salary_offered:   float = Field(default=0,         ge=0, description="Annual salary in INR (0 = not provided)")
    offer_text:       str   = Field(default="",        description="Full offer letter or email body")


class StatsResponse(BaseModel):
    total_checks: int
    scams_caught: int
    suspicious:   int
    safe:         int
    scam_rate_pct: float


# ─────────────────────────────────────────────────────────────
#  Unified Fusion Scorer
# ─────────────────────────────────────────────────────────────
def fuse_scores(cyber_report: dict, ml: dict) -> tuple[int, str, list[str]]:
    """
    Single scoring function — no duplicate verdict logic.
    Cyber engine provides the base score (logistic-normalised).
    ML layer adds penalty only for signals not already captured by cyber.
    Trust Shield: if cyber is highly confident SAFE, soft ML signals are muted —
    but fee_language ALWAYS applies (hard cap).
    """
    base        = cyber_report.get("overall_score", 100)
    reasons     = list(cyber_report.get("reasons", []))
    is_trusted  = (
        cyber_report.get("confidence", 0) > 0.85
        and cyber_report.get("verdict") == "SAFE"
    )

    ml_penalty = 0
    for name, result in ml.get("details", {}).items():
        if not isinstance(result, dict) or not result.get("flag"):
            continue
        # Always apply fee_language; mute other soft signals for trusted domains
        if is_trusted and name != "fee_language":
            continue
        ml_penalty += result.get("penalty", 0)
        reasons.append(result.get("reason", name))

    # Hard cap: fee language detected → score can never exceed 20
    fee = ml.get("details", {}).get("fee_language", {})
    final = max(0, base - ml_penalty)
    if fee.get("hard_cap"):
        final = min(final, 20)
        if "Fee language hard cap applied" not in reasons:
            reasons.append("Fee language hard cap applied — score capped at 20")

    # Single verdict thresholds
    if   final >= 80: verdict = "VERIFIED"
    elif final >= 55: verdict = "UNVERIFIED"
    elif final >= 30: verdict = "SUSPICIOUS"
    else:             verdict = "SCAM"

    return int(final), verdict, reasons


# ─────────────────────────────────────────────────────────────
#  API Endpoints
# ─────────────────────────────────────────────────────────────
@app.post("/api/check")
def check(req: CheckRequest):
    cyber_input = {
        "job_url":         req.job_url,
        "company_claimed": req.company_claimed,
        "recruiter_email": req.recruiter_email,
        "phone_number":    req.phone_number,
        "salary_offered":  req.salary_offered,
        "offer_text":      req.offer_text,
    }

    try:
        cyber_report = run_cyber_analyze(cyber_input)
    except Exception as exc:
        logger.error("Cyber engine error: %s", exc)
        cyber_report = {"overall_score": 50, "reasons": [f"Cyber engine error: {exc}"],
                        "signals": [], "confidence": 0.0, "verdict": "REVIEW",
                        "summary": "Partial analysis — cyber engine failed",
                        "recommendations": ["Run analysis again; cyber checks unavailable"]}

    try:
        ml_report = run_ml_checks(req.offer_text, req.salary_offered, req.company_claimed)
    except Exception as exc:
        logger.error("ML engine error: %s", exc)
        ml_report = {"details": {}}

    trust_score, verdict, reasons = fuse_scores(cyber_report, ml_report)

    rid = str(uuid.uuid4())[:8]
    combined_signals = {
        "cyber_signals": cyber_report.get("signals", []),
        "ml_details":    ml_report.get("details", {}),
    }

    pool = get_pool()
    con  = pool.acquire()
    try:
        con.execute(
            "INSERT INTO checks (id, url, company, email, score, verdict, signals) "
            "VALUES (?,?,?,?,?,?,?)",
            (rid, req.job_url, req.company_claimed, req.recruiter_email,
             trust_score, verdict, json.dumps(combined_signals)),
        )
        con.commit()
    except Exception as exc:
        logger.error("DB insert error: %s", exc)
    finally:
        pool.release(con)

    return {
        "request_id":      rid,
        "trust_score":     trust_score,
        "verdict":         verdict,
        "reasons":         reasons,
        "summary":         cyber_report.get("summary", ""),
        "recommendations": cyber_report.get("recommendations", []),
        "signals":         combined_signals,
        "field_analysis":  cyber_report.get("field_analysis", {}),
    }


@app.get("/api/stats", response_model=StatsResponse)
def stats():
    pool = get_pool()
    con  = pool.acquire()
    try:
        row = con.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN verdict='SCAM'       THEN 1 ELSE 0 END) AS scams,
                SUM(CASE WHEN verdict='SUSPICIOUS' THEN 1 ELSE 0 END) AS suspicious,
                SUM(CASE WHEN verdict='VERIFIED'   THEN 1 ELSE 0 END) AS safe
            FROM checks
        """).fetchone()
    finally:
        pool.release(con)

    total      = row["total"] or 0
    scams      = row["scams"] or 0
    suspicious = row["suspicious"] or 0
    safe       = row["safe"] or 0
    rate       = round((scams / total * 100), 1) if total else 0.0

    return StatsResponse(
        total_checks=total,
        scams_caught=scams,
        suspicious=suspicious,
        safe=safe,
        scam_rate_pct=rate,
    )


@app.get("/api/history")
def history(limit: int = 20, offset: int = 0):
    """Return recent audit history for the dashboard."""
    if limit > 100:
        limit = 100
    pool = get_pool()
    con  = pool.acquire()
    try:
        rows = con.execute(
            "SELECT id, url, company, score, verdict, ts FROM checks "
            "ORDER BY ts DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    finally:
        pool.release(con)
    return [dict(r) for r in rows]


@app.get("/health")
def health():
    return {"status": "ok", "version": "4.0.0"}