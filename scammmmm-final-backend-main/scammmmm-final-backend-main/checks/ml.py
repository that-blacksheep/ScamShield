"""
ScamShield — ML Analysis Layer (v4.0)
Fixes: safe model loading, shared SALARY_RANGES used by cyber.py,
       removed dead internal verdict, unified hard-cap contract,
       fee_language key name consistent with main.py fuser.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger("scamshield.ml")

# ─────────────────────────────────────────────────────────────
#  Shared salary ranges — imported by cyber.py too
# ─────────────────────────────────────────────────────────────
SALARY_RANGES: Dict[str, tuple[float, float]] = {
    "default":    (200_000,  8_000_000),
    "fresher":    (200_000,    800_000),
    "entry":      (300_000,  1_200_000),
    "mid":        (600_000,  3_000_000),
    "senior":   (1_200_000,  6_000_000),
    "lead":     (2_000_000,  9_000_000),
    "manager":  (2_500_000, 12_000_000),
    "director": (5_000_000, 25_000_000),
    "vp":      (10_000_000, 50_000_000),
}

# ─────────────────────────────────────────────────────────────
#  Fee-language detection patterns
# ─────────────────────────────────────────────────────────────
FEE_PATTERNS = [
    r"\bregistration\s+fee\b",
    r"\bpay\s+(?:rs\.?|inr|₹)?\s*\d+",
    r"\bsecurity\s+deposit\b",
    r"\bprocessing\s+fee\b",
    r"\bpay\s+before\s+joining\b",
    r"\bapplication\s+fee\b",
    r"\bfee\s+required\b",
    r"\brefundable\s+deposit\b",
    r"\btraining\s+fee\b",
    r"\bkit\s+fee\b",
    r"\bupfront\s+(payment|fee|charge)\b",
]

# ─────────────────────────────────────────────────────────────
#  Model — safe lazy load
# ─────────────────────────────────────────────────────────────
_model = None
_model_load_attempted = False

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "scam_classifier.pkl"


def _get_model():
    global _model, _model_load_attempted
    if _model_load_attempted:
        return _model
    _model_load_attempted = True
    try:
        import joblib
        _model = joblib.load(MODEL_PATH)
        logger.info("ML model loaded from %s", MODEL_PATH)
    except FileNotFoundError:
        logger.warning(
            "ML model not found at %s — run train_classifier.py first. "
            "NLP checks will be skipped.", MODEL_PATH
        )
        _model = None
    except Exception as exc:
        logger.error("Failed to load ML model: %s", exc)
        _model = None
    return _model


# ─────────────────────────────────────────────────────────────
#  Individual checks
# ─────────────────────────────────────────────────────────────
def check_fee_language(offer_text: str) -> Dict:
    text    = offer_text.lower()
    matches = sum(1 for p in FEE_PATTERNS if re.search(p, text, re.IGNORECASE))
    flag    = matches >= 1
    return {
        "flag":     flag,
        "matches":  matches,
        "penalty":  40 + (matches * 10) if flag else 0,
        "reason":   (
            f"{matches} payment-related scam indicator(s) detected."
            if flag else "No fee language detected."
        ),
        # hard_cap triggers when 2+ fee patterns match
        "hard_cap": matches >= 2,
    }


def check_salary_anomaly(salary: float, company: str = "") -> Dict:
    if salary == 0:
        return {"flag": False, "penalty": 0, "reason": "No salary provided.", "hard_cap": False}

    _, max_salary = SALARY_RANGES["default"]
    if salary > max_salary:
        penalty = min(40, 30 + int((salary / max_salary - 1) * 5))
        return {
            "flag":     True,
            "penalty":  penalty,
            "reason":   f"Salary ₹{salary:,.0f} unusually high (market max ₹{max_salary:,.0f}).",
            "hard_cap": False,
        }
    if salary < 60_000:
        return {
            "flag":     True,
            "penalty":  20,
            "reason":   f"Salary ₹{salary:,.0f}/yr is below minimum wage — bait-and-switch risk.",
            "hard_cap": False,
        }
    return {"flag": False, "penalty": 0, "reason": "Salary within expected range.", "hard_cap": False}


def check_nlp_classifier(offer_text: str) -> Dict:
    model = _get_model()
    if model is None:
        return {
            "flag": False, "confidence": 0.0, "penalty": 0,
            "reason": "NLP model unavailable — run train_classifier.py.",
            "hard_cap": False,
        }
    try:
        prob = float(model.predict_proba([offer_text])[0][1])
    except Exception as exc:
        logger.error("NLP inference error: %s", exc)
        return {"flag": False, "confidence": 0.0, "penalty": 0,
                "reason": f"NLP inference error: {exc}", "hard_cap": False}

    flag = prob > 0.75
    return {
        "flag":       flag,
        "confidence": round(prob, 3),
        "penalty":    35 if flag else 0,
        "reason":     "NLP classifier flagged offer as scam-like." if flag else "Text appears legitimate.",
        "hard_cap":   prob > 0.90,   # extreme confidence → hard cap in fuser
    }


# ─────────────────────────────────────────────────────────────
#  Public entry point
# ─────────────────────────────────────────────────────────────
def run_ml_checks(offer_text: str, salary: float = 0, company: str = "") -> Dict:
    """
    Returns a dict with `details` keyed by check name.
    Each detail entry has: flag, penalty, reason, hard_cap.
    The `trust_score` and `reasons` fields are included for convenience
    but the AUTHORITATIVE verdict comes from main.py's fuse_scores().
    """
    fee_result    = check_fee_language(offer_text)
    salary_result = check_salary_anomaly(salary, company)
    nlp_result    = check_nlp_classifier(offer_text)

    details = {
        "fee_language":    fee_result,
        "salary_anomaly":  salary_result,
        "nlp":             nlp_result,
    }

    # Convenience score for standalone use (not used by main.py fuser)
    total_penalty = sum(d["penalty"] for d in details.values())
    convenience_score = max(0, min(100, 100 - total_penalty))

    reasons = [d["reason"] for d in details.values() if d.get("flag")]

    return {
        "trust_score": convenience_score,   # indicative only
        "reasons":     reasons,
        "details":     details,
    }