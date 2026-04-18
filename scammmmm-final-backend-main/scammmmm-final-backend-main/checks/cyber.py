"""
ScamShield — Cybersecurity Analysis Engine v4.0
================================================
Changes from v3.0:
  - phone_number field now read from CheckRequest (was always empty)
  - WHOIS/SSL calls wrapped with explicit timeouts (no thread leak)
  - Duplicate Cyrillic homoglyph key removed
  - Missing-library warnings emitted at import time (not silently skipped)
  - check_company_reputation: replaced non-deterministic zlib seed heuristic
    with a proper "unknown company" penalty
  - Unified SALARY_RANGES imported from checks.ml (single source of truth)
  - All other logic preserved from v3.0
"""

from __future__ import annotations

import logging
import math
import re
import socket
import ssl
import statistics
import zlib
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

# ── Import shared salary ranges from ml layer ──────────────────────────────
try:
    from checks.ml import SALARY_RANGES
except ImportError:
    SALARY_RANGES: Dict[str, Tuple[float, float]] = {}

# ── Optional deps with startup warnings ───────────────────────────────────
logger = logging.getLogger("scamshield.cyber")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(_h)

try:
    import whois as _whois
    _HAS_WHOIS = True
except ImportError:
    _HAS_WHOIS = False
    logger.warning(
        "python-whois not installed — domain age checks will be skipped. "
        "Install with: pip install python-whois"
    )

try:
    from rapidfuzz import fuzz as _fuzz
    _HAS_RAPIDFUZZ = True
except ImportError:
    _HAS_RAPIDFUZZ = False
    logger.warning(
        "rapidfuzz not installed — falling back to trigram similarity for typosquat detection. "
        "Install with: pip install rapidfuzz"
    )

# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 1 — CONSTANTS & DATASETS  (unchanged from v3.0)
# ═══════════════════════════════════════════════════════════════════════════

CANONICAL_COMPANY_DOMAINS: Dict[str, str] = {
    "google": "google.com", "alphabet": "google.com",
    "microsoft": "microsoft.com", "msft": "microsoft.com",
    "amazon": "amazon.com", "aws": "amazon.com",
    "apple": "apple.com",
    "meta": "meta.com", "facebook": "facebook.com", "instagram": "meta.com",
    "netflix": "netflix.com",
    "tesla": "tesla.com",
    "openai": "openai.com",
    "anthropic": "anthropic.com",
    "nvidia": "nvidia.com",
    "intel": "intel.com",
    "amd": "amd.com",
    "qualcomm": "qualcomm.com",
    "samsung": "samsung.com",
    "sony": "sony.com",
    "lg": "lg.com",
    "infosys": "infosys.com",
    "tcs": "tcs.com", "tata consultancy": "tcs.com",
    "wipro": "wipro.com",
    "hcl": "hcltech.com", "hcltech": "hcltech.com",
    "tech mahindra": "techmahindra.com", "techmahindra": "techmahindra.com",
    "mphasis": "mphasis.com",
    "cognizant": "cognizant.com",
    "capgemini": "capgemini.com",
    "l&t infotech": "ltimindtree.com", "ltimindtree": "ltimindtree.com",
    "persistent": "persistent.com",
    "hexaware": "hexaware.com",
    "mindtree": "ltimindtree.com",
    "flipkart": "flipkart.com",
    "paytm": "paytm.com",
    "zomato": "zomato.com",
    "swiggy": "swiggy.com",
    "byju's": "byjus.com", "byjus": "byjus.com",
    "ola": "olacabs.com",
    "razorpay": "razorpay.com",
    "zerodha": "zerodha.com",
    "freshworks": "freshworks.com",
    "zoho": "zoho.com",
    "meesho": "meesho.com",
    "cred": "cred.club",
    "nykaa": "nykaa.com",
    "delhivery": "delhivery.com",
    "ibm": "ibm.com",
    "oracle": "oracle.com",
    "sap": "sap.com",
    "salesforce": "salesforce.com",
    "adobe": "adobe.com",
    "servicenow": "servicenow.com",
    "workday": "workday.com",
    "zendesk": "zendesk.com",
    "atlassian": "atlassian.com",
    "jira": "atlassian.com",
    "github": "github.com",
    "gitlab": "gitlab.com",
    "docker": "docker.com",
    "hashicorp": "hashicorp.com",
    "databricks": "databricks.com",
    "snowflake": "snowflake.com",
    "uber": "uber.com",
    "airbnb": "airbnb.com",
    "twitter": "twitter.com", "x": "x.com",
    "linkedin": "linkedin.com",
    "spotify": "spotify.com",
    "shopify": "shopify.com",
    "stripe": "stripe.com",
    "twilio": "twilio.com",
    "okta": "okta.com",
    "palo alto networks": "paloaltonetworks.com",
    "crowdstrike": "crowdstrike.com",
    "fortinet": "fortinet.com",
    "deloitte": "deloitte.com",
    "accenture": "accenture.com",
    "pwc": "pwc.com", "pricewaterhousecoopers": "pwc.com",
    "kpmg": "kpmg.com",
    "ey": "ey.com", "ernst & young": "ey.com",
    "mckinsey": "mckinsey.com",
    "bcg": "bcg.com", "boston consulting": "bcg.com",
    "bain": "bain.com",
    "gartner": "gartner.com",
    "bosch": "bosch.com",
    "siemens": "siemens.com",
    "philips": "philips.com",
    "honeywell": "honeywell.com",
    "ge": "ge.com", "general electric": "ge.com",
    "3m": "3m.com",
    "hdfc": "hdfc.com", "hdfc bank": "hdfcbank.com",
    "icici": "icicibank.com",
    "axis bank": "axisbank.com",
    "sbi": "sbi.co.in",
    "kotak": "kotak.com",
    "reliance": "ril.com",
    "tata": "tata.com",
    "mahindra": "mahindra.com",
    "bajaj": "bajaj.com",
}

FREE_EMAIL_PROVIDERS: Set[str] = {
    "gmail.com", "yahoo.com", "yahoo.co.in", "yahoo.co.uk", "yahoo.fr",
    "hotmail.com", "hotmail.co.uk", "hotmail.fr", "hotmail.in",
    "outlook.com", "outlook.in", "outlook.co.uk",
    "live.com", "live.in", "live.co.uk",
    "msn.com",
    "rediffmail.com", "rediff.com",
    "protonmail.com", "proton.me",
    "yandex.com", "yandex.ru",
    "zoho.com",
    "aol.com",
    "icloud.com", "me.com", "mac.com",
    "gmx.com", "gmx.net", "gmx.de",
    "mail.com", "email.com",
    "fastmail.com", "fastmail.fm",
    "hushmail.com",
    "tutanota.com", "tuta.io",
    "lycos.com", "rocketmail.com",
    "inbox.com",
    "ymail.com",
    "mail.ru", "bk.ru", "list.ru", "internet.ru",
    "wp.pl", "o2.pl",
    "web.de", "t-online.de",
    "libero.it",
    "virgilio.it",
    "laposte.net",
    "orange.fr",
    "free.fr",
    "sfr.fr",
}

DISPOSABLE_EMAIL_DOMAINS: Set[str] = {
    "temp-mail.org", "temp-mail.io", "tempmail.com",
    "guerrillamail.com", "guerrillamail.info", "guerrillamail.biz",
    "10minutemail.com", "10minutemail.net", "10minutemail.de",
    "mailinator.com", "mailinator.net",
    "sharklasers.com", "guerrillamailblock.com", "grr.la",
    "getnada.com", "dispostable.com",
    "yopmail.com", "yopmail.fr",
    "throwam.com", "throwawaymail.com",
    "spamgourmet.com", "spamgourmet.net",
    "trashmail.com", "trashmail.io", "trashmail.me",
    "spamherelots.com", "spam4.me",
    "filzmail.com",
    "mailnull.com",
    "spamdecoy.net",
    "tempr.email",
    "fakeinbox.com",
    "mailnesia.com",
    "maildrop.cc",
    "discard.email",
    "mailexpire.com",
    "spambox.us",
    "tempail.com",
    "getairmail.com",
    "nwldx.com",
    "tempinbox.com",
    "0-mail.com",
    "spamtrap.ro",
    "deadaddress.com",
    "no-spam.ws",
    "jetable.fr.nf",
}

SUSPICIOUS_TLDS: Set[str] = {
    "ga", "cf", "tk", "ml", "gq",
    "xyz", "top", "click", "buzz", "site", "online", "club", "work",
    "loan", "biz", "info", "link",
    "win", "racing", "date", "download", "review", "trade", "stream",
    "accountant", "cricket", "party", "science", "faith",
    "bid", "webcam", "men", "gdn",
    "icu", "bar", "monster", "cyou", "rest", "sbs", "quest",
    "bond", "cfd",
}

SEMI_SUSPICIOUS_TLDS: Set[str] = {"co", "io", "cc", "net", "org", "us", "me"}

URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at",
    "tiny.cc", "bl.ink", "soo.gd", "clck.ru", "short.io",
    "lnkd.in", "go.ly", "snip.ly", "bc.vc", "adf.ly",
    "linktr.ee", "beacons.ai",
}

TRUSTED_JOB_BOARDS: Set[str] = {
    "linkedin.com", "naukri.com", "indeed.com", "glassdoor.com",
    "monster.com", "shine.com", "timesjobs.com", "foundit.in",
    "instahyre.com", "cutshort.io", "wellfound.com", "angellist.com",
    "internshala.com", "iimjobs.com", "hirist.com", "amazon.jobs",
    "careers.wipro.com", "infosys.com", "careers.infosys.com",
}

SCAM_DOMAIN_KEYWORDS: List[str] = [
    "job-offer", "job-apply", "career-portal", "hiring-now",
    "work-from-home", "wfh-jobs", "earn-online", "part-time-jobs",
    "apply-now", "get-hired", "instant-job", "easy-job",
    "salary-daily", "daily-earning", "earn-daily",
    "online-income", "home-income", "passive-income",
    "recruitment-hub", "job-vacancy", "vacancy-alert",
]

# FIX: removed duplicate Cyrillic "а" key (was listed twice in v3.0)
HOMOGLYPH_MAP: Dict[str, str] = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "6": "g", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s", "!": "i",
    "\u0430": "a",   # Cyrillic а
    "\u0435": "e",   # Cyrillic е
    "\u043e": "o",   # Cyrillic о
    "\u0440": "p",   # Cyrillic р
    "\u0441": "c",   # Cyrillic с
    "\u0443": "y",   # Cyrillic у
    "\u0445": "x",   # Cyrillic х
    "\u0456": "i",   # Cyrillic і
    "\u0455": "s",   # Cyrillic ѕ
    "\u03bf": "o",   # Greek ο
    "\u03c1": "p",   # Greek ρ
    "\u0261": "g",   # IPA ɡ
    "\u217c": "l",   # Roman numeral ⅼ
    "vv": "w", "rn": "m",
}

SCAM_TEXT_TIERS: Dict[str, Dict] = {
    "CRITICAL": {
        "penalty": 22,
        "phrases": [
            "processing fee", "wire transfer", "send money", "advance payment",
            "western union", "registration fee", "security deposit", "money gram",
            "upfront fee", "refundable deposit", "pay to work", "investment required",
            "training fee", "kit fee", "pay for kit", "buy starter kit",
            "courier charges", "customs duty payment", "initial investment",
            "pay first", "money order", "paypal transfer",
        ],
    },
    "HIGH": {
        "penalty": 13,
        "phrases": [
            "guaranteed income", "100% placement", "money back guarantee",
            "click here to accept", "login to your bank", "confirm your bank",
            "share your otp", "otp verification", "guaranteed job",
            "100% job guarantee", "no rejection", "your selection is confirmed",
            "you have been selected", "congratulations you won",
            "claim your offer", "limited time offer", "offer expires",
        ],
    },
    "MEDIUM": {
        "penalty": 8,
        "phrases": [
            "no experience required", "no qualification required",
            "immediate joining", "urgent requirement", "limited seats",
            "act now", "hurry", "don't miss", "last chance",
            "work from home", "earn from home", "part time job",
            "data entry", "copy paste job", "typing job", "online survey job",
            "liking job", "ad posting job", "affiliate job",
            "earn \u20b9", "earn rs.", "earn usd", "per day earning",
            "weekly payout", "daily payment", "instant payment",
        ],
    },
    "CONTEXTUAL": {
        "penalty": 5,
        "phrases": [
            "whatsapp", "telegram", "connect here", "chat with us",
            "contact on whatsapp", "message on telegram",
            "google form", "google forms", "fill the form",
        ],
    },
    "PRESSURE": {
        "penalty": 6,
        "phrases": [
            "seats filling fast", "only few seats left", "respond within",
            "reply within 24 hours", "immediate response required",
            "failure to respond", "offer will lapse",
        ],
    },
}

_SALARY_DB: Dict[str, Any] = {
    "fresher":          (200_000,    800_000),
    "entry":            (300_000,  1_200_000),
    "mid":              (600_000,  3_000_000),
    "senior":         (1_200_000,  6_000_000),
    "lead":           (2_000_000,  9_000_000),
    "manager":        (2_500_000, 12_000_000),
    "director":       (5_000_000, 25_000_000),
    "vp":            (10_000_000, 50_000_000),
    "default":          (300_000,  8_000_000),
    "big_tech_ceiling":  60_000_000,
    "indian_it_ceiling": 15_000_000,
    "startup_ceiling":   25_000_000,
}

BIG_TECH_COMPANIES: Set[str] = {
    "google", "microsoft", "amazon", "apple", "meta",
    "openai", "anthropic", "nvidia",
}
INDIAN_IT_COMPANIES: Set[str] = {
    "tcs", "infosys", "wipro", "hcl", "tech mahindra",
    "mphasis", "cognizant", "capgemini", "ltimindtree",
    "persistent", "hexaware",
}

SUSPICIOUS_COUNTRY_CODES: Dict[str, str] = {
    "900": "Premium-rate (900)",
    "976": "Premium-rate (976)",
    "809": "Premium-rate Caribbean",
    "284": "BVI premium",
    "876": "Jamaica scam hub",
    "473": "Grenada scam",
    "649": "Turks & Caicos premium",
}

VOIP_PATTERNS: List[re.Pattern] = [
    re.compile(r"^1(800|888|877|866|855|844|833)\d{7}$"),
]

# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 2 — NORMALISATION
# ═══════════════════════════════════════════════════════════════════════════

def _homoglyph_normalize(text: str) -> str:
    result = text.lower()
    result = result.replace("vv", "w").replace("rn", "m")
    return "".join(HOMOGLYPH_MAP.get(c, c) for c in result)


def normalize_input(data: dict) -> dict:
    normalized: Dict[str, Any] = {"_raw": dict(data)}

    job_url = (data.get("job_url") or "").strip().strip("\"'")
    normalized["job_url"] = job_url
    domain = ""
    subdomains: List[str] = []
    url_path = ""
    if job_url and job_url.lower() not in {"n/a", "none"}:
        try:
            parsed = urlparse(job_url if "://" in job_url else f"https://{job_url}")
            domain = (parsed.hostname or "").lower().strip(".")
            url_path = parsed.path or ""
            parts = domain.split(".")
            if len(parts) > 2:
                subdomains = parts[:-2]
        except Exception:
            domain = ""
    normalized["domain"] = domain
    normalized["url_path"] = url_path
    normalized["subdomains"] = subdomains
    normalized["domain_normalized"] = _homoglyph_normalize(domain)

    email = (data.get("recruiter_email") or "").strip().lower()
    normalized["recruiter_email"] = email
    normalized["email_domain"] = email.split("@", 1)[1] if "@" in email else ""
    normalized["email_local"]  = email.split("@", 1)[0] if "@" in email else ""

    # FIX: phone_number now correctly read from input
    phone = str(data.get("phone_number") or "")
    normalized["phone_number"] = phone
    normalized["phone_clean"]  = re.sub(r"\D", "", phone)

    company_raw = (data.get("company_claimed") or "").strip()
    company = company_raw.lower()
    normalized["company_claimed"]   = company_raw
    normalized["company"]           = company
    normalized["canonical_domain"]  = CANONICAL_COMPANY_DOMAINS.get(company, "")
    normalized["company_normalized"] = _homoglyph_normalize(company)

    salary = data.get("salary_offered")
    try:
        normalized["salary_offered"] = float(salary) if salary is not None else None
    except Exception:
        normalized["salary_offered"] = None

    normalized["offer_text"] = (data.get("offer_text") or "").strip()
    return normalized


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 3 — HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _skip(reason: str) -> dict:
    return {"flag": False, "penalty": 0, "reason": reason,
            "category": "SYSTEM", "confidence": 0.0}

def _flag(penalty: int, reason: str, category: str,
          confidence: float = 0.85) -> dict:
    return {"flag": True, "penalty": int(penalty), "reason": reason,
            "category": category, "confidence": round(min(confidence, 0.99), 2)}

def _clean(reason: str, category: str, confidence: float = 0.90) -> dict:
    return {"flag": False, "penalty": 0, "reason": reason,
            "category": category, "confidence": round(confidence, 2)}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _penalty_stack(*penalties: float) -> float:
    total = 0.0
    for i, p in enumerate(sorted(penalties, reverse=True)):
        total += p / (1 + i * 0.15)
    return total


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 4 — INDIVIDUAL CHECKS
# ═══════════════════════════════════════════════════════════════════════════

def check_domain_age(data: dict) -> dict:
    domain = data.get("domain")
    if not domain or domain.lower() in {"n/a", "none", "unknown"}:
        return _skip("N/A")
    if not _HAS_WHOIS:
        return _skip("python-whois not installed")
    try:
        # FIX: explicit timeout via socket default (whois library doesn't expose timeout param)
        import socket as _sock
        old_timeout = _sock.getdefaulttimeout()
        _sock.setdefaulttimeout(8)
        try:
            w = _whois.whois(domain)
        finally:
            _sock.setdefaulttimeout(old_timeout)

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if not creation:
            return _skip("No creation date in WHOIS")
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation).days
        if age_days < 3:
            return _flag(45, f"Domain is brand new ({age_days}d old)", "DOMAIN_RISK", 0.97)
        if age_days < 14:
            return _flag(35, f"Domain created {age_days}d ago — very suspicious for recruitment",
                         "DOMAIN_RISK", 0.92)
        if age_days < 60:
            return _flag(20, f"Domain is only {age_days}d old", "DOMAIN_RISK", 0.80)
        if age_days < 180:
            return _flag(8, f"Relatively new domain ({age_days}d)", "DOMAIN_RISK", 0.65)
        return _clean(f"Domain age: {age_days}d — established", "DOMAIN_RISK")
    except Exception as exc:
        return _skip(f"WHOIS error: {exc}")


def check_email_validity(data: dict) -> dict:
    domain  = data.get("email_domain")
    local   = data.get("email_local", "")
    company = data.get("company", "")
    email   = data.get("recruiter_email", "")

    if not domain:
        return _skip("No email provided")

    if domain in DISPOSABLE_EMAIL_DOMAINS:
        return _flag(48, f"Disposable email service detected: {domain}",
                     "EMAIL_RISK", 0.99)

    if domain in FREE_EMAIL_PROVIDERS:
        company_clean = company.replace(" ", "")
        local_clean = local.replace(".", "").replace("_", "").replace("-", "")
        company_first = company.split()[0] if company else ""
        impersonates = (
            (len(company_clean) >= 2 and company_clean in local_clean) or
            (len(company_first) >= 3 and company_first in local_clean)
        )
        if company and impersonates:
            return _flag(45, f"Recruiter impersonates '{company}' via free email ({email})",
                         "EMAIL_RISK", 0.95)
        # Numeric or random local part on free email = higher penalty
        digit_ratio_local = sum(c.isdigit() for c in local) / max(len(local), 1)
        if digit_ratio_local > 0.55:
            return _flag(45, f"Numeric throwaway address on free email ({email})",
                         "EMAIL_RISK", 0.92)
        return _flag(30, f"Recruiter uses free consumer email ({domain})",
                     "EMAIL_RISK", 0.88)

    digit_ratio = sum(c.isdigit() for c in local) / max(len(local), 1)
    if digit_ratio > 0.55:
        return _flag(30, f"Email local-part is mostly numeric ({local}@{domain}) — likely auto-generated",
                     "EMAIL_RISK", 0.88)

    entropy = _shannon_entropy(local)
    if entropy > 3.8 and len(local) > 4:
        return _flag(35, f"Email local-part appears randomly generated (entropy={entropy:.2f})",
                     "EMAIL_RISK", 0.85)

    if company and company.replace(" ", "") in local and domain not in (
        data.get("canonical_domain", ""), ""
    ):
        return _flag(25, f"Email mimics '{company}' in local-part but domain is unrelated",
                     "EMAIL_RISK", 0.88)

    return _clean(f"Email domain '{domain}' is business-class", "EMAIL_RISK")


def check_typosquat(data: dict) -> dict:
    domain    = data.get("domain", "")
    canonical = data.get("canonical_domain", "")
    company   = data.get("company", "")

    if not domain or domain.lower() in {"n/a", "none", "unknown"}:
        return _skip("N/A")

    if any(domain == jb or domain.endswith("." + jb) for jb in TRUSTED_JOB_BOARDS) or domain == canonical:
        return _clean(f"URL is a trusted job board or canonical domain ({domain}) — typosquat check skipped",
                      "IMPERSONATION_RISK", 0.95)

    best_match_score = 0
    best_match_name  = ""
    d_base = domain.rsplit(".", 1)[0]

    for name, cdomain in CANONICAL_COMPANY_DOMAINS.items():
        c_base = cdomain.rsplit(".", 1)[0]
        if _HAS_RAPIDFUZZ:
            sim = _fuzz.ratio(d_base, c_base)
        else:
            def trigrams(s):
                return {s[i:i+3] for i in range(len(s)-2)}
            t1, t2 = trigrams(d_base), trigrams(c_base)
            sim = 100 * len(t1 & t2) / max(len(t1 | t2), 1) if t1 or t2 else 0

        if sim > best_match_score and d_base != c_base:
            best_match_score = sim
            best_match_name  = name

    if best_match_score >= 90:
        return _flag(40, f"High-confidence typosquat: '{domain}' mimics '{best_match_name}'",
                     "IMPERSONATION_RISK", min(0.95, best_match_score / 100))
    if best_match_score >= 78:
        return _flag(28, f"Probable typosquat: '{domain}' resembles '{best_match_name}' ({best_match_score:.0f}% sim)",
                     "IMPERSONATION_RISK", best_match_score / 100)
    if best_match_score >= 65:
        return _flag(14, f"Possible lookalike: '{domain}' similar to '{best_match_name}' ({best_match_score:.0f}% sim)",
                     "IMPERSONATION_RISK", 0.60)

    d_norm = _homoglyph_normalize(d_base)
    for _, cdomain in CANONICAL_COMPANY_DOMAINS.items():
        c_norm = _homoglyph_normalize(cdomain.rsplit(".", 1)[0])
        if d_norm == c_norm and d_base != cdomain.rsplit(".", 1)[0]:
            return _flag(45, f"Homoglyph attack detected: '{domain}' is visually identical to a known brand",
                         "IMPERSONATION_RISK", 0.97)

    # Brand-name-in-domain check: if domain contains a known brand name
    # but is NOT the official domain, flag as likely impersonation
    d_lower = d_base.lower().replace("-", "").replace("_", "").replace(".", "")
    for name, cdomain in CANONICAL_COMPANY_DOMAINS.items():
        brand = name.lower().replace(" ", "")
        c_base_clean = cdomain.rsplit(".", 1)[0].lower()
        if len(brand) >= 3 and brand in d_lower and d_base.lower() != c_base_clean:
            # The domain embeds a real brand name but is NOT the official domain
            return _flag(35, f"Brand impersonation: '{domain}' contains brand name '{name}' but is not the official domain '{cdomain}'",
                         "IMPERSONATION_RISK", 0.88)

    return _clean("No typosquat or homoglyph spoofing detected", "IMPERSONATION_RISK")


def check_url_structure(data: dict) -> dict:
    domain   = data.get("domain", "")
    url_path = data.get("url_path", "")
    subs     = data.get("subdomains", [])

    if not domain or domain.lower() in {"n/a", "none", "unknown"}:
        return _skip("N/A")

    penalties: List[Tuple[int, str, float]] = []

    if domain in URL_SHORTENERS:
        penalties.append((35, f"URL shortener hides true destination ({domain}) — never used in legitimate recruitment", 0.90))

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        penalties.append((30, "URL uses a raw IP address — never legitimate recruitment", 0.95))

    tld = domain.split(".")[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        penalties.append((14, f"Uses high-risk TLD (.{tld})", 0.72))
    elif tld in SEMI_SUSPICIOUS_TLDS:
        penalties.append((5, f"Uses semi-suspicious TLD (.{tld})", 0.50))

    is_job_board_domain = any(domain == jb or domain.endswith("." + jb) for jb in TRUSTED_JOB_BOARDS)
    if not is_job_board_domain:
        for known_name, known_domain in CANONICAL_COMPANY_DOMAINS.items():
            brand_base = known_domain.rsplit(".", 1)[0]
            for sub in subs:
                if brand_base in sub or known_name.replace(" ", "") in sub:
                    penalties.append((35, f"Brand impersonation via subdomain: '{domain}'", 0.92))
                    break

    for kw in SCAM_DOMAIN_KEYWORDS:
        if kw in domain:
            penalties.append((20, f"Domain contains known scam keyword: '{kw}'", 0.85))
            break

    d_base  = domain.rsplit(".", 1)[0]
    entropy = _shannon_entropy(d_base)
    if entropy > 3.6 and len(d_base) > 12:
        penalties.append((18, f"Domain has DGA-like randomness (entropy={entropy:.2f})", 0.75))

    path_lower = url_path.lower()
    suspicious_path_terms = ["login", "verify", "confirm", "secure", "update", "account", "wallet", "bank"]
    path_hits = [t for t in suspicious_path_terms if t in path_lower]
    if len(path_hits) >= 2:
        penalties.append((15, f"URL path contains phishing keywords: {path_hits}", 0.80))

    if not penalties:
        return _clean("URL structure looks normal", "URL_RISK")

    total    = _penalty_stack(*[p[0] for p in penalties])
    reasons  = "; ".join(p[1] for p in penalties)
    avg_conf = statistics.mean(p[2] for p in penalties)
    return _flag(int(min(45, total)), reasons, "URL_RISK", avg_conf)


def check_ssl(data: dict) -> dict:
    domain = data.get("domain")
    if not domain or domain.lower() in {"n/a", "none", "unknown"}:
        return _skip("N/A")

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(socket.AF_INET),
                             server_hostname=domain) as s:
            s.settimeout(5)   # FIX: explicit 5 s timeout
            s.connect((domain, 443))
            cert = s.getpeercert()

        issuer_dict  = dict(x[0] for x in cert.get("issuer", []))
        subject_dict = dict(x[0] for x in cert.get("subject", []))
        issuer  = issuer_dict.get("organizationName", "").lower()
        subject = subject_dict.get("commonName", "").lower()

        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (exp - datetime.now(timezone.utc)).days
                if days_left < 0:
                    return _flag(35, "SSL certificate has EXPIRED", "INFRASTRUCTURE_RISK", 0.98)
                if days_left < 10:
                    return _flag(20, f"SSL certificate expires in {days_left}d — poorly maintained",
                                 "INFRASTRUCTURE_RISK", 0.85)
            except ValueError:
                pass

        free_cas = ["let's encrypt", "zerossl", "buypass", "ssl.com", "sectigo automated"]
        if any(ca in issuer for ca in free_cas):
            return _flag(12, f"Free/automated SSL (CA: {issuer}) — easy to obtain for scam sites",
                         "INFRASTRUCTURE_RISK", 0.70)

        if domain not in subject and f"*.{'.'.join(domain.split('.')[1:])}" not in subject:
            return _flag(22, f"SSL subject '{subject}' doesn't match domain '{domain}'",
                         "INFRASTRUCTURE_RISK", 0.88)

        return _clean(f"Valid SSL from '{issuer}'", "INFRASTRUCTURE_RISK")

    except ssl.SSLCertVerificationError:
        return _flag(30, "SSL certificate verification failed (untrusted CA or self-signed)",
                     "INFRASTRUCTURE_RISK", 0.90)
    except (socket.timeout, ConnectionRefusedError):
        return _flag(22, "No SSL response — site may be down or HTTPS not configured",
                     "INFRASTRUCTURE_RISK", 0.78)
    except Exception as exc:
        return _flag(15, f"SSL check inconclusive: {exc}", "INFRASTRUCTURE_RISK", 0.55)


def check_salary_anomaly(data: dict) -> dict:
    salary  = data.get("salary_offered")
    company = data.get("company", "")

    if salary is None or salary == 0:
        return _skip("No salary provided")

    # Use shared SALARY_RANGES from ml layer
    lo, hi = SALARY_RANGES.get("default", (300_000, 8_000_000))

    # Extract role if passed directly from frontend's Salary Tab (Role: <role>)
    offer_text = data.get("offer_text", "")
    role = ""
    if offer_text.startswith("Role: "):
        role = offer_text.replace("Role: ", "").strip().lower()

    if company in BIG_TECH_COMPANIES:
        ceiling = _SALARY_DB["big_tech_ceiling"]
    elif company in INDIAN_IT_COMPANIES:
        ceiling = _SALARY_DB["indian_it_ceiling"]
    else:
        ceiling = _SALARY_DB["startup_ceiling"]

    # Fraudulent 'Data Entry' / 'Typing' jobs usually dangle high salaries
    scam_roles = {"data entry", "data entry operator", "typist", "form filling", "packing", "home packing"}
    if role in scam_roles or any(r in role for r in scam_roles):
        ceiling = 300_000  # Cap data entry at exactly ₹3 LPA

    if salary > ceiling:
        ratio = salary / ceiling
        role_msg = f" for '{role.title()}' role" if role else ""
        return _flag(28, f"Salary ₹{salary:,.0f} is {ratio:.1f}× the realistic ceiling (₹{ceiling:,.0f}){role_msg}",
                     "SALARY_RISK", min(0.97, 0.75 + (ratio - 1) * 0.05))

    if salary > hi * 2.5:
        return _flag(18, f"Salary \u20b9{salary:,.0f} is unusually high vs market max \u20b9{hi:,.0f}",
                     "SALARY_RISK", 0.80)

    if salary > 0 and salary % 100_000 == 0 and salary > 2_000_000:
        return _flag(6, f"Salary is a suspiciously round number (\u20b9{salary:,.0f})", "SALARY_RISK", 0.55)

    if salary < 60_000:
        if salary < 50_000:
            return _flag(30, f"Salary ₹{salary:,.0f}/year is absurdly low — almost certainly fraudulent",
                         "SALARY_RISK", 0.95)
        return _flag(20, f"Salary ₹{salary:,.0f}/year is below minimum wage — likely fraudulent",
                     "SALARY_RISK", 0.82)

    return _clean(f"Salary \u20b9{salary:,.0f} is within market range", "SALARY_RISK")


def check_offer_text(data: dict) -> dict:
    raw  = data.get("offer_text", "")
    text = raw.lower()

    if not text or len(text.strip()) < 15:
        return _skip("No offer text provided or text too short")

    findings: List[str] = []
    raw_penalties: List[float] = []

    for tier, cfg in SCAM_TEXT_TIERS.items():
        hits = [p for p in cfg["phrases"] if p in text]
        if hits:
            base = cfg["penalty"]
            tier_penalty = base * (1 + (len(hits) - 1) * 0.18)
            raw_penalties.append(tier_penalty)
            findings.append(f"[{tier}] {', '.join(hits[:4])}")

    caps_words = re.findall(r"\b[A-Z]{5,}\b", raw)
    excl_count = raw.count("!")
  
    if len(caps_words) > 8 and excl_count > 3:
        raw_penalties.append(10)
        findings.append(f"Urgency signals: {len(caps_words)} CAPS words, {excl_count} exclamation marks")

    emoji_count = len(re.findall(
        r"[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF"
        r"\U0001F680-\U0001F6FF\U0001F1E0-\U0001F1FF\u2605\u2713\u2714\u2705\u2b50\U0001F4B0\U0001F4B5\U0001F4B8]",
        raw
    ))
    if emoji_count > 6:
        raw_penalties.append(8)
        findings.append(f"Excessive emoji use ({emoji_count}) — common in social-media scam posts")

    form_links = re.findall(r"docs\.google\.com/forms|forms\.gle|tally\.so|typeform\.com", text)
    if form_links:
        raw_penalties.append(12)
        findings.append(f"Links to external form service: {form_links[0]}")

    social_cta = re.findall(r"(wa\.me|t\.me|whatsapp\.com/|telegram\.me)", text)
    if social_cta:
        raw_penalties.append(14)
        findings.append(f"Direct messaging CTA to unverifiable channel: {social_cta[0]}")

    if re.search(r"\b(routing|account|ifsc|swift)\s*(number|no\.?|code)", text):
        raw_penalties.append(25)
        findings.append("Requests banking details directly in offer text")

    if len(text.strip()) < 80 and raw_penalties:
        raw_penalties.append(6)
        findings.append("Offer text is suspiciously brief and contains risky keywords")

    if not raw_penalties:
        return _clean("No scam patterns found in offer text", "CONTENT_RISK")

    total = _penalty_stack(*raw_penalties)
    return _flag(
        int(min(50, total)),
        f"Suspicious patterns detected: {'; '.join(findings)}",
        "CONTENT_RISK",
        min(0.95, 0.65 + 0.04 * len(raw_penalties)),
    )


def check_phone_validity(data: dict) -> dict:
    phone = data.get("phone_clean", "")

    if not phone:
        return _skip("No phone number provided")

    if len(phone) < 7 or len(phone) > 15:
        return _flag(18, f"Phone length {len(phone)} is outside E.164 spec (7\u201315 digits)",
                     "CONTACT_RISK", 0.85)

    unique_digits = len(set(phone))
    if unique_digits <= 2:
        return _flag(25, f"Phone is almost all identical digits ({phone}) — fake",
                     "CONTACT_RISK", 0.93)

    ascending  = all(int(phone[i]) <= int(phone[i+1]) for i in range(len(phone)-1))
    descending = all(int(phone[i]) >= int(phone[i+1]) for i in range(len(phone)-1))
    if ascending or descending:
        return _flag(20, "Phone number is a sequential pattern — likely fake",
                     "CONTACT_RISK", 0.88)

    for code, label in SUSPICIOUS_COUNTRY_CODES.items():
        if phone.startswith(code) or phone.startswith("1" + code):
            return _flag(30, f"Phone uses premium-rate prefix ({label})",
                         "CONTACT_RISK", 0.90)

    for pat in VOIP_PATTERNS:
        if pat.match(phone):
            return _flag(10, "Toll-free / VoIP number — identity harder to trace",
                         "CONTACT_RISK", 0.60)

    return _clean("Phone number passes E.164 and pattern validation", "CONTACT_RISK")


def check_company_reputation(data: dict) -> dict:
    company  = data.get("company", "").lower()
    canonical = data.get("canonical_domain", "")

    if not company or company in {"unknown", "n/a", ""}:
        return _skip("No company name provided")

    if canonical:
        return _clean(f"Established registered entity: '{company}' \u2192 {canonical}",
                      "REPUTATION_AUDIT", 0.98)

    # FIX: replaced non-deterministic zlib seed heuristic with explicit penalty
    generic_names = [
        "global solutions", "universal services", "prime consultants",
        "best hr", "top recruiters", "elite staffing", "digital marketing firm",
        "online services", "it solutions", "tech solutions", "manpower",
        "recruitment agency", "hr consultants", "placement agency",
    ]
    if any(g in company for g in generic_names):
        return _flag(18, f"Company name '{company}' matches generic scam company pattern",
                     "REPUTATION_AUDIT", 0.80)

    # Unknown company with no canonical mapping — mild penalty
    return _flag(10, f"No canonical domain found for '{company}' — could not verify registry",
                 "REPUTATION_AUDIT", 0.55)


def check_cross_field_consistency(data: dict) -> dict:
    company   = data.get("company", "")
    canonical = data.get("canonical_domain", "")
    email_dom = data.get("email_domain", "")
    url_dom   = data.get("domain", "")

    if not company:
        return _skip("No company to cross-reference")

    issues: List[str] = []
    raw_penalties: List[float] = []

    if canonical:
        if email_dom and email_dom != canonical and email_dom not in FREE_EMAIL_PROVIDERS:
            issues.append(f"Email domain '{email_dom}' \u2260 official domain '{canonical}'")
            raw_penalties.append(22)

        if url_dom and url_dom not in {"n/a", "none", "unknown", ""}:
            is_job_board = any(url_dom == jb or url_dom.endswith("." + jb) for jb in TRUSTED_JOB_BOARDS)
            if url_dom != canonical and not url_dom.endswith("." + canonical) and not is_job_board:
                issues.append(f"Job URL domain '{url_dom}' \u2260 official domain '{canonical}'")
                raw_penalties.append(20)

    if not raw_penalties:
        if canonical:
            return _clean("Email and URL domains are consistent with claimed company",
                          "CONSISTENCY_RISK", 0.95)
        return _skip("No canonical domain to validate against")

    total = _penalty_stack(*raw_penalties)
    return _flag(int(min(40, total)), " | ".join(issues), "CONSISTENCY_RISK",
                 min(0.95, 0.70 + len(issues) * 0.08))


def check_subdomain_abuse(data: dict) -> dict:
    subs   = data.get("subdomains", [])
    domain = data.get("domain", "")

    if not subs or not domain:
        return _skip("N/A")

    for known_name, known_domain in CANONICAL_COMPANY_DOMAINS.items():
        brand_base = known_domain.rsplit(".", 1)[0]
        sub_str    = ".".join(subs).lower()
        if brand_base in sub_str or known_name.replace(" ", "") in sub_str:
            return _flag(40,
                         f"Brand subdomain abuse: '{domain}' fakes '{known_name}' in subdomain",
                         "IMPERSONATION_RISK", 0.93)

    return _clean("No brand name found in subdomain structure", "IMPERSONATION_RISK")


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 5 — CHECK REGISTRY
# ═══════════════════════════════════════════════════════════════════════════

CHECK_REGISTRY = [
    {"name": "domain_age",              "field": "job_url",           "func": check_domain_age},
    {"name": "typosquat",               "field": "job_url",           "func": check_typosquat},
    {"name": "url_structure",           "field": "job_url",           "func": check_url_structure},
    {"name": "subdomain_abuse",         "field": "job_url",           "func": check_subdomain_abuse},
    {"name": "ssl",                     "field": "job_url",           "func": check_ssl},
    {"name": "email_validity",          "field": "recruiter_email",   "func": check_email_validity},
    {"name": "salary_anomaly",          "field": "salary_offered",    "func": check_salary_anomaly},
    {"name": "offer_text",              "field": "offer_text",        "func": check_offer_text},
    {"name": "phone_validity",          "field": "phone_number",      "func": check_phone_validity},
    {"name": "company_reputation",      "field": "company_claimed",   "func": check_company_reputation},
    {"name": "cross_field_consistency", "field": "company_claimed",   "func": check_cross_field_consistency},
]

# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 6 — CORRELATION RULES
# ═══════════════════════════════════════════════════════════════════════════

CORRELATION_RULES = [
    ({"email_validity", "domain_age"},        28, "New domain + free email — coordinated scam setup"),
    ({"typosquat", "ssl"},                    22, "Brand impersonation domain with automated SSL"),
    ({"salary_anomaly", "offer_text"},        18, "High-pay bait paired with scammy offer language"),
    ({"url_structure", "offer_text"},         15, "Suspicious URL infrastructure + scammy content"),
    ({"cross_field_consistency", "typosquat"},30, "Email and URL both misrepresent the claimed company"),
    ({"subdomain_abuse", "ssl"},              25, "Subdomain brand-faking with automated SSL — phishing kit"),
    ({"email_validity", "offer_text"},        20, "Free email recruiter with high-pressure / payment-demand text"),
    ({"company_reputation", "salary_anomaly"},18, "Unknown company offering above-market salary"),
    ({"domain_age", "url_structure"},         20, "Brand-new domain with suspicious URL characteristics"),
    ({"phone_validity", "email_validity"},    15, "Both contact channels fail validation — full fabrication"),
    ({"cross_field_consistency", "email_validity", "domain_age"},
                                              38, "Triple signal: mismatched domains + free email + new domain"),
    ({"typosquat", "offer_text", "salary_anomaly"},
                                              35, "Full impersonation kit: spoofed domain + scam text + inflated salary"),
]

# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 7 — SCORING ENGINE
# ═══════════════════════════════════════════════════════════════════════════

def _logistic_score(raw_penalty: float, steepness: float = 0.045) -> float:
    return 100 / (1 + math.exp(steepness * (raw_penalty - 55)))


def analyze(data: dict) -> dict:
    norm    = normalize_input(data)
    results = []

    # FIX: ThreadPoolExecutor with timeout so no thread hangs indefinitely
    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = {pool.submit(c["func"], norm): c for c in CHECK_REGISTRY}
        for f in as_completed(futures, timeout=20):
            try:
                res = f.result()
            except Exception as exc:
                logger.error("Check failed: %s", exc)
                res = _skip(f"Runtime error: {exc}")
            res.update({"check": futures[f]["name"], "field": futures[f]["field"]})
            results.append(res)

    if not results:
        # Defensive: if all checks fail, return a neutral report
        return {
            "verdict": "REVIEW", "overall_score": 50, "overall_risk": "MEDIUM",
            "confidence": 0.0, "summary": "All checks failed — no signals available.",
            "reasons": ["Engine error: no checks completed"],
            "recommendations": ["Manual review required"],
            "field_analysis": {}, "signals": [],
            "metadata": {"version": "4.0.0", "checks_executed": 0, "correlations_fired": 0, "raw_penalty": 0},
        }

    raw_penalty = sum(r["penalty"] * r["confidence"] for r in results)

    flagged      = {r["check"] for r in results if r["flag"]}
    correlations = []
    for req, base_pen, reason in CORRELATION_RULES:
        if req.issubset(flagged):
            involved    = [r for r in results if r["check"] in req]
            avg_conf    = statistics.mean(r["confidence"] for r in involved)
            amp_penalty = base_pen * avg_conf
            correlations.append({
                "penalty": round(amp_penalty, 2),
                "reason":  reason,
                "checks":  list(req),
            })
            raw_penalty += amp_penalty

    final_score = max(0.0, min(100.0, _logistic_score(raw_penalty)))

    # --- CANONICAL COMPANY FAST-PATH ---
    # If the company is a verified canonical entity with ZERO flags raised,
    # bypass coverage uncertainty entirely — it is definitively legitimate.
    has_flags = any(r["flag"] for r in results)
    is_canonical = any(
        r["check"] == "company_reputation"
        and not r["flag"]
        and "Established registered entity" in r.get("reason", "")
        for r in results
    )
    if is_canonical and not has_flags:
        final_score = max(final_score, 90.0)

    # Coverage-based uncertainty: only apply if NOT a canonical company
    active  = [r for r in results if r["confidence"] > 0]
    coverage = len(active) / max(len(CHECK_REGISTRY), 1)

    if coverage < 0.45:
        # Very low coverage — cap score and force REVIEW
        uncertainty_penalty = (1.0 - coverage) * 25
        final_score = max(0.0, min(final_score - uncertainty_penalty, 72))
    elif coverage < 0.65:
        # Moderate coverage — slight penalty
        uncertainty_penalty = (1.0 - coverage) * 12
        final_score = max(0.0, final_score - uncertainty_penalty)

    if final_score >= 82:
        verdict, risk = "SAFE", "LOW"
    elif final_score >= 58:
        verdict, risk = "REVIEW", "MEDIUM"
    elif final_score >= 28:
        verdict, risk = "LIKELY SCAM", "HIGH"
    else:
        verdict, risk = "SCAM", "CRITICAL"

    # If coverage too low AND not a verified canonical company, never say SAFE
    if coverage < 0.45 and verdict == "SAFE" and not (is_canonical and not has_flags):
        verdict, risk = "REVIEW", "MEDIUM"

    # Apply canonical fast-path verdict override
    if is_canonical and not has_flags:
        verdict, risk = "SAFE", "LOW"

    active_confs = [r["confidence"] for r in results if r["confidence"] > 0]
    mean_conf    = statistics.mean(active_confs) if active_confs else 0.0
    final_conf   = round(mean_conf * 0.75 + coverage * 0.25, 2)

    field_sums: Dict[str, float] = defaultdict(float)
    for r in results:
        field_sums[r["field"]] += r["penalty"]

    field_analysis = {
        f: {
            "score": int(s),
            "risk":  "CRITICAL" if s > 40 else "HIGH" if s > 25 else "MEDIUM" if s > 12 else "LOW",
        }
        for f, s in field_sums.items()
    }

    reasons = (
        [r["reason"] for r in results if r["flag"]]
        + [c["reason"] for c in correlations]
    )

    recs: List[str] = []
    if risk in {"HIGH", "CRITICAL"}:
        recs.append("CRITICAL: Do NOT share personal information (Aadhaar, PAN, bank details, OTP) with this recruiter.")
        recs.append("Report this posting to the job platform, cybercrime.gov.in (India), and warn others.")
    elif risk == "MEDIUM":
        recs.append("Exercise caution and independently verify the employer details before sharing any personal data.")

    if "salary_anomaly" in flagged:
        recs.append("Verify typical market salaries on Glassdoor, LinkedIn Salary, or AmbitionBox. The offered compensation appears irregular.")
    if "email_validity" in flagged:
        recs.append("Confirm the recruiter email matches the company's official domain listed on their website.")
    if "cross_field_consistency" in flagged:
        recs.append("The job URL and email domain do not match the claimed company — independently verify on the official site.")
    if "typosquat" in flagged or "subdomain_abuse" in flagged:
        recs.append("The website URL appears to impersonate a real company. Contact the official company directly to verify this posting.")
    if "offer_text" in flagged:
        recs.append("The offer text contains common scam indicators (e.g., pressure tactics, fee requests). Do not send money.")
    if "domain_age" in flagged:
        recs.append("The domain provided is very new. Established businesses typically use older domains.")
    if "phone_validity" in flagged:
        recs.append("The provided contact number is suspicious or invalid. Rely on official company contact channels.")

    if not recs or risk == "LOW":
        recs = ["Proceed with normal due diligence — verify the company through official channels before sharing personal data."]

    return {
        "verdict":       verdict,
        "overall_score": int(final_score),
        "overall_risk":  risk,
        "confidence":    final_conf,
        "summary": (
            f"ScamShield v4.0 identified {len(flagged)} threat signal(s) across "
            f"{len(correlations)} correlated pattern(s). Risk level: {risk}."
        ),
        "reasons":         reasons,
        "recommendations": recs,
        "field_analysis":  field_analysis,
        "signals":         results,
        "metadata": {
            "version":            "4.0.0",
            "timestamp":          datetime.now(timezone.utc).isoformat(),
            "checks_executed":    len(results),
            "correlations_fired": len(correlations),
            "raw_penalty":        round(raw_penalty, 2),
        },
    }


# ═══════════════════════════════════════════════════════════════════════════
#  SECTION 8 — PUBLIC WRAPPER
# ═══════════════════════════════════════════════════════════════════════════

def run_cyber_checks(job_url: str, recruiter_email: str, company_claimed: str,
                     salary_offered: float = 0, phone_number: str = "") -> dict:
    sample = {
        "job_url":         job_url,
        "company_claimed": company_claimed,
        "recruiter_email": recruiter_email,
        "phone_number":    phone_number,
        "salary_offered":  salary_offered if salary_offered else None,
        "offer_text":      "",
    }
    report = analyze(sample)
    signals_dict = {s["check"]: s for s in report["signals"]}
    signals_dict["advanced_report"] = report
    return signals_dict