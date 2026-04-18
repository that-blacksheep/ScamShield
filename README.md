# 🛡️ ScamShield — AI-Powered Recruitment Fraud Detection

ScamShield is a production-grade, full-stack cybersecurity intelligence system that detects recruitment scams, fraudulent job offers, and phishing attempts in real-time using a **multi-layer detection engine** backed by domain heuristics, WHOIS/DNS analysis, fuzzy matching, NLP, and machine learning.

---

## 📁 Project Structure

```
Final-repo-scam_sheild/
│
├── req.txt                             # Python backend requirements (pip install -r req.txt)
│
├── fries-rishi-main/                   # Frontend
│   └── scamshield-frontend/
│       ├── src/
│       │   ├── App.jsx                 # Main React UI (all tabs + logic)
│       │   └── index.css / App.css
│       ├── index.html
│       ├── vite.config.js
│       └── package.json               # npm dependencies
│
└── scammmmm-final-backend-main/        # Backend
    └── scammmmm-final-backend-main/
        ├── main.py                     # FastAPI v4.0 — entrypoint + fusion scorer
        ├── checks/
        │   ├── cyber.py               # 11-check cyber intelligence engine (v4.0)
        │   └── ml.py                  # ML/NLP salary & fee-language checker (v4.0)
        ├── train_classifier.py        # Script to train NLP scam classifier
        ├── test_comprehensive.py      # Automated test suite (200 cases)
        └── scamshield.db              # SQLite audit log (auto-created)
```

---

## ⚙️ Detection Engine — How It Works

ScamShield runs **11 parallel detection checks** across every input field:

| Check | What It Does |
|---|---|
| `domain_age` | WHOIS lookup — flags brand-new domains (< 60 days) |
| `typosquat` | `rapidfuzz` fuzzy match against 80+ known brands |
| `url_structure` | Detects IP-based URLs, suspicious TLDs (`.xyz`, `.tk`, `.gq`), DGA entropy |
| `subdomain_abuse` | Catches `amazon.fake-jobs.com` style impersonation |
| `ssl` | Verifies HTTPS certificate validity, expiry, and CA trust |
| `email_validity` | Flags free Gmail/Yahoo spoofing, disposable inboxes, high-entropy addresses |
| `salary_anomaly` | Per-role salary ceiling checks with scam-role detection (Data Entry, Typist) |
| `offer_text` | NLP tier matching against 40+ scam phrase patterns (5 severity tiers) |
| `phone_validity` | E.164 validation + premium-rate prefix detection |
| `company_reputation` | Canonical domain registry with 80+ companies — returns `VERIFIED` instantly |
| `cross_field_consistency` | Ensures email domain, URL, and company all align |

All signals are fused via a **logistic confidence scorer** with correlation amplification for multi-signal attacks.

---

## 📦 Requirements

### Python (Backend)

```bash
pip install -r req.txt
```

| Package | Version | Purpose |
|---|---|---|
| `fastapi` | ≥ 0.100.0 | REST API framework |
| `uvicorn[standard]` | ≥ 0.23.0 | ASGI server |
| `pydantic` | ≥ 2.0.0 | Request/response validation |
| `pydantic-settings` | ≥ 2.0.0 | Environment-based config (`.env` support) |
| `python-whois` | ≥ 0.8.0 | WHOIS domain-age lookups |
| `rapidfuzz` | ≥ 3.0.0 | Fuzzy string matching for typosquat detection |
| `scikit-learn` | ≥ 1.3.0 | TF-IDF + Logistic Regression NLP classifier |
| `joblib` | ≥ 1.3.0 | ML model serialization |

> **Python 3.10+** is required.

### Node.js (Frontend)

```bash
cd fries-rishi-main/scamshield-frontend
npm install
```

| Package | Version | Purpose |
|---|---|---|
| `react` | ^19.2.4 | UI framework |
| `react-dom` | ^19.2.4 | DOM rendering |
| `axios` | ^1.15.0 | HTTP client for API calls |
| `framer-motion` | ^12.38.0 | Animations & transitions |
| `lucide-react` | ^1.8.0 | Icon library |
| `pdfjs-dist` | ^3.11.174 | In-browser PDF parsing |
| `vite` | ^8.0.4 | Build tool & dev server |

> **Node.js 18+** and npm required.

---

## 🚀 Running Locally

### 1. Backend Setup

```bash
cd scammmmm-final-backend-main\scammmmm-final-backend-main

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Mac / Linux

# Install dependencies
pip install -r ..\..\req.txt

# (Optional) Train the NLP model for advanced text analysis
python train_classifier.py

# Start the API server
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

✅ Backend live at: `http://127.0.0.1:8000`  
📄 Swagger UI at: `http://127.0.0.1:8000/docs`

---

### 2. Frontend Setup

Open a **new terminal window**:

```bash
cd fries-rishi-main\scamshield-frontend

npm install
npm run dev
```

✅ Frontend live at: `http://localhost:5173`

---

## 🧪 Running the Test Suite

With the backend server running, execute:

```bash
cd scammmmm-final-backend-main\scammmmm-final-backend-main
venv\Scripts\activate
python test_comprehensive.py
```

Expected output:
```
FINAL RESULTS: 200 PASSED / 0 FAILED / 200 TOTAL
```

The suite covers **200 edge cases** across 4 categories:
- **LEGIT** — real company domains, real recruiter emails, realistic salaries
- **SCAM** — typosquats, free-email impersonation, absurd salary baits, phishing URLs
- **SUSPICIOUS** — ambiguous signals, borderline cases
- **RANDOM** — garbage input that should be rejected or flagged `UNVERIFIED`

---

## 📡 API Reference

### `POST /api/check`

All fields are optional. The engine scores whatever is provided.

```json
{
  "job_url":          "https://tcs-jobs-hiring.net/apply",
  "company_claimed":  "TCS",
  "recruiter_email":  "tcs.official@gmail.com",
  "phone_number":     "+91 9876543210",
  "salary_offered":   50000000,
  "offer_text":       "Send a refundable security deposit to confirm your slot."
}
```

**Response:**

```json
{
  "request_id":      "a3f7c2b1",
  "trust_score":     12,
  "verdict":         "SCAM",
  "reasons":         ["Brand-new domain", "Free email impersonation", "Fee language detected"],
  "summary":         "Critical threat signals detected",
  "recommendations": ["Do not proceed", "Report to cybercrime portal"],
  "field_analysis":  { "domain": {...}, "email": {...} },
  "signals":         { "cyber_signals": [...], "ml_details": {...} }
}
```

### Verdict Scale

| Score | Verdict | Meaning |
|---|---|---|
| 80–100 | `VERIFIED` | Confirmed legitimate entity — all checks passed |
| 55–79 | `UNVERIFIED` | Could not fully verify — exercise caution |
| 30–54 | `SUSPICIOUS` | Multiple red flags — likely fraudulent |
| 0–29 | `SCAM` | Critical threat signals — definite scam |

### Other Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/stats` | GET | Total scans, scams caught, scam rate % |
| `/api/history` | GET | Last N scan records (paginated) |
| `/health` | GET | Health check — `{"status": "ok", "version": "4.0.0"}` |
| `/docs` | GET | FastAPI interactive Swagger UI |

---

## 🧠 NLP Model (Optional but Recommended)

The NLP classifier (`scam_classifier.pkl`) enables advanced semantic scam text detection using a **TF-IDF + Logistic Regression** pipeline trained on ~120 labelled offer texts.

Train it once before starting the server:

```bash
python train_classifier.py
```

Without the model, the engine still runs all 11 cyber checks at full accuracy. The NLP layer adds an additional penalty layer for offer-text analysis.

---

## 🔐 Key Security Features

- **Hard Fee Cap**: Any offer containing fee-transfer language is hard-capped to score ≤ 20 regardless of other signals
- **Canonical Override**: 80+ known legitimate companies (Google, TCS, Swiggy, Razorpay, etc.) bypass uncertainty penalties and return `VERIFIED` immediately
- **Correlation Amplification**: Multiple weak signals compound — e.g. new domain + free email + salary anomaly triggers a 38-point amplification bonus
- **Graceful Degradation**: Missing dependencies (WHOIS timeout, no ML model) do not crash the engine — checks are skipped with `confidence=0`
- **Thread-safe DB Pool**: SQLite connection pool of 5 connections ensures concurrent requests are handled without race conditions

---

## 🖥️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19 + Vite 8, Framer Motion, Lucide React |
| Backend | FastAPI 0.100+ + Uvicorn |
| Cyber Engine | `rapidfuzz`, `python-whois`, `re`, `socket`, `ssl` |
| ML/NLP | `scikit-learn` (TF-IDF + LogReg), `joblib` |
| Config | `pydantic-settings` (`.env` based) |
| Database | SQLite (thread-safe connection pool, auto-created) |
| Testing | Custom Python test runner (200 cases) |

---

## 👥 Team

**ScamShield** — Developed as a full-stack cybersecurity project.

- Backend & Cyber Engine: Scammmm Final Backend Team
- Frontend: Fries Rishi Team
