# 🛡️ ScamShield — AI-Powered Recruitment Fraud Detection

ScamShield is a full-stack cybersecurity intelligence system that detects recruitment scams, fraudulent job offers, and phishing attempts in real-time using a multi-layer detection engine backed by heuristics, WHOIS/DNS analysis, NLP, and machine learning.

---

## 📁 Project Structure

```
Final-repo-scam_sheild/
│
├── fries-rishi-main/                   # Frontend
│   └── scamshield-frontend/
│       ├── src/
│       │   ├── App.jsx                 # Main React UI (all tabs + logic)
│       │   ├── api/                    # Axios API client
│       │   └── index.css / App.css
│       ├── index.html
│       └── package.json
│
└── scammmmm-final-backend-main/        # Backend
    └── scammmmm-final-backend-main/
        ├── main.py                     # FastAPI entrypoint + fuse scorer
        ├── checks/
        │   ├── cyber.py               # 6-layer cyber intelligence engine
        │   └── ml.py                  # ML/NLP salary & fee-language checker
        ├── train_classifier.py        # Script to train NLP scam classifier
        ├── test_comprehensive.py      # 200-case automated test suite
        └── requirements.txt
```

---

## ⚙️ Detection Engine — How It Works

ScamShield runs **11 parallel detection checks** across every input field:

| Check | What It Does |
|---|---|
| `domain_age` | WHOIS lookup — flags brand-new domains (<60 days) |
| `typosquat` | `rapidfuzz` fuzzy match against 80+ known brands |
| `url_structure` | Detects IP-based URLs, suspicious TLDs (`.xyz`, `.tk`, `.gq`) |
| `subdomain_abuse` | Catches `amazon.fake-jobs.com` style impersonation |
| `ssl` | Verifies HTTPS certificate validity |
| `email_validity` | Flags free Gmail/Yahoo spoofing, disposable inboxes, high-entropy addresses |
| `salary_anomaly` | Per-role salary ceiling checks with scam-role detection (Data Entry, Typist) |
| `offer_text` | NLP tier matching against 40+ scam phrase patterns |
| `phone_validity` | E.164 validation + premium-rate prefix detection |
| `company_reputation` | Canonical domain registry with 80+ companies — returns `VERIFIED` instantly for known entities |
| `cross_field_consistency` | Ensures email domain, URL, and company all align |

All signals are fused via a **logistic confidence scorer** with correlation amplification for multi-signal attacks.

---

## 🚀 Running Locally

### Prerequisites
- **Python 3.10+**
- **Node.js 18+** and npm

---

### 1. Backend Setup

```bash
cd scammmmm-final-backend-main\scammmmm-final-backend-main

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Mac / Linux

# Install dependencies
pip install -r requirements.txt

# (Optional) Train the NLP model for advanced text analysis
python train_classifier.py

# Start the API server
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

✅ Backend live at: `http://127.0.0.1:8000`

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

The suite covers **200 edge cases** (50 per field):
- **20 LEGIT** — real company domains, real recruiter emails, realistic salaries
- **20 SCAM** — typosquats, free-email impersonation, absurd salary baits, phishing URLs
- **10 RANDOM** — garbage input that should be rejected or flagged `UNVERIFIED`

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
  "trust_score": 12,
  "verdict": "SCAM",
  "reasons": ["Brand-new domain", "Free email impersonation", "Fee language detected"],
  "field_analysis": { ... },
  "signals": { "cyber_signals": [...], "ml_details": {...} }
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
| `/api/stats` | GET | Total scans, scams caught, scam rate |
| `/api/history` | GET | Last N scan records |
| `/docs` | GET | FastAPI interactive Swagger UI |

---

## 🧠 NLP Model (Optional)

The NLP classifier (`scam_classifier.pkl`) enables advanced semantic scam text detection. Train it once:

```bash
python train_classifier.py
```

Without the model, the engine still runs all 10 cyber checks at full accuracy. The NLP layer adds an additional penalty layer for offer-text analysis.

---

## 🔐 Key Security Features

- **Hard Fee Cap**: Any offer containing fee-transfer language is hard-capped to score ≤ 20 regardless of other signals
- **Canonical Override**: Known legitimate companies (Google, TCS, Swiggy, Razorpay, etc.) bypass uncertainty penalties and return `VERIFIED` immediately
- **Correlation Amplification**: Multiple weak signals compound — e.g. new domain + free email + salary anomaly triggers a 38-point amplification
- **Graceful Degradation**: Missing dependencies (WHOIS timeout, no ML model) do not crash the engine — checks are skipped with confidence=0

---

## 📦 Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 18 + Vite, Vanilla CSS |
| Backend | FastAPI + Uvicorn |
| Cyber Engine | `rapidfuzz`, `python-whois`, `re`, `socket` |
| ML/NLP | `scikit-learn`, `joblib` |
| Database | SQLite (via connection pool) |
| Testing | Custom Python test runner (200 cases) |
