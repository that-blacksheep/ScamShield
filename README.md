# 🛡️ ScamShield — AI-Powered Placement Scam Detection

> **Built for Avenir 2026 · Hackathon PS-02**  
> A forensic-grade tool to detect, analyze, and expose fake job recruitment scams targeting students and fresh graduates.

---

## The Problem

Fake placement scams cost Indian students crores every year — fraudulent offer letters, ghost companies, upfront "registration fees," and bait-and-switch salary traps. Traditional red-flag checklists don't scale. ScamShield does.

---

## What ScamShield Does

ScamShield combines NLP classification, real-time salary benchmarking, and deep e-mail header forensics into a single clinical investigation workspace.

| Module | What It Catches |
|---|---|
| **Job URL Investigator** | Registration fees, domain hygiene, infrastructure red flags |
| **E-mail Audit Engine** | Urgency manipulation, spoofed headers, fraud signal patterns |
| **Salary Calibration** | Bait-and-switch compensation vs. live market rates |
| **Company Verifier** | Fraudulent naming conventions, ghost firm fingerprints |

---

## Tech Stack

**Frontend**
- React + Vite
- Tailwind CSS
- Framer Motion
- Lucide Icons

**Backend**
- FastAPI + Uvicorn
- Scikit-learn + Joblib
- Custom NLP scam classification pipeline

---

## Getting Started

### Prerequisites
- Python 3.8+
- Node.js 18+

---

### 1. Backend (FastAPI)

```bash
# Navigate to backend
cd scammmmm-final-backend-main/scammmmm-final-backend-main

# (Optional) Set up virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# Install dependencies
pip install -r req.txt

# Start the server
python -m uvicorn main:app --reload --port 8000
```

API live at → `http://localhost:8000`

---

### 2. Frontend (React/Vite)

```bash
# Navigate to frontend
cd fries-rishi-main/frontend

# Install dependencies
npm install

# Start dev server
npm run dev
```

Interface live at → `http://localhost:5173`

---

## Project Structure

```
scamshield/
├── fries-rishi-main/
│   └── frontend/               # React (Vite) application
│       ├── src/
│       │   ├── components/     # Forensic UI modules
│       │   ├── pages/          # Dashboard, Audit, Salary, Verify
│       │   └── App.tsx
│       └── package.json
│
└── scammmmm-final-backend-main/
    └── scammmmm-final-backend-main/
        ├── main.py             # FastAPI entry point
        ├── model/              # Trained scam classifier
        ├── utils/              # NLP preprocessing, scoring logic
        └── req.txt
```

---

## Team

Built by **Team ScamShield** at **Avenir 2026 (Innovatrix Hackathon)**  
Developed under **ScamShield Forensic Labs**

---

## License

This project was built for hackathon demonstration purposes.  
Contact the team before reuse or redistribution.
