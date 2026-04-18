# 🛡️ ScamShield Forensic Workspace

ScamShield is a high-end forensic investigation tool designed to detect and analyze AI-driven job recruitment scams. It combines advanced NLP classification, real-time salary calibration, and deep-header e-mail auditing into a clinical, minimalist interface.

## 📂 Project Structure
- **/fries-rishi-main/frontend**: React (Vite) application with Tailwind CSS and Framer Motion.
- **/scammmmm-final-backend-main/scammmmm-final-backend-main**: FastAPI backend with ML scoring logic.

---

## 🚀 Getting Started

### 1. Backend Setup (FastAPI)
The backend handles the forensic analysis scoring and ML classification.

**Prerequisites:** Python 3.8+

1. **Navigate to the backend directory:**
   ```bash
   cd scammmmm-final-backend-main/scammmmm-final-backend-main
   ```

2. **(Optional) Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/scripts/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r req.txt
   ```

4. **Run the server:**
   ```bash
   python -m uvicorn main:app --reload --port 8000
   ```
   *The API will be live at `http://localhost:8000`*

---

### 2. Frontend Setup (React/Vite)
The frontend provides the clinical forensic dashboard and real-time chat interface.

**Prerequisites:** Node.js 18+

1. **Navigate to the frontend directory:**
   ```bash
   cd fries-rishi-main/frontend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Run the development server:**
   ```bash
   npm run dev
   ```
   *The interface will be live at `http://localhost:5173`*

---

## 🔍 Features
- **Job URL Investigation**: Analyzes job postings for registration fees, infrastructure markers, and domain hygiene.
- **E-mail Audit Tool**: Parses suspicious recruiter emails for urgency tactics and fraud signals.
- **Salary Calibration**: Cross-checks compensation against market rates to detect bait-and-switch scams.
- **Company Verification**: Cross-references recruitment firms against fraudulent naming conventions.

## 🛠️ Tech Stack
- **Frontend**: React, Vite, Framer Motion, Tailwind CSS, Lucide Icons.
- **Backend**: FastAPI, Scikit-learn, Joblib, Uvicorn.
- **Analysis**: Custom NLP classification for scam pattern detection.

---
*Developed for ScamShield Forensic Labs.*
