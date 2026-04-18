"""
ScamShield — ML Training Script (v4.0)
Improvements: expanded dataset (~120 samples), stratified train/test split,
              classification report printed, model saved with metadata.
Run: python train_classifier.py
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline

# ─────────────────────────────────────────────────────────────
#  SCAM SAMPLES  (label = 1)
# ─────────────────────────────────────────────────────────────
SCAM = [
    # Payment / deposit demands
    "Pay a registration fee before joining the company",
    "Send security deposit of Rs 5000 to confirm your job",
    "Processing fee required for generating your offer letter",
    "Pay INR 5000 to start work from home immediately",
    "Deposit money before training starts, refundable after 3 months",
    "Pay Rs 3000 for document processing and ID verification",
    "Refundable deposit required for laptop dispatch from warehouse",
    "Application charge of Rs 2000 must be paid today to secure seat",
    "Pay training kit fee of 1500 rupees to our account before joining",
    "Upfront fee of Rs 4000 required for background check processing",
    "Send Rs 999 via UPI to unlock your onboarding documents",
    "Wire transfer of $300 required for international work permit",
    "Pay money order for equipment insurance before laptop is shipped",
    "Registration amount of Rs 7500 to be deposited before offer letter",

    # Task / crypto / rating scams
    "Your task is to optimize 40 products daily to earn USDT commission",
    "Work 2 hours a day clicking buttons to increase app ratings and earn instantly",
    "Join our Telegram group to receive daily tasks and earn 5000 INR per day",
    "Submit your crypto wallet address to receive your daily salary",
    "Like and subscribe to YouTube videos to earn quick cash rewards",
    "Rate Amazon products on our app to earn Rs 800 per day",
    "Complete Google Play tasks daily, get paid in USDT directly",
    "Boost app ratings on the Play Store to earn passive income daily",
    "Earn by liking Instagram reels posted by our brand partners",
    "Daily task: add 5-star reviews to assigned products for Rs 500/task",

    # Phishing / credential theft
    "Your employee portal login has been compromised, re-verify bank details here",
    "Click this link to download your mandatory payroll software immediately",
    "To view your secret offer letter enter your Gmail password on our portal",
    "Urgent: Update your PAN and Aadhaar on this external link to avoid cancellation",
    "Sync your bank account to our new HR portal to receive your signing bonus",
    "Enter your net banking credentials to verify your identity for onboarding",
    "Provide your UPI PIN to complete salary account linking process now",
    "Your Aadhaar OTP is required on the employer portal to validate your offer",

    # Fake check / equipment scam
    "We will send you a check for $2000 to purchase equipment from our vendor",
    "Deposit this digital check and wire back remaining balance for office setup",
    "The company will provide a check for MacBook, you must pay insurance first",
    "We provide home office funds via mobile deposit check, cash it and buy supplies",
    "Receive our company cheque, deduct your commission and send balance via NEFT",

    # High pressure / unrealistic
    "Immediate joining! No interview required! Limited seats left, act now!",
    "CONGRATULATIONS!!! You are selected without any technical round. Pay fee now.",
    "WhatsApp us immediately to secure your position before it is gone.",
    "Work from home, no experience needed, 1 lakh per month guaranteed income.",
    "Earn massive income with zero skills, quick selection process via WhatsApp",
    "URGENT REQUIREMENT: 50 candidates needed today, salary Rs 80000 per month",
    "No rejection guaranteed! 100% placement! Pay confirmation deposit now.",
    "You have been selected from our database! Limited offer expires in 2 hours.",
    "Reply within 24 hours or offer will lapse, act fast, seats filling very fast",

    # WhatsApp / Telegram contact
    "Contact our HR on WhatsApp at +91-XXXXXXXXXX to confirm your selection",
    "Join this Telegram channel to receive your daily work assignment and payment",
    "Message our recruiter on wa.me to get the job link and start earning today",
    "All communication is via Telegram only, download and message our bot now",

    # Classic scam phrases
    "Earn Rs 500 per hour from home doing simple data entry, no experience needed",
    "Copy paste job available, earn Rs 15000 per week from your mobile",
    "Online typing job from home, earn Rs 2000 per day guaranteed",
    "Ad posting job vacancy, earn Rs 3000 daily working 2 hours",
    "Affiliate link sharing job, no investment, daily payment via PhonePe",
    "Survey job from home, earn Rs 1000 per survey without any qualification",
    "Form filling work from home, earn Rs 800 per form submitted online",
]

# ─────────────────────────────────────────────────────────────
#  LEGITIMATE SAMPLES  (label = 0)
# ─────────────────────────────────────────────────────────────
LEGIT = [
    # Standard recruitment
    "Your interview is scheduled for tomorrow at 10 AM via Google Meet",
    "Please share your updated resume and a cover letter for the role",
    "We are pleased to offer you the position of Software Engineer at our firm",
    "Your joining date is next Monday, please complete the onboarding form",
    "Please complete the background verification form sent to your email",
    "Welcome to the team, your first day orientation is on the 1st of next month",
    "Please attend the technical interview via Microsoft Teams using the calendar link",
    "Your onboarding session starts next week, HR will coordinate the schedule",
    "Congratulations on clearing all rounds, here is your official offer letter PDF",
    "We look forward to welcoming you to our engineering team on your start date",

    # Verification and compliance (legitimate)
    "The background check will be conducted by a third-party agency, FirstAdvantage",
    "Please upload your previous 3 months salary slips and Form 16 for verification",
    "Your offer is contingent upon a successful reference check and degree audit",
    "Please provide your UAN number for Provident Fund transfer from previous employer",
    "We require a copy of your last employment letter and relieving certificate",
    "Your education credentials will be verified by our onboarding team within 5 days",
    "Please submit your identity documents via our secure HR portal for verification",
    "A soft copy of your appointment letter will be sent within 2 business days",

    # Professional logistics
    "The company-provided laptop will be shipped via BlueDart after your day one",
    "The technical round will focus on Data Structures, Algorithms, and System Design",
    "Please join the Microsoft Teams link in the calendar invite for the HR round",
    "You will receive your corporate email credentials during the orientation session",
    "All interview feedback will be shared within 3 to 5 business days",
    "Our recruiter will schedule a call to discuss the compensation package in detail",
    "The role requires occasional travel to our Bangalore office for quarterly reviews",
    "Please read and sign the employment contract and return it by the end of the week",
    "Your pre-employment medical examination is scheduled at our empanelled clinic",
    "IT asset requisition form will be sent for your laptop and access card setup",

    # Benefits and legal
    "The role includes group medical insurance for you and your dependents",
    "Please review the Non-Disclosure Agreement attached with your employment contract",
    "Your variable pay is tied to the annual performance review cycle in March",
    "The company will never ask for any payment or deposit during the recruitment process",
    "Please refer to the employee handbook for our leave and holiday policy details",
    "ESOP vesting schedule is 4 years with 1 year cliff as per our standard policy",
    "Gratuity is applicable after 5 years of continuous service per the Payment of Gratuity Act",
    "Your health insurance coverage of 5 lakhs per annum starts from day one",
    "We offer a flexible work from home policy of up to 3 days per week",
    "Annual salary revision is tied to company performance and individual KPIs",

    # Salary discussions (legitimate)
    "The CTC for this role is between 12 and 15 lakhs per annum based on experience",
    "We are able to offer a take-home salary of Rs 85000 per month for this position",
    "Your salary breakup includes basic pay HRA and special allowances as per company policy",
    "The offered CTC of 18 LPA will be revisited after your probation period of 6 months",
    "Salary will be credited to your registered bank account on the last working day",

    # Interview process
    "The hiring process consists of 3 rounds: technical, system design, and HR interview",
    "Your coding assessment link has been sent to your email, please complete it in 48 hours",
    "The final round will be with the VP of Engineering via video call next Friday",
    "Please prepare a system design case study to be presented during the interview",
    "Our panel will evaluate problem solving, communication, and culture fit today",
    "Interview feedback is shared within a week and we aim to close offers in 2 weeks",
    "A recruiter from our talent acquisition team will reach out via official email",
]

# ─────────────────────────────────────────────────────────────
#  Training
# ─────────────────────────────────────────────────────────────
def train():
    texts  = SCAM + LEGIT
    labels = [1] * len(SCAM) + [0] * len(LEGIT)

    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 3),      # unigrams, bigrams, trigrams
            stop_words="english",
            max_df=0.90,
            min_df=1,
            sublinear_tf=True,       # log-scaled TF
        )),
        ("clf", LogisticRegression(
            C=5.0,
            class_weight="balanced",
            max_iter=1000,
            solver="lbfgs",
        )),
    ])

    # 5-fold cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(model, texts, labels, cv=cv, scoring="f1")
    print(f"\nCross-validation F1: {scores.mean():.3f} ± {scores.std():.3f}")

    # Fit on full dataset
    model.fit(texts, labels)

    # Print classification report on training data (sanity check)
    preds = model.predict(texts)
    print("\nTraining-set classification report:")
    print(classification_report(labels, preds, target_names=["Legit", "Scam"]))

    # Save model + metadata
    out_dir = Path(__file__).resolve().parent / "models"
    out_dir.mkdir(exist_ok=True)
    model_path = out_dir / "scam_classifier.pkl"
    joblib.dump(model, model_path)

    meta = {
        "version": "4.0",
        "samples": len(texts),
        "scam_samples": len(SCAM),
        "legit_samples": len(LEGIT),
        "cv_f1_mean": round(float(scores.mean()), 4),
        "cv_f1_std":  round(float(scores.std()), 4),
        "ngram_range": [1, 3],
    }
    with open(out_dir / "model_meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\nModel saved → {model_path}")
    print(f"Metadata   → {out_dir / 'model_meta.json'}")
    print(f"Samples    → {len(texts)} total ({len(SCAM)} scam / {len(LEGIT)} legit)")


if __name__ == "__main__":
    train()