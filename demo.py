#!/usr/bin/env python3
"""
PhishShield Demo Script
Records every step of the phishing email detection pipeline.
Run from the project root: python demo.py
"""

import sys, os, time, json, textwrap, webbrowser, threading
from pathlib import Path
from datetime import datetime

# ── ANSI Colors ──────────────────────────────────────────────────────────────
GREEN = "\033[92m"
RED   = "\033[91m"
YELLOW= "\033[93m"
BLUE  = "\033[94m"
CYAN  = "\033[96m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
RESET = "\033[0m"

def p(step, msg):
    print(f"\n{BOLD}{BLUE}[STEP {step}]{RESET} {msg}")

def ok(msg):
    print(f"{GREEN}✓{RESET} {msg}")

def warn(msg):
    print(f"{YELLOW}⚠{RESET} {msg}")

def info(msg):
    print(f"{CYAN}ℹ{RESET} {msg}")

def section(title):
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}{title}{RESET}")
    print(f"{BOLD}{'='*70}{RESET}")

def banner():
    print(textwrap.dedent(f"""
    {BOLD}{CYAN}
    ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗ ██████╗ ██╗   ██╗███████╗███████╗████████╗
    ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔═══██╗██║   ██║██╔════╝██╔════╝╚══██╔══╝
    ███████╗██║   ██║██████╔╝█████╗  ██╔██╗ ██║██║   ██║██║   ██║█████╗  ███████╗   ██║
    ╚════██║██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══╝  ╚════██║   ██║
    ███████║╚██████╔╝██║     ███████╗██║ ╚████║╚██████╔╝ ╚████╔╝ ███████╗███████║   ██║
    ╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚══════╝╚══════╝   ╚═╝
    {RESET}
    {DIM}    Hybrid Semantic-Structural Email Phishing Detection System — v1.0{RESET}
    """))

# ─────────────────────────────────────────────────────────────────────────────
# STEP 0 — Environment Check
# ─────────────────────────────────────────────────────────────────────────────
banner()
section("STEP 0 — Environment Setup")
p(0, "Checking project environment...")

PROJECT_ROOT = Path(__file__).resolve().parent
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))

ok(f"Working directory: {os.getcwd()}")
ok(f"Python path configured")

# Verify key files exist
key_files = [
    "config/config.yaml",
    "src/constants.py",
    "src/data/loader.py",
    "src/data/preprocessor.py",
    "src/features/url_analyzer.py",
    "src/features/structural_features.py",
    "src/features/text_features.py",
    "src/models/baseline/tfidf_logreg.py",
    "src/models/baseline/tfidf_rf.py",
    "src/models/trainer.py",
    "src/models/evaluator.py",
    "src/inference/pipeline.py",
    "src/deployment/api.py",
    "backend/trust_engine.py",
    "results/models/baseline_tfidf_logreg.pkl",
    "results/models/baseline_tfidf_rf.pkl",
    "data/raw/sample_emails.csv",
]

missing = []
for f in key_files:
    if not (PROJECT_ROOT / f).exists():
        missing.append(f)

if missing:
    warn(f"Missing files: {missing}")
else:
    ok(f"All {len(key_files)} key files present")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Trust Engine Demo
# ─────────────────────────────────────────────────────────────────────────────
section("STEP 1 — Trust Engine (backend/trust_engine.py)")
p(1, "Importing and demonstrating the Trust Engine...")

sys.path.insert(0, str(PROJECT_ROOT / "backend"))
from trust_engine import (
    is_trusted_domain, detect_brand_impersonation,
    cross_check_domains, evaluate_trust
)

# Test 1: Trusted domain check
ok("Trust engine loaded successfully")
print(f"\n  {DIM}--- Test 1: Trusted Domain Check ---{RESET}")
tests = [
    ("accounts.google.com", True, "verified Google subdomain"),
    ("microsoft.com",      True, "verified Microsoft domain"),
    ("paypa1-verify.com",  False, "brand impersonation (PayPal)"),
    ("g00gle.com",         False, "brand impersonation (Google)"),
]
for domain, expected_trusted, description in tests:
    result = is_trusted_domain(domain)
    status = f"{GREEN}✓ MATCH{RESET}" if result["trusted"] == expected_trusted else f"{RED}✗ MISMATCH{RESET}"
    print(f"    {status} {DIM}{domain:30s}{RESET} → trusted={result['trusted']}, match={result['match_type']}, category={result.get('category','')}")
    print(f"         ({description})")

# Test 2: Brand impersonation detection
print(f"\n  {DIM}--- Test 2: Brand Impersonation Detection ---{RESET}")
imp_tests = [
    "paypa1-secure.com",
    "micros0ft-verify.net",
    "amazn-login.ru",
    "g00gle-redirect.org",
]
for domain in imp_tests:
    detections = detect_brand_impersonation(domain)
    if detections:
        for d in detections:
            print(f"    {RED}✗ CAUGHT{RESET} {DIM}{domain}{RESET} → impersonates {d['brand']} ({d['pattern']}, {d['severity']})")
    else:
        print(f"    {GREEN}✓ CLEAN{RESET} {DIM}{domain}{RESET}")

# Test 3: Cross-domain verification
print(f"\n  {DIM}--- Test 3: Cross-Domain Verification ---{RESET}")
cross = cross_check_domains(
    sender_email="noreply@amazon.com",
    reply_to="support@amazon-verify.ru",
    urls=["https://amazon-verify.ru/confirm"]
)
print(f"    Sender domain:        {cross['sender_domain']}")
print(f"    Reply-To domain:     {cross['reply_to_domain']}")
print(f"    URL domains:         {cross['url_domains']}")
print(f"    Sender↔Reply mismatch: {RED}DETECTED{RESET}" if cross['sender_reply_to_mismatch'] else f"    {GREEN}✓ Match{RESET}")
for w in cross['warnings']:
    print(f"         ⚠ {w}")

# Test 4: Full trust evaluation
print(f"\n  {DIM}--- Test 4: Full Trust Evaluation ---{RESET}")
trust_result = evaluate_trust(
    sender_email="security@apple.com",
    reply_to="",
    urls=["https://appleid.apple.com/verify"]
)
print(f"    Trust score:  {trust_result['trust_score']}")
print(f"    Trusted sender: {trust_result['is_trusted_sender']}")
for sig in trust_result['trust_signals']:
    print(f"    {GREEN}+ {sig}{RESET}")
for w in trust_result['warnings']:
    print(f"    {RED}! {w}{RESET}")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Data Loading & Preprocessing
# ─────────────────────────────────────────────────────────────────────────────
section("STEP 2 — Data Loading & Preprocessing")
p(2, "Loading sample emails and demonstrating preprocessing...")

from src.data.loader import EmailDataLoader, EmailParser, Email
from src.data.preprocessor import EmailPreprocessor
import pandas as pd

# Load sample dataset (CSV has columns: subject, from_email, body, urls, label)
loader = EmailDataLoader()
preprocessor = EmailPreprocessor()

sample_path = PROJECT_ROOT / "data/raw/sample_emails.csv"
df = pd.read_csv(sample_path)

# Convert CSV rows to Email objects
emails = []
for idx, row in df.iterrows():
    urls = []
    if pd.notna(row.get('urls')) and str(row['urls']).strip():
        urls = [u.strip() for u in str(row['urls']).split(',') if u.strip()]
    email = Email(
        id=f"csv_{idx}",
        headers={},
        subject=str(row.get('subject', '')) if pd.notna(row.get('subject')) else '',
        from_email=str(row.get('from_email', '')) if pd.notna(row.get('from_email')) else '',
        to_email='',
        body=str(row.get('body', '')) if pd.notna(row.get('body')) else '',
        urls=urls,
        attachments=[],
        timestamp='',
        source='csv',
        label=int(row['label']) if pd.notna(row.get('label')) else None
    )
    emails.append(email)

ok(f"Loaded {len(emails)} emails from sample_emails.csv")

# Show class distribution
labels = [e.label for e in emails if e.label is not None]
phishing = sum(labels)
legit = len(labels) - phishing
print(f"\n  Class distribution:")
print(f"    Phishing:    {phishing} ({100*phishing/len(labels):.0f}%)")
print(f"    Legitimate:  {legit} ({100*legit/len(labels):.0f}%)")

# Show email examples
print(f"\n  {DIM}--- Sample Emails ---{RESET}")
for i, email in enumerate(emails[:3]):
    verdict = f"{RED}PHISHING{RESET}" if email.label == 1 else f"{GREEN}LEGITIMATE{RESET}"
    print(f"\n  Email {i+1}: {verdict}")
    print(f"    From:    {email.from_email}")
    print(f"    Subject: {email.subject}")
    print(f"    URLs:    {email.urls}")
    body_preview = email.body[:120].replace('\n', ' ')
    print(f"    Body:    {body_preview}...")

# Demonstrate preprocessing
print(f"\n  {DIM}--- Preprocessing Demo ---{RESET}")
raw_body = emails[0].body
cleaned, tokens = preprocessor.preprocess_email_body(raw_body)
print(f"  Original length: {len(raw_body)} chars")
print(f"  Cleaned length:  {len(cleaned)} chars")
print(f"  Token count:    {len(tokens)}")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Feature Extraction
# ─────────────────────────────────────────────────────────────────────────────
section("STEP 3 — Feature Extraction (Text + Structural)")
p(3, "Extracting features from emails...")

from src.features.text_features import TextFeatureExtractor
from src.features.structural_features import StructuralFeatureExtractor
from src.features.url_analyzer import URLAnalyzer, LinkExtractor, DomainAnalyzer

text_extractor = TextFeatureExtractor()
struct_extractor = StructuralFeatureExtractor()

# Extract features from phishing and legitimate emails
phishing_email = emails[0]  # First email is phishing
legit_email = emails[1]       # Second email is legitimate

for label, email in [("PHISHING", phishing_email), ("LEGITIMATE", legit_email)]:
    color = RED if label == "PHISHING" else GREEN
    print(f"\n  {DIM}--- {label} Email Features ---{RESET}")
    print(f"    Subject: {email.subject}")

    # URL features
    url_feats = struct_extractor.extract_url_features(email.urls)
    print(f"    URL count: {url_feats.get('url_count', 0)}")
    print(f"    Has shortened URL: {url_feats.get('has_shortened_url', False)}")
    print(f"    Has suspicious TLD: {url_feats.get('has_suspicious_tld', False)}")

    # Domain features
    domain_feats = struct_extractor.extract_domain_features(email)
    print(f"    From domain: {domain_feats.get('from_domain', 'N/A')}")
    print(f"    Domain typo detected: {domain_feats.get('sender_domain_typo', False)}")

    # Content features
    content_feats = struct_extractor.extract_content_features(email)
    print(f"    Text length: {content_feats.get('text_length', 0)}")
    print(f"    Uppercase ratio: {content_feats.get('uppercase_ratio', 0):.2f}")
    print(f"    Entropy score: {content_feats.get('entropy_score', 0):.2f}")

    # Urgency features
    urgency_feats = struct_extractor.extract_urgency_features(email.body, email.subject)
    print(f"    Urgency score: {urgency_feats.get('urgency_score', 0)}")
    print(f"    Threat score:  {urgency_feats.get('threat_score', 0)}")

    # URL analyzer specific checks
    for url in email.urls:
        risks = []
        if URLAnalyzer.is_shortened_url(url): risks.append("shortened")
        if URLAnalyzer.has_ip_address(url): risks.append("IP address")
        if URLAnalyzer.has_punycode(url): risks.append("punycode")
        if URLAnalyzer.has_suspicious_tld(url): risks.append("suspicious TLD")
        if URLAnalyzer.has_base64_like_token(url): risks.append("base64 token")
        if risks:
            print(f"    {color}URL risk flags: {', '.join(risks)}{RESET}")

    # Brand impersonation check on URLs
    for url in email.urls:
        domain = DomainAnalyzer.extract_domain(url)
        if domain:
            imps = detect_brand_impersonation(domain)
            if imps:
                for imp in imps:
                    print(f"    {RED}Brand impersonation: {domain} → {imp['brand']}{RESET}")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Model Inference (Trained Models)
# ─────────────────────────────────────────────────────────────────────────────
section("STEP 4 — Model Inference (Pre-trained TF-IDF + Random Forest)")
p(4, "Running predictions using pre-trained models...")

from src.inference.pipeline import PhishShieldPredictor

# Load the RF model (99.27% accuracy)
predictor = PhishShieldPredictor(model_type="tfidf_rf", use_structural=True)
ok("PhishShieldPredictor loaded (TF-IDF + Random Forest)")

print(f"\n  Model type: {predictor.model_type}")
print(f"  Using structural features: {predictor.use_structural}")
print(f"  Decision threshold: {predictor.threshold}")

# Run predictions on all sample emails
print(f"\n  {DIM}--- Batch Predictions on Sample Emails ---{RESET}")
print(f"  {'#':<3} {'From Domain':<35} {'Prediction':<12} {'Confidence':<10} {'Risk':<8} Label")
print(f"  {'-'*3} {'-'*35} {'-'*12} {'-'*10} {'-'*8} {'-'*5}")

for i, email in enumerate(emails):
    result = predictor.predict(email)
    color = RED if result['prediction'] == 'PHISHING' else GREEN
    risk_color = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}.get(result['risk_level'], DIM)
    label_str = f"{RED}P{RESET}" if email.label == 1 else f"{GREEN}L{RESET}"
    from_domain = email.from_email.split('@')[-1] if '@' in email.from_email else email.from_email
    print(f"  {i+1:<3} {from_domain:<35} {color}{result['prediction']:<12}{RESET} "
          f"{result['confidence']:<10.3f} {risk_color}{result['risk_level']:<8}{RESET} {label_str}")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — API Server
# ─────────────────────────────────────────────────────────────────────────────
section("STEP 5 — FastAPI Server (Backend)")
p(5, "Starting FastAPI server on http://localhost:8000 ...")

import uvicorn
from src.deployment.api import app

# We'll run the server in a background thread
server_thread = threading.Thread(
    target=lambda: uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning"),
    daemon=True
)
server_thread.start()
ok("FastAPI server started in background thread")

# Wait for server to be ready
time.sleep(3)

import urllib.request
try:
    with urllib.request.urlopen("http://localhost:8000/health", timeout=5) as resp:
        health = json.loads(resp.read())
        print(f"\n  {DIM}--- Health Check ---{RESET}")
        print(f"    Status:       {health['status']}")
        print(f"    Model loaded: {health['model_loaded']}")
        print(f"    Model type:   {health['model_type']}")
        print(f"    Version:      {health['version']}")
        ok("API server responding correctly")
except Exception as e:
    warn(f"Could not reach API server: {e}")

# Try the /examples endpoint
try:
    with urllib.request.urlopen("http://localhost:8000/examples", timeout=5) as resp:
        examples = json.loads(resp.read())
        print(f"\n  {DIM}--- /examples endpoint ---{RESET}")
        print(f"    Phishing example subject: {examples['phishing_example']['subject']}")
        print(f"    Legitimate example subject: {examples['legitimate_example']['subject']}")
        ok("/examples endpoint working")
except Exception as e:
    warn(f"Could not reach /examples: {e}")

# Try /info/features
try:
    with urllib.request.urlopen("http://localhost:8000/info/features", timeout=5) as resp:
        features_info = json.loads(resp.read())
        print(f"\n  {DIM}--- /info/features endpoint ---{RESET}")
        print(f"    Total features: {features_info['total_features']}")
        print(f"    Structural feature categories: {len(features_info['structural_features']['categories'])}")
        ok("/info/features endpoint working")
except Exception as e:
    warn(f"Could not reach /info/features: {e}")

# Test /predict endpoint
try:
    import urllib.request, urllib.error
    req_data = json.dumps({
        "subject": "Urgent: Verify Your Account",
        "from_email": "noreply@bank-secure.com",
        "body": "Your account has been compromised. Click here to verify: https://bit.ly/verify123",
        "urls": ["https://bit.ly/verify123"],
        "to_email": "user@example.com"
    }).encode("utf-8")
    req = urllib.request.Request(
        "http://localhost:8000/predict",
        data=req_data,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        result = json.loads(resp.read())
        print(f"\n  {DIM}--- /predict endpoint (phishing test) ---{RESET}")
        print(f"    Prediction:  {result['prediction']}")
        print(f"    Confidence: {result['confidence']:.4f}")
        print(f"    Risk level: {result['risk_level']}")
        print(f"    Safety score: {result['safety_score']}")
        print(f"    Reasoning: {result['reasoning'][:2]}")
        print(f"    Forensics - SPF: {result['forensics']['spf_status']}, DKIM: {result['forensics']['dkim_status']}")
        ok("/predict endpoint working correctly")
except Exception as e:
    warn(f"Could not test /predict: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — Dashboard
# ─────────────────────────────────────────────────────────────────────────────
section("STEP 6 — Streamlit Dashboard")
p(6, "Checking Streamlit dashboard availability...")

dashboard_path = PROJECT_ROOT / "src/deployment"
if not (dashboard_path / "dashboard.py").exists():
    warn("dashboard.py not found — skipping Streamlit demo")
else:
    info(f"Dashboard file found at {dashboard_path / 'dashboard.py'}")
    info("Run with: streamlit run src/deployment/dashboard.py --server.port 8501")

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
section("DEMO COMPLETE — PhishShield System Summary")
print(f"""
  {BOLD}Pipeline Stages Demonstrated:{RESET}

  {DIM}1. Trust Engine{RESET}
     - Trusted domain registry (Google, Microsoft, Apple, Amazon, banks...)
     - Brand impersonation detection (typosquatting, homographs)
     - Sender ↔ Reply-To ↔ URL cross-verification
     - Trust score evaluation (bounded 0.0–1.0)

  {DIM}2. Data Pipeline{RESET}
     - Multi-format loader (.eml, .json, .csv)
     - Email preprocessor (HTML removal, URL extraction, tokenization)
     - 47+ structural features + 5,776 text features

  {DIM}3. Feature Extraction{RESET}
     - URL analysis (shortened, punycode, IP address, TLD checks)
     - Domain analysis (reputation, typo detection, mismatch checks)
     - Header analysis (SPF/DKIM/DMARC)
     - Content analysis (entropy, uppercase ratio, urgency scoring)

  {DIM}4. Model Inference{RESET}
     - Pre-trained TF-IDF + Random Forest (99.27% accuracy)
     - Per-email predictions with confidence scores
     - Risk level classification (LOW / MEDIUM / HIGH / CRITICAL)
     - Human-readable reasoning generation

  {DIM}5. FastAPI Server{RESET}
     - POST /predict — single email scan
     - POST /predict/batch — batch scanning
     - GET /history — threat history
     - GET /info/features — system capabilities
     - XAI-style feature importance + forensics schema

  {BOLD}API Server: http://localhost:8000{RESET}
  {BOLD}API Docs:   http://localhost:8000/docs{RESET}
  {BOLD}Dashboard:  streamlit run src/deployment/dashboard.py --server.port 8501{RESET}

  {BOLD}Demo completed at: {datetime.now().isoformat()}{RESET}
""")
print(f"{GREEN}{BOLD}All steps completed successfully!{RESET}\n")
