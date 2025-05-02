# PhishTrace — AI-Powered Phishing Email Detection System

![Python](https://img.shields.io/badge/python-3.8+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109-green)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-Academic%20Project-orange)

**PhishTrace** is a full-stack AI-powered cybersecurity system for **real-time phishing email detection**. It combines a **hybrid ML pipeline** (DistilBERT + XGBoost) with **DNS verification**, **VirusTotal threat intelligence**, and a **browser extension** for Gmail to deliver instant, explainable phishing verdicts.

> **⚠️ Disclaimer:** This project is developed for **academic and defensive cybersecurity purposes only**. It is not intended for malicious use or unauthorized email interception.

---

## ✨ Features

- **Hybrid AI Detection** — DistilBERT semantic analysis + XGBoost structural classification
- **Real-Time Browser Extension** — Chrome/Edge extension with inline Gmail banner injection
- **DNS Verification** — Live domain resolution and sender validation
- **VirusTotal Integration** — Asynchronous URL reputation scanning (optional, API key required)
- **Trust Engine** — Brand impersonation detection, sender/reply-to cross-validation
- **Web Dashboard** — Threat history, forensic reports, and detailed risk breakdowns
- **Explainable Verdicts** — Human-readable reasoning for every classification
- **Risk Scoring** — 0–100 safety score with CRITICAL / HIGH / MEDIUM / LOW levels

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         Gmail (Browser)                              │
│  Content Script extracts: Subject, Sender, Body, URLs, Reply-To     │
└──────────────────────────┬───────────────────────────────────────────┘
                           │ HTTP POST
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    FastAPI Backend (port 8000)                        │
│                                                                      │
│  ┌─────────────────────┐   ┌──────────────────────────────────────┐ │
│  │  Hybrid ML Pipeline │   │  Background Threat Intelligence      │ │
│  │                     │   │                                      │ │
│  │  DistilBERT (768d)  │   │  DNS Resolution ──► Sender Verify   │ │
│  │       +             │   │  VirusTotal API ──► URL Reputation   │ │
│  │  XGBoost Classifier │   │  Trust Engine  ──► Brand Detection   │ │
│  └─────────┬───────────┘   └────────────────┬─────────────────────┘ │
│            └────────────────┬────────────────┘                       │
│                             ▼                                        │
│              Unified Risk Score + Reasoning                          │
└──────────────────────────┬───────────────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
     Extension Popup            Web Dashboard
     (Risk Gauge + Verdict)     (Forensics + History)
```

---

## 📁 Folder Structure

```
phishing-email-detector/
├── backend/                  # FastAPI backend (main runtime)
│   ├── api.py                # Unified API — /predict, /health, /scan
│   ├── virustotal_client.py  # VirusTotal API v3 integration
│   ├── dns_resolver.py       # DNS verification engine
│   ├── trust_engine.py       # Brand impersonation + trust scoring
│   ├── external_scanner.py   # Background VT + DNS scan orchestrator
│   ├── feature_extractor.py  # Structural feature extraction
│   └── model_pipeline.py     # Heuristic fallback predictor
│
├── chrome-extension/         # Chrome browser extension (Manifest V3)
│   ├── manifest.json
│   ├── background.js         # Service worker — API communication
│   ├── content.js            # Gmail DOM extraction
│   ├── popup.html/js/css     # Extension popup UI
│   └── config.js             # API URL configuration
│
├── edge-extension/           # Edge browser extension
│
├── web-dashboard/            # Standalone web dashboard
│   ├── index.html            # Threat history view
│   ├── report.html           # Detailed forensic report
│   └── extractor.js          # Client-side email analysis
│
├── dashboard/                # Alternative dashboard (static HTML)
│
├── src/                      # ML source code
│   ├── data/                 # Data loading, preprocessing
│   ├── features/             # Text + structural feature extractors
│   ├── models/               # Baseline + upgraded model training
│   ├── inference/            # End-to-end prediction pipeline
│   ├── explainability/       # SHAP / LIME integrations
│   └── deployment/           # Alternative API deployment
│
├── config/                   # YAML configuration files
├── tests/                    # pytest test suite
├── scripts/                  # Training, setup, and utility scripts
├── data/raw/                 # Sample email datasets
├── results/                  # Model outputs, metrics, plots
├── docs/                     # Architecture diagrams
│
├── .env.example              # Environment variable template
├── .gitignore                # Git exclusions
├── requirements.txt          # Python dependencies
├── setup.py                  # Package setup
└── README.md                 # This file
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.8+**
- **Chrome or Edge browser** (for extension)
- **Virtual environment** (recommended)

### 1. Clone and Setup

```bash
git clone <repo-url>
cd phishing-email-detector

# Create virtual environment
python -m venv .venv
source .venv/bin/activate   # macOS/Linux
# .venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
# Copy the example config
cp .env.example .env

# Edit .env and add your VirusTotal API key (optional)
# Get a free key at: https://www.virustotal.com/gui/my-apikey
```

### 3. Start the Backend API

```bash
python -m uvicorn backend.api:app --host 127.0.0.1 --port 8000 --reload
```

**Verify it's running:**
```bash
curl http://127.0.0.1:8000/health
```

**Open Swagger Docs:**
```
http://127.0.0.1:8000/docs
```

### 4. Start the Web Dashboard (separate terminal)

```bash
cd web-dashboard
python -m http.server 8501
```

### 5. Load the Browser Extension

**Chrome:**
1. Navigate to `chrome://extensions/`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the `chrome-extension/` folder

**Edge:**
1. Navigate to `edge://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `edge-extension/` folder

### 6. Test on Gmail

1. Open [Gmail](https://mail.google.com)
2. Open any email
3. Click the PhishTrace extension icon
4. See the risk analysis popup + inline banner

---

## 🔑 Adding VirusTotal API Key

VirusTotal integration is **optional** — the system works without it using DNS + ML analysis.

To enable it:

1. Sign up at [virustotal.com](https://www.virustotal.com/gui/join-us)
2. Get your free API key from [My API Key](https://www.virustotal.com/gui/my-apikey)
3. Add it to your `.env` file:
   ```
   VIRUSTOTAL_API_KEY=your_actual_api_key_here
   ```
4. Restart the backend server

The backend reads the key from the environment variable `VIRUSTOTAL_API_KEY` and gracefully skips VT scanning if it's not set.

---

## 🔌 API Reference

### `GET /health`
Returns server status, model availability, and timestamp.

### `POST /predict`
Analyze an email for phishing indicators.

```json
{
  "subject": "Verify Your Account",
  "body": "Click here to verify your identity",
  "from_email": "noreply@bank-secure.com",
  "reply_to": "",
  "urls": ["https://bit.ly/verify"]
}
```

**Response:**
```json
{
  "phishing": true,
  "confidence": 0.87,
  "safety_score": 13,
  "risk_level": "CRITICAL",
  "recommended_action": "BLOCK_AND_REPORT",
  "reasoning": [
    "🔗 Uses URL shortener to mask final destination",
    "⏳ Contains language creating false urgency"
  ],
  "scan_id": "uuid-here",
  "external_scan_id": "uuid-here",
  "external_scan_poll_url": "/api/external-scan/{id}"
}
```

### `GET /api/external-scan/{scan_id}`
Poll for background DNS + VirusTotal scan results.

### `GET /scan/{scan_id}`
Retrieve a previous scan result by ID.

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=backend --cov-report=html
```

---

## 🎬 Demo Flow

1. **Start backend** → `python -m uvicorn backend.api:app --host 127.0.0.1 --port 8000`
2. **Start dashboard** → `cd web-dashboard && python -m http.server 8501`
3. **Load extension** → Chrome/Edge developer mode → Load unpacked
4. **Open Gmail** → Open any email → Click PhishTrace icon
5. **View results** → Risk gauge, verdict, reasoning, and detailed report
6. **Check dashboard** → `http://127.0.0.1:8501` for threat history

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **ML / AI** | PyTorch, Transformers (DistilBERT), XGBoost, scikit-learn |
| **NLP** | spaCy, TF-IDF, BeautifulSoup |
| **Backend** | FastAPI, Uvicorn, Pydantic |
| **Threat Intel** | VirusTotal API v3, DNS resolution |
| **Extension** | Chrome Manifest V3, Service Worker |
| **Dashboard** | HTML/CSS/JS (vanilla) |
| **Testing** | pytest |

---

## 📊 Model Details

- **Text Branch:** DistilBERT (`distilbert-base-uncased`) — 768-dim semantic embeddings
- **Structural Branch:** XGBoost with 10 engineered metadata features
- **Fusion:** Combined embedding + structural features → scaled → XGBoost prediction
- **Fallback:** Heuristic scoring when ML models are not loaded

### Placing Model Files

Trained model files (`.pkl`) should be placed in `results/models/`:
- `hybrid_xgboost.pkl` — Trained XGBoost classifier
- `scaler.pkl` — Feature scaler

> These files are excluded from Git due to size. Use the training scripts in `scripts/` to generate them, or contact the project authors.

---

## 👥 Authors

- **Sailesh** — Lead Developer & ML Engineer

### Supervisor

- Faculty Supervisor (as applicable)

---

## 📜 License

MIT License — See [LICENSE](LICENSE) for details.

---

## ⚠️ Disclaimer

This project is developed strictly for **academic and defensive cybersecurity research purposes**. It is intended to demonstrate AI-powered phishing detection techniques in an educational context.

- Do **not** use this tool for unauthorized email interception
- Do **not** use this tool for malicious purposes
- The authors are **not responsible** for any misuse of this software
- All email analysis is performed **locally** — no email content is uploaded to external servers (except optional VirusTotal URL scanning)

---

*Built with ❤️ for cybersecurity education*
