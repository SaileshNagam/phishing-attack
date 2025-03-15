import os
import sys
import datetime
import uuid
import time
import pickle
import json
import numpy as np
from pathlib import Path
from typing import List, Optional, Dict, Any

# Load .env before anything reads env vars
from dotenv import load_dotenv
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")
load_dotenv()  # also check CWD .env

import torch
from transformers import AutoTokenizer, AutoModel
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import uvicorn

# Ensure backend/ is on sys.path for sibling imports
_backend_dir = str(Path(__file__).resolve().parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from dns_resolver import resolve_domains, resolve_sender_domain, dns_summary
from trust_engine import evaluate_trust
from url_tools import prepare_urls_for_scanning
from external_scan_store import create_scan as create_external_scan, get_scan as get_external_scan
from external_scan_store import save_vt_result, get_vt_result
from external_scanner import run_external_scan, submit_urls_for_vt_scan, poll_vt_analyses
from virustotal_client import vt_client

DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

class EmailInput(BaseModel):
    subject: str = ""
    from_email: str = ""
    body: str = ""
    reply_to: Optional[str] = ""
    urls: Optional[List[str]] = []
    sender_email: Optional[str] = None  # alias accepted from legacy callers
    include_external_scan: bool = True  # NEW: control whether to run VT scan

    def __init__(self, **data):
        # Allow sender_email as alias for from_email
        if 'sender_email' in data and not data.get('from_email'):
            data['from_email'] = data.pop('sender_email')
        elif 'sender_email' in data:
            data.pop('sender_email', None)
        super().__init__(**data)

class PredictionResponse(BaseModel):
    phishing: bool
    confidence: float
    safety_score: int
    risk_level: str
    recommended_action: str
    reasoning: List[str]
    structural_indicators: dict
    scan_id: str
    timestamp: str
    dns_results: Optional[List[dict]] = None
    dns_summary: Optional[dict] = None
    trust_analysis: Optional[dict] = None
    email_meta: Optional[dict] = None
    # External scan fields (VT + DNS background scan)
    external_scan_id: Optional[str] = None
    external_scan_status: Optional[str] = None
    external_scan_poll_url: Optional[str] = None
    external_scan_message: Optional[str] = None

class HealthResponse(BaseModel):
    status: str
    version: str
    models_loaded: dict
    timestamp: str


# ─── VirusTotal API Models ──────────────────────────────────────────────────

class VTSubmitRequest(BaseModel):
    urls: List[str]


class VTSubmitResponse(BaseModel):
    scan_id: str
    submitted: List[Dict[str, Any]]


class VTReportRequest(BaseModel):
    urls: List[str]


class VTReportResponse(BaseModel):
    results: List[Dict[str, Any]]


class VTScanPollResponse(BaseModel):
    scan_id: str
    urls: List[str]
    completed: int
    queued: int
    failed: int
    results: List[Dict[str, Any]]

# Use the existing feature_extractor from the backend folder for DNS checks
from feature_extractor import extract_structural_features

class HybridModelManager:
    def __init__(self):
        self.xgb_model = None
        self.scaler = None
        self.tokenizer = None
        self.bert_model = None
        self.device = DEVICE
        
    def load_models(self):
        """Load XGBoost, scaler, and DistilBERT models"""
        try:
            # We look for models in ../results/models relative to the backend folder
            base_dir = Path(__file__).resolve().parent.parent
            models_dir = base_dir / 'results/models'
            
            xgb_path = models_dir / 'hybrid_xgboost.pkl'
            with open(xgb_path, 'rb') as f:
                self.xgb_model = pickle.load(f)
            
            scaler_path = models_dir / 'scaler.pkl'
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            
            self.tokenizer = AutoTokenizer.from_pretrained('distilbert-base-uncased')
            self.bert_model = AutoModel.from_pretrained('distilbert-base-uncased').to(self.device)
            self.bert_model.eval()
            print("✓ All Hybrid models loaded successfully in unified backend")
        except Exception as e:
            print(f"⚠️ Could not load complete hybrid ML models: {e}. Falling back to default heuristics logic.")
            self.xgb_model = None
            self.bert_model = None
    
    def get_text_embedding(self, text: str) -> np.ndarray:
        if not text or len(text.strip()) == 0:
            return np.zeros(768)
        try:
            inputs = self.tokenizer(
                text[:512], truncation=True, max_length=256,
                return_tensors='pt', padding=True
            ).to(self.device)
            with torch.no_grad():
                outputs = self.bert_model(**inputs)
                embeddings = outputs.last_hidden_state[:, 0, :].cpu().numpy()
            return embeddings[0]
        except Exception as e:
            return np.zeros(768)
            
    def predict(self, email: EmailInput) -> dict:
        # Step 1: Structural Extraction (including Live DNS)
        struct_feats = extract_structural_features(
            email.subject, email.body, email.from_email, email.reply_to, email.urls or []
        )
        
        # Branch for when real models are loaded
        if self.xgb_model is not None and self.scaler is not None:
            combined_text = f"{email.subject} {email.body} {email.from_email}"
            text_embedding = self.get_text_embedding(combined_text)
            
            # Map struct_feats back to the 10 features expected by xgb model
            xgb_features = [
                len(email.subject),
                struct_feats["urgency_score"] > 0,
                0, # placeholder for 're:'/'fwd:'
                1 if '@' in email.from_email else 0,
                len(email.from_email.split('@')[1]) if '@' in email.from_email else 0,
                struct_feats["shortened_url_detected"],
                struct_feats["url_count"],
                struct_feats["shortened_url_detected"],
                sum(1 for u in (email.urls or []) if u.startswith('https')),
                0 # placeholder for 'click'
            ]
            
            combined_features = np.concatenate([text_embedding, np.array(xgb_features, dtype=np.float32)])
            scaled_features = self.scaler.transform(combined_features.reshape(1, -1))
            
            probability = float(self.xgb_model.predict_proba(scaled_features)[0][1])
            is_phishing = probability > 0.5
            confidence = probability if is_phishing else (1.0 - probability)
        else:
            # Fallback Heuristics
            probability = min(1.0, (
                struct_feats["shortened_url_detected"] * 0.4 +
                struct_feats["domain_mismatch"] * 0.4 +
                struct_feats.get("unresolved_sender_domain", 0) * 0.5 +
                struct_feats.get("unresolved_url_domain", 0) * 0.4 +
                (struct_feats["urgency_score"] / 20.0) +
                (struct_feats["sensitive_keyword_count"] * 0.1)
            ))
            
            text = (email.subject + " " + email.body).lower()
            if "update your account" in text or "verify" in text:
                probability += 0.3
            probability = min(1.0, probability)
            
            is_phishing = probability >= 0.5
            confidence = probability if is_phishing else (1.0 - probability)
            
        # Determine risk level
        if probability > 0.75:
            risk_level = "CRITICAL"
            action = "BLOCK_AND_REPORT"
        elif probability >= 0.45:
            risk_level = "MEDIUM"
            action = "WARN"
        else:
            risk_level = "LOW"
            action = "ALLOW"
            
        safety_score = int((1.0 - probability) * 100)
            
        # Unified Reasoning with DNS
        reasons = []
        if struct_feats.get("unresolved_sender_domain"):
            reasons.append("⚠️ Sender domain failed DNS resolution. This is a strong indicator of spoofing.")
        if struct_feats.get("unresolved_url_domain"):
            reasons.append("⚠️ Extracted URLs point to domains that fail DNS resolution (potentially removed or newly registered).")
        if struct_feats.get("domain_mismatch"):
            reasons.append("⚠️ Reply-To email differs from Sender email.")
        if struct_feats.get("shortened_url_detected"):
            reasons.append("🔗 Uses URL shortener to mask final destination.")
        if struct_feats.get("urgency_score", 0) > 0:
            reasons.append("⏳ Contains language creating false urgency.")
        if not reasons:
            if is_phishing:
                reasons.append("Semantic NLP Model flagged suspicious text patterns.")
            else:
                reasons.append("No structural or semantic threats detected. Email seems safe.")
                
        # ── DNS Resolution ──────────────────────────────────────────────────
        url_dns_results = []
        sender_dns = None
        try:
            url_dns_results = resolve_domains(email.urls or [])
            sender_dns = resolve_sender_domain(email.from_email)
            if sender_dns:
                url_dns_results.append(sender_dns)
        except Exception as e:
            print(f"[DNS] Resolution error: {e}")

        dns_sum = dns_summary(url_dns_results)

        # Add DNS-based reasons
        unresolved_domains = [r["domain"] for r in url_dns_results if not r["resolves"]]
        if unresolved_domains:
            reasons.append(f"\u26a0\ufe0f DNS: {len(unresolved_domains)} domain(s) failed resolution: {', '.join(unresolved_domains[:3])}")

        # ── Trust Analysis ──────────────────────────────────────────────────
        trust_result = {}
        try:
            trust_result = evaluate_trust(email.from_email, email.reply_to or "", email.urls or [])

            # Trust score adjusts probability — bounded contribution (max -0.15)
            if trust_result.get("trust_score", 0) > 0.3 and not trust_result.get("brand_impersonation"):
                trust_adjustment = min(0.15, trust_result["trust_score"] * 0.25)
                probability = max(0.0, probability - trust_adjustment)
                is_phishing = probability >= 0.5
                confidence = probability if is_phishing else (1.0 - probability)
                safety_score = int((1.0 - probability) * 100)

                # Recalculate risk level after trust adjustment
                if probability > 0.75:
                    risk_level = "CRITICAL"
                    action = "BLOCK_AND_REPORT"
                elif probability >= 0.45:
                    risk_level = "MEDIUM"
                    action = "WARN"
                else:
                    risk_level = "LOW"
                    action = "ALLOW"

            # Brand impersonation increases risk
            if trust_result.get("brand_impersonation"):
                brands = [imp["brand"] for imp in trust_result["brand_impersonation"]]
                reasons.append(f"\u26a0\ufe0f Brand impersonation detected: {', '.join(set(brands))}")
                probability = min(1.0, probability + 0.2)
                is_phishing = True
                confidence = probability
                risk_level = "CRITICAL"
                action = "BLOCK_AND_REPORT"
                safety_score = int((1.0 - probability) * 100)

            if trust_result.get("is_trusted_sender") and not trust_result.get("brand_impersonation"):
                reasons.append(f"\u2705 Sender domain is a verified {trust_result['sender_trust'].get('category', '')} domain")

            for w in trust_result.get("warnings", [])[:2]:
                reasons.append(f"\u26a0\ufe0f {w}")

        except Exception as e:
            print(f"[Trust] Evaluation error: {e}")

        scan_id = str(uuid.uuid4())

        result = {
            "phishing": is_phishing,
            "confidence": confidence,
            "safety_score": safety_score,
            "risk_level": risk_level,
            "recommended_action": action,
            "reasoning": reasons[:5],
            "structural_indicators": struct_feats,
            "scan_id": scan_id,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "dns_results": url_dns_results,
            "dns_summary": dns_sum,
            "trust_analysis": trust_result,
            "email_meta": {
                "subject": email.subject,
                "sender": email.from_email,
                "reply_to": email.reply_to or "",
                "url_count": len(email.urls or []),
                "urls": email.urls or [],
                "body": email.body[:2000] if email.body else "",  # First 2000 chars for report
            },
        }
        return result

app = FastAPI(
    title="PhishShield Unified API",
    description="Backend for Extension and Web Dashboard",
    version="3.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

manager = HybridModelManager()

@app.on_event("startup")
def startup():
    manager.load_models()

@app.get("/health", response_model=HealthResponse)
def health_check():
    return {
        "status": "online",
        "version": "3.0",
        "models_loaded": {
            "distilbert": manager.bert_model is not None,
            "xgboost": manager.xgb_model is not None
        },
        "timestamp": datetime.datetime.utcnow().isoformat()
    }

# ── In-Memory Scan Store (1-hour TTL) ──────────────────────────────────────────
_scan_store: Dict[str, dict] = {}
_SCAN_TTL = 3600  # 1 hour

def _store_scan(scan_id: str, data: dict):
    _scan_store[scan_id] = {"data": data, "ts": time.time()}
    # Prune old entries
    cutoff = time.time() - _SCAN_TTL
    expired = [k for k, v in _scan_store.items() if v["ts"] < cutoff]
    for k in expired:
        del _scan_store[k]

def _get_scan(scan_id: str) -> Optional[dict]:
    entry = _scan_store.get(scan_id)
    if not entry:
        return None
    if time.time() - entry["ts"] > _SCAN_TTL:
        del _scan_store[scan_id]
        return None
    return entry["data"]

@app.post("/predict", response_model=PredictionResponse)
def analyze_email(req: EmailInput, background_tasks: BackgroundTasks):
    result = manager.predict(req)

    # ── External Scan (DNS + VirusTotal) via BackgroundTask ──────────────
    scannable_urls = prepare_urls_for_scanning(
        request_urls=req.urls,
        body_text=req.body or "",
    )

    ext_scan_id = str(uuid.uuid4())

    if scannable_urls:
        # Create external scan record and enqueue background task
        create_external_scan(ext_scan_id, scannable_urls)
        background_tasks.add_task(run_external_scan, ext_scan_id, scannable_urls)
        result["external_scan_id"] = ext_scan_id
        result["external_scan_status"] = "queued"
        result["external_scan_poll_url"] = f"/api/external-scan/{ext_scan_id}"
        result["external_scan_message"] = (
            "ML scan completed. DNS and VirusTotal scan started in background."
        )
    else:
        # No scannable URLs — mark as completed immediately
        create_external_scan(ext_scan_id, [])
        from external_scan_store import update_scan as update_ext_scan
        update_ext_scan(ext_scan_id, status="completed")
        result["external_scan_id"] = ext_scan_id
        result["external_scan_status"] = "completed"
        result["external_scan_poll_url"] = f"/api/external-scan/{ext_scan_id}"
        result["external_scan_message"] = (
            "ML scan completed. No URLs found for external scanning."
        )

    # Store for retrieval by scan_id (ML result store)
    _store_scan(result["scan_id"], result)
    return result

@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    data = _get_scan(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found or expired")
    return data

@app.get("/history")
def get_history(limit: int = 200):
    """Return recent scan results from in-memory store for dashboard display."""
    records = []
    cutoff = time.time() - _SCAN_TTL
    for scan_id in list(_scan_store.keys()):
        entry = _scan_store[scan_id]
        if entry["ts"] < cutoff:
            del _scan_store[scan_id]
            continue
        records.append(entry["data"])
    records.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    return {"records": records[:limit]}

# ── External Scan Polling Endpoint ─────────────────────────────────────────────

@app.get("/api/external-scan/{scan_id}")
def poll_external_scan(scan_id: str):
    """Poll for DNS + VirusTotal background scan results."""
    data = get_external_scan(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="External scan not found or expired")
    return data


# ─── VirusTotal-specific Endpoints ──────────────────────────────────────────

@app.post("/external/virustotal/submit")
def submit_urls_for_virustotal(req: VTSubmitRequest, background_tasks: BackgroundTasks):
    """Submit URLs to VirusTotal for scanning (non-blocking)."""
    if not vt_client.available:
        return {
            "scan_id": str(uuid.uuid4()),
            "submitted": [],
            "error": "VirusTotal API key not configured"
        }

    # Submit URLs without blocking
    submission_results = submit_urls_for_vt_scan(req.urls)

    return {
        "scan_id": str(uuid.uuid4()),
        "submitted": submission_results
    }


@app.get("/external/virustotal/status/{analysis_id}")
def get_virustotal_status(analysis_id: str):
    """Check status of a VirusTotal analysis."""
    if not vt_client.available:
        return {
            "status": "not_configured",
            "error": "VirusTotal API key not configured"
        }

    result = vt_client.get_url_analysis(analysis_id)
    return result


@app.post("/external/virustotal/report")
def get_virustotal_reports(req: VTReportRequest):
    """Get VirusTotal reports for multiple URLs (returns cached or fetches if configured)."""
    results = []

    for url in req.urls:
        # Try to get cached result first
        cached = get_vt_result(url)
        if cached:
            results.append(cached)
            continue

        # If not cached and VT is configured, try to get current report
        if vt_client.available:
            # Try to get existing report without submitting new scan
            url_id = vt_client.get_url_id(url)
            # Note: We use the URL analysis endpoint which could return queued status
            vt_response = vt_client.get_url_analysis(url_id)

            if not vt_response.get("skipped"):
                normalized = vt_client.normalize_vt_response(url, url_id, vt_response)
                save_vt_result(url, normalized)
                results.append(normalized)
                continue

        # If no cache and no VT report, return not_configured status
        results.append({
            "url": url,
            "domain": url.split("://")[-1].split("/")[0] if "://" in url else url,
            "status": "not_configured",
            "risk_level": "UNKNOWN",
        })

    return {"results": results}


@app.get("/external/virustotal/scan/{scan_id}")
def get_virustotal_scan_results(scan_id: str):
    """Poll for all VirusTotal results in an external scan."""
    # Get the external scan record
    external_scan = get_external_scan(scan_id)
    if not external_scan:
        raise HTTPException(status_code=404, detail="Scan not found or expired")

    # Extract VT results from the scan results
    vt_results = []
    completed_count = 0
    queued_count = 0
    failed_count = 0

    for result in external_scan.get("results", []):
        # Check if this result has VT data
        if "virustotal_url" in result:
            vt_results.append(result["virustotal_url"])
            # Count status
            if result.get("virustotal_url", {}).get("status") == "completed":
                completed_count += 1
            elif result.get("virustotal_url", {}).get("status") == "queued":
                queued_count += 1
            else:
                failed_count += 1

    return VTScanPollResponse(
        scan_id=scan_id,
        urls=external_scan.get("urls", []),
        completed=completed_count,
        queued=queued_count,
        failed=failed_count,
        results=vt_results
    )

# Serve Web Dashboard Statically from /dashboard endpoint
web_path = Path(__file__).resolve().parent.parent / "web-dashboard"
if web_path.exists():
    app.mount("/dashboard", StaticFiles(directory=str(web_path), html=True), name="web-dashboard")

@app.get("/")
def root():
    return RedirectResponse(url='/health')

if __name__ == "__main__":
    # Run backend API on 127.0.0.1:8000
    # Dashboard should be served separately on port 8501 using:
    # cd dashboard && python -m http.server 8501
    uvicorn.run(app, host="127.0.0.1", port=8000)
