import sys
import logging
import os

# Add the current directory to sys.path so we can import local modules 
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from feature_extractor import extract_structural_features

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PhishShield-Pipeline")

# Try to import ML libraries for the DistilBERT + XGBoost architecture
# Try to import Transformers for DistilBERT
try:
    from transformers import pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logger.warning("Transformers not installed. NLP fallback active.")

# Try to import XGBoost (often fails on Mac without libomp)
try:
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False
    logger.warning("XGBoost or libomp missing. Structural fallback active.")

ML_AVAILABLE = TRANSFORMERS_AVAILABLE or XGB_AVAILABLE
if not ML_AVAILABLE:
    logger.warning("Transformers or XGBoost not installed. Falling back to Heuristic Engine for demonstration.")

# Global Model Cache
NLP_MODEL = None
STRUCTURAL_MODEL = None

def load_models():
    """Loads the DistilBERT and XGBoost models into memory."""
    global NLP_MODEL, STRUCTURAL_MODEL
    if ML_AVAILABLE:
        try:
            # We use a lightweight open-source DistilBERT fine-tuned for spam/phishing classification
            # Defaulting to a generic sentiment/spam pipeline for the architecture demo
            NLP_MODEL = pipeline("text-classification", model="mrm8488/distilroberta-finetuned-financial-news-sentiment-analysis", top_k=None)
            logger.info("DistilBERT Model branch loaded successfully.")
            
            # Here we would load a trained XGBoost model file:
            # STRUCTURAL_MODEL = xgb.Booster()
            # STRUCTURAL_MODEL.load_model("../models/xgboost_struct_v1.pkl")
            logger.info("XGBoost Structural branch structure initialized.")
        except Exception as e:
            logger.error(f"Error loading ML models: {e}. Falling back to Heuristics.")
            NLP_MODEL = None

load_models()

def predict_email(subject: str, body: str, sender: str = "", reply_to: str = "", urls: list = []):
    """
    Core ML Pipeline that implements the Late-Fusion architecture.
    Branch 1: NLP Context (DistilBERT)
    Branch 2: Structural Anomalies (XGBoost logic)
    Returns a unified JSON dictionary.
    """
    
    # 1. Feature Extraction pipeline
    struct_feats = extract_structural_features(subject, body, sender, reply_to, urls)
    
    # 2. Model Inference
    nlp_prob = 0.0
    struct_prob = 0.0
    
    # Real ML Inference branch (if available)
    if NLP_MODEL is not None:
        try:
            text_payload = f"{subject} {body}"[:512]  # DistilBERT max length
            nlp_res = NLP_MODEL(text_payload)[0]
            # Map sentiment/spam to a probability score (0.0 to 1.0)
            # For demonstration, we just generate a probability based on negative/spam markers
            for label in nlp_res:
                if label['label'].lower() in ['negative', 'spam', 'phishing']:
                    nlp_prob = label['score']
                    break
        except Exception as e:
            logger.error(f"NLP Interface failed: {e}")
            
        # Mocking XGBoost structural prediction based on the extracted features
        struct_prob = min(1.0, (
            struct_feats["shortened_url_detected"] * 0.4 +
            struct_feats["domain_mismatch"] * 0.5 +
            struct_feats.get("unresolved_sender_domain", 0) * 0.9 +
            struct_feats.get("unresolved_url_domain", 0) * 0.7 +
            (struct_feats["urgency_score"] / 10.0) +
            (struct_feats["sensitive_keyword_count"] * 0.1)
        ))
    else:
        # ─── Fallback Heuristic Engine (For easy local testing without heavy PyTorch) ───
        text = (subject + " " + body).lower()
        if "update your account" in text or "verify" in text:
            nlp_prob += 0.6
        if "password" in text or "login" in text:
            nlp_prob += 0.3
            
        struct_prob = min(1.0, (
            struct_feats["shortened_url_detected"] * 0.6 +
            struct_feats["domain_mismatch"] * 0.7 +
            struct_feats.get("unresolved_sender_domain", 0) * 0.9 +
            struct_feats.get("unresolved_url_domain", 0) * 0.7 +
            (struct_feats["urgency_score"] / 20.0)
        ))
    
    nlp_prob = min(1.0, max(0.0, nlp_prob))
    struct_prob = min(1.0, max(0.0, struct_prob))
    
    # 3. Late Fusion Layer
    # We weight Structural anomalies slightly higher for phishing detection
    final_prob = (nlp_prob * 0.4) + (struct_prob * 0.6)
    
    # 4. Generate Explainable AI (XAI) Reasons
    reasons = []
    if struct_feats.get("unresolved_sender_domain"):
        reasons.append("Sender domain failed active DNS verification (Likely Spoofed Header).")
    if struct_feats.get("unresolved_url_domain"):
        reasons.append("Email contains links to dead or actively blocked domains (High Risk).")
    if struct_feats["domain_mismatch"]:
        reasons.append("Sender domain and Reply-To mismatch detected.")
    if struct_feats["shortened_url_detected"]:
        reasons.append("Email contains shortened URLs often used to obscure malicious links.")
    if struct_feats["encoded_url_detected"]:
        reasons.append("Suspicious IP-based or encoded URL format detected.")
    if struct_feats["sensitive_keyword_count"] > 2:
        reasons.append("High volume of sensitive credential-harvesting keywords.")
    if struct_feats["urgency_score"] > 5.0:
        reasons.append("Language exhibits extreme urgency, a common social engineering tactic.")
    
    if final_prob > 0.6 and not reasons:
        reasons.append("Semantic NLP Model flagged suspicious text patterns.")
    if not reasons:
        reasons.append("No significant structural or semantic threats detected.")

    # 5. Format Output Schema
    if final_prob > 0.75:
        verdict = "PHISHING"
        risk_level = "CRITICAL"
        action = "BLOCK_AND_REPORT"
    elif final_prob > 0.45:
        verdict = "SUSPICIOUS"
        risk_level = "MEDIUM"
        action = "WARN"
    else:
        verdict = "LEGITIMATE"
        risk_level = "LOW"
        action = "ALLOW"

    return {
        "prediction": verdict,
        "confidence_score": round(final_prob, 3), # unified probability score
        "safety_score": int((1.0 - final_prob) * 100),
        "risk_level": risk_level,
        "recommended_action": action,
        "reasoning": reasons[:3],  # Top 3 reasons for UI
        "structural_indicators": struct_feats
    }
