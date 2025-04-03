#!/usr/bin/env python3
"""
PhishShield API with Hybrid DistilBERT + XGBoost Model
"""

import pickle
import json
import numpy as np
from pathlib import Path
from typing import List, Optional

import torch
from transformers import AutoTokenizer, AutoModel
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

# Data Models
class EmailInput(BaseModel):
    subject: str = ""
    from_email: str = ""
    body: str = ""
    urls: Optional[List[str]] = []

class PredictionResponse(BaseModel):
    phishing: bool
    confidence: float
    risk_level: str
    reasoning: List[str]
    model: str = "hybrid_distilbert_xgboost"

class HealthResponse(BaseModel):
    status: str
    models_loaded: int
    model_type: str

# Model Manager
class HybridModelManager:
    def __init__(self):
        self.xgb_model = None
        self.scaler = None
        self.tokenizer = None
        self.bert_model = None
        self.config = None
        self.device = DEVICE
        
    def load_models(self):
        """Load XGBoost, scaler, and DistilBERT models"""
        models_dir = Path('results/models')
        
        # Load XGBoost
        xgb_path = models_dir / 'hybrid_xgboost.pkl'
        with open(xgb_path, 'rb') as f:
            self.xgb_model = pickle.load(f)
        print(f"✓ XGBoost model loaded")
        
        # Load scaler
        scaler_path = models_dir / 'scaler.pkl'
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        print(f"✓ Scaler loaded")
        
        # Load DistilBERT
        self.tokenizer = AutoTokenizer.from_pretrained('distilbert-base-uncased')
        self.bert_model = AutoModel.from_pretrained('distilbert-base-uncased').to(self.device)
        self.bert_model.eval()
        print(f"✓ DistilBERT model loaded")
        
        # Load config
        config_path = models_dir / 'hybrid_config.json'
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        
        return self.xgb_model is not None and self.scaler is not None
    
    def get_text_embedding(self, text: str) -> np.ndarray:
        """Extract DistilBERT embedding"""
        try:
            if not text or len(text.strip()) == 0:
                return np.zeros(768)
            
            inputs = self.tokenizer(
                text[:512],
                truncation=True,
                max_length=256,
                return_tensors='pt',
                padding=True
            ).to(self.device)
            
            with torch.no_grad():
                outputs = self.bert_model(**inputs)
                embeddings = outputs.last_hidden_state[:, 0, :].cpu().numpy()
            
            return embeddings[0]
        except Exception as e:
            print(f"Embedding error: {e}")
            return np.zeros(768)
    
    def extract_structural_features(self, subject: str, from_email: str, urls: List[str]) -> np.ndarray:
        """Extract structural features"""
        features = []
        
        # Subject features
        features.append(len(subject) if subject else 0)
        features.append(1 if subject and any(x in subject.lower() for x in 
                       ['urgent', 'verify', 'confirm', 'action', 'click']) else 0)
        features.append(1 if subject and any(x in subject.lower() for x in 
                       ['re:', 'fwd:', '---']) else 0)
        
        # Email features
        features.append(1 if from_email and '@' in from_email else 0)
        domain = from_email.split('@')[1].lower() if '@' in from_email else ''
        features.append(len(domain))
        features.append(1 if domain and any(x in domain for x in ['bit.ly', 'tinyurl', 'short']) else 0)
        
        # URL features
        url_list = urls if urls else []
        features.append(len(url_list))
        features.append(sum(1 for u in url_list if any(x in u for x in ['bit.ly', 'tinyurl'])))
        features.append(sum(1 for u in url_list if u.startswith('https')))
        features.append(sum(1 for u in url_list if 'click' in u.lower()))
        
        return np.array(features, dtype=np.float32)
    
    def predict(self, email: EmailInput) -> PredictionResponse:
        """Make prediction using hybrid model"""
        try:
            # Get text embedding
            combined_text = f"{email.subject} {email.body} {email.from_email}"
            text_embedding = self.get_text_embedding(combined_text)
            
            # Get structural features
            structural_features = self.extract_structural_features(
                email.subject, 
                email.from_email, 
                email.urls or []
            )
            
            # Combine features
            combined_features = np.concatenate([text_embedding, structural_features])
            combined_features = combined_features.reshape(1, -1)
            
            # Scale
            scaled_features = self.scaler.transform(combined_features)
            
            # Predict
            prediction = self.xgb_model.predict(scaled_features)[0]
            probability = self.xgb_model.predict_proba(scaled_features)[0]
            
            is_phishing = bool(prediction == 1)
            confidence = float(probability[1]) if is_phishing else float(probability[0])
            
            # Risk level
            if confidence > 0.9:
                risk_level = "CRITICAL"
            elif confidence > 0.7:
                risk_level = "HIGH"
            elif confidence > 0.5:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"
            
            # Generate reasoning
            reasoning = self._generate_reasoning(
                email, is_phishing, confidence, structural_features
            )
            
            return PredictionResponse(
                phishing=is_phishing,
                confidence=confidence,
                risk_level=risk_level,
                reasoning=reasoning
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")
    
    def _generate_reasoning(self, email: EmailInput, is_phishing: bool, confidence: float, features: np.ndarray) -> List[str]:
        """Generate human-readable reasoning"""
        reasons = []
        
        subject_lower = email.subject.lower() if email.subject else ""
        body_lower = email.body.lower() if email.body else ""
        from_lower = email.from_email.lower() if email.from_email else ""
        
        # Urgency indicators
        if any(x in subject_lower + body_lower for x in ['urgent', 'verify', 'confirm', 'action required', 'click']):
            reasons.append("⚠️ Contains urgency/verification language (suspicious indicator)")
        
        # URL features
        if features[6] > 0:  # Has URLs
            if features[7] > 0:  # Has shortened URLs
                reasons.append("🔗 Contains shortened URLs (bit.ly, tinyurl - suspicious)")
            if features[8] > 0:  # Has HTTPS
                reasons.append("✓ Uses HTTPS (legitimate indicator)")
        
        # Domain features
        if '@' in from_lower and features[5] > 0:  # Suspicious domain
            reasons.append("⚠️ Uses suspicious domain pattern")
        
        # Text features
        if len(email.body) < 100:
            reasons.append("📝 Very short email body (suspicious)")
        elif len(email.body) > 1000:
            reasons.append("📝 Long email body (more likely legitimate)")
        
        # Model confidence
        if confidence > 0.9:
            reasons.append(f"🤖 Model confidence: {confidence:.1%} - High certainty")
        elif confidence > 0.5:
            reasons.append(f"🤖 Model confidence: {confidence:.1%}")
        
        if not reasons:
            if is_phishing:
                reasons.append("Classified as phishing based on semantic analysis")
            else:
                reasons.append("Email appears legitimate")
        
        return reasons

# Initialize FastAPI
app = FastAPI(
    title="PhishShield - Hybrid Detector",
    description="Advanced phishing detection using DistilBERT + XGBoost",
    version="2.0"
)

manager = HybridModelManager()

@app.on_event("startup")
def startup():
    """Load models on startup"""
    manager.load_models()

@app.get("/", tags=["Info"])
def root():
    return {
        "name": "PhishShield API",
        "version": "2.0 - Hybrid DistilBERT + XGBoost",
        "docs": "/docs",
        "model": "Advanced semantic + structural analysis"
    }

@app.get("/health", tags=["System"])
def health():
    return HealthResponse(
        status="healthy" if manager.xgb_model else "error",
        models_loaded=3 if manager.xgb_model else 0,
        model_type="hybrid_distilbert_xgboost"
    )

@app.post("/predict", response_model=PredictionResponse, tags=["Predictions"])
def predict(email: EmailInput):
    """Predict if email is phishing"""
    return manager.predict(email)

@app.get("/info/model", tags=["Info"])
def model_info():
    return {
        "type": "Hybrid",
        "components": [
            "DistilBERT (768-dim embeddings)",
            "Structural Features (10 engineered features)",
            "XGBoost Classifier"
        ],
        "total_features": 778,
        "accuracy": 0.9867,
        "roc_auc": 0.9979,
        "description": "Combines semantic understanding with structural analysis for phishing detection"
    }

@app.get("/examples", tags=["Info"])
def examples():
    return {
        "phishing_example": {
            "subject": "Verify Your Account Now!",
            "from_email": "noreply@bank-secure.ru",
            "body": "Click the link to verify your account",
            "urls": ["https://bit.ly/verify"]
        },
        "legitimate_example": {
            "subject": "Meeting reminder",
            "from_email": "boss@company.com",
            "body": "Remember our meeting at 3 PM today",
            "urls": []
        }
    }

def startup_message():
    print("\n" + "="*70)
    print("PhishShield API - Hybrid DistilBERT + XGBoost")
    print("="*70)
    print("\n🚀 Features:")
    print("  • DistilBERT embeddings for semantic understanding")
    print("  • Structural feature analysis (URLs, domain, urgency)")
    print("  • XGBoost ensemble prediction")
    print("  • 98.67% accuracy, 99.79% ROC-AUC")
    print("\n📚 Available endpoints:")
    print("  • GET  /health - Health check")
    print("  • POST /predict - Predict email")
    print("  • GET  /info/model - Model info")
    print("  • GET  /examples - Usage examples")
    print("\n📖 Interactive docs: http://localhost:8000/docs")
    print("="*70 + "\n")

if __name__ == '__main__':
    startup_message()
    uvicorn.run(app, host='0.0.0.0', port=8000, log_level='info')
