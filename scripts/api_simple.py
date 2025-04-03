#!/usr/bin/env python
"""
PhishShield API - Simplified Version
REST API for email phishing detection
"""

import sys
import os
from pathlib import Path

# Add project to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional
import pickle
import numpy as np
from datetime import datetime
import logging
import uvicorn
import argparse

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ==================== Pydantic Models ====================

class EmailInput(BaseModel):
    """Single email input"""
    subject: str
    from_email: str
    body: str
    urls: Optional[List[str]] = None


class PredictionResponse(BaseModel):
    """Prediction response"""
    phishing: bool
    confidence: float
    risk_level: str
    reasoning: List[str]


# ==================== Model Manager ====================

class ModelManager:
    """Load and manage trained models"""
    
    def __init__(self, model_dir: str = "results/models"):
        """Initialize model manager"""
        self.model_dir = Path(model_dir)
        self.models = {}
        self.vectorizer = None
        self.load_models()
    
    def load_models(self):
        """Load trained models"""
        logger.info(f"Loading models from {self.model_dir}...")
        
        # Load Logistic Regression model
        lr_file = self.model_dir / "baseline_tfidf_logreg.pkl"
        if lr_file.exists():
            with open(lr_file, 'rb') as f:
                lr_data = pickle.load(f)
                self.models['logreg'] = lr_data['model']
                self.vectorizer = lr_data['vectorizer']
            logger.info(f"✓ Loaded: baseline_tfidf_logreg")
        
        # Load Random Forest model
        rf_file = self.model_dir / "baseline_tfidf_rf.pkl"
        if rf_file.exists():
            with open(rf_file, 'rb') as f:
                rf_data = pickle.load(f)
                self.models['rf'] = rf_data['model']
            logger.info(f"✓ Loaded: baseline_tfidf_rf")
        
        if not self.models:
            raise RuntimeError("No models found! Please train models first.")
        
        logger.info(f"✓ {len(self.models)} models loaded successfully")
    
    def predict(self, email_text: str) -> dict:
        """Make prediction"""
        if not self.vectorizer or not self.models:
            raise RuntimeError("Models not loaded")
        
        # Vectorize text
        X = self.vectorizer.transform([email_text])
        
        # Get predictions from all models
        confidences = []
        for model_name, model in self.models.items():
            proba = model.predict_proba(X)[0]
            confidence = proba[1]  # Probability of phishing
            confidences.append(confidence)
        
        # Average confidence
        avg_confidence = np.mean(confidences)
        
        # Determine if phishing
        is_phishing = avg_confidence > 0.5
        
        # Risk level
        if avg_confidence > 0.8:
            risk_level = "CRITICAL"
        elif avg_confidence > 0.6:
            risk_level = "HIGH"
        elif avg_confidence > 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # Generate reasoning
        reasoning = self._generate_reasoning(email_text, avg_confidence)
        
        return {
            'phishing': is_phishing,
            'confidence': float(avg_confidence),
            'risk_level': risk_level,
            'reasoning': reasoning
        }
    
    def _generate_reasoning(self, email_text: str, confidence: float) -> List[str]:
        """Generate simple reasoning"""
        reasons = []
        
        email_lower = email_text.lower()
        
        # Check for common phishing indicators
        if any(word in email_lower for word in ['verify', 'confirm', 'urgent', 'immediate']):
            reasons.append("Contains urgency/verification language")
        
        if any(word in email_lower for word in ['bit.ly', 'tinyurl', 'short', 'ow.ly']):
            reasons.append("Contains shortened URLs (suspicious)")
        
        if any(word in email_lower for word in ['click here', 'click link', 'click now']):
            reasons.append("Contains suspicious call-to-action")
        
        if any(domain in email_lower for domain in ['.ru', '.tk', '.ml', '.ga']):
            reasons.append("Uses suspicious domain TLD")
        
        if confidence > 0.7:
            reasons.append(f"High phishing probability ({confidence*100:.1f}%)")
        
        # Default reason if none found
        if not reasons:
            reasons.append(f"Classified by ML model ({confidence*100:.1f}% confidence)")
        
        return reasons[:5]  # Top 5 reasons


# ==================== FastAPI App ====================

app = FastAPI(
    title="PhishShield API",
    description="Phishing Email Detection API",
    version="1.0.0"
)

# Initialize model manager
model_manager = None


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "PhishShield API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "models_loaded": len(model_manager.models) if model_manager else 0
    }


@app.post("/predict", response_model=PredictionResponse)
async def predict_email(email: EmailInput):
    """Predict if email is phishing"""
    if not model_manager:
        raise HTTPException(status_code=503, detail="Models not loaded")
    
    try:
        # Combine email fields
        email_text = f"{email.subject} {email.from_email} {email.body}"
        if email.urls:
            email_text += " " + " ".join(email.urls)
        
        # Make prediction
        result = model_manager.predict(email_text)
        
        return PredictionResponse(**result)
    
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/info/model")
async def model_info():
    """Get model information"""
    if not model_manager:
        raise HTTPException(status_code=503, detail="Models not loaded")
    
    return {
        "models": list(model_manager.models.keys()),
        "model_count": len(model_manager.models),
        "vectorizer": "TF-IDF (5000 features, bigrams)",
        "training_date": "2026-03-13",
        "accuracy": "99.27% (RF) / 98.61% (LR)",
        "precision": "97.86% (RF) / 97.73% (LR)",
        "recall": "96.06% (RF) / 90.55% (LR)",
        "roc_auc": "99.95% (RF) / 99.87% (LR)"
    }


@app.get("/examples")
async def examples():
    """Get example requests"""
    return {
        "phishing_example": {
            "url": "POST /predict",
            "body": {
                "subject": "Verify Your Account Now!",
                "from_email": "noreply@bank-secure.ru",
                "body": "Click to verify your account within 2 hours",
                "urls": ["https://bit.ly/verify123"]
            },
            "expected_result": {
                "phishing": True,
                "confidence": 0.85,
                "risk_level": "HIGH"
            }
        },
        "legitimate_example": {
            "url": "POST /predict",
            "body": {
                "subject": "Meeting Tomorrow at 3 PM",
                "from_email": "john@company.com",
                "body": "Let's discuss the Q1 project status",
                "urls": ["https://company.com/calendar"]
            },
            "expected_result": {
                "phishing": False,
                "confidence": 0.15,
                "risk_level": "LOW"
            }
        }
    }


def startup():
    """Initialize models"""
    global model_manager
    try:
        model_manager = ModelManager()
        logger.info("✓ API ready for predictions")
        return True
    except Exception as e:
        logger.error(f"✗ Failed to load models: {e}")
        return False


# ==================== Main ====================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="PhishShield API Server")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host address")
    parser.add_argument("--port", type=int, default=8000, help="Port number")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    
    args = parser.parse_args()
    
    # Start models
    if not startup():
        print("✗ Failed to start API")
        return 1
    
    print("\n" + "="*70)
    print("PhishShield API Server - Started")
    print("="*70)
    print(f"\n🚀 API running on http://{args.host}:{args.port}")
    print(f"📚 OpenAPI Docs: http://{args.host}:{args.port}/docs")
    print(f"🔧 ReDoc: http://{args.host}:{args.port}/redoc")
    print("\nPress Ctrl+C to stop\n")
    
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n✓ API Stopped")
