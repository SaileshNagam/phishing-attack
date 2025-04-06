#!/usr/bin/env python3
"""
PhishShield - Streamlit Web Dashboard
Interactive web application for phishing email detection using Hybrid DistilBERT + XGBoost
"""

import streamlit as st
import pandas as pd
import json
import pickle
import numpy as np
from pathlib import Path

import torch
from transformers import AutoTokenizer, AutoModel

# Page configuration
st.set_page_config(
    page_title="PhishShield - Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

# ============================================================================
# Load Models (Cached)
# ============================================================================

@st.cache_resource
def load_models():
    """Load XGBoost, scaler, and DistilBERT models"""
    models_dir = Path('results/models')
    
    try:
        # Load XGBoost
        with open(models_dir / 'hybrid_xgboost.pkl', 'rb') as f:
            xgb_model = pickle.load(f)
        
        # Load scaler
        with open(models_dir / 'scaler.pkl', 'rb') as f:
            scaler = pickle.load(f)
        
        # Load DistilBERT
        tokenizer = AutoTokenizer.from_pretrained('distilbert-base-uncased')
        bert_model = AutoModel.from_pretrained('distilbert-base-uncased').to(DEVICE)
        bert_model.eval()
        
        # Load config
        with open(models_dir / 'hybrid_config.json', 'r') as f:
            config = json.load(f)
        
        return {
            'xgb': xgb_model,
            'scaler': scaler,
            'tokenizer': tokenizer,
            'bert': bert_model,
            'config': config
        }
    except Exception as e:
        st.error(f"Error loading models: {e}")
        return None

# ============================================================================
# Feature Extraction Functions
# ============================================================================

def get_text_embedding(text, models):
    """Extract DistilBERT embedding"""
    try:
        if not text or len(text.strip()) == 0:
            return np.zeros(768)
        
        inputs = models['tokenizer'](
            text[:512],
            truncation=True,
            max_length=256,
            return_tensors='pt',
            padding=True
        ).to(DEVICE)
        
        with torch.no_grad():
            outputs = models['bert'](**inputs)
            embeddings = outputs.last_hidden_state[:, 0, :].cpu().numpy()
        
        return embeddings[0]
    except Exception as e:
        st.warning(f"Embedding error: {e}")
        return np.zeros(768)

def extract_structural_features(subject, from_email, urls):
    """Extract structural features"""
    features = []
    
    subject = subject if isinstance(subject, str) else ''
    from_email = from_email if isinstance(from_email, str) else ''
    urls = urls if isinstance(urls, list) else []
    
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
    features.append(len(urls))
    features.append(sum(1 for u in urls if any(x in u for x in ['bit.ly', 'tinyurl'])))
    features.append(sum(1 for u in urls if u.startswith('https')))
    features.append(sum(1 for u in urls if 'click' in u.lower()))
    
    return np.array(features, dtype=np.float32)

def predict_email(subject, from_email, body, urls, models):
    """Make prediction"""
    try:
        # Get embeddings
        combined_text = f"{subject} {body} {from_email}"
        text_embedding = get_text_embedding(combined_text, models)
        
        # Get structural features
        structural_features = extract_structural_features(subject, from_email, urls)
        
        # Combine
        combined_features = np.concatenate([text_embedding, structural_features])
        combined_features = combined_features.reshape(1, -1)
        
        # Scale
        scaled_features = models['scaler'].transform(combined_features)
        
        # Predict
        prediction = models['xgb'].predict(scaled_features)[0]
        probability = models['xgb'].predict_proba(scaled_features)[0]
        
        is_phishing = bool(prediction == 1)
        confidence = float(probability[1]) if is_phishing else float(probability[0])
        
        # Risk level
        if confidence > 0.9:
            risk_level = "🔴 CRITICAL"
        elif confidence > 0.7:
            risk_level = "🟠 HIGH"
        elif confidence > 0.5:
            risk_level = "🟡 MEDIUM"
        else:
            risk_level = "🟢 LOW"
        
        # Reasoning
        reasoning = []
        subject_lower = subject.lower() if subject else ""
        body_lower = body.lower() if body else ""
        
        if any(x in subject_lower + body_lower for x in ['urgent', 'verify', 'confirm', 'action required', 'click']):
            reasoning.append("⚠️ Contains urgency/verification language")
        
        if len(urls) > 0:
            if any(x in u for x in ['bit.ly', 'tinyurl'] for u in urls):
                reasoning.append("🔗 Contains shortened URLs (suspicious)")
            if any(u.startswith('https') for u in urls):
                reasoning.append("✓ Uses HTTPS (legitimate indicator)")
        
        if len(body) < 100:
            reasoning.append("📝 Very short email body")
        
        if not reasoning:
            if is_phishing:
                reasoning.append("🤖 Classified as phishing based on content analysis")
            else:
                reasoning.append("✓ Email appears legitimate")
        
        return {
            'phishing': is_phishing,
            'confidence': confidence,
            'risk_level': risk_level,
            'reasoning': reasoning
        }
    except Exception as e:
        st.error(f"Prediction error: {e}")
        return None

# ============================================================================
# UI Components
# ============================================================================

def show_header():
    """Display header"""
    st.markdown("# 🛡️ PhishShield - Phishing Email Detector")
    st.markdown("*Advanced AI-powered phishing detection using DistilBERT + XGBoost*")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Accuracy", "98.67%", "+0.06%")
    with col2:
        st.metric("ROC-AUC", "99.79%", "⭐ Excellent")
    with col3:
        st.metric("Inference", "<500ms", "✓ Real-time")

def show_prediction_interface(models):
    """Main prediction interface"""
    st.markdown("---")
    st.markdown("## 📧 Test Email")
    
    col1, col2 = st.columns(2)
    
    with col1:
        subject = st.text_input("Subject", placeholder="Enter email subject")
        from_email = st.text_input("From Email", placeholder="sender@example.com")
    
    with col2:
        body = st.text_area("Body", placeholder="Enter email body", height=120)
    
    urls_input = st.text_area("URLs (one per line)", placeholder="https://example.com\nhttps://bit.ly/link", height=80)
    urls = [u.strip() for u in urls_input.split('\n') if u.strip()]
    
    st.markdown("---")
    
    if st.button("🔍 Analyze Email", type="primary", use_container_width=True):
        if not subject or not from_email or not body:
            st.error("❌ Please fill in all fields")
            return
        
        with st.spinner("Analyzing email..."):
            result = predict_email(subject, from_email, body, urls, models)
        
        if result:
            show_prediction_result(result)

def show_prediction_result(result):
    """Display prediction result"""
    st.markdown("---")
    st.markdown("## 🎯 Prediction Result")
    
    col1, col2 = st.columns(2)
    
    with col1:
        status = "🚨 PHISHING" if result['phishing'] else "✅ LEGITIMATE"
        st.markdown(f"### {status}")
        
        confidence_pct = result['confidence'] * 100
        st.markdown(f"**Confidence**: {confidence_pct:.1f}%")
        st.markdown(f"**Risk Level**: {result['risk_level']}")
    
    with col2:
        # Visual confidence bar
        st.markdown("**Confidence Visualization**")
        confidence_bars = int(result['confidence'] * 10)
        bar_vis = "🟥" * confidence_bars + "⬜" * (10 - confidence_bars)
        st.markdown(bar_vis)
    
    st.markdown("---")
    st.markdown("### 💡 Reasoning")
    for reason in result['reasoning']:
        st.markdown(f"- {reason}")

def show_examples():
    """Show example emails"""
    st.markdown("---")
    st.markdown("## 📚 Example Emails")
    
    with st.expander("📮 Phishing Example", expanded=False):
        st.code("""
Subject: URGENT: Verify Your Account Now!
From: verify@secure-bank-ru.com
Body: Your account has been locked. Click the link below to verify immediately.
URLs: https://bit.ly/bank_verify_secure
        """, language="text")
        st.info("🚨 This is a typical phishing email with urgency, shortened URLs, and suspicious domain")
    
    with st.expander("✅ Legitimate Example", expanded=False):
        st.code("""
Subject: Meeting reminder - Q1 Review
From: manager@company.com
Body: This is a reminder about our Q1 review meeting at 2 PM today in Conference Room B.
URLs: (none)
        """, language="text")
        st.info("✓ This is a legitimate business email with no suspicious indicators")

def show_about():
    """Show about information"""
    st.markdown("---")
    st.markdown("## ℹ️ About PhishShield")
    
    with st.expander("🏗️ Architecture", expanded=False):
        st.markdown("""
        PhishShield uses a hybrid architecture:
        
        **Branch 1: Semantic Analysis**
        - DistilBERT transformer model
        - Understands email content and meaning
        - 768-dimensional embeddings
        
        **Branch 2: Structural Analysis**
        - URL patterns and domain reputation
        - Urgency indicators
        - Sender information
        - 10 engineered features
        
        **Fusion: XGBoost Classifier**
        - Combines both signals
        - 200 decision trees
        - Achieves 98.67% accuracy
        """)
    
    with st.expander("📊 Performance Metrics", expanded=False):
        metrics_data = {
            'Metric': ['Accuracy', 'Precision', 'Recall', 'ROC-AUC', 'F1-Score'],
            'Value': ['98.67%', '95.69%', '93.18%', '99.79%', '94.41%']
        }
        
        st.dataframe(pd.DataFrame(metrics_data), use_container_width=True)
    
    with st.expander("🛠️ Technology Stack", expanded=False):
        st.markdown("""
        - **DistilBERT**: Lightweight transformer (66M parameters)
        - **XGBoost**: Gradient boosting (200 trees)
        - **Streamlit**: Web framework
        - **PyTorch**: Deep learning
        - **scikit-learn**: Machine learning utilities
        """)

# ============================================================================
# Main Application
# ============================================================================

def main():
    """Main application"""
    try:
        # Load models
        models = load_models()
        
        if models is None:
            st.error("❌ Failed to load models")
            st.info("Make sure you've trained the model first: `python scripts/train_hybrid.py`")
            return
        
        # Show interface
        show_header()
        show_prediction_interface(models)
        show_examples()
        show_about()
        
    except Exception as e:
        st.error(f"❌ Application Error: {e}")
        st.info("Check that all required packages are installed and models are trained")

if __name__ == '__main__':
    main()
