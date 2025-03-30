#!/usr/bin/env python3
"""
Hybrid Phishing Detector: DistilBERT + XGBoost
- DistilBERT: Extract semantic embeddings from email text
- XGBoost: Combine embeddings with structural features
"""

import os
import json
import pickle
import warnings
import numpy as np
import pandas as pd
from pathlib import Path

import torch
from transformers import AutoTokenizer, AutoModel
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                             f1_score, roc_auc_score, confusion_matrix)

warnings.filterwarnings('ignore')

DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"Using device: {DEVICE}")

class HybridModelTrainer:
    """Train hybrid DistilBERT + XGBoost model for phishing detection"""
    
    def __init__(self, model_name='distilbert-base-uncased'):
        self.model_name = model_name
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.bert_model = AutoModel.from_pretrained(model_name).to(DEVICE)
        self.bert_model.eval()
        self.xgb_model = None
        self.scaler = StandardScaler()
        
    def get_text_embedding(self, text, max_length=256):
        """Extract DistilBERT embedding for text"""
        try:
            if not isinstance(text, str) or len(text.strip()) == 0:
                return np.zeros(768)
            
            inputs = self.tokenizer(
                text[:512],  # Max 512 tokens
                truncation=True,
                max_length=max_length,
                return_tensors='pt',
                padding=True
            ).to(DEVICE)
            
            with torch.no_grad():
                outputs = self.bert_model(**inputs)
                embeddings = outputs.last_hidden_state[:, 0, :].cpu().numpy()
            
            return embeddings[0]
        except Exception as e:
            print(f"Error in embedding: {e}")
            return np.zeros(768)
    
    def extract_structural_features(self, subject, from_email, urls):
        """Extract URL/header/metadata features"""
        features = []
        
        # Handle NaN values
        subject = subject if isinstance(subject, str) else ''
        from_email = from_email if isinstance(from_email, str) else ''
        urls = urls if isinstance(urls, str) else ''
        
        # Subject features
        features.append(len(str(subject)) if subject else 0)
        features.append(1 if subject and any(x in str(subject).lower() for x in 
                       ['urgent', 'verify', 'confirm', 'action', 'click']) else 0)
        features.append(1 if subject and any(x in str(subject).lower() for x in 
                       ['re:', 'fwd:', '---']) else 0)
        
        # Email features
        features.append(1 if from_email and '@' in str(from_email) else 0)
        domain = str(from_email).split('@')[1].lower() if '@' in str(from_email) else ''
        features.append(len(domain))
        features.append(1 if domain and ('bit.ly' in domain or 'tinyurl' in domain or 'short' in domain) else 0)
        
        # URL features
        url_list = urls.split(',') if urls else []
        features.append(len(url_list))
        features.append(sum(1 for u in url_list if 'bit.ly' in str(u) or 'tinyurl' in str(u)))
        features.append(sum(1 for u in url_list if str(u).startswith('https')))
        features.append(sum(1 for u in url_list if 'click' in str(u).lower()))
        
        return np.array(features, dtype=np.float32)
    
    def prepare_data(self, data_path):
        """Load and prepare data"""
        print(f"Loading data from {data_path}...")
        df = pd.read_csv(data_path)
        
        print(f"Total samples: {len(df)}")
        print(f"Columns: {df.columns.tolist()}")
        
        # Combine text fields
        df['combined_text'] = (df['subject'].fillna('') + ' ' + 
                               df['body'].fillna('') + ' ' + 
                               df['from_email'].fillna(''))
        
        # Extract features
        print("Extracting structural features...")
        structural_features = []
        for idx, row in df.iterrows():
            if idx % 2000 == 0:
                print(f"  Processing row {idx}/{len(df)}")
            features = self.extract_structural_features(
                row.get('subject'), 
                row.get('from_email'), 
                row.get('urls')
            )
            structural_features.append(features)
        
        structural_features = np.array(structural_features)
        
        print("Extracting DistilBERT embeddings...")
        embeddings = []
        for idx, text in enumerate(df['combined_text']):
            if idx % 2000 == 0:
                print(f"  Processing text {idx}/{len(df)}")
            emb = self.get_text_embedding(text)
            embeddings.append(emb)
        
        embeddings = np.array(embeddings)
        
        # Combine embeddings + structural features
        X = np.concatenate([embeddings, structural_features], axis=1)
        y = df['label'].values
        
        print(f"Feature shape: {X.shape}")
        print(f"Labels: {y.shape}")
        print(f"Label distribution: {np.bincount(y)}")
        
        return X, y, embeddings, structural_features
    
    def train(self, X, y):
        """Train XGBoost on combined features"""
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        print(f"\nTraining XGBoost...")
        print(f"Train set: {X_train_scaled.shape}")
        print(f"Test set: {X_test_scaled.shape}")
        
        # Train XGBoost
        self.xgb_model = XGBClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            n_jobs=-1,
            early_stopping_rounds=20,
            eval_metric='logloss'
        )
        
        self.xgb_model.fit(
            X_train_scaled, y_train,
            eval_set=[(X_test_scaled, y_test)],
            verbose=False
        )
        
        # Evaluate
        y_pred = self.xgb_model.predict(X_test_scaled)
        y_proba = self.xgb_model.predict_proba(X_test_scaled)[:, 1]
        
        metrics = {
            'accuracy': float(accuracy_score(y_test, y_pred)),
            'precision': float(precision_score(y_test, y_pred)),
            'recall': float(recall_score(y_test, y_pred)),
            'f1': float(f1_score(y_test, y_pred)),
            'roc_auc': float(roc_auc_score(y_test, y_proba)),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
        }
        
        return metrics, X_test_scaled, y_test
    
    def save_models(self, results_dir):
        """Save all models and scalers"""
        models_dir = Path(results_dir) / 'models'
        models_dir.mkdir(parents=True, exist_ok=True)
        
        # Save XGBoost model
        xgb_path = models_dir / 'hybrid_xgboost.pkl'
        with open(xgb_path, 'wb') as f:
            pickle.dump(self.xgb_model, f)
        print(f"✓ XGBoost model saved: {xgb_path}")
        
        # Save scaler
        scaler_path = models_dir / 'scaler.pkl'
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        print(f"✓ Scaler saved: {scaler_path}")
        
        # Save DistilBERT config
        config_path = models_dir / 'hybrid_config.json'
        config = {
            'type': 'hybrid',
            'text_model': 'distilbert-base-uncased',
            'embedding_dim': 768,
            'structural_features': 10,
            'total_features': 778
        }
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"✓ Config saved: {config_path}")

def main():
    print("="*70)
    print("HYBRID PHISHING DETECTOR: DistilBERT + XGBoost")
    print("="*70)
    
    # Paths
    data_path = 'data/processed/emails_unified.csv'
    results_dir = 'results'
    metrics_dir = Path(results_dir) / 'metrics'
    metrics_dir.mkdir(parents=True, exist_ok=True)
    
    if not Path(data_path).exists():
        print(f"❌ Data file not found: {data_path}")
        return
    
    # Initialize trainer
    trainer = HybridModelTrainer()
    
    # Prepare data
    X, y, embeddings, structural = trainer.prepare_data(data_path)
    
    # Train
    metrics, X_test, y_test = trainer.train(X, y)
    
    # Display results
    print("\n" + "="*70)
    print("HYBRID MODEL RESULTS")
    print("="*70)
    print(f"✅ Accuracy:   {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
    print(f"✅ Precision:  {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
    print(f"✅ Recall:     {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
    print(f"✅ F1-Score:   {metrics['f1']:.4f}")
    print(f"✅ ROC-AUC:    {metrics['roc_auc']:.4f} ({metrics['roc_auc']*100:.2f}%)")
    print(f"\nConfusion Matrix:\n{np.array(metrics['confusion_matrix'])}")
    
    # Save models
    trainer.save_models(results_dir)
    
    # Save metrics
    metrics_path = metrics_dir / 'hybrid_evaluation.json'
    with open(metrics_path, 'w') as f:
        json.dump({'hybrid_distilbert_xgboost': metrics}, f, indent=2)
    print(f"✓ Metrics saved: {metrics_path}")
    
    print("\n✅ Training complete!")
    print("="*70)

if __name__ == '__main__':
    main()
