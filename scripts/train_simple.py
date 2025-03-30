#!/usr/bin/env python
"""
Simple ML Trainer - Works with adapted data directly
Trains TF-IDF + Logistic Regression and Random Forest models
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import pandas as pd
import numpy as np
import pickle
import json
import logging
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SimpleModelTrainer:
    """Train models on adapted email data"""
    
    def __init__(self, data_file: str = "data/processed/emails_unified.csv",
                 output_dir: str = "results/models",
                 metrics_dir: str = "results/metrics"):
        """Initialize trainer"""
        self.data_file = Path(data_file)
        self.output_dir = Path(output_dir)
        self.metrics_dir = Path(metrics_dir)
        
        # Create directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.metrics_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Data file: {self.data_file}")
        logger.info(f"Output dir: {self.output_dir}")
        logger.info(f"Metrics dir: {self.metrics_dir}")
    
    def load_data(self):
        """Load adapted dataset"""
        logger.info("Loading data...")
        
        if not self.data_file.exists():
            logger.error(f"Data file not found: {self.data_file}")
            raise FileNotFoundError(f"Data file not found: {self.data_file}")
        
        df = pd.read_csv(self.data_file)
        logger.info(f"Loaded {len(df)} emails")
        logger.info(f"Columns: {list(df.columns)}")
        
        # Combine text fields
        df['combined_text'] = (
            df['subject'].fillna('') + ' ' +
            df['body'].fillna('') + ' ' +
            df['urls'].fillna('')
        )
        
        # Handle missing labels
        if 'label' not in df.columns:
            logger.warning("No 'label' column found, assuming all legitimate (0)")
            df['label'] = 0
        
        X = df['combined_text'].values
        y = df['label'].values
        
        logger.info(f"✓ Data loaded: {len(X)} samples")
        logger.info(f"  Label distribution: {np.bincount(y)}")
        
        return X, y, df
    
    def train_models(self, X, y):
        """Train both models"""
        logger.info("\n" + "="*70)
        logger.info("Training Models")
        logger.info("="*70)
        
        # Split data
        logger.info("Splitting data: 80% train, 20% test...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        logger.info(f"  Train: {len(X_train)} samples")
        logger.info(f"  Test: {len(X_test)} samples")
        
        # TF-IDF vectorization
        logger.info("\nVectorizing text with TF-IDF...")
        vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            min_df=2,
            max_df=0.9
        )
        X_train_tfidf = vectorizer.fit_transform(X_train)
        X_test_tfidf = vectorizer.transform(X_test)
        logger.info(f"✓ Features shape: {X_train_tfidf.shape}")
        
        results = {}
        
        # Model 1: Logistic Regression
        logger.info("\n[1/2] Training TF-IDF + Logistic Regression...")
        lr_model = LogisticRegression(max_iter=1000, random_state=42, n_jobs=-1)
        lr_model.fit(X_train_tfidf, y_train)
        
        y_pred_lr = lr_model.predict(X_test_tfidf)
        y_pred_proba_lr = lr_model.predict_proba(X_test_tfidf)[:, 1]
        
        lr_metrics = {
            'accuracy': accuracy_score(y_test, y_pred_lr),
            'precision': precision_score(y_test, y_pred_lr),
            'recall': recall_score(y_test, y_pred_lr),
            'f1': f1_score(y_test, y_pred_lr),
            'roc_auc': roc_auc_score(y_test, y_pred_proba_lr),
        }
        
        logger.info(f"  Accuracy: {lr_metrics['accuracy']:.4f}")
        logger.info(f"  Precision: {lr_metrics['precision']:.4f}")
        logger.info(f"  Recall: {lr_metrics['recall']:.4f}")
        logger.info(f"  F1-Score: {lr_metrics['f1']:.4f}")
        logger.info(f"  ROC-AUC: {lr_metrics['roc_auc']:.4f}")
        
        results['baseline_tfidf_logreg'] = {
            'model': lr_model,
            'vectorizer': vectorizer,
            'metrics': lr_metrics,
            'conf_matrix': confusion_matrix(y_test, y_pred_lr).tolist()
        }
        
        # Model 2: Random Forest
        logger.info("\n[2/2] Training TF-IDF + Random Forest...")
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1
        )
        rf_model.fit(X_train_tfidf, y_train)
        
        y_pred_rf = rf_model.predict(X_test_tfidf)
        y_pred_proba_rf = rf_model.predict_proba(X_test_tfidf)[:, 1]
        
        rf_metrics = {
            'accuracy': accuracy_score(y_test, y_pred_rf),
            'precision': precision_score(y_test, y_pred_rf),
            'recall': recall_score(y_test, y_pred_rf),
            'f1': f1_score(y_test, y_pred_rf),
            'roc_auc': roc_auc_score(y_test, y_pred_proba_rf),
        }
        
        logger.info(f"  Accuracy: {rf_metrics['accuracy']:.4f}")
        logger.info(f"  Precision: {rf_metrics['precision']:.4f}")
        logger.info(f"  Recall: {rf_metrics['recall']:.4f}")
        logger.info(f"  F1-Score: {rf_metrics['f1']:.4f}")
        logger.info(f"  ROC-AUC: {rf_metrics['roc_auc']:.4f}")
        
        results['baseline_tfidf_rf'] = {
            'model': rf_model,
            'vectorizer': vectorizer,
            'metrics': rf_metrics,
            'conf_matrix': confusion_matrix(y_test, y_pred_rf).tolist()
        }
        
        return results, (X_train, X_test, y_train, y_test)
    
    def save_models(self, results):
        """Save trained models"""
        logger.info("\n" + "="*70)
        logger.info("Saving Models")
        logger.info("="*70)
        
        for name, data in results.items():
            model_file = self.output_dir / f"{name}.pkl"
            
            # Save model and vectorizer together
            model_data = {
                'model': data['model'],
                'vectorizer': data['vectorizer']
            }
            
            with open(model_file, 'wb') as f:
                pickle.dump(model_data, f)
            
            size_mb = model_file.stat().st_size / (1024 * 1024)
            logger.info(f"✓ Saved: {model_file.name} ({size_mb:.1f}MB)")
        
        logger.info("\n✓ All models saved!")
        return True
    
    def save_metrics(self, results):
        """Save evaluation metrics"""
        logger.info("\n" + "="*70)
        logger.info("Saving Metrics")
        logger.info("="*70)
        
        metrics_file = self.metrics_dir / "evaluation_report.json"
        
        metrics_data = {}
        for name, data in results.items():
            metrics_data[name] = {
                'metrics': data['metrics'],
                'confusion_matrix': data['conf_matrix']
            }
        
        with open(metrics_file, 'w') as f:
            json.dump(metrics_data, f, indent=2)
        
        logger.info(f"✓ Saved metrics to: {metrics_file}")
        
        # Print summary
        logger.info("\n" + "="*70)
        logger.info("Training Summary")
        logger.info("="*70)
        for name, metrics_data in metrics_data.items():
            logger.info(f"\n{name}:")
            for metric, value in metrics_data['metrics'].items():
                logger.info(f"  {metric}: {value:.4f}")


def main():
    """Main entry point"""
    print("\n" + "="*70)
    print("Simple ML Model Trainer")
    print("="*70 + "\n")
    
    try:
        trainer = SimpleModelTrainer()
        
        # Load data
        X, y, df = trainer.load_data()
        
        # Train models
        results, _ = trainer.train_models(X, y)
        
        # Save models
        trainer.save_models(results)
        
        # Save metrics
        trainer.save_metrics(results)
        
        print("\n" + "="*70)
        print("✓ TRAINING COMPLETE!")
        print("="*70)
        print("\nNext steps:")
        print("  1. Start API: python scripts/run_api.py")
        print("  2. Start Dashboard: streamlit run scripts/streamlit_app.py")
        print("\nGenerated files:")
        print(f"  • Models: {trainer.output_dir}/")
        print(f"  • Metrics: {trainer.metrics_dir}/")
        
        return 0
        
    except Exception as e:
        logger.error(f"✗ Training failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
