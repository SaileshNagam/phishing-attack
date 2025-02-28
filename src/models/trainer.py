"""
Model Trainer
Train and evaluate baseline models
"""

import logging
import json
from pathlib import Path
from typing import Tuple, Dict, List
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold
import pandas as pd

# Import our models
from src.models.baseline.tfidf_logreg import (
    TFIDFLogisticRegression,
    evaluate_model as eval_logreg
)
from src.models.baseline.tfidf_rf import (
    TFIDFRandomForest,
    evaluate_model as eval_rf
)
from src.data.loader import EmailDataLoader
from src.data.preprocessor import EmailPreprocessor

logger = logging.getLogger(__name__)


class ModelTrainer:
    """Train and compare baseline models"""
    
    def __init__(
        self,
        data_dir: str,
        output_dir: str = "models/trained",
        test_size: float = 0.15,
        val_size: float = 0.15,
        random_state: int = 42
    ):
        """
        Initialize trainer
        
        Args:
            data_dir: Directory with email data
            output_dir: Where to save trained models
            test_size: Fraction for test set
            val_size: Fraction for validation set
            random_state: Random seed
        """
        self.data_dir = Path(data_dir)
        self.output_dir = Path(output_dir)
        self.test_size = test_size
        self.val_size = val_size
        self.random_state = random_state
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.preprocessor = EmailPreprocessor()
        self.loader = EmailDataLoader()
        
        self.train_texts = None
        self.val_texts = None
        self.test_texts = None
        self.train_labels = None
        self.val_labels = None
        self.test_labels = None
    
    def load_and_preprocess_data(self) -> Tuple[List[str], np.ndarray]:
        """
        Load emails and preprocess texts
        
        Returns:
            Texts and labels
        """
        logger.info(f"Loading emails from {self.data_dir}...")
        
        # Load emails
        emails = self.loader.load_directory(str(self.data_dir))
        logger.info(f"Loaded {len(emails)} emails")
        
        # Preprocess
        logger.info("Preprocessing texts...")
        texts = []
        labels = []
        
        for email in emails:
            try:
                # Preprocess body
                clean_text = self.preprocessor.preprocess_email_body(email.body)[0]
                if len(clean_text.strip()) > 0:
                    texts.append(clean_text)
                    labels.append(int(email.label) if email.label is not None else 0)
            except Exception as e:
                logger.warning(f"Error preprocessing email {email.id}: {e}")
                continue
        
        logger.info(f"Preprocessed {len(texts)} emails")
        
        return texts, np.array(labels)
    
    def split_data(
        self,
        texts: List[str],
        labels: np.ndarray
    ) -> None:
        """
        Split data into train/val/test with stratification
        
        Args:
            texts: All texts
            labels: All labels
        """
        logger.info("Splitting data with stratification...")
        
        # First split: test (15%) and temp (85%)
        temp_texts, self.test_texts, temp_labels, self.test_labels = train_test_split(
            texts,
            labels,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=labels
        )
        
        # Second split: train (70%) and val (15%)
        # Adjust val_size to account for removing test set
        val_size_adjusted = self.val_size / (1 - self.test_size)
        
        self.train_texts, self.val_texts, self.train_labels, self.val_labels = train_test_split(
            temp_texts,
            temp_labels,
            test_size=val_size_adjusted,
            random_state=self.random_state,
            stratify=temp_labels
        )
        
        logger.info(f"Train set: {len(self.train_texts)} samples")
        logger.info(f"  Phishing: {np.sum(self.train_labels)} ({100*np.mean(self.train_labels):.1f}%)")
        logger.info(f"Validation set: {len(self.val_texts)} samples")
        logger.info(f"  Phishing: {np.sum(self.val_labels)} ({100*np.mean(self.val_labels):.1f}%)")
        logger.info(f"Test set: {len(self.test_texts)} samples")
        logger.info(f"  Phishing: {np.sum(self.test_labels)} ({100*np.mean(self.test_labels):.1f}%)")
    
    def train_baseline_models(self) -> Dict[str, Dict]:
        """
        Train both baseline models
        
        Returns:
            Results dictionary with models and metrics
        """
        if self.train_texts is None:
            raise ValueError("Data not split yet. Call split_data() first.")
        
        results = {}
        
        # ============================================================
        # Model 1: TF-IDF + Logistic Regression
        # ============================================================
        logger.info("\n" + "="*60)
        logger.info("Training TF-IDF + Logistic Regression...")
        logger.info("="*60)
        
        model_lr = TFIDFLogisticRegression()
        model_lr.fit(self.train_texts, self.train_labels)
        
        # Validation evaluation
        val_metrics_lr = eval_logreg(
            model_lr,
            self.val_texts,
            self.val_labels,
            "TF-IDF + Logistic Regression (Validation)"
        )
        
        results['tfidf_logreg'] = {
            'model': model_lr,
            'val_metrics': val_metrics_lr,
            'test_metrics': None
        }
        
        # ============================================================
        # Model 2: TF-IDF + Random Forest
        # ============================================================
        logger.info("\n" + "="*60)
        logger.info("Training TF-IDF + Random Forest...")
        logger.info("="*60)
        
        model_rf = TFIDFRandomForest(n_estimators=100)
        model_rf.fit(self.train_texts, self.train_labels)
        
        # Validation evaluation
        val_metrics_rf = eval_rf(
            model_rf,
            self.val_texts,
            self.val_labels,
            "TF-IDF + Random Forest (Validation)"
        )
        
        results['tfidf_rf'] = {
            'model': model_rf,
            'val_metrics': val_metrics_rf,
            'test_metrics': None
        }
        
        return results
    
    def evaluate_on_test(self, results: Dict[str, Dict]) -> Dict[str, Dict]:
        """
        Final evaluation on test set
        
        Args:
            results: Results from training
        
        Returns:
            Updated results with test metrics
        """
        if self.test_texts is None:
            raise ValueError("Test set not available")
        
        logger.info("\n" + "="*70)
        logger.info("FINAL EVALUATION ON TEST SET")
        logger.info("="*70)
        
        # ============================================================
        # TF-IDF + Logistic Regression
        # ============================================================
        logger.info("\nTF-IDF + Logistic Regression (Test Set)")
        logger.info("-" * 50)
        
        model_lr = results['tfidf_logreg']['model']
        test_metrics_lr = eval_logreg(
            model_lr,
            self.test_texts,
            self.test_labels,
            "TF-IDF + Logistic Regression (Test)"
        )
        results['tfidf_logreg']['test_metrics'] = test_metrics_lr
        
        # ============================================================
        # TF-IDF + Random Forest
        # ============================================================
        logger.info("\nTF-IDF + Random Forest (Test Set)")
        logger.info("-" * 50)
        
        model_rf = results['tfidf_rf']['model']
        test_metrics_rf = eval_rf(
            model_rf,
            self.test_texts,
            self.test_labels,
            "TF-IDF + Random Forest (Test)"
        )
        results['tfidf_rf']['test_metrics'] = test_metrics_rf
        
        return results
    
    def compare_models(self, results: Dict[str, Dict]) -> pd.DataFrame:
        """
        Compare baseline models
        
        Args:
            results: Results from training and testing
        
        Returns:
            Comparison DataFrame
        """
        logger.info("\n" + "="*70)
        logger.info("BASELINE MODEL COMPARISON")
        logger.info("="*70)
        
        comparison_data = {
            'Model': ['TF-IDF + LogReg', 'TF-IDF + RF'],
            'Val Accuracy': [
                results['tfidf_logreg']['val_metrics']['accuracy'],
                results['tfidf_rf']['val_metrics']['accuracy']
            ],
            'Val Precision': [
                results['tfidf_logreg']['val_metrics']['precision'],
                results['tfidf_rf']['val_metrics']['precision']
            ],
            'Val Recall': [
                results['tfidf_logreg']['val_metrics']['recall'],
                results['tfidf_rf']['val_metrics']['recall']
            ],
            'Val F1': [
                results['tfidf_logreg']['val_metrics']['f1'],
                results['tfidf_rf']['val_metrics']['f1']
            ],
            'Test Accuracy': [
                results['tfidf_logreg']['test_metrics']['accuracy'],
                results['tfidf_rf']['test_metrics']['accuracy']
            ],
            'Test Precision': [
                results['tfidf_logreg']['test_metrics']['precision'],
                results['tfidf_rf']['test_metrics']['precision']
            ],
            'Test Recall': [
                results['tfidf_logreg']['test_metrics']['recall'],
                results['tfidf_rf']['test_metrics']['recall']
            ],
            'Test F1': [
                results['tfidf_logreg']['test_metrics']['f1'],
                results['tfidf_rf']['test_metrics']['f1']
            ],
        }
        
        df = pd.DataFrame(comparison_data)
        
        # Print formatted table
        logger.info("\n" + df.to_string(index=False))
        
        # Save to CSV
        csv_path = self.output_dir / "baseline_comparison.csv"
        df.to_csv(csv_path, index=False)
        logger.info(f"\nComparison saved to {csv_path}")
        
        return df
    
    def save_models(self, results: Dict[str, Dict]) -> None:
        """Save trained models"""
        lr_path = self.output_dir / "tfidf_logreg.pkl"
        rf_path = self.output_dir / "tfidf_rf.pkl"
        
        results['tfidf_logreg']['model'].save(str(lr_path))
        results['tfidf_rf']['model'].save(str(rf_path))
        
        logger.info(f"Models saved to {self.output_dir}")
    
    def save_results(self, results: Dict[str, Dict], comparison_df: pd.DataFrame) -> None:
        """Save detailed results as JSON"""
        results_dict = {
            'tfidf_logreg': {
                'val_metrics': results['tfidf_logreg']['val_metrics'],
                'test_metrics': results['tfidf_logreg']['test_metrics'],
            },
            'tfidf_rf': {
                'val_metrics': results['tfidf_rf']['val_metrics'],
                'test_metrics': results['tfidf_rf']['test_metrics'],
            }
        }
        
        json_path = self.output_dir / "results.json"
        with open(json_path, 'w') as f:
            json.dump(results_dict, f, indent=2)
        
        logger.info(f"Results saved to {json_path}")
    
    def run_full_pipeline(self, data_dir: str) -> Tuple[Dict[str, Dict], pd.DataFrame]:
        """
        Run complete training pipeline
        
        Args:
            data_dir: Directory with email data
        
        Returns:
            Results and comparison dataframe
        """
        # Load and preprocess
        texts, labels = self.load_and_preprocess_data()
        
        # Split data
        self.split_data(texts, labels)
        
        # Train models
        results = self.train_baseline_models()
        
        # Evaluate on test set
        results = self.evaluate_on_test(results)
        
        # Compare models
        comparison_df = self.compare_models(results)
        
        # Save models and results
        self.save_models(results)
        self.save_results(results, comparison_df)
        
        return results, comparison_df


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Example usage
    trainer = ModelTrainer(
        data_dir="data/raw",
        output_dir="models/trained"
    )
    
    # Run pipeline
    results, comparison = trainer.run_full_pipeline("data/raw")
    
    print("\n✅ Baseline models training complete!")
    print(f"Models saved to: models/trained/")
    print(f"Comparison saved to: models/trained/baseline_comparison.csv")
