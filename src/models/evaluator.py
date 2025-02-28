"""
Model Evaluator
Comprehensive evaluation, cross-validation, and ablation studies
"""

import logging
from typing import Dict, List, Tuple, Optional
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, roc_curve, precision_recall_curve,
    classification_report
)
import matplotlib.pyplot as plt
from pathlib import Path

logger = logging.getLogger(__name__)


class ModelEvaluator:
    """Comprehensive model evaluation and analysis"""
    
    def __init__(self, output_dir: str = "evaluation"):
        """
        Initialize evaluator
        
        Args:
            output_dir: Where to save evaluation plots/reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def cross_validation_score(
        self,
        model,
        texts: List[str],
        labels: np.ndarray,
        cv: int = 5,
        model_name: str = "Model"
    ) -> Dict[str, float]:
        """
        Perform stratified k-fold cross-validation
        
        Args:
            model: Model with fit/predict methods
            texts: Training texts
            labels: Training labels
            cv: Number of folds
            model_name: Name for logging
        
        Returns:
            Cross-validation metrics
        """
        logger.info(f"\n{'='*60}")
        logger.info(f"Cross-Validation ({cv}-fold): {model_name}")
        logger.info(f"{'='*60}")
        
        skf = StratifiedKFold(n_splits=cv, shuffle=True, random_state=42)
        
        fold_metrics = {
            'accuracy': [],
            'precision': [],
            'recall': [],
            'f1': [],
            'roc_auc': []
        }
        
        for fold, (train_idx, val_idx) in enumerate(skf.split(texts, labels), 1):
            logger.info(f"\nFold {fold}/{cv}")
            
            # Split data
            train_texts = [texts[i] for i in train_idx]
            val_texts = [texts[i] for i in val_idx]
            train_labels = labels[train_idx]
            val_labels = labels[val_idx]
            
            # Train model
            try:
                model.fit(train_texts, train_labels)
            except Exception as e:
                logger.error(f"Error fitting model on fold {fold}: {e}")
                continue
            
            # Evaluate
            try:
                predictions = model.predict(val_texts)
                probabilities = model.predict_proba(val_texts)[:, 1]
                
                fold_metrics['accuracy'].append(accuracy_score(val_labels, predictions))
                fold_metrics['precision'].append(precision_score(val_labels, predictions))
                fold_metrics['recall'].append(recall_score(val_labels, predictions))
                fold_metrics['f1'].append(f1_score(val_labels, predictions))
                fold_metrics['roc_auc'].append(roc_auc_score(val_labels, probabilities))
                
                logger.info(f"  Accuracy: {fold_metrics['accuracy'][-1]:.4f}")
                logger.info(f"  F1-Score: {fold_metrics['f1'][-1]:.4f}")
            except Exception as e:
                logger.error(f"Error evaluating fold {fold}: {e}")
                continue
        
        # Aggregate results
        results = {}
        for metric, scores in fold_metrics.items():
            if scores:
                results[f'{metric}_mean'] = np.mean(scores)
                results[f'{metric}_std'] = np.std(scores)
                results[f'{metric}_scores'] = scores
        
        # Log summary
        logger.info(f"\n{'='*60}")
        logger.info("Cross-Validation Summary")
        logger.info(f"{'='*60}")
        logger.info(f"Accuracy:  {results['accuracy_mean']:.4f} ± {results['accuracy_std']:.4f}")
        logger.info(f"Precision: {results['precision_mean']:.4f} ± {results['precision_std']:.4f}")
        logger.info(f"Recall:    {results['recall_mean']:.4f} ± {results['recall_std']:.4f}")
        logger.info(f"F1-Score:  {results['f1_mean']:.4f} ± {results['f1_std']:.4f}")
        logger.info(f"ROC-AUC:   {results['roc_auc_mean']:.4f} ± {results['roc_auc_std']:.4f}")
        
        return results
    
    def per_class_metrics(
        self,
        predictions: np.ndarray,
        labels: np.ndarray,
        model_name: str = "Model"
    ) -> pd.DataFrame:
        """
        Per-class precision, recall, F1
        
        Args:
            predictions: Predicted labels
            labels: True labels
            model_name: Name for logging
        
        Returns:
            DataFrame with per-class metrics
        """
        # Classification report
        report = classification_report(
            labels,
            predictions,
            target_names=['Legitimate', 'Phishing'],
            output_dict=True
        )
        
        df = pd.DataFrame(report).transpose()
        
        logger.info(f"\nPer-Class Metrics: {model_name}")
        logger.info(f"\n{df.to_string()}")
        
        return df
    
    def confusion_analysis(
        self,
        predictions: np.ndarray,
        labels: np.ndarray,
        model_name: str = "Model"
    ) -> Tuple[np.ndarray, Dict]:
        """
        Analyze confusion matrix
        
        Args:
            predictions: Predicted labels
            labels: True labels
            model_name: Name for logging
        
        Returns:
            Confusion matrix and analysis dict
        """
        cm = confusion_matrix(labels, predictions)
        
        tn, fp, fn, tp = cm.ravel()
        
        analysis = {
            'tn': tn,
            'fp': fp,
            'fn': fn,
            'tp': tp,
            'specificity': tn / (tn + fp) if (tn + fp) > 0 else 0,
            'sensitivity': tp / (tp + fn) if (tp + fn) > 0 else 0,
        }
        
        logger.info(f"\nConfusion Matrix Analysis: {model_name}")
        logger.info(f"  True Negatives (TN):  {tn}")
        logger.info(f"  False Positives (FP): {fp}")
        logger.info(f"  False Negatives (FN): {fn}")
        logger.info(f"  True Positives (TP):  {tp}")
        logger.info(f"  Specificity (TN/(TN+FP)): {analysis['specificity']:.4f}")
        logger.info(f"  Sensitivity (TP/(TP+FN)): {analysis['sensitivity']:.4f}")
        
        return cm, analysis
    
    def feature_importance_analysis(
        self,
        model,
        top_n: int = 20,
        model_name: str = "Model"
    ) -> List[Tuple[str, float]]:
        """
        Analyze feature importance
        
        Args:
            model: Model with get_feature_importance method
            top_n: Number of top features
            model_name: Name for logging
        
        Returns:
            List of (feature, importance) tuples
        """
        try:
            top_features = model.get_feature_importance(top_n=top_n)
            
            logger.info(f"\nTop {top_n} Features: {model_name}")
            for i, (feature, importance) in enumerate(top_features, 1):
                logger.info(f"  {i:2d}. {feature:30s} {importance:.6f}")
            
            return top_features
        except AttributeError:
            logger.warning(f"Model {model_name} doesn't have get_feature_importance method")
            return []
    
    def ablation_study(
        self,
        model_predictions: Dict[str, np.ndarray],
        labels: np.ndarray,
        model_names: List[str] = None
    ) -> pd.DataFrame:
        """
        Compare models in ablation study
        
        Args:
            model_predictions: Dict of model_name -> predictions
            labels: True labels
            model_names: Optional list of model names for context
        
        Returns:
            Ablation study results DataFrame
        """
        logger.info(f"\n{'='*70}")
        logger.info("ABLATION STUDY: MODEL COMPARISON")
        logger.info(f"{'='*70}")
        
        results = []
        
        for model_name, predictions in model_predictions.items():
            metrics = {
                'Model': model_name,
                'Accuracy': accuracy_score(labels, predictions),
                'Precision': precision_score(labels, predictions),
                'Recall': recall_score(labels, predictions),
                'F1': f1_score(labels, predictions),
            }
            
            results.append(metrics)
        
        df = pd.DataFrame(results)
        
        logger.info(f"\n{df.to_string(index=False)}")
        
        return df
    
    def error_analysis(
        self,
        texts: List[str],
        predictions: np.ndarray,
        labels: np.ndarray,
        model_name: str = "Model",
        sample_size: int = 5
    ) -> Dict[str, List]:
        """
        Analyze misclassified examples
        
        Args:
            texts: Email texts
            predictions: Predicted labels
            labels: True labels
            model_name: Name for logging
            sample_size: Number of errors to show
        
        Returns:
            Dict with false positives and false negatives
        """
        # Find errors
        errors = predictions != labels
        error_indices = np.where(errors)[0]
        
        fp_indices = np.where((predictions == 1) & (labels == 0))[0]  # False Positives
        fn_indices = np.where((predictions == 0) & (labels == 1))[0]  # False Negatives
        
        logger.info(f"\nError Analysis: {model_name}")
        logger.info(f"  Total Errors: {len(error_indices)} / {len(labels)}")
        logger.info(f"  False Positives (labeling legit as phishing): {len(fp_indices)}")
        logger.info(f"  False Negatives (missing phishing): {len(fn_indices)}")
        
        result = {
            'false_positives': [],
            'false_negatives': []
        }
        
        # Show samples of false positives
        if len(fp_indices) > 0:
            logger.info(f"\nSample False Positives (first {min(sample_size, len(fp_indices))}):")
            for idx in fp_indices[:sample_size]:
                logger.info(f"  [{idx}] {texts[idx][:100]}...")
                result['false_positives'].append({
                    'index': int(idx),
                    'text_preview': texts[idx][:200],
                    'true_label': int(labels[idx]),
                    'predicted_label': int(predictions[idx])
                })
        
        # Show samples of false negatives
        if len(fn_indices) > 0:
            logger.info(f"\nSample False Negatives (first {min(sample_size, len(fn_indices))}):")
            for idx in fn_indices[:sample_size]:
                logger.info(f"  [{idx}] {texts[idx][:100]}...")
                result['false_negatives'].append({
                    'index': int(idx),
                    'text_preview': texts[idx][:200],
                    'true_label': int(labels[idx]),
                    'predicted_label': int(predictions[idx])
                })
        
        return result
    
    def save_evaluation_report(
        self,
        results: Dict,
        filename: str = "evaluation_report.txt"
    ) -> None:
        """Save evaluation report to file"""
        report_path = self.output_dir / filename
        
        with open(report_path, 'w') as f:
            f.write("MODEL EVALUATION REPORT\n")
            f.write("="*70 + "\n\n")
            
            for key, value in results.items():
                f.write(f"{key}:\n")
                if isinstance(value, dict):
                    for k, v in value.items():
                        f.write(f"  {k}: {v}\n")
                else:
                    f.write(f"  {value}\n")
                f.write("\n")
        
        logger.info(f"Report saved to {report_path}")


class AblationStudyFramework:
    """Framework for comprehensive ablation studies"""
    
    def __init__(self, output_dir: str = "ablation_studies"):
        """Initialize ablation framework"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.evaluator = ModelEvaluator(output_dir)
    
    def compare_baseline_models(
        self,
        model_logreg,
        model_rf,
        test_texts: List[str],
        test_labels: np.ndarray
    ) -> pd.DataFrame:
        """
        Compare baseline models
        
        Args:
            model_logreg: TF-IDF + LogReg model
            model_rf: TF-IDF + RF model
            test_texts: Test emails
            test_labels: Test labels
        
        Returns:
            Comparison DataFrame
        """
        logger.info("\n" + "="*70)
        logger.info("ABLATION STUDY: BASELINE MODEL COMPARISON")
        logger.info("="*70)
        
        predictions = {
            'TF-IDF + LogisticRegression': model_logreg.predict(test_texts),
            'TF-IDF + RandomForest': model_rf.predict(test_texts)
        }
        
        comparison_df = self.evaluator.ablation_study(
            predictions,
            test_labels
        )
        
        # Save
        csv_path = self.output_dir / "baseline_ablation.csv"
        comparison_df.to_csv(csv_path, index=False)
        logger.info(f"Saved to {csv_path}")
        
        return comparison_df
    
    def feature_contribution_study(
        self,
        model_logreg,
        model_rf,
        feature_names_dict: Dict[str, List[str]] = None
    ) -> Dict[str, pd.DataFrame]:
        """
        Compare feature importance across models
        
        Args:
            model_logreg: TF-IDF + LogReg model
            model_rf: TF-IDF + RF model
            feature_names_dict: Optional dict of feature names
        
        Returns:
            Dict with feature importance DataFrames
        """
        logger.info("\n" + "="*70)
        logger.info("ABLATION STUDY: FEATURE IMPORTANCE ANALYSIS")
        logger.info("="*70)
        
        results = {}
        
        # Get top features from each model
        features_lr = self.evaluator.feature_importance_analysis(
            model_logreg,
            top_n=20,
            model_name="TF-IDF + LogisticRegression"
        )
        
        features_rf = self.evaluator.feature_importance_analysis(
            model_rf,
            top_n=20,
            model_name="TF-IDF + RandomForest"
        )
        
        # Create DataFrames
        if features_lr:
            df_lr = pd.DataFrame(features_lr, columns=['Feature', 'Importance'])
            results['tfidf_logreg'] = df_lr
        
        if features_rf:
            df_rf = pd.DataFrame(features_rf, columns=['Feature', 'Importance'])
            results['tfidf_rf'] = df_rf
        
        return results


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger.info("Model Evaluator and Ablation Study Framework")
    logger.info("Use with trained models for comprehensive evaluation")
