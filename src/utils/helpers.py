"""
PhishShield Utilities and Helpers
Common utility functions for the project
"""

import logging
import json
from pathlib import Path
from typing import Dict, List, Optional
import numpy as np

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================

def load_config(config_path: str) -> Dict:
    """Load YAML configuration file"""
    import yaml
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        logger.info(f"Configuration loaded from {config_path}")
        return config
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        raise


# ============================================================================
# Model Management
# ============================================================================

def save_model(model, vectorizer, output_path: str, model_type: str) -> None:
    """
    Save trained model and vectorizer
    
    Args:
        model: Trained sklearn model
        vectorizer: TF-IDF vectorizer
        output_path: Path to save model
        model_type: Type of model (for logging)
    """
    import pickle
    
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        with open(output_path, 'wb') as f:
            pickle.dump({
                'model': model,
                'tfidf_vectorizer': vectorizer,
                'model_type': model_type
            }, f)
        logger.info(f"Model saved to {output_path}")
    except Exception as e:
        logger.error(f"Failed to save model: {e}")
        raise


def load_model(model_path: str) -> tuple:
    """
    Load pre-trained model
    
    Args:
        model_path: Path to saved model
    
    Returns:
        (model, vectorizer) tuple
    """
    import pickle
    
    try:
        with open(model_path, 'rb') as f:
            data = pickle.load(f)
        logger.info(f"Model loaded from {model_path}")
        return data['model'], data['tfidf_vectorizer']
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        raise


# ============================================================================
# Data Processing
# ============================================================================

def combine_embeddings(tfidf: np.ndarray, structural: np.ndarray) -> np.ndarray:
    """
    Combine TF-IDF and structural features
    
    Args:
        tfidf: TF-IDF feature matrix (n_samples, n_tfidf_features)
        structural: Structural feature matrix (n_samples, n_structural_features)
    
    Returns:
        Combined feature matrix
    """
    return np.hstack([tfidf, structural])


def normalize_features(features: np.ndarray, method: str = 'standard') -> np.ndarray:
    """
    Normalize features
    
    Args:
        features: Feature matrix
        method: 'standard' or 'minmax'
    
    Returns:
        Normalized features
    """
    from sklearn.preprocessing import StandardScaler, MinMaxScaler
    
    if method == 'standard':
        scaler = StandardScaler()
    elif method == 'minmax':
        scaler = MinMaxScaler()
    else:
        raise ValueError(f"Unknown normalization method: {method}")
    
    return scaler.fit_transform(features)


# ============================================================================
# Results and Reporting
# ============================================================================

def save_predictions(predictions: List[Dict], output_path: str) -> None:
    """
    Save predictions to JSON file
    
    Args:
        predictions: List of prediction results
        output_path: Path to save predictions
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        with open(output_path, 'w') as f:
            json.dump(predictions, f, indent=2, default=str)
        logger.info(f"Predictions saved to {output_path}")
    except Exception as e:
        logger.error(f"Failed to save predictions: {e}")
        raise


def generate_report(predictions: List[Dict]) -> Dict:
    """
    Generate summary report from predictions
    
    Args:
        predictions: List of prediction results
    
    Returns:
        Report dictionary with statistics
    """
    total = len(predictions)
    
    if total == 0:
        return {
            'total': 0,
            'phishing': 0,
            'legitimate': 0,
            'phishing_ratio': 0,
            'avg_confidence': 0,
            'min_confidence': 0,
            'max_confidence': 0
        }
    
    phishing_count = sum(1 for p in predictions if p.get('prediction') == 'PHISHING')
    confidences = [p.get('confidence', 0) for p in predictions]
    
    return {
        'total': total,
        'phishing': phishing_count,
        'legitimate': total - phishing_count,
        'phishing_ratio': phishing_count / total,
        'avg_confidence': np.mean(confidences),
        'min_confidence': np.min(confidences),
        'max_confidence': np.max(confidences),
        'std_confidence': np.std(confidences),
    }


# ============================================================================
# Visualization
# ============================================================================

def plot_confusion_matrix(y_true, y_pred, output_path: Optional[str] = None):
    """Plot confusion matrix"""
    from sklearn.metrics import confusion_matrix
    import matplotlib.pyplot as plt
    import seaborn as sns
    
    cm = confusion_matrix(y_true, y_pred)
    
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cbar=True,
                xticklabels=['Legitimate', 'Phishing'],
                yticklabels=['Legitimate', 'Phishing'])
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.title('Confusion Matrix')
    
    if output_path:
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        logger.info(f"Confusion matrix saved to {output_path}")
    
    return plt


def plot_roc_curve(y_true, y_pred_proba, output_path: Optional[str] = None):
    """Plot ROC curve"""
    from sklearn.metrics import roc_curve, auc
    import matplotlib.pyplot as plt
    
    fpr, tpr, _ = roc_curve(y_true, y_pred_proba)
    roc_auc = auc(fpr, tpr)
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.2f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random Classifier')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve')
    plt.legend(loc="lower right")
    plt.grid()
    
    if output_path:
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        logger.info(f"ROC curve saved to {output_path}")
    
    return plt


def plot_precision_recall_curve(y_true, y_pred_proba, output_path: Optional[str] = None):
    """Plot precision-recall curve"""
    from sklearn.metrics import precision_recall_curve, auc
    import matplotlib.pyplot as plt
    
    precision, recall, _ = precision_recall_curve(y_true, y_pred_proba)
    pr_auc = auc(recall, precision)
    
    plt.figure(figsize=(8, 6))
    plt.plot(recall, precision, color='darkblue', lw=2, label=f'PR curve (AUC = {pr_auc:.2f})')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve')
    plt.legend(loc="best")
    plt.grid()
    
    if output_path:
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        logger.info(f"Precision-Recall curve saved to {output_path}")
    
    return plt


# ============================================================================
# Logging and Debugging
# ============================================================================

def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> None:
    """
    Setup logging configuration
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
    """
    log_format = "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s"
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format=log_format,
    )
    
    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        formatter = logging.Formatter(log_format)
        file_handler.setFormatter(formatter)
        
        # Add to root logger
        root_logger = logging.getLogger()
        root_logger.addHandler(file_handler)
        logger.info(f"Logging to file: {log_file}")


# ============================================================================
# Validation
# ============================================================================

def validate_email_format(email_str: str) -> bool:
    """Validate email address format"""
    from email_validator import validate_email, EmailNotValidError
    
    try:
        validate_email(email_str)
        return True
    except EmailNotValidError:
        return False


def validate_url(url: str) -> bool:
    """Validate URL format"""
    import re
    url_pattern = r'https?://[^\s]+$'
    return bool(re.match(url_pattern, url))
