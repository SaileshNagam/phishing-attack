"""
Baseline Model 2: TF-IDF + Random Forest
Ensemble-based baseline with good interpretability
"""

import logging
from typing import Dict, List, Tuple, Optional
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import pickle

logger = logging.getLogger(__name__)


class TFIDFRandomForest:
    """TF-IDF + Random Forest baseline model"""
    
    def __init__(
        self,
        max_features: int = 5000,
        ngram_range: Tuple[int, int] = (1, 2),
        n_estimators: int = 100,
        max_depth: int = 20,
        min_samples_leaf: int = 2,
        random_state: int = 42
    ):
        """
        Initialize model
        
        Args:
            max_features: Max TF-IDF features
            ngram_range: N-gram range for TF-IDF
            n_estimators: Number of trees
            max_depth: Maximum tree depth
            min_samples_leaf: Minimum samples in leaf
            random_state: Random seed
        """
        self.max_features = max_features
        self.ngram_range = ngram_range
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_leaf = min_samples_leaf
        self.random_state = random_state
        
        self.tfidf = TfidfVectorizer(
            max_features=max_features,
            ngram_range=ngram_range,
            lowercase=True,
            stop_words='english',
            min_df=2,
            max_df=0.95,
            sublinear_tf=True
        )
        
        self.classifier = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_leaf=min_samples_leaf,
            max_features='sqrt',
            random_state=random_state,
            n_jobs=-1,
            class_weight='balanced'
        )
        
        self.is_fitted = False
    
    def fit(self, texts: List[str], labels: np.ndarray) -> None:
        """
        Train the model
        
        Args:
            texts: List of email body texts
            labels: Binary labels (0=legitimate, 1=phishing)
        """
        logger.info("Fitting TF-IDF vectorizer...")
        X = self.tfidf.fit_transform(texts)
        
        logger.info("Fitting Random Forest classifier...")
        self.classifier.fit(X, labels)
        
        self.is_fitted = True
        logger.info("Model fitted successfully")
    
    def predict(self, texts: List[str]) -> np.ndarray:
        """
        Predict on new texts
        
        Args:
            texts: List of email texts
        
        Returns:
            Predictions (0 or 1)
        """
        if not self.is_fitted:
            raise ValueError("Model must be fitted first")
        
        X = self.tfidf.transform(texts)
        return self.classifier.predict(X)
    
    def predict_proba(self, texts: List[str]) -> np.ndarray:
        """
        Predict probabilities
        
        Args:
            texts: List of email texts
        
        Returns:
            Probabilities (shape: n_samples x 2)
        """
        if not self.is_fitted:
            raise ValueError("Model must be fitted first")
        
        X = self.tfidf.transform(texts)
        return self.classifier.predict_proba(X)
    
    def get_feature_importance(self, top_n: int = 20) -> List[Tuple[str, float]]:
        """
        Get most important features (words)
        
        Args:
            top_n: Number of top features to return
        
        Returns:
            List of (feature, importance) tuples
        """
        if not self.is_fitted:
            raise ValueError("Model must be fitted first")
        
        # Get feature names
        feature_names = self.tfidf.get_feature_names_out()
        
        # Get feature importances
        importances = self.classifier.feature_importances_
        
        # Get top features
        top_indices = np.argsort(importances)[-top_n:][::-1]
        
        results = []
        for idx in top_indices:
            feature = feature_names[idx]
            importance = importances[idx]
            results.append((feature, importance))
        
        return results
    
    def save(self, filepath: str) -> None:
        """Save model to file"""
        with open(filepath, 'wb') as f:
            pickle.dump(self, f)
        logger.info(f"Model saved to {filepath}")
    
    @staticmethod
    def load(filepath: str) -> 'TFIDFRandomForest':
        """Load model from file"""
        with open(filepath, 'rb') as f:
            model = pickle.load(f)
        logger.info(f"Model loaded from {filepath}")
        return model


def hyperparameter_search(
    texts: List[str],
    labels: np.ndarray,
    cv: int = 5
) -> Dict:
    """
    Perform hyperparameter grid search
    
    Args:
        texts: Training texts
        labels: Training labels
        cv: Cross-validation folds
    
    Returns:
        Best model and results
    """
    logger.info("Starting hyperparameter search...")
    
    # TF-IDF vectorizer
    tfidf = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        lowercase=True,
        stop_words='english',
        min_df=2,
        max_df=0.95
    )
    
    # Transform texts
    X = tfidf.fit_transform(texts)
    
    # Model
    classifier = RandomForestClassifier(
        max_features='sqrt',
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    
    # Parameter grid
    param_grid = {
        'n_estimators': [50, 100, 200],
        'max_depth': [10, 15, 20, None],
        'min_samples_leaf': [1, 2, 4],
    }
    
    # Grid search
    grid_search = GridSearchCV(
        classifier,
        param_grid,
        cv=cv,
        scoring='f1',
        n_jobs=-1,
        verbose=1
    )
    
    grid_search.fit(X, labels)
    
    results = {
        'best_params': grid_search.best_params_,
        'best_score': grid_search.best_score_,
        'best_model': grid_search.best_estimator_,
        'cv_results': grid_search.cv_results_
    }
    
    logger.info(f"Best params: {grid_search.best_params_}")
    logger.info(f"Best CV F1: {grid_search.best_score_:.4f}")
    
    return results


def evaluate_model(
    model: TFIDFRandomForest,
    texts: List[str],
    labels: np.ndarray,
    model_name: str = "TF-IDF + Random Forest"
) -> Dict[str, float]:
    """
    Evaluate model performance
    
    Args:
        model: Trained model
        texts: Test texts
        labels: Test labels
        model_name: Name for logging
    
    Returns:
        Metrics dictionary
    """
    # Predictions
    predictions = model.predict(texts)
    probabilities = model.predict_proba(texts)[:, 1]
    
    # Calculate metrics
    metrics = {
        'accuracy': accuracy_score(labels, predictions),
        'precision': precision_score(labels, predictions),
        'recall': recall_score(labels, predictions),
        'f1': f1_score(labels, predictions),
        'roc_auc': roc_auc_score(labels, probabilities),
    }
    
    logger.info(f"\n{model_name} Performance:")
    logger.info(f"  Accuracy:  {metrics['accuracy']:.4f}")
    logger.info(f"  Precision: {metrics['precision']:.4f}")
    logger.info(f"  Recall:    {metrics['recall']:.4f}")
    logger.info(f"  F1-Score:  {metrics['f1']:.4f}")
    logger.info(f"  ROC-AUC:   {metrics['roc_auc']:.4f}")
    
    return metrics


if __name__ == "__main__":
    # Example usage
    print("TF-IDF + Random Forest Baseline Model")
    
    # Sample data
    sample_texts = [
        "Urgent: Verify your account immediately",
        "Check out this promotional offer",
        "Welcome to our newsletter",
        "Click here to reset password",
        "Your account has been accessed",
        "New job opportunity available",
    ]
    sample_labels = np.array([1, 0, 0, 1, 1, 0])
    
    # Train model
    model = TFIDFRandomForest(n_estimators=10)  # Small for demo
    model.fit(sample_texts, sample_labels)
    
    # Get feature importance
    top_features = model.get_feature_importance(top_n=10)
    print("\nTop Features:")
    for feat, importance in top_features:
        print(f"  {feat}: {importance:.4f}")
    
    # Predict
    predictions = model.predict(sample_texts)
    print(f"\nPredictions: {predictions}")
    
    # Probabilities
    probas = model.predict_proba(sample_texts)
    print(f"Probabilities:\n{probas}")
