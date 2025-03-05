"""
Phishing Detection Inference Pipeline
Main module for making predictions on emails
"""

import logging
import pickle
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional

from src.constants import (
    MODELS_DIR,
    BASELINE_TFIDF_LOGREG,
    BASELINE_TFIDF_RF,
    DEFAULT_DECISION_THRESHOLD,
)
from src.data.loader import Email, EmailDataLoader
from src.data.preprocessor import EmailPreprocessor
from src.features.url_analyzer import URLAnalyzer, LinkExtractor, DomainAnalyzer
from src.features.structural_features import StructuralFeatureExtractor
from src.features.text_features import TextFeatureExtractor

logger = logging.getLogger(__name__)


class PhishShieldPredictor:
    """
    Main inference class for phishing email detection
    Combines baseline models for predictions
    """
    
    def __init__(
        self,
        model_type: str = "tfidf_logreg",
        model_path: Optional[str] = None,
        use_structural: bool = True,
        threshold: float = DEFAULT_DECISION_THRESHOLD
    ):
        """
        Initialize the predictor
        
        Args:
            model_type: Type of model to use ('tfidf_logreg', 'tfidf_rf')
            model_path: Path to saved model (if None, uses default from MODELS_DIR)
            use_structural: Whether to use structural features
            threshold: Decision threshold for classification
        """
        self.model_type = model_type
        self.use_structural = use_structural
        self.threshold = threshold
        self.model = None
        self.tfidf_vectorizer = None
        self.preprocessor = EmailPreprocessor()
        self.text_extractor = TextFeatureExtractor()
        self.struct_extractor = StructuralFeatureExtractor()
        
        # Load model
        self._load_model(model_path)
        
        logger.info(
            f"PhishShieldPredictor initialized with model={model_type}, "
            f"threshold={threshold}, use_structural={use_structural}"
        )
    
    def _load_model(self, model_path: Optional[str] = None) -> None:
        """Load pre-trained model"""
        if model_path is None:
            if self.model_type == "tfidf_logreg":
                model_path = MODELS_DIR / BASELINE_TFIDF_LOGREG
            elif self.model_type == "tfidf_rf":
                model_path = MODELS_DIR / BASELINE_TFIDF_RF
            else:
                raise ValueError(f"Unknown model type: {self.model_type}")
        
        model_path = Path(model_path)
        
        if not model_path.exists():
            logger.warning(
                f"Model not found at {model_path}. "
                f"Using untrained model. Make sure to train first."
            )
            return
        
        try:
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
                self.model = model_data.get('model')
                # Support both 'vectorizer' and 'tfidf_vectorizer' key names
                self.tfidf_vectorizer = model_data.get('vectorizer') or model_data.get('tfidf_vectorizer')
            logger.info(f"Model loaded successfully from {model_path}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    def predict(self, email: Email) -> Dict:
        """
        Main prediction method
        
        Args:
            email: Email object
        
        Returns:
            Dictionary with prediction results
        """
        if self.model is None:
            raise RuntimeError("Model not loaded. Train or load a model first.")
        
        # Extract features
        features = self._extract_features(email)

        # Get prediction
        if self.tfidf_vectorizer is None:
            raise RuntimeError("TF-IDF vectorizer not available")

        X = features['tfidf_features'].reshape(1, -1)

        # Predict (compute probabilities once for efficiency)
        proba = self.model.predict_proba(X)[0]
        prediction = np.argmax(proba)
        confidence = np.max(proba)

        # Generate reasoning
        reasoning = self._generate_reasoning(email)

        # Determine risk level
        risk_level = self._calculate_risk_level(confidence, prediction)

        return {
            'prediction': 'PHISHING' if prediction == 1 else 'LEGITIMATE',
            'confidence': float(confidence),
            'pred_proba': {
                'legitimate': float(proba[0]),
                'phishing': float(proba[1]),
            },
            'risk_level': risk_level,
            'reasoning': reasoning,
            'features_used': {
                'text_features_dim': features['tfidf_features'].shape[-1],
                'has_urls': len(email.urls) > 0,
                'url_count': len(email.urls),
            }
        }
    
    def predict_batch(self, emails: List[Email], batch_size: int = 32) -> List[Dict]:
        """
        Predict on a batch of emails
        
        Args:
            emails: List of Email objects
            batch_size: Batch size for processing
        
        Returns:
            List of prediction results
        """
        results = []
        total = len(emails)
        
        for i in range(0, total, batch_size):
            batch = emails[i:i + batch_size]

            # Extract features for batch
            X_batch = []
            for email in batch:
                feature_dict = self._extract_features(email)
                X_batch.append(feature_dict['tfidf_features'])
            
            X_batch = np.vstack(X_batch)

            # Predict on batch (compute probabilities once for efficiency)
            proba = self.model.predict_proba(X_batch)
            predictions = np.argmax(proba, axis=1)
            confidences = np.max(proba, axis=1)
            
            # Process results
            for j, email in enumerate(batch):
                result = {
                    'email_id': email.id,
                    'prediction': 'PHISHING' if predictions[j] == 1 else 'LEGITIMATE',
                    'confidence': float(confidences[j]),
                    'risk_level': self._calculate_risk_level(confidences[j], predictions[j]),
                }
                results.append(result)
            
            logger.info(f"Processed {min(i + batch_size, total)}/{total} emails")
        
        return results
    
    def _extract_features(self, email: Email) -> Dict:
        """Extract all features from email"""
        # Preprocess text
        cleaned, _ = self.preprocessor.preprocess_email_body(email.body)
        
        # TF-IDF features
        tfidf_vec = self.tfidf_vectorizer.transform([cleaned]).toarray()[0]
        
        # Structural features (for future use)
        structural_features = {}
        if self.use_structural:
            try:
                url_feats = self.struct_extractor.extract_url_features(email.urls)
                domain_feats = self.struct_extractor.extract_domain_features(email)
                header_feats = self.struct_extractor.extract_header_features(email)
                content_feats = self.struct_extractor.extract_content_features(email)
                urgency_feats = self.struct_extractor.extract_urgency_features(
                    email.body, email.subject
                )
                
                structural_features = {
                    **url_feats,
                    **domain_feats,
                    **header_feats,
                    **content_feats,
                    **urgency_feats,
                }
            except Exception as e:
                logger.warning(f"Failed to extract structural features: {e}")
        
        return {
            'tfidf_features': tfidf_vec,
            'structural_features': structural_features,
            'cleaned_text': cleaned,
        }
    
    def _generate_reasoning(self, email: Email) -> List[str]:
        """Generate human-readable reasoning for prediction"""
        reasons = []
        
        # Check for suspicious URLs
        if email.urls:
            for url in email.urls:
                if URLAnalyzer.is_shortened_url(url):
                    reasons.append(f"Shortened URL detected: {url}")
                if URLAnalyzer.has_ip_address(url):
                    reasons.append("URL uses IP address instead of domain")
                if URLAnalyzer.has_punycode(url):
                    reasons.append("Punycode/IDN encoding detected in URL")
                if URLAnalyzer.has_suspicious_tld(url):
                    reasons.append("Suspicious TLD detected in URL")
        
        # Domain mismatches
        from_domain = DomainAnalyzer.extract_domain(email.from_email)
        reply_to = email.headers.get('reply-to', '')
        if reply_to:
            reply_domain = DomainAnalyzer.extract_domain(reply_to)
            if from_domain and reply_domain and from_domain != reply_domain:
                reasons.append(f"From domain {from_domain} doesn't match Reply-To domain {reply_domain}")
        
        # Urgency keywords
        text_combined = (email.body + ' ' + email.subject).lower()
        urgency_kws = ['urgent', 'immediate', 'action required', 'asap']
        if any(kw in text_combined for kw in urgency_kws):
            reasons.append("Urgent language detected")
        
        # Credential keywords
        cred_kws = ['password', 'verify', 'confirm', 'authenticate', 'login']
        if any(kw in text_combined for kw in cred_kws):
            reasons.append("Credential solicitation detected")
        
        # Link mismatches
        if '<a' in email.body:
            links = LinkExtractor.extract_html_links(email.body)
            for text, url in links:
                if LinkExtractor.is_link_mismatch(text, url):
                    reasons.append(f"Link mismatch: text='{text}' vs url='{url}'")
        
        return reasons if reasons else ["Detected as phishing based on text patterns"]
    
    def _calculate_risk_level(self, confidence: float, prediction: int) -> str:
        """Determine risk level based on confidence and prediction"""
        if prediction == 0:  # Legitimate
            return "LOW"
        
        if confidence > 0.95:
            return "CRITICAL"
        elif confidence > 0.85:
            return "HIGH"
        elif confidence > 0.70:
            return "MEDIUM"
        else:
            return "LOW"


class EmailBatchProcessor:
    """Process emails in batches with parallel inference"""
    
    def __init__(self, predictor: PhishShieldPredictor, n_jobs: int = 4):
        """
        Initialize batch processor
        
        Args:
            predictor: PhishShieldPredictor instance
            n_jobs: Number of parallel jobs
        """
        self.predictor = predictor
        self.n_jobs = n_jobs
    
    def process_file(self, file_path: str) -> List[Dict]:
        """
        Process emails from a file
        
        Args:
            file_path: Path to email file (.eml, .json, .jsonl)
        
        Returns:
            List of predictions
        """
        loader = EmailDataLoader()
        emails = loader.load_from_file(file_path)
        
        return self.predictor.predict_batch(emails)
    
    def process_directory(self, dir_path: str) -> Dict:
        """
        Process all emails in a directory
        
        Args:
            dir_path: Path to directory containing email files
        
        Returns:
            Results dictionary with statistics
        """
        loader = EmailDataLoader()
        emails = loader.load_from_directory(dir_path)
        
        predictions = self.predictor.predict_batch(emails)
        
        # Calculate statistics
        total = len(predictions)
        phishing_count = sum(1 for p in predictions if p['prediction'] == 'PHISHING')
        
        stats = {
            'total_emails': total,
            'phishing_detected': phishing_count,
            'legitimate': total - phishing_count,
            'phishing_ratio': phishing_count / total if total > 0 else 0,
            'avg_confidence': np.mean([p['confidence'] for p in predictions]),
            'predictions': predictions,
        }
        
        return stats
