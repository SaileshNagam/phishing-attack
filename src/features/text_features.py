"""
Text feature extraction
Extracts TF-IDF, embeddings, and text-based features
"""

import logging
from typing import Dict, List, Tuple, Optional
import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer

logger = logging.getLogger(__name__)


class TextFeatureExtractor:
    """Extract text-based features"""
    
    def __init__(self, max_features: int = 5000):
        """
        Initialize text feature extractor
        
        Args:
            max_features: Maximum number of TF-IDF features
        """
        self.max_features = max_features
        self.tfidf_vectorizer = None
        self.tfidf_vectorizer_fitted = False
    
    def fit_tfidf(self, texts: List[str]) -> None:
        """
        Fit TF-IDF vectorizer on texts
        
        Args:
            texts: List of email body texts
        """
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=self.max_features,
            ngram_range=(1, 2),
            lowercase=True,
            stop_words='english',
            min_df=2,
            max_df=0.95,
            sublinear_tf=True
        )
        self.tfidf_vectorizer.fit(texts)
        self.tfidf_vectorizer_fitted = True
        logger.info(f"TF-IDF vectorizer fitted with {len(self.tfidf_vectorizer.get_feature_names_out())} features")
    
    def transform_tfidf(self, texts: List[str]) -> np.ndarray:
        """
        Transform texts to TF-IDF vectors
        
        Args:
            texts: List of texts
        
        Returns:
            TF-IDF matrix of shape (n_texts, max_features)
        """
        if not self.tfidf_vectorizer_fitted:
            raise ValueError("TF-IDF vectorizer must be fitted first")
        
        return self.tfidf_vectorizer.transform(texts).toarray()
    
    def get_text_embeddings(
        self,
        texts: List[str],
        model_name: str = "answerdotai/ModernBERT-base",
        batch_size: int = 32,
        device: str = "cpu"
    ) -> np.ndarray:
        """
        Get embeddings using transformer model
        
        Args:
            texts: List of texts
            model_name: HuggingFace model ID
            batch_size: Batch size for inference
            device: Device to use ('cpu' or 'cuda')
        
        Returns:
            Embedding matrix of shape (n_texts, embedding_dim)
        """
        try:
            from transformers import AutoTokenizer, AutoModel
            import torch
            
            # Load model and tokenizer
            logger.info(f"Loading {model_name}...")
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModel.from_pretrained(model_name)
            model.to(device)
            model.eval()
            
            all_embeddings = []
            
            # Process in batches
            for batch_start in range(0, len(texts), batch_size):
                batch_texts = texts[batch_start:batch_start + batch_size]
                
                # Tokenize
                encoded = tokenizer(
                    batch_texts,
                    padding=True,
                    truncation=True,
                    max_length=512,
                    return_tensors='pt'
                )
                
                # Move to device
                for key in encoded:
                    encoded[key] = encoded[key].to(device)
                
                # Get embeddings
                with torch.no_grad():
                    outputs = model(**encoded)
                    # Use [CLS] token representation
                    embeddings = outputs.last_hidden_state[:, 0, :].cpu().numpy()
                
                all_embeddings.append(embeddings)
            
            # Concatenate all batches
            result = np.vstack(all_embeddings)
            logger.info(f"Generated embeddings: {result.shape}")
            return result
        
        except Exception as e:
            logger.error(f"Failed to get embeddings: {e}")
            raise
    
    @staticmethod
    def count_keyword_occurrences(text: str, keywords: List[str]) -> int:
        """Count occurrences of keywords in text"""
        text_lower = text.lower()
        count = 0
        for keyword in keywords:
            count += text_lower.count(keyword.lower())
        return count
    
    @staticmethod
    def calculate_keyword_scores(body: str, subject: str) -> Dict[str, float]:
        """
        Calculate keyword-based scores
        
        Returns:
            Dictionary with urgency, credential, threat, etc. scores
        """
        from src.constants import (
            URGENCY_KEYWORDS,
            CREDENTIAL_KEYWORDS,
            ACTION_CTA_KEYWORDS,
            THREAT_KEYWORDS,
            LEGITIMACY_KEYWORDS
        )
        
        text_combined = (body + ' ' + subject).lower()
        words = len(text_combined.split())
        
        if words == 0:
            return {
                'urgency_score': 0.0,
                'credential_score': 0.0,
                'action_cta_score': 0.0,
                'threat_score': 0.0,
                'legitimacy_score': 0.0,
            }
        
        # Count keywords
        urgency_count = TextFeatureExtractor.count_keyword_occurrences(text_combined, URGENCY_KEYWORDS)
        credential_count = TextFeatureExtractor.count_keyword_occurrences(text_combined, CREDENTIAL_KEYWORDS)
        action_count = TextFeatureExtractor.count_keyword_occurrences(text_combined, ACTION_CTA_KEYWORDS)
        threat_count = TextFeatureExtractor.count_keyword_occurrences(text_combined, THREAT_KEYWORDS)
        legitimacy_count = TextFeatureExtractor.count_keyword_occurrences(text_combined, LEGITIMACY_KEYWORDS)
        
        # Normalize by word count
        def normalize(count, text_words):
            return min(1.0, count / max(1, text_words / 100))
        
        return {
            'urgency_score': normalize(urgency_count, words),
            'credential_score': normalize(credential_count, words),
            'action_cta_score': normalize(action_count, words),
            'threat_score': normalize(threat_count, words),
            'legitimacy_score': normalize(legitimacy_count, words),
        }
    
    @staticmethod
    def extract_subject_features(subject: str) -> Dict[str, float]:
        """
        Extract subject line features
        
        Returns:
            Dictionary with subject features
        """
        words = len(subject.split())
        
        # Count urgency keywords in subject
        from src.constants import URGENCY_KEYWORDS
        urgency_in_subject = TextFeatureExtractor.count_keyword_occurrences(subject, URGENCY_KEYWORDS)
        
        return {
            'subject_length': words,
            'subject_urgency_score': min(1.0, urgency_in_subject / max(1, words / 10)),
            'subject_has_caps': float(subject.isupper() and len(subject) > 5),  # ALL CAPS
        }


class EmbeddingCache:
    """Cache for text embeddings to avoid recomputation"""
    
    def __init__(self):
        self.cache = {}
    
    def get(self, text_hash: str) -> Optional[np.ndarray]:
        """Get cached embedding"""
        return self.cache.get(text_hash)
    
    def set(self, text_hash: str, embedding: np.ndarray) -> None:
        """Cache embedding"""
        self.cache[text_hash] = embedding
    
    def clear(self) -> None:
        """Clear cache"""
        self.cache.clear()


class FeatureExtractor:
    """Main feature extraction pipeline"""
    
    def __init__(self, use_embeddings: bool = True, embedding_model: str = "answerdotai/ModernBERT-base"):
        """
        Initialize feature extractor
        
        Args:
            use_embeddings: Whether to extract embeddings
            embedding_model: HuggingFace model ID for embeddings
        """
        self.text_extractor = TextFeatureExtractor()
        self.use_embeddings = use_embeddings
        self.embedding_model = embedding_model
        self.embedding_cache = EmbeddingCache()
    
    def fit(self, emails: List) -> None:
        """
        Fit feature extractors on training data
        
        Args:
            emails: List of Email objects
        """
        # Extract body texts
        texts = [email.body for email in emails]
        
        # Fit TF-IDF
        self.text_extractor.fit_tfidf(texts)
        logger.info("Feature extractors fitted")
    
    def extract_features(self, email) -> Dict:
        """
        Extract all features from an email
        
        Args:
            email: Email object
        
        Returns:
            Dictionary with all extracted features
        """
        features = {}
        
        # Text features
        if self.text_extractor.tfidf_vectorizer_fitted:
            tfidf = self.text_extractor.transform_tfidf([email.body])[0]
            features['tfidf'] = tfidf
        
        # Keyword scores
        keyword_scores = TextFeatureExtractor.calculate_keyword_scores(email.body, email.subject)
        features.update(keyword_scores)
        
        # Subject features
        subject_features = TextFeatureExtractor.extract_subject_features(email.subject)
        features.update(subject_features)
        
        # Structural features
        from src.features.structural_features import StructuralFeatureExtractor
        
        body_tokens = email.body.split()  # Simple tokenization
        structural_features = StructuralFeatureExtractor.extract_all_features(email, body_tokens)
        features.update(structural_features)
        
        # Embeddings (optional)
        if self.use_embeddings:
            try:
                embeddings = self.text_extractor.get_text_embeddings([email.body])
                features['embeddings'] = embeddings[0]
            except Exception as e:
                logger.warning(f"Failed to get embeddings: {e}")
                # Create zero embedding as fallback
                features['embeddings'] = np.zeros(768)
        
        return features


if __name__ == "__main__":
    from src.data.loader import load_sample_email
    
    # Test text feature extraction
    sample_email = load_sample_email()
    
    extractor = TextFeatureExtractor()
    
    # Test keyword scores
    keyword_scores = TextFeatureExtractor.calculate_keyword_scores(sample_email.body, sample_email.subject)
    print("Keyword Scores:")
    for key, value in keyword_scores.items():
        print(f"  {key}: {value:.3f}")
    
    # Test subject features
    subject_features = TextFeatureExtractor.extract_subject_features(sample_email.subject)
    print("\nSubject Features:")
    for key, value in subject_features.items():
        print(f"  {key}: {value}")
