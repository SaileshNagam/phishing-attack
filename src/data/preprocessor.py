"""
Text preprocessing module
Handles text cleaning, tokenization, lemmatization, and normalization
"""

import re
import logging
from typing import List, Tuple
from html import unescape

import spacy
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Try to load spacy model
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    logger.warning("spacy model not found. Run: python -m spacy download en_core_web_sm")
    nlp = None


class TextPreprocessor:
    """Text cleaning and preprocessing"""
    
    # Email patterns to remove
    EMAIL_SIGNATURE_PATTERNS = [
        r'--\s*\n.*?(regards|thanks|sincerely|best)',
        r'(Sent from|Sent on).*',
        r'___\n.*?\n___',
    ]
    
    # Common footer patterns
    FOOTER_PATTERNS = [
        r'-----\s*(Original Message|Forwarded Message).*',
        r'\[cid:.*?\]',
        r'(Disclaimer|Copyright|Confidential):.*?(?=\n\n|\Z)',
    ]
    
    @staticmethod
    def remove_html(text: str) -> str:
        """Remove HTML tags from text"""
        soup = BeautifulSoup(text, 'html.parser')
        
        # Get text
        text = soup.get_text()
        
        # Decode HTML entities
        text = unescape(text)
        
        return text
    
    @staticmethod
    def remove_urls(text: str) -> str:
        """Remove URLs from text"""
        url_pattern = r'https?://[^\s\)<>\"]*'
        return re.sub(url_pattern, '', text)
    
    @staticmethod
    def remove_email_addresses(text: str) -> str:
        """Remove email addresses from text"""
        email_pattern = r'\S+@\S+'
        return re.sub(email_pattern, 'EMAIL', text)
    
    @staticmethod
    def remove_phone_numbers(text: str) -> str:
        """Remove phone numbers from text"""
        phone_pattern = r'(\+\d{1,3})?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}'
        return re.sub(phone_pattern, 'PHONE', text)
    
    @staticmethod
    def remove_numbers(text: str) -> str:
        """Remove standalone numbers"""
        return re.sub(r'\b\d+\b', '', text)
    
    @staticmethod
    def remove_special_chars(text: str, keep_basic: bool = True) -> str:
        """Remove special characters"""
        if keep_basic:
            # Keep alphanumeric, spaces, basic punctuation
            text = re.sub(r'[^a-zA-Z0-9\s\.\,\!\?\-]', '', text)
        else:
            text = re.sub(r'[^a-zA-Z0-9\s]', '', text)
        
        return text
    
    @staticmethod
    def remove_email_signature(text: str) -> str:
        """Remove email signature and footers"""
        for pattern in TextPreprocessor.EMAIL_SIGNATURE_PATTERNS:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE | re.DOTALL)
        
        for pattern in TextPreprocessor.FOOTER_PATTERNS:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE | re.DOTALL)
        
        return text
    
    @staticmethod
    def normalize_whitespace(text: str) -> str:
        """Normalize whitespace"""
        # Replace multiple spaces with single space
        text = re.sub(r' +', ' ', text)
        # Replace multiple newlines with single newline
        text = re.sub(r'\n+', '\n', text)
        # Strip leading/trailing whitespace
        text = text.strip()
        return text
    
    @staticmethod
    def normalize_encoding(text: str) -> str:
        """Normalize text encoding"""
        try:
            # Handle UTF-8 encoding issues
            if isinstance(text, bytes):
                text = text.decode('utf-8', errors='ignore')
            
            # Normalize unicode characters
            text = text.encode('utf-8', errors='ignore').decode('utf-8')
        except Exception as e:
            logger.warning(f"Encoding normalization failed: {e}")
        
        return text
    
    @staticmethod
    def lowercase(text: str) -> bool:
        """Convert text to lowercase"""
        return text.lower()
    
    @staticmethod
    def preprocess_text(
        text: str,
        remove_html_tags: bool = True,
        remove_urls_flag: bool = False,  # Keep URLs for structural analysis
        remove_emails: bool = True,
        remove_phones: bool = True,
        remove_numbers_flag: bool = False,
        remove_signature: bool = True,
        normalize_whitespace_flag: bool = True,
        lowercase_flag: bool = True,
    ) -> str:
        """
        Full text preprocessing pipeline
        
        Args:
            text: Input text
            Various flags for preprocessing steps
        
        Returns:
            Preprocessed text
        """
        # Normalize encoding first
        text = TextPreprocessor.normalize_encoding(text)
        
        # Remove HTML
        if remove_html_tags:
            text = TextPreprocessor.remove_html(text)
        
        # Remove signature
        if remove_signature:
            text = TextPreprocessor.remove_email_signature(text)
        
        # Remove URLs (optional)
        if remove_urls_flag:
            text = TextPreprocessor.remove_urls(text)
        
        # Remove emails
        if remove_emails:
            text = TextPreprocessor.remove_email_addresses(text)
        
        # Remove phones
        if remove_phones:
            text = TextPreprocessor.remove_phone_numbers(text)
        
        # Remove numbers
        if remove_numbers_flag:
            text = TextPreprocessor.remove_numbers(text)
        
        # Normalize whitespace
        if normalize_whitespace_flag:
            text = TextPreprocessor.normalize_whitespace(text)
        
        # Lowercase
        if lowercase_flag:
            text = TextPreprocessor.lowercase(text)
        
        return text


class Tokenizer:
    """Tokenization using spaCy"""
    
    @staticmethod
    def tokenize(text: str, remove_stopwords: bool = False) -> List[str]:
        """
        Tokenize text using spaCy
        
        Args:
            text: Input text
            remove_stopwords: Whether to remove stopwords
        
        Returns:
            List of tokens
        """
        if nlp is None:
            logger.warning("spaCy model not loaded. Falling back to simple tokenization.")
            return Tokenizer._simple_tokenize(text, remove_stopwords)
        
        doc = nlp(text)
        
        tokens = []
        for token in doc:
            # Skip punctuation and whitespace
            if token.is_punct or token.is_space:
                continue
            
            # Skip stopwords if requested
            if remove_stopwords and token.is_stop:
                continue
            
            # Skip very short tokens
            if len(token.text) < 2:
                continue
            
            tokens.append(token.text)
        
        return tokens
    
    @staticmethod
    def lemmatize(tokens: List[str]) -> List[str]:
        """
        Lemmatize tokens using spaCy
        
        Args:
            tokens: List of tokens
        
        Returns:
            List of lemmatized tokens
        """
        if nlp is None:
            return tokens  # Fallback if model not loaded
        
        lemmas = []
        for token_text in tokens:
            # Create a doc from the token
            doc = nlp(token_text)
            if len(doc) > 0:
                lemmas.append(doc[0].lemma_)
            else:
                lemmas.append(token_text)
        
        return lemmas
    
    @staticmethod
    def _simple_tokenize(text: str, remove_stopwords: bool = False) -> List[str]:
        """Simple fallback tokenization"""
        # Split on whitespace and punctuation
        tokens = re.findall(r'\b[a-z]+\b', text.lower())
        
        if remove_stopwords:
            from src.constants import STOPWORDS
            tokens = [t for t in tokens if t not in STOPWORDS]
        
        return tokens


class EmailPreprocessor:
    """Full email preprocessing pipeline"""
    
    def __init__(self):
        self.text_preprocessor = TextPreprocessor()
        self.tokenizer = Tokenizer()
    
    def preprocess_email_body(self, body: str) -> Tuple[str, List[str]]:
        """
        Preprocess email body
        
        Returns:
            (cleaned_text, tokens)
        """
        # Clean text
        cleaned_text = self.text_preprocessor.preprocess_text(body)
        
        # Tokenize
        tokens = self.tokenizer.tokenize(cleaned_text, remove_stopwords=True)
        
        # Lemmatize
        lemmas = self.tokenizer.lemmatize(tokens)
        
        return cleaned_text, lemmas
    
    def preprocess_subject(self, subject: str) -> Tuple[str, List[str]]:
        """
        Preprocess email subject
        
        Returns:
            (cleaned_subject, tokens)
        """
        # Light preprocessing for subject (keep more intact)
        cleaned_subject = TextPreprocessor.normalize_encoding(subject)
        cleaned_subject = TextPreprocessor.normalize_whitespace(cleaned_subject)
        cleaned_subject = TextPreprocessor.lowercase(cleaned_subject)
        
        # Tokenize with less filtering
        tokens = self.tokenizer.tokenize(cleaned_subject, remove_stopwords=False)
        
        return cleaned_subject, tokens


if __name__ == "__main__":
    # Test preprocessing
    sample_text = """
    <html>
    <body>
    <h1>Urgent: Verify Your Account</h1>
    <p>Please click <a href="https://malicious.com">here</a> to verify your account.</p>
    <p>Email: support@example.com | Phone: (555) 123-4567</p>
    </body>
    </html>
    
    --
    Sent from my iPhone
    """
    
    # Test text preprocessing
    cleaned = TextPreprocessor.preprocess_text(sample_text)
    print(f"Cleaned text:\n{cleaned}\n")
    
    # Test tokenization
    preprocessor = EmailPreprocessor()
    tokens = Tokenizer.tokenize(cleaned)
    print(f"Tokens: {tokens}\n")
    
    # Test subject preprocessing
    subject = "<html>URGENT: Verify Account!!!</html>"
    cleaned_subject, subject_tokens = preprocessor.preprocess_subject(subject)
    print(f"Cleaned subject: {cleaned_subject}")
    print(f"Subject tokens: {subject_tokens}")
