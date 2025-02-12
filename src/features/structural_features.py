"""
Structural feature extraction
Extracts 45+ features from URLs, headers, and metadata
"""

import re
import logging
from typing import Dict, List
from statistics import mean, stdev

from src.data.loader import Email
from src.features.url_analyzer import URLAnalyzer, LinkExtractor, DomainAnalyzer
from src.constants import URGENCY_KEYWORDS, CREDENTIAL_KEYWORDS, THREAT_KEYWORDS

logger = logging.getLogger(__name__)


class StructuralFeatureExtractor:
    """Extract structural features from emails"""
    
    @staticmethod
    def extract_url_features(urls: List[str]) -> Dict:
        """Extract URL-related features (15 features)"""
        features = {
            'url_count': len(urls),
            'max_url_length': 0,
            'avg_url_length': 0.0,
            'min_url_length': 0,
            'url_length_std_dev': 0.0,
            'subdomain_depth': 0,
            'max_domain_digit_ratio': 0.0,
            'max_url_special_ratio': 0.0,
            'has_shortened_url': 0,
            'has_percent_encoding': 0,
            'has_base64_token': 0,
            'has_punycode': 0,
            'has_ip_address': 0,
            'has_redirect_pattern': 0,
            'has_suspicious_tld': 0,
        }
        
        if not urls:
            return features
        
        url_lengths = []
        subdomain_depths = []
        digit_ratios = []
        special_char_ratios = []
        
        for url in urls:
            analysis = URLAnalyzer.analyze_url(url)
            
            url_lengths.append(len(url))
            subdomain_depths.append(analysis['subdomain_depth'])
            digit_ratios.append(analysis['digit_ratio'])
            special_char_ratios.append(analysis['special_char_ratio'])
            
            # Set boolean flags (if any URL has the indicator, set to 1)
            if analysis['is_shortened']:
                features['has_shortened_url'] = 1
            if analysis['has_percent_encoding']:
                features['has_percent_encoding'] = 1
            if analysis['has_base64_token']:
                features['has_base64_token'] = 1
            if analysis['has_punycode']:
                features['has_punycode'] = 1
            if analysis['has_ip_address']:
                features['has_ip_address'] = 1
            if analysis['has_redirect_pattern']:
                features['has_redirect_pattern'] = 1
            if analysis['has_suspicious_tld']:
                features['has_suspicious_tld'] = 1
        
        # Calculate aggregates
        features['max_url_length'] = max(url_lengths)
        features['min_url_length'] = min(url_lengths)
        features['avg_url_length'] = mean(url_lengths)
        
        if len(url_lengths) > 1:
            features['url_length_std_dev'] = stdev(url_lengths)
        
        features['subdomain_depth'] = max(subdomain_depths) if subdomain_depths else 0
        features['max_domain_digit_ratio'] = max(digit_ratios) if digit_ratios else 0.0
        features['max_url_special_ratio'] = max(special_char_ratios) if special_char_ratios else 0.0
        
        return features
    
    @staticmethod
    def extract_domain_features(email: Email) -> Dict:
        """Extract domain-related features (12 features)"""
        features = {
            'domain_age_days': 0,  # TODO: WHOIS API integration
            'domain_reputation': 0.5,  # TODO: External API integration
            'is_mx_record_valid': 0,  # TODO: DNS validation
            'is_spf_valid': 0,  # TODO: SPF record check
            'from_reply_mismatch': 0,
            'from_return_mismatch': 0,
            'sender_domain_mismatch': 0,
            'sender_has_phone': 0,
            'sender_has_website': 0,
            'sender_domain_typo': 0,
            'has_domain_reputation': 0.5,
            'domain_registration_age': 0,
        }
        
        # Extract domains
        from_domain = DomainAnalyzer.extract_domain(email.from_email).lower()
        reply_to_domain = email.headers.get('reply-to', '')
        if reply_to_domain:
            reply_to_domain = DomainAnalyzer.extract_domain(reply_to_domain).lower()
        
        return_path_domain = email.headers.get('return-path', '')
        if return_path_domain:
            return_path_domain = DomainAnalyzer.extract_domain(return_path_domain).lower()
        
        # Domain mismatches
        if from_domain and reply_to_domain and from_domain != reply_to_domain:
            features['from_reply_mismatch'] = 1
        
        if from_domain and return_path_domain and from_domain != return_path_domain:
            features['from_return_mismatch'] = 1
        
        # Sender format checks
        if re.search(r'\+?1?\s?\(?[0-9]{3}\)?[\s.-][0-9]{3}[\s.-][0-9]{4}', email.from_email):
            features['sender_has_phone'] = 1
        
        if re.search(r'https?://', email.from_email):
            features['sender_has_website'] = 1
        
        # Check for domain typos (e.g., gm4il.com vs gmail.com)
        # Simple heuristic: if domain contains numbers and common company names
        known_companies = ['google', 'amazon', 'apple', 'microsoft', 'facebook', 'twitter', 'linkedin']
        for company in known_companies:
            if company in from_domain:
                # Check for letter-number substitution
                obfuscated = from_domain.replace('0', 'o').replace('1', 'i').replace('3', 'e')
                if obfuscated == company + '.com' or obfuscated.startswith(company + '.'):
                    features['sender_domain_typo'] = 1
                    break
        
        return features
    
    @staticmethod
    def extract_header_features(email: Email) -> Dict:
        """Extract header-related features (10 features)"""
        features = {
            'has_spf': 0,
            'has_dkim': 0,
            'has_dmarc': 0,
            'auth_score': 0.0,
            'has_link_mismatch': 0,
            'has_html_form': 0,
            'recipient_count': 0,
            'cc_count': 0,
            'bcc_count_inferred': 0,
            'has_reply_encoding_issue': 0,
        }
        
        # Authentication headers
        raw_headers = str(email.headers)
        if 'received-spf' in raw_headers.lower() or 'spf' in raw_headers.lower():
            features['has_spf'] = 1
        
        if 'dkim-signature' in raw_headers.lower():
            features['has_dkim'] = 1
        
        if 'authentication-results' in raw_headers.lower() or 'dmarc' in raw_headers.lower():
            features['has_dmarc'] = 1
        
        # Authentication score
        auth_count = features['has_spf'] + features['has_dkim'] + features['has_dmarc']
        features['auth_score'] = auth_count / 3.0
        
        # HTML form detection
        if '<form' in email.body.lower():
            features['has_html_form'] = 1
        
        # Link mismatch detection
        links = LinkExtractor.extract_html_links(email.body)
        for visible_text, url in links:
            if LinkExtractor._check_link_mismatch(visible_text, url):
                features['has_link_mismatch'] = 1
                break
        
        # Recipient counts
        to_list = email.to_email.split(',')
        features['recipient_count'] = len([x.strip() for x in to_list if x.strip()])
        
        cc_header = email.headers.get('cc', '')
        cc_list = cc_header.split(',') if cc_header else []
        features['cc_count'] = len([x.strip() for x in cc_list if x.strip()])
        
        return features
    
    @staticmethod
    def extract_content_features(email: Email, body_tokens: List[str] = None) -> Dict:
        """Extract content metadata features (8 features)"""
        features = {
            'text_length': 0,
            'subject_length': 0,
            'sentence_count': 0,
            'avg_word_length': 0.0,
            'uppercase_ratio': 0.0,
            'entropy_score': 0.0,
            'has_risky_attachment': 0,
            'attachment_count': 0,
        }
        
        # Text metrics
        if body_tokens:
            features['text_length'] = len(body_tokens)
        else:
            # Fallback: count words
            features['text_length'] = len(email.body.split())
        
        features['subject_length'] = len(email.subject.split()) if email.subject else 0
        
        # Sentence count
        features['sentence_count'] = email.body.count('.') + email.body.count('!') + email.body.count('?')
        
        # Average word length
        words = email.body.split()
        if words:
            features['avg_word_length'] = mean(len(w) for w in words)
        
        # Uppercase ratio
        if email.body:
            uppercase_count = sum(1 for c in email.body if c.isupper())
            features['uppercase_ratio'] = uppercase_count / len(email.body)
        
        # Entropy score
        features['entropy_score'] = StructuralFeatureExtractor._calculate_entropy(email.body)
        
        # Attachment features
        features['attachment_count'] = len(email.attachments)
        
        risky_extensions = ['.exe', '.bat', '.scr', '.vbs', '.js', '.zip', '.rar']
        for att in email.attachments:
            filename = att.get('filename', '').lower()
            if any(filename.endswith(ext) for ext in risky_extensions):
                features['has_risky_attachment'] = 1
                break
        
        return features
    
    @staticmethod
    def extract_urgency_features(body: str, subject: str) -> Dict:
        """Extract urgency and intent features"""
        features = {
            'urgency_score': 0.0,
            'credential_score': 0.0,
            'action_cta_score': 0.0,
            'threat_score': 0.0,
            'legitimacy_score': 0.0,
        }
        
        # Convert to lowercase for matching
        body_lower = body.lower()
        subject_lower = subject.lower()
        text_combined = body_lower + ' ' + subject_lower
        
        # Count keywords
        urgency_count = sum(text_combined.count(kw.lower()) for kw in URGENCY_KEYWORDS)
        credential_count = sum(text_combined.count(kw.lower()) for kw in CREDENTIAL_KEYWORDS)
        threat_count = sum(text_combined.count(kw.lower()) for kw in THREAT_KEYWORDS)
        
        # Normalize by text length
        total_words = len(text_combined.split())
        if total_words > 0:
            features['urgency_score'] = min(1.0, urgency_count / max(1, total_words / 100))
            features['credential_score'] = min(1.0, credential_count / max(1, total_words / 100))
            features['action_cta_score'] = min(1.0, sum(1 for kw in ['click', 'verify'] 
                                                        if kw in body_lower) / max(1, total_words / 100))
            features['threat_score'] = min(1.0, threat_count / max(1, total_words / 100))
        
        # Legitimacy (inverse signal)
        legitimacy_keywords = ['regards', 'sincerely', 'thank you', 'professional', 'official']
        legitimacy_count = sum(text_combined.count(kw.lower()) for kw in legitimacy_keywords)
        features['legitimacy_score'] = min(1.0, legitimacy_count / max(1, total_words / 100))
        
        return features
    
    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of text"""
        import math
        
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_length = len(text)
        for count in char_counts.values():
            probability = count / text_length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def extract_all_features(email: Email, body_tokens: List[str] = None) -> Dict:
        """
        Extract all structural features
        
        Returns:
            Dictionary with 45+ structural features
        """
        features = {}
        
        # Extract features from each category
        url_features = StructuralFeatureExtractor.extract_url_features(email.urls)
        domain_features = StructuralFeatureExtractor.extract_domain_features(email)
        header_features = StructuralFeatureExtractor.extract_header_features(email)
        content_features = StructuralFeatureExtractor.extract_content_features(email, body_tokens)
        urgency_features = StructuralFeatureExtractor.extract_urgency_features(email.body, email.subject)
        
        # Merge all features
        features.update(url_features)
        features.update(domain_features)
        features.update(header_features)
        features.update(content_features)
        features.update(urgency_features)
        
        # Calculated features
        features['body_subject_ratio'] = (
            features.get('text_length', 1) / max(1, features.get('subject_length', 1))
        )
        features['url_text_ratio'] = (
            features.get('url_count', 0) / max(1, features.get('text_length', 1))
        )
        
        return features


class LinkExtractor:
    """Helper class for link extraction"""
    
    @staticmethod
    def extract_html_links(html_content: str):
        """Extract HTML links from content"""
        from bs4 import BeautifulSoup
        
        soup = BeautifulSoup(html_content, 'html.parser')
        links = []
        
        for link in soup.find_all('a'):
            href = link.get('href', '')
            text = link.get_text().strip()
            if href:
                links.append((text, href))
        
        return links
    
    @staticmethod
    def _check_link_mismatch(visible_text: str, url: str) -> bool:
        """Check if visible text doesn't match actual URL"""
        visible_lower = visible_text.lower().strip()
        url_lower = url.lower().strip()
        
        # Direct match or URL appears in text = no mismatch
        if visible_lower == url_lower or url_lower in visible_lower:
            return False
        
        # If text looks like it's trying to impersonate something = mismatch
        if '.' in visible_lower and len(visible_lower) < 50 and len(visible_lower) > 5:
            return True
        
        return False


if __name__ == "__main__":
    from src.data.loader import load_sample_email
    
    # Test feature extraction
    sample_email = load_sample_email()
    features = StructuralFeatureExtractor.extract_all_features(sample_email)
    
    print("Extracted Features:")
    for key, value in sorted(features.items()):
        print(f"  {key}: {value}")
    
    print(f"\nTotal features extracted: {len(features)}")
