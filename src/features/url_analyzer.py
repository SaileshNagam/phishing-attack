"""
URL analysis and parsing module
Extracts and analyzes URLs for phishing indicators
"""

import re
import logging
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse, parse_qs, unquote
import ipaddress

from src.constants import SHORTENED_URL_DOMAINS, SUSPICIOUS_TLDS

logger = logging.getLogger(__name__)


class URLAnalyzer:
    """Analyze URLs for phishing indicators"""
    
    @staticmethod
    def is_shortened_url(url: str) -> bool:
        """Check if URL uses a shortened URL service"""
        domain = urlparse(url).netloc.lower()
        base_domain = domain.split(':')[0]  # Remove port if present
        return base_domain in SHORTENED_URL_DOMAINS
    
    @staticmethod
    def has_percent_encoding(url: str) -> bool:
        """Check for percent-encoded characters (%XX)"""
        return '%' in url
    
    @staticmethod
    def has_base64_like_token(url: str) -> bool:
        """Detect base64-like strings in URL"""
        pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        return bool(re.search(pattern, url))
    
    @staticmethod
    def has_punycode(url: str) -> bool:
        """Detect punycode/IDN encoding"""
        return 'xn--' in url.lower()
    
    @staticmethod
    def has_ip_address(url: str) -> bool:
        """Check if URL contains IP address instead of domain"""
        domain = urlparse(url).netloc.split(':')[0]  # Remove port
        
        # Try to parse as IP
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def has_redirect_pattern(url: str) -> bool:
        """Check for redirect patterns (multiple //)"""
        return url.count('://') > 1 or url.count('//') > 2
    
    @staticmethod
    def has_suspicious_tld(url: str) -> bool:
        """Check for suspicious TLDs"""
        domain = urlparse(url).netloc.lower()
        
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return True
        
        return False
    
    @staticmethod
    def get_subdomain_depth(url: str) -> int:
        """Calculate subdomain nesting depth"""
        domain = urlparse(url).netloc.lower()
        
        # Remove port if present
        domain = domain.split(':')[0]
        
        # Count dots to get depth
        depth = domain.count('.')
        
        # Subtract 1 for TLD (e.g., .com)
        return max(0, depth - 1)
    
    @staticmethod
    def get_digit_ratio(url: str) -> float:
        """Calculate ratio of digits in domain"""
        domain = urlparse(url).netloc.lower()
        domain = domain.split(':')[0]  # Remove port
        
        if not domain:
            return 0.0
        
        digit_count = sum(1 for c in domain if c.isdigit())
        return digit_count / len(domain)
    
    @staticmethod
    def get_special_char_ratio(url: str) -> float:
        """Calculate ratio of special characters in URL"""
        if not url:
            return 0.0
        
        # Count special characters (not alphanumeric, /, :, ., -)
        special_chars = sum(1 for c in url if not c.isalnum() and c not in ['/', ':', '.', '-', '_', '?', '=', '&', '#', '@'])
        return special_chars / len(url)
    
    @staticmethod
    def extract_query_parameters(url: str) -> Dict[str, List[str]]:
        """Extract query parameters from URL"""
        try:
            parsed = urlparse(url)
            return parse_qs(parsed.query)
        except Exception as e:
            logger.warning(f"Failed to parse query parameters from {url}: {e}")
            return {}
    
    @staticmethod
    def is_link_mismatch(link_text: str, link_url: str) -> bool:
        """
        Check if visible link text doesn't match actual URL
        Indicates potential phishing
        """
        # Normalize both texts
        link_text_normalized = link_text.lower().strip()
        link_url_normalized = link_url.lower().strip()
        
        # Direct match
        if link_text_normalized == link_url_normalized:
            return False
        
        # Check if URL appears in link text
        if link_url_normalized in link_text_normalized:
            return False
        
        # Check if domain appears in link text
        domain = urlparse(link_url).netloc
        if domain.lower() in link_text_normalized:
            return False
        
        # If link text is a domain-like expression, check
        if '.' in link_text_normalized and len(link_text_normalized) < 50:
            # Might be trying to impersonate a legitimate domain
            return True
        
        return False
    
    @staticmethod
    def analyze_url(url: str) -> Dict:
        """
        Comprehensive URL analysis
        
        Returns:
            Dictionary with all URL features
        """
        return {
            'url': url,
            'is_shortened': URLAnalyzer.is_shortened_url(url),
            'has_percent_encoding': URLAnalyzer.has_percent_encoding(url),
            'has_base64_token': URLAnalyzer.has_base64_like_token(url),
            'has_punycode': URLAnalyzer.has_punycode(url),
            'has_ip_address': URLAnalyzer.has_ip_address(url),
            'has_redirect_pattern': URLAnalyzer.has_redirect_pattern(url),
            'has_suspicious_tld': URLAnalyzer.has_suspicious_tld(url),
            'subdomain_depth': URLAnalyzer.get_subdomain_depth(url),
            'digit_ratio': URLAnalyzer.get_digit_ratio(url),
            'special_char_ratio': URLAnalyzer.get_special_char_ratio(url),
            'length': len(url),
            'query_params': URLAnalyzer.extract_query_parameters(url),
        }


class LinkExtractor:
    """Extract visible links from email body"""
    
    @staticmethod
    def extract_html_links(html_content: str) -> List[Tuple[str, str]]:
        """
        Extract HTML links (href and visible text)
        
        Returns:
            List of (visible_text, url) tuples
        """
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
    def extract_text_links(text: str) -> List[Tuple[str, str]]:
        """
        Extract URLs from plain text
        These are shown as URLs in text
        
        Returns:
            List of (url, url) tuples
        """
        url_pattern = r'https?://[^\s\)<>\"]*'
        urls = re.findall(url_pattern, text)
        
        # Return tuples of (text, url) where text is the URL itself
        return [(url, url) for url in urls]
    
    @staticmethod
    def is_link_mismatch(link_text: str, link_url: str) -> bool:
        """
        Check if visible link text doesn't match actual URL
        Indicates potential phishing
        """
        return URLAnalyzer.is_link_mismatch(link_text, link_url)
    
    @staticmethod
    def _check_link_mismatch(link_text: str, link_url: str) -> bool:
        """Internal method for link mismatch checking"""
        return LinkExtractor.is_link_mismatch(link_text, link_url)


class DomainAnalyzer:
    """Analyze email domain for validation"""
    
    @staticmethod
    def extract_domain(email_address: str) -> str:
        """Extract domain from email address"""
        try:
            # Remove angle brackets if present
            email_address = email_address.strip('<>')
            
            # Get domain part after @
            if '@' in email_address:
                return email_address.split('@')[1].lower()
        except Exception as e:
            logger.warning(f"Failed to extract domain from {email_address}: {e}")
        
        return ""
    
    @staticmethod
    def get_base_domain(domain: str) -> str:
        """
        Get base domain (second-level domain)
        E.g., "mail.google.com" -> "google.com"
        """
        parts = domain.split('.')
        
        # Handle special cases (co.uk, etc.)
        if len(parts) > 2 and parts[-2] in ['co', 'com', 'org', 'gov', 'edu']:
            return '.'.join(parts[-3:])
        elif len(parts) >= 2:
            return '.'.join(parts[-2:])
        
        return domain
    
    @staticmethod
    def is_domain_typo_of(suspicious_domain: str, legitimate_domain: str) -> bool:
        """
        Check if suspicious domain is a typo or impersonation of legitimate domain
        
        Uses Levenshtein distance
        """
        from difflib import SequenceMatcher
        
        suspicious_base = DomainAnalyzer.get_base_domain(suspicious_domain)
        legitimate_base = DomainAnalyzer.get_base_domain(legitimate_domain)
        
        # Direct match
        if suspicious_base == legitimate_base:
            return False
        
        # Calculate similarity
        similarity = SequenceMatcher(None, suspicious_base, legitimate_base).ratio()
        
        # If >80% similar, likely a typo
        return similarity > 0.80
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Check if domain is valid format"""
        # Basic domain validation
        pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
        return bool(re.match(pattern, domain.lower()))


if __name__ == "__main__":
    # Test URL analysis
    test_urls = [
        'https://bit.ly/verify',
        'https://gmail.com',
        'https://gm4il.com',  # Typo of gmail
        'https://192.168.1.1',
        'https://example.com%3Fphishing%3Dtrue',
        'https://example%2Ecom/path',
    ]
    
    for url in test_urls:
        analysis = URLAnalyzer.analyze_url(url)
        print(f"\nURL: {url}")
        print(f"  Shortened: {analysis['is_shortened']}")
        print(f"  Punycode: {analysis['has_punycode']}")
        print(f"  IP Address: {analysis['has_ip_address']}")
        print(f"  Suspicious TLD: {analysis['has_suspicious_tld']}")
        print(f"  Digit Ratio: {analysis['digit_ratio']:.2f}")
