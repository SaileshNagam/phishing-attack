import re
import socket
from urllib.parse import urlparse
import signal
from contextlib import contextmanager

# Common URL shorteners
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", 
    "buff.ly", "rebrand.ly", "lnkd.in"
}

# Suspicious TLDs Often Used in Phishing
SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".link", ".win", ".bid"}

# DNS timeout (seconds) - fail fast if domain doesn't respond
DNS_TIMEOUT = 1.0

def resolve_domain_fast(domain: str, timeout: float = DNS_TIMEOUT) -> bool:
    """
    Fast DNS resolution with timeout.
    Returns True if domain resolves, False on timeout or error.
    Does NOT block analysis - DNS is optional for feature extraction.
    """
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(domain)
        socket.setdefaulttimeout(None)
        return True
    except (socket.timeout, socket.gaierror, socket.error, OSError):
        socket.setdefaulttimeout(None)
        return False
    except Exception:
        socket.setdefaulttimeout(None)
        return False

def extract_structural_features(subject: str, body: str, sender: str, reply_to: str, urls: list) -> dict:
    """
    Extracts structural anomalies and heuristics for XGBoost structural branch.
    Returns a dictionary of numerical/boolean features.
    """
    features = {
        "url_count": len(urls),
        "shortened_url_detected": 0,
        "suspicious_tld_detected": 0,
        "encoded_url_detected": 0,
        "domain_mismatch": 0,
        "urgency_score": 0.0,
        "html_form_presence": 0,
        "sensitive_keyword_count": 0,
        "unresolved_url_domain": 0,
        "unresolved_sender_domain": 0
    }
    
    # ── Active Sender Domain Verification (with timeout) ──
    if sender and "@" in sender:
        sender_domain = sender.split("@")[-1].strip(">").strip()
        # Use fast DNS with 1-second timeout (won't block analysis)
        if not resolve_domain_fast(sender_domain):
            features["unresolved_sender_domain"] = 1
    
    # URL Analysis & Active Verification
    for url in urls:
        try:
            domain = urlparse(url).netloc.lower()
            if not domain: continue
            
            # Active Check (with timeout - won't block analysis)
            if not resolve_domain_fast(domain):
                features["unresolved_url_domain"] = 1
                
            if domain in SHORTENERS:
                features["shortened_url_detected"] = 1
            
            if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
                features["suspicious_tld_detected"] = 1
                
            # Check for simple hex/base64 characteristics or IPs disguised
            if re.search(r'(%[0-9A-Fa-f]{2})+', url) or re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                features["encoded_url_detected"] = 1
        except Exception:
            pass

    # Metadata Constraints (Sender vs Reply-To)
    if reply_to and sender and reply_to.lower() != sender.lower():
        features["domain_mismatch"] = 1
        
    # Heuristics on text
    text = (subject + " " + body).lower()
    
    urgency_words = ["urgent", "immediate", "action required", "suspend", "verify now", "alert"]
    features["urgency_score"] = sum(text.count(w) for w in urgency_words) * 2.0
    
    sensitive_words = ["password", "login", "bank", "account", "ssn", "credit card", "billing"]
    features["sensitive_keyword_count"] = sum(text.count(w) for w in sensitive_words)
    
    if "<form" in text or "method=\"post\"" in text:
        features["html_form_presence"] = 1

    return features
