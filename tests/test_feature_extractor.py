"""
PhishShield Feature Extraction Unit Tests

Tests for the feature_extractor.py module:
- URL analysis
- Domain mismatch detection  
- Keyword analysis
- Encoding detection

Run with: pytest tests/test_feature_extractor.py -v
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from feature_extractor import (
    extract_structural_features,
    SHORTENERS,
    SUSPICIOUS_TLDS
)


# ─────────────────────────────────────────────────────────────────────────────
# URL ANALYSIS TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestURLAnalysis:
    """Tests for URL detection and classification"""
    
    def test_shortener_database_populated(self):
        """Shortener list should contain known services"""
        assert "bit.ly" in SHORTENERS
        assert "tinyurl.com" in SHORTENERS
        assert "t.co" in SHORTENERS
        assert len(SHORTENERS) > 5
    
    def test_suspicious_tld_database_populated(self):
        """Suspicious TLD list should contain risky extensions"""
        assert ".xyz" in SUSPICIOUS_TLDS
        assert ".top" in SUSPICIOUS_TLDS
        assert ".club" in SUSPICIOUS_TLDS
        assert len(SUSPICIOUS_TLDS) > 3
    
    def test_detect_single_shortener(self):
        """Should detect URL shortener"""
        features = extract_structural_features(
            subject="Check this",
            body="",
            sender="",
            reply_to="",
            urls=["https://bit.ly/phishing"]
        )
        assert features["shortened_url_detected"] == 1
    
    def test_detect_multiple_shorteners(self):
        """Should detect multiple shorteners in same email"""
        features = extract_structural_features(
            subject="",
            body="",
            sender="",
            reply_to="",
            urls=[
                "https://bit.ly/link1",
                "https://tinyurl.com/link2",
                "https://ow.ly/link3"
            ]
        )
        assert features["shortened_url_detected"] == 1  # Flag set to 1 if any detected
    
    def test_no_shortener_for_legitimate_url(self):
        """Legitimate URLs should not be flagged"""
        features = extract_structural_features(
            subject="",
            body="",
            sender="",
            reply_to="",
            urls=["https://google.com/search"]
        )
        assert features["shortened_url_detected"] == 0
    
    def test_detect_suspicious_tld(self):
        """Should detect suspicious TLDs"""
        features = extract_structural_features(
            subject="",
            body="",
            sender="",
            reply_to="",
            urls=["https://phishing.xyz"]
        )
        assert features["suspicious_tld_detected"] == 1
    
    def test_detect_ip_address_url(self):
        """Should detect IP-based URLs"""
        features = extract_structural_features(
            subject="",
            body="",
            sender="",
            reply_to="",
            urls=["https://192.168.1.1/admin"]
        )
        assert features["encoded_url_detected"] == 1
    
    def test_detect_percent_encoded_url(self):
        """Should detect percent-encoded characters in URL"""
        features = extract_structural_features(
            subject="",
            body="",
            sender="",
            reply_to="",
            urls=["https://example.com/path%2Fadmin%3Fpass%3D123"]
        )
        assert features["encoded_url_detected"] == 1
    
    def test_url_count_accuracy(self):
        """URL count should be exact"""
        urls = [
            "https://example1.com",
            "https://example2.com",
            "https://example3.com",
            "https://example4.com",
            "https://example5.com"
        ]
        features = extract_structural_features(
            subject="", body="", sender="", reply_to="", urls=urls
        )
        assert features["url_count"] == 5


# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN MISMATCH TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestDomainMismatch:
    """Tests for sender/reply-to mismatch detection"""
    
    def test_exact_match_no_mismatch(self):
        """Same sender and reply-to should not be flagged"""
        features = extract_structural_features(
            subject="", body="",
            sender="user@company.com",
            reply_to="user@company.com",
            urls=[]
        )
        assert features["domain_mismatch"] == 0
    
    def test_different_domains_mismatch(self):
        """Different sender and reply-to should be flagged"""
        features = extract_structural_features(
            subject="", body="",
            sender="support@paypal.com",
            reply_to="phishing@attacker.com",
            urls=[]
        )
        assert features["domain_mismatch"] == 1
    
    def test_mismatch_case_insensitive(self):
        """Domain mismatch check should be case-insensitive"""
        features = extract_structural_features(
            subject="", body="",
            sender="User@Company.COM",
            reply_to="user@company.com",
            urls=[]
        )
        assert features["domain_mismatch"] == 0
    
    def test_empty_reply_to_no_mismatch(self):
        """Empty reply-to should not cause mismatch"""
        features = extract_structural_features(
            subject="", body="",
            sender="user@company.com",
            reply_to="",
            urls=[]
        )
        assert features["domain_mismatch"] == 0
    
    def test_similar_but_different_domains(self):
        """Similar but different domains should be flagged"""
        features = extract_structural_features(
            subject="", body="",
            sender="noreply@amazon.com",
            reply_to="support@amaz0n.com",  # 0 instead of O
            urls=[]
        )
        assert features["domain_mismatch"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# KEYWORD ANALYSIS TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestKeywordAnalysis:
    """Tests for urgency and sensitive keyword detection"""
    
    def test_urgency_keywords_detected(self):
        """Should detect urgency keywords"""
        features = extract_structural_features(
            subject="URGENT: Action Required Immediately!",
            body="This requires immediate attention and urgent action.",
            sender="", reply_to="", urls=[]
        )
        assert features["urgency_score"] > 0
    
    def test_no_urgency_normal_email(self):
        """Normal email should have low urgency"""
        features = extract_structural_features(
            subject="Meeting tomorrow at 2pm",
            body="Hi, just wanted to confirm our meeting.",
            sender="", reply_to="", urls=[]
        )
        assert features["urgency_score"] < 2.0
    
    def test_sensitive_keywords_detected(self):
        """Should detect sensitive keywords"""
        features = extract_structural_features(
            subject="",
            body="Please verify your password and account. Enter your credit card information.",
            sender="", reply_to="", urls=[]
        )
        assert features["sensitive_keyword_count"] > 0
    
    def test_no_sensitive_keywords_normal_email(self):
        """Normal email should not trigger sensitive keywords"""
        features = extract_structural_features(
            subject="",
            body="Hi there, hope you're doing well. Let me know if you need anything.",
            sender="", reply_to="", urls=[]
        )
        assert features["sensitive_keyword_count"] == 0
    
    def test_multiple_urgency_keywords(self):
        """Multiple urgency keywords should increase score"""
        features = extract_structural_features(
            subject="Urgent: Immediate action required",
            body="Alert: suspend verification NOW",
            sender="", reply_to="", urls=[]
        )
        assert features["urgency_score"] >= 2.0
    
    def test_html_form_detection(self):
        """Should detect HTML form tags in body"""
        features = extract_structural_features(
            subject="",
            body="<form action=submit method=POST><input type=password></form>",
            sender="", reply_to="", urls=[]
        )
        assert features["html_form_presence"] == 1
    
    def test_no_html_form_plain_text(self):
        """Plain text should not be flagged as form"""
        features = extract_structural_features(
            subject="",
            body="This is plain text without any forms.",
            sender="", reply_to="", urls=[]
        )
        assert features["html_form_presence"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# REAL-WORLD EXAMPLE TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestRealWorldExamples:
    """Test with realistic phishing and legitimate emails"""
    
    def test_real_phishing_example_1(self):
        """Classic PayPal phishing attempt"""
        features = extract_structural_features(
            subject="Your PayPal account needs immediate verification",
            body="""Click here now to verify your identity and update your payment method.
            Verify Account: https://bit.ly/paypal-verify
            Your account will be suspended in 24 hours if not verified.""",
            sender="noreply@paypal-secure.xyz",
            reply_to="support@paypal-verify.top",
            urls=["https://bit.ly/paypal-verify"]
        )
        
        # Should flag multiple indicators
        assert features["shortened_url_detected"] == 1
        assert features["suspicious_tld_detected"] >= 1
        assert features["domain_mismatch"] == 1
        assert features["urgency_score"] > 0
    
    def test_real_phishing_example_2(self):
        """Amazon credential harvest"""
        features = extract_structural_features(
            subject="Urgent: Update your Amazon payment information",
            body="""Your Amazon account has suspicious activity.
            Confirm password: ______
            Credit card: ______
            https://192.168.1.100/amazon/verify""",
            sender="security@amazon-alerts.club",
            reply_to="noreply@amazon-alerts.link",
            urls=["https://192.168.1.100/amazon/verify"]
        )
        
        assert features["encoded_url_detected"] == 1
        assert features["suspicious_tld_detected"] >= 1
        assert features["sensitive_keyword_count"] > 0
        assert features["urgency_score"] > 0
    
    def test_legitimate_company_email(self):
        """Legitimate company communication"""
        features = extract_structural_features(
            subject="Meeting Reminder: Q1 Planning Session",
            body="""Hi team,

Just a reminder that our Q1 planning session is tomorrow at 2 PM.
See you then!

Reference: https://calendar.company.com/event/12345""",
            sender="manager@company.com",
            reply_to="manager@company.com",
            urls=["https://calendar.company.com/event/12345"]
        )
        
        assert features["domain_mismatch"] == 0
        assert features["shortened_url_detected"] == 0
        assert features["sensitive_keyword_count"] == 0
        assert features["urgency_score"] < 2.0
    
    def test_legitimate_shopping_confirmation(self):
        """Legitimate e-commerce transaction"""
        features = extract_structural_features(
            subject="Order Confirmation #12345",
            body="""Thank you for your order!
            Order ID: 12345
            Total: $99.99
            Track your order: https://amazon.com/orders/12345""",
            sender="orders@amazon.com",
            reply_to="orders@amazon.com",
            urls=["https://amazon.com/orders/12345"]
        )
        
        assert features["domain_mismatch"] == 0
        assert features["shortened_url_detected"] == 0
        assert features["suspicious_tld_detected"] == 0
        assert features["urgency_score"] < 2.0


# ─────────────────────────────────────────────────────────────────────────────
# EDGE CASES
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases:
    """Test edge cases and boundary conditions"""
    
    def test_empty_all_fields(self):
        """Should handle completely empty input"""
        features = extract_structural_features("", "", "", "", [])
        assert features["url_count"] == 0
        assert features["urgency_score"] == 0
        assert features["domain_mismatch"] == 0
    
    def test_very_long_subject_and_body(self):
        """Should handle very large emails"""
        long_subject = "A" * 5000
        long_body = "B" * 50000
        features = extract_structural_features(
            long_subject, long_body, "", "", []
        )
        assert isinstance(features, dict)
    
    def test_special_characters_and_unicode(self):
        """Should handle special characters and emoji"""
        features = extract_structural_features(
            subject="💰 ¡Urgente! Pay €euro£ ₹rupees₽ 🚨",
            body="你好 مرحبا שלום Привет",
            sender="test@example.com",
            reply_to="test@example.com",
            urls=[]
        )
        assert isinstance(features, dict)
    
    def test_malformed_urls_dont_crash(self):
        """Malformed URLs should not crash feature extraction"""
        features = extract_structural_features(
            "", "", "", "",
            urls=[
                "ht!tp://invalid",
                "ftp://legacy.proto",
                "not-a-url-at-all",
                "",
                None  # This might cause issues
            ]
        )
        assert isinstance(features, dict)
    
    def test_repeated_keywords(self):
        """Repeated keywords should increase scores"""
        features = extract_structural_features(
            subject="urgent urgent urgent immediate immediate",
            body="",
            sender="", reply_to="", urls=[]
        )
        # Urgency should be high with multiple instances
        assert features["urgency_score"] > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
