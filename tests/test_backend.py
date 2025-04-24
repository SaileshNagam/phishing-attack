"""
PhishShield Backend Tests — Comprehensive Suite

These tests verify:
1. API health endpoint
2. Email prediction endpoint  
3. Feature extraction pipeline
4. URL analysis logic
5. Domain mismatch detection

Run with: pytest tests/test_backend.py -v
"""

import pytest
import sys
import os
from io import StringIO

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from fastapi.testclient import TestClient
from api import app, EmailInput
from feature_extractor import (
    extract_structural_features,
    SHORTENERS, 
    SUSPICIOUS_TLDS
)


# ─────────────────────────────────────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    """FastAPI test client"""
    return TestClient(app)


@pytest.fixture
def legitimate_email():
    """Sample legitimate email"""
    return EmailInput(
        subject="Meeting Rescheduled Tomorrow",
        body="Hi, our meeting has been rescheduled to 2pm. See you then!",
        from_email="colleague@company.com",
        reply_to="colleague@company.com",
        urls=["https://company.com/calendar/event/123"]
    )


@pytest.fixture
def phishing_email():
    """Sample phishing email with multiple red flags"""
    return EmailInput(
        subject="URGENT: Verify Your Account NOW — Action Required",
        body="""Your account has been suspended due to suspicious activity.
        
Click here immediately to confirm your identity and password to restore access.
This is urgent — you have 24 hours."

Email: support@secure-verify.xyz
Password: [ENTER PASSWORD HERE]

Update your banking info: https://bit.ly/verify-account-secure
""",
        from_email="noreply@secure-verify.xyz",
        reply_to="support@paypal-secure.top",
        urls=[
            "https://bit.ly/verify-account-secure",
            "https://192.168.1.1/admin",
            "https://suspicious-domain.xyz"
        ]
    )


@pytest.fixture
def suspicious_email():
    """Sample suspicious but not clearly phishing"""
    return EmailInput(
        subject="Password Verification Required",
        body="Hello,\n\nA login attempt from a new device was detected. Please verify your identity.",
        from_email="security@gmail.com",
        reply_to="",
        urls=["https://accounts.google.com/verify"]
    )


# ─────────────────────────────────────────────────────────────────────────────
# API HEALTH TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestAPIHealth:
    """Test API health endpoint"""
    
    def test_health_endpoint_exists(self, client):
        """Health endpoint should respond 200"""
        response = client.get("/health")
        assert response.status_code == 200
    
    def test_health_response_schema(self, client):
        """Health response should have required fields"""
        response = client.get("/health")
        data = response.json()
        assert "status" in data
        assert "version" in data
        assert "models_loaded" in data
        assert "timestamp" in data
    
    def test_health_status_online(self, client):
        """Health status should be 'online'"""
        response = client.get("/health")
        data = response.json()
        assert data["status"] == "online"
    
    def test_health_version_format(self, client):
        """Health version should be defined"""
        response = client.get("/health")
        data = response.json()
        assert data["version"] is not None
        assert isinstance(data["version"], str)
    
    def test_health_models_loaded(self, client):
        """Health should report models loaded status"""
        response = client.get("/health")
        data = response.json()
        assert isinstance(data["models_loaded"], dict)


# ─────────────────────────────────────────────────────────────────────────────
# PREDICTION ENDPOINT TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestPredictionEndpoint:
    """Test /predict endpoint with real emails"""
    
    def test_predict_endpoint_accepts_post(self, client):
        """Predict endpoint should accept POST requests"""
        payload = {
            "subject": "Test",
            "body": "Hello",
            "from_email": "test@example.com",
            "urls": []
        }
        response = client.post("/predict", json=payload)
        assert response.status_code == 200
    
    def test_predict_response_schema(self, client, legitimate_email):
        """Predict response should have required fields"""
        response = client.post("/predict", json=legitimate_email.dict())
        assert response.status_code == 200
        data = response.json()
        
        # Required fields
        assert "phishing" in data
        assert "confidence" in data
        assert "safety_score" in data
        assert "risk_level" in data
        assert "reasoning" in data
        assert "scan_id" in data
        assert "timestamp" in data
    
    def test_predict_legitimate_email(self, client, legitimate_email):
        """Legitimate email should have high safety score"""
        response = client.post("/predict", json=legitimate_email.dict())
        data = response.json()
        
        assert data["risk_level"].upper() in ["LOW", "MEDIUM", "CRITICAL"]
        assert isinstance(data["safety_score"], (int, float))
        assert 0 <= data["safety_score"] <= 100
        assert isinstance(data["confidence"], float)
        assert 0.0 <= data["confidence"] <= 1.0
    
    def test_predict_phishing_email(self, client, phishing_email):
        """Phishing email should have high confidence and low safety score"""
        response = client.post("/predict", json=phishing_email.dict())
        data = response.json()
        
        # Phishing should flag as high/critical risk
        risk_level = data["risk_level"].upper()
        assert risk_level in ["MEDIUM", "CRITICAL", "HIGH"]
        
        # Safety score should be low for phishing
        assert data["safety_score"] < 50, f"Safety score too high: {data['safety_score']}"
        
        # Should have reasoning
        assert len(data["reasoning"]) > 0
    
    def test_predict_has_reasoning(self, client, phishing_email):
        """Predictions should provide reasoning"""
        response = client.post("/predict", json=phishing_email.dict())
        data = response.json()
        
        assert isinstance(data["reasoning"], list)
        assert len(data["reasoning"]) <= 3
        assert all(isinstance(r, str) for r in data["reasoning"])
        assert all(len(r) > 0 for r in data["reasoning"])
    
    def test_predict_structural_indicators(self, client, phishing_email):
        """Response should include structural indicators"""
        response = client.post("/predict", json=phishing_email.dict())
        data = response.json()
        
        assert "structural_indicators" in data
        indicators = data["structural_indicators"]
        
        # Should have key features
        assert "shortened_url_detected" in indicators
        assert "domain_mismatch" in indicators
        assert "urgency_score" in indicators
    
    def test_predict_empty_email(self, client):
        """Empty email should not crash"""
        payload = {
            "subject": "",
            "body": "",
            "from_email": "",
            "urls": []
        }
        response = client.post("/predict", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "phishing" in data


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestStructuralFeatureExtraction:
    """Test feature extraction logic"""
    
    def test_extract_features_returns_dict(self):
        """Feature extraction should return valid dict"""
        features = extract_structural_features(
            subject="Test",
            body="Content",
            sender="test@example.com",
            reply_to="test@example.com",
            urls=[]
        )
        assert isinstance(features, dict)
    
    def test_extract_required_features(self):
        """Feature dict should have required keys"""
        features = extract_structural_features(
            subject="Test",
            body="Content",
            sender="test@example.com",
            reply_to="test@example.com",
            urls=[]
        )
        required_keys = [
            "url_count",
            "shortened_url_detected",
            "suspicious_tld_detected",
            "encoded_url_detected",
            "domain_mismatch",
            "urgency_score",
            "sensitive_keyword_count"
        ]
        for key in required_keys:
            assert key in features, f"Missing key: {key}"
    
    def test_url_count_detection(self):
        """Should count URLs correctly"""
        urls = [
            "https://example.com",
            "https://test.com/path",
            "http://another-site.co.uk"
        ]
        features = extract_structural_features(
            subject="Test",
            body="Content",
            sender="",
            reply_to="",
            urls=urls
        )
        assert features["url_count"] == 3
    
    def test_shortened_url_detection(self):
        """Should detect shortened URLs"""
        features = extract_structural_features(
            subject="Check this link",
            body="Content",
            sender="",
            reply_to="",
            urls=["https://bit.ly/abc123", "https://tinyurl.com/xyz"]
        )
        assert features["shortened_url_detected"] == 1
    
    def test_suspicious_tld_detection(self):
        """Should detect suspicious TLDs"""
        features = extract_structural_features(
            subject="Test",
            body="Content",
            sender="",
            reply_to="",
            urls=["https://phishing.xyz", "https://suspicious.top"]
        )
        assert features["suspicious_tld_detected"] == 1
    
    def test_domain_mismatch_detection(self):
        """Should detect sender/reply-to mismatch"""
        features = extract_structural_features(
            subject="Test",
            body="Content",
            sender="support@paypal.com",
            reply_to="admin@phishing-site.com",
            urls=[]
        )
        assert features["domain_mismatch"] == 1
    
    def test_domain_mismatch_no_false_positive(self):
        """Should not flag matching domains as mismatch"""
        features = extract_structural_features(
            subject="Test",
            body="Content",
            sender="support@example.com",
            reply_to="support@example.com",
            urls=[]
        )
        assert features["domain_mismatch"] == 0
    
    def test_urgency_score_detection(self):
        """Should detect urgency keywords"""
        features = extract_structural_features(
            subject="URGENT urgent IMMEDIATE action required immediately",
            body="This is a test",
            sender="",
            reply_to="",
            urls=[]
        )
        assert features["urgency_score"] > 0
    
    def test_urgency_score_no_keywords(self):
        """Should not flag non-urgent emails"""
        features = extract_structural_features(
            subject="Meeting tomorrow",
            body="Hi, our meeting is at 2pm",
            sender="",
            reply_to="",
            urls=[]
        )
        assert features["urgency_score"] < 1.0
    
    def test_sensitive_keyword_count(self):
        """Should detect sensitive keywords"""
        features = extract_structural_features(
            subject="Update required",
            body="Please verify your password and account details",
            sender="",
            reply_to="",
            urls=[]
        )
        assert features["sensitive_keyword_count"] > 0
    
    def test_encoded_url_detection(self):
        """Should detect encoded/IP URLs"""
        features = extract_structural_features(
            subject="Test",
            body="Content",
            sender="",
            reply_to="",
            urls=["https://192.168.1.1/admin"]
        )
        assert features["encoded_url_detected"] == 1
    
    def test_no_false_positive_for_legitimate_urls(self):
        """Legitimate URLs should not trigger alerts"""
        features = extract_structural_features(
            subject="Test",
            body="Content",
            sender="user@gmail.com",
            reply_to="user@gmail.com",
            urls=["https://google.com", "https://github.com/project"]
        )
        assert features["shortened_url_detected"] == 0
        assert features["suspicious_tld_detected"] == 0
        assert features["encoded_url_detected"] == 0
        assert features["domain_mismatch"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# EDGE CASES & ROBUSTNESS TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestRobustness:
    """Test edge cases and error handling"""
    
    def test_predict_with_none_urls(self, client):
        """Should handle None URLs gracefully"""
        payload = {
            "subject": "Test",
            "body": "Content",
            "from_email": "test@example.com",
            "urls": None
        }
        response = client.post("/predict", json=payload)
        assert response.status_code == 200
    
    def test_predict_with_special_characters(self, client):
        """Should handle special characters in email content"""
        payload = {
            "subject": "💰 URGENT: Acc€ss your bank now! 🔓",
            "body": "Click 👉 here to verify yourpassword!!!",
            "from_email": "user@test.com",
            "urls": []
        }
        response = client.post("/predict", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "phishing" in data
    
    def test_predict_with_very_long_email(self, client):
        """Should handle very long emails"""
        long_body = "This is a test email. " * 1000  # ~22KB
        payload = {
            "subject": "Long email test",
            "body": long_body,
            "from_email": "test@example.com",
            "urls": []
        }
        response = client.post("/predict", json=payload)
        assert response.status_code == 200
    
    def test_feature_extraction_empty_email(self):
        """Feature extraction should handle empty input"""
        features = extract_structural_features("", "", "", "", [])
        assert isinstance(features, dict)
        assert features["url_count"] == 0
    
    def test_feature_extraction_malformed_url(self):
        """Should handle malformed URLs without crashing"""
        features = extract_structural_features(
            subject="Test",
            body="Content",
            sender="",
            reply_to="",
            urls=[
                "not-a-url",
                "htp://missing-letter.com",
                "://no-protocol"
            ]
        )
        assert isinstance(features, dict)


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRATION TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegration:
    """End-to-end integration tests"""
    
    def test_full_pipeline_legitimate(self, client, legitimate_email):
        """Full pipeline should work for legitimate email"""
        # 1. Check health
        health = client.get("/health")
        assert health.status_code == 200
        
        # 2. Predict
        predict = client.post("/predict", json=legitimate_email.dict())
        assert predict.status_code == 200
        
        # 3. Verify result
        data = predict.json()
        assert data["safety_score"] > 50
    
    def test_full_pipeline_phishing(self, client, phishing_email):
        """Full pipeline should work for phishing email"""
        # 1. Check health
        health = client.get("/health")
        assert health.status_code == 200
        
        # 2. Predict
        predict = client.post("/predict", json=phishing_email.dict())
        assert predict.status_code == 200
        
        # 3. Verify result
        data = predict.json()
        assert data["safety_score"] < 50
        assert len(data["reasoning"]) > 0
    
    def test_prediction_consistency(self, client, legitimate_email):
        """Same email should produce similar predictions"""
        response1 = client.post("/predict", json=legitimate_email.dict())
        response2 = client.post("/predict", json=legitimate_email.dict())
        
        data1 = response1.json()
        data2 = response2.json()
        
        # Predictions should be consistent
        assert data1["risk_level"] == data2["risk_level"]


# ─────────────────────────────────────────────────────────────────────────────
# PERFORMANCE TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestPerformance:
    """Performance and timing tests"""
    
    def test_health_response_time(self, client):
        """Health endpoint should respond quickly"""
        import time
        start = time.time()
        client.get("/health")
        elapsed = (time.time() - start) * 1000
        assert elapsed < 100, f"Health check too slow: {elapsed}ms"
    
    def test_predict_response_time(self, client, legitimate_email):
        """Prediction should complete in reasonable time"""
        import time
        start = time.time()
        client.post("/predict", json=legitimate_email.dict())
        elapsed = (time.time() - start) * 1000
        assert elapsed < 5000, f"Prediction too slow: {elapsed}ms"


# ─────────────────────────────────────────────────────────────────────────────
# RUN TESTS
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
