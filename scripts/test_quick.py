#!/usr/bin/env python
"""
Quick test script for PhishShield inference
Tests that all components work together
"""

import sys
import logging
from pathlib import Path

# Setup path
sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_imports():
    """Test that all modules can be imported"""
    print("[1/5] Testing imports...")
    try:
        from src.data.loader import Email, EmailDataLoader, EmailParser
        from src.data.preprocessor import EmailPreprocessor
        from src.features.url_analyzer import URLAnalyzer, LinkExtractor, DomainAnalyzer
        from src.features.structural_features import StructuralFeatureExtractor
        from src.features.text_features import TextFeatureExtractor
        from src.inference.pipeline import PhishShieldPredictor
        print("    ✓ All imports successful")
        return True
    except Exception as e:
        print(f"    ✗ Import failed: {e}")
        return False


def test_email_creation():
    """Test email object creation"""
    print("[2/5] Testing email object creation...")
    try:
        from src.data.loader import Email
        
        email = Email(
            id="test_1",
            headers={},
            subject="Test Subject",
            from_email="sender@example.com",
            to_email="recipient@example.com",
            body="This is a test email body",
            urls=["https://example.com"],
            attachments=[],
            timestamp="2024-03-13",
            source="test",
            label=None
        )
        print(f"    ✓ Email created: {email.id}")
        return True
    except Exception as e:
        print(f"    ✗ Email creation failed: {e}")
        return False


def test_feature_extraction():
    """Test feature extraction"""
    print("[3/5] Testing feature extraction...")
    try:
        from src.data.loader import Email
        from src.features.url_analyzer import URLAnalyzer
        
        # Test URL analyzer
        test_url = "https://bit.ly/verify"
        analysis = URLAnalyzer.analyze_url(test_url)
        
        assert analysis['is_shortened'], "Should detect shortened URL"
        print(f"    ✓ URL analysis works (detected shortened: {analysis['is_shortened']})")
        
        return True
    except Exception as e:
        print(f"    ✗ Feature extraction failed: {e}")
        return False


def test_preprocessing():
    """Test preprocessing"""
    print("[4/5] Testing text preprocessing...")
    try:
        from src.data.preprocessor import EmailPreprocessor
        
        preprocessor = EmailPreprocessor()
        text = "Hello, this is a TEST email with <html>tags</html>"
        cleaned, tokens = preprocessor.preprocess_email_body(text)
        
        assert len(tokens) > 0, "Should have tokens"
        print(f"    ✓ Preprocessing works")
        print(f"      Original: {text[:50]}...")
        print(f"      Cleaned:  {cleaned[:50]}...")
        print(f"      Tokens:   {tokens[:3]}")
        
        return True
    except Exception as e:
        print(f"    ✗ Preprocessing failed: {e}")
        return False


def test_predictor_initialization():
    """Test predictor initialization"""
    print("[5/5] Testing predictor initialization...")
    try:
        from src.inference.pipeline import PhishShieldPredictor
        
        predictor = PhishShieldPredictor(model_type="tfidf_logreg")
        print(f"    ✓ Predictor initialized")
        print(f"      Model type: {predictor.model_type}")
        print(f"      Threshold: {predictor.threshold}")
        
        if predictor.model is None:
            print(f"    ⚠ Model not loaded (expected - train a model first)")
        
        return True
    except Exception as e:
        print(f"    ✗ Predictor initialization failed: {e}")
        return False


def main():
    print("\n" + "="*60)
    print("PhishShield - Quick Test Suite")
    print("="*60 + "\n")
    
    tests = [
        test_imports,
        test_email_creation,
        test_feature_extraction,
        test_preprocessing,
        test_predictor_initialization,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"    ✗ Test error: {e}")
            results.append(False)
        print()
    
    # Summary
    print("="*60)
    passed = sum(results)
    total = len(results)
    print(f"Results: {passed}/{total} tests passed")
    print("="*60 + "\n")
    
    if passed == total:
        print("✓ All tests passed! PhishShield is ready to use.")
        print("\nNext steps:")
        print("1. Train models: python -m src.models.trainer")
        print("2. Start API:    python scripts/run_api.py")
        print("3. Start Dashboard: python scripts/run_dashboard.sh")
        return 0
    else:
        print("✗ Some tests failed. Check the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
