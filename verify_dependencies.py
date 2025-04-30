#!/usr/bin/env python
"""
Verify project dependencies are installed correctly
LightGBM is optional (needed for upgraded models only)
"""

import sys

print("Python executable:", sys.executable)
print("Python version:", sys.version)
print("\n" + "="*70)
print("PHISHING EMAIL DETECTOR - DEPENDENCY VERIFICATION")
print("="*70)

required_packages = {
    'torch': 'Deep Learning Framework',
    'transformers': 'Transformers for NLP',
    'sklearn': 'scikit-learn for ML',
    'spacy': 'NLP processing',
    'pandas': 'Data manipulation',
    'numpy': 'Numerical computing',
    'fastapi': 'API Framework',
    'streamlit': 'Dashboard Framework',
    'beautifulsoup4': 'Web scraping',
    'tldextract': 'Domain parsing',
    'shap': 'Model explainability',
    'lime': 'Local explainability',
}

optional_packages = {
    'lightgbm': 'Gradient Boosting (for upgraded models)',
}

print("\n📦 REQUIRED PACKAGES")
print("-" * 70)

all_passed = True
for pkg_import, description in required_packages.items():
    try:
        if pkg_import == 'sklearn':
            import sklearn
            version = sklearn.__version__
        elif pkg_import == 'beautifulsoup4':
            import bs4
            version = bs4.__version__
        else:
            mod = __import__(pkg_import)
            version = getattr(mod, '__version__', 'unknown')
        
        status = "✓"
        print(f"{status} {pkg_import:20s} {version:15s} - {description}")
    except Exception as e:
        all_passed = False
        print(f"✗ {pkg_import:20s} {'FAILED':15s} - {description}")
        print(f"  Error: {str(e)[:50]}")

# Check spacy model
try:
    import spacy
    nlp = spacy.load('en_core_web_sm')
    print(f"  ✓ spacy.load('en_core_web_sm') - Model loaded successfully")
except Exception as e:
    all_passed = False
    print(f"  ✗ spacy.load('en_core_web_sm') - Failed: {e}")

print("\n📦 OPTIONAL PACKAGES")
print("-" * 70)

for pkg_import, description in optional_packages.items():
    try:
        mod = __import__(pkg_import)
        version = getattr(mod, '__version__', 'unknown')
        print(f"✓ {pkg_import:20s} {version:15s} - {description}")
    except Exception as e:
        print(f"⚠ {pkg_import:20s} {'NOT INSTALLED':15s} - {description}")
        if "libomp" in str(e).lower():
            print(f"  Note: LightGBM on macOS requires libomp. Install with:")
            print(f"  brew install libomp")

print("\n" + "="*70)
if all_passed:
    print("✓ ALL REQUIRED DEPENDENCIES INSTALLED SUCCESSFULLY")
    print("  Project is ready to use!")
else:
    print("✗ SOME REQUIRED DEPENDENCIES FAILED")
    sys.exit(1)
print("="*70)
