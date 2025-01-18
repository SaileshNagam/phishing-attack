from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="phishield",
    version="1.0.0",
    author="Cybersecurity AI Team",
    author_email="team@phishield.dev",
    description="Hybrid Semantic-Structural Email Phishing Detection System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/username/phishing-email-detector",
    packages=find_packages(),
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
    ],
    install_requires=[
        "torch>=2.1.2",
        "transformers>=4.37.2",
        "scikit-learn>=1.3.2",
        "lightgbm>=4.0.0",
        "numpy>=1.24.3",
        "pandas>=2.0.3",
        "scipy>=1.11.4",
        "beautifulsoup4>=4.12.2",
        "spacy>=3.7.2",
        "tldextract>=5.1.1",
        "email-validator>=2.1.0",
        "requests>=2.31.0",
        "python-dotenv>=1.0.0",
        "shap>=0.43.0",
        "lime>=0.3.0",
        "fastapi>=0.109.0",
        "uvicorn>=0.26.0",
        "pydantic>=2.5.2",
        "streamlit>=1.28.1",
        "pyarrow>=13.0.0",
        "pyyaml>=6.0.1",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-cov>=4.1.0",
            "black>=23.12.0",
            "pylint>=3.0.3",
            "jupyter>=1.0.0",
            "ipython>=8.18.1",
        ],
    },
    entry_points={
        "console_scripts": [
            "phishield=src.deployment.cli:main",
        ],
    },
)
