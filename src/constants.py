"""
PhishShield: Constants and configuration defaults
"""

# ============================================================================
# PROJECT METADATA
# ============================================================================
PROJECT_NAME = "PhishShield"
PROJECT_VERSION = "1.0.0"
PROJECT_DESCRIPTION = "Hybrid Semantic-Structural Email Phishing Detection System"

# ============================================================================
# PATH CONSTANTS
# ============================================================================
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
CONFIG_DIR = PROJECT_ROOT / "config"
RESULTS_DIR = PROJECT_ROOT / "results"
MODELS_DIR = RESULTS_DIR / "models"
PLOTS_DIR = RESULTS_DIR / "plots"
LOGS_DIR = PROJECT_ROOT / "logs"

# Data paths
DATA_RAW = DATA_DIR / "raw"
DATA_PROCESSED = DATA_DIR / "processed"
DATA_FEATURES = DATA_DIR / "features"
DATA_DOWNLOADS = DATA_DIR / "downloads"

# ============================================================================
# MODEL NAMES & IDENTIFIERS
# ============================================================================
# Text encoders
MODERNBERT_MODEL_ID = "answerdotai/ModernBERT-base"
DISTILBERT_MODEL_ID = "distilbert-base-uncased"
MOBILEBERT_MODEL_ID = "google/mobilebert-uncased"

# Model files
BASELINE_TFIDF_LOGREG = "baseline_tfidf_logreg.pkl"
BASELINE_TFIDF_RF = "baseline_tfidf_rf.pkl"
TEXT_ENCODER_MODEL = "text_encoder_modernbert.pt"
STRUCTURAL_LIGHTGBM = "structural_lightgbm.pkl"
FUSION_META_LEARNER = "fusion_meta_learner.pkl"

# ============================================================================
# FEATURE DIMENSIONS
# ============================================================================
TFIDF_MAX_FEATURES = 5000
TEXT_EMBEDDING_DIM = 768
DISTILBERT_EMBEDDING_DIM = 768
MOBILEBERT_EMBEDDING_DIM = 256
STRUCTURAL_FEATURES_COUNT = 45
TOTAL_TEXT_FEATURES = 5776  # TF-IDF + urgency + subject + embeddings
TOTAL_FEATURES_HYBRID = 5821  # Text + Structural

# ============================================================================
# HYPERPARAMETERS
# ============================================================================
RANDOM_SEED = 42
DEFAULT_BATCH_SIZE = 32
DEFAULT_MAX_LENGTH = 512
DEFAULT_LEARNING_RATE = 2e-5
DEFAULT_EPOCHS = 3

# Train/Val/Test split
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15

# ============================================================================
# CLASSIFICATION THRESHOLDS
# ============================================================================
DEFAULT_DECISION_THRESHOLD = 0.5
PRECISION_THRESHOLD = 0.65  # Strict (fewer false positives)
RECALL_THRESHOLD = 0.35     # Loose (catch more phishing)
CONFIDENCE_THRESHOLD = 0.3  # Minimum confidence to output

# ============================================================================
# TEXT PROCESSING CONSTANTS
# ============================================================================
STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from",
    "has", "he", "in", "is", "it", "its", "of", "on", "or", "that",
    "the", "to", "was", "will", "with", "you", "your"
}

URGENCY_KEYWORDS = [
    "urgent",
    "immediate",
    "action required",
    "asap",
    "immediately",
    "quickly",
    "now",
    "today",
    "tonight",
]

CREDENTIAL_KEYWORDS = [
    "password",
    "login",
    "credentials",
    "username",
    "authenticate",
    "verify",
    "confirm",
    "email",
    "account",
    "access",
    "authorized",
]

ACTION_CTA_KEYWORDS = [
    "click",
    "click here",
    "tap",
    "open",
    "download",
    "update",
    "proceed",
    "start",
    "begin",
    "continue",
]

THREAT_KEYWORDS = [
    "suspend",
    "block",
    "limited",
    "locked",
    "risk",
    "violation",
    "unauthorized",
    "problem",
    "issue",
    "error",
    "compromised",
]

LEGITIMACY_KEYWORDS = [
    "regards",
    "sincerely",
    "thank you",
    "appreciate",
    "best",
    "warmly",
    "professional",
    "legal",
    "official",
]

# ============================================================================
# URL ANALYSIS CONSTANTS
# ============================================================================
SHORTENED_URL_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "short.link",
    "is.gd",
    "v.gd",
    "buff.ly",
    "short.link",
    "adf.ly",
    "j.mp",
}

SUSPICIOUS_TLDS = {
    ".ru",      # Russia
    ".cn",      # China
    ".tk",      # Tokelau (free domain)
    ".ml",      # Mali (free domain)
    ".ga",      # Gabon (free domain)
    ".cf",      # Central African Republic (free domain)
    ".top",     # Generic TLD, often abused
    ".download",
    ".stream",
    ".webcam",
    ".faith",
    ".racing",
}

RISKY_EXTENSIONS = {
    ".exe",
    ".bat",
    ".scr",
    ".vbs",
    ".js",
    ".zip",
    ".rar",
    ".7z",
    ".cab",
    ".msi",
    ".com",     # Old DOS executable
    ".pif",
}

# ============================================================================
# SHORT EMAIL CONSTANTS
# ============================================================================
SHORT_EMAIL_TOKEN_THRESHOLD = 50  # Emails with <50 tokens are "short"
SHORT_EMAIL_STRUCT_BOOST = 1.3    # Boost structural branch weight
SHORT_EMAIL_TEXT_REDUCE = 0.7     # Reduce text branch weight

# ============================================================================
# EXPLAINABILITY CONSTANTS
# ============================================================================
MAX_EXPLANATION_REASONS = 3
MIN_IMPORTANCE_THRESHOLD = 0.05
SHAP_BACKGROUND_SAMPLES = 1000
LIME_NUM_SAMPLES = 1000
LIME_NUM_FEATURES = 10

# ============================================================================
# CLASS LABELS
# ============================================================================
CLASS_PHISHING = 1
CLASS_LEGITIMATE = 0

LABEL_NAMES = {
    0: "LEGITIMATE",
    1: "PHISHING",
}

LABEL_TO_INT = {
    "legitimate": 0,
    "ham": 0,
    "legitimate_email": 0,
    "phishing": 1,
    "spam": 1,
    "phishing_email": 1,
}

# ============================================================================
# RISK LEVELS
# ============================================================================
RISK_LEVELS = {
    "LOW": 0.33,
    "MEDIUM": 0.66,
    "HIGH": 1.0,
}

RISK_LEVEL_NAMES = {
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
}

# ============================================================================
# ERROR MESSAGES
# ============================================================================
ERROR_INVALID_EMAIL_FORMAT = "Invalid email format: missing required fields"
ERROR_EMAIL_TOO_LONG = "Email body exceeds maximum length"
ERROR_NO_URLS = "No URLs found in email"
ERROR_MODEL_NOT_LOADED = "Model not loaded. Call load_model() first."
ERROR_INVALID_LABEL = "Invalid label. Must be 0 (legitimate) or 1 (phishing)"

# ============================================================================
# LOGGING
# ============================================================================
LOG_FORMAT = "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ============================================================================
# API CONSTANTS
# ============================================================================
API_VERSION = "v1"
API_TIMEOUT = 30  # seconds
MAX_BATCH_SIZE = 100
MAX_CONCURRENT_REQUESTS = 10

# ============================================================================
# PERFORMANCE TARGETS
# ============================================================================
TARGET_ACCURACY = 0.95
TARGET_PRECISION = 0.94
TARGET_RECALL = 0.96
TARGET_F1 = 0.95
TARGET_LATENCY_MS = 200  # milliseconds per email

# ============================================================================
# DATASET STATISTICS
# ============================================================================
AVG_EMAIL_LENGTH = 350  # tokens
MEDIAN_EMAIL_LENGTH = 250
MAX_EMAIL_LENGTH = 10000
MIN_EMAIL_LENGTH = 5

EXPECTED_VOCABULARY_SIZE = 50000

# Supported file formats
SUPPORTED_INPUT_FORMATS = {".eml", ".txt", ".json", ".msg"}
SUPPORTED_OUTPUT_FORMATS = {".json", ".csv", ".parquet"}
