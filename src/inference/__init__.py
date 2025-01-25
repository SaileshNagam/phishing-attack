"""
PhishShield Inference Module
Prediction and batch processing for emails
"""

from .pipeline import PhishShieldPredictor, EmailBatchProcessor

__all__ = [
    'PhishShieldPredictor',
    'EmailBatchProcessor',
]

