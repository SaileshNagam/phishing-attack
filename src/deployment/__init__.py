"""
PhishShield Deployment Module
FastAPI and Streamlit applications for serving the model
"""

# Import API app for ASGI servers
try:
    from .api import app
    __all__ = ['app']
except ImportError:
    __all__ = []

