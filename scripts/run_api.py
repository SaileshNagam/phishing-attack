#!/usr/bin/env python
"""
Script to start the FastAPI server
Usage: python run_api.py --host 0.0.0.0 --port 8000
"""

import argparse
import uvicorn
import logging
import sys
from pathlib import Path

# Add project root to Python path for proper imports
project_root = Path(__file__).parent.parent.absolute()
sys.path.insert(0, str(project_root))

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="Start PhishShield FastAPI server (PRODUCTION)"
    )
    parser.add_argument("--host", default="0.0.0.0", help="Server host")
    parser.add_argument("--port", type=int, default=8000, help="Server port")
    parser.add_argument("--workers", type=int, default=1, help="Number of workers")
    parser.add_argument("--log-level", default="info", help="Log level")
    parser.add_argument("--reload", action="store_true", help="Auto-reload on code changes")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("🛡️  PHISHIELD - PHISHING EMAIL DETECTION API")
    print("="*70)
    print(f"🚀 Starting Production API Server")
    print(f"   Model: TF-IDF + Random Forest (99.27% accuracy)")
    print(f"   Host: {args.host}:{args.port}")
    print(f"   Workers: {args.workers}")
    print(f"   Log Level: {args.log_level}")
    print(f"")
    print(f"📊 Interactive API Docs: http://localhost:{args.port}/docs")
    print(f"🔧 ReDoc: http://localhost:{args.port}/redoc")
    print(f"💚 Health Check: http://localhost:{args.port}/health")
    print("="*70 + "\n")
    
    uvicorn.run(
        "src.deployment.api:app",
        host=args.host,
        port=args.port,
        workers=args.workers,
        log_level=args.log_level,
        reload=args.reload
    )


if __name__ == "__main__":
    main()
