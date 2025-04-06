#!/usr/bin/env python
"""
Script to start the Streamlit dashboard
Usage: python run_dashboard.py
"""

import subprocess
import sys


def main():
    print("🚀 Starting PhishShield Streamlit Dashboard")
    print("📊 Opening at: http://localhost:8501")
    print("")
    
    try:
        subprocess.run([
            sys.executable, "-m", "streamlit", "run",
            "scripts/streamlit_app.py",
            "--logger.level=info"
        ], cwd=".")
    except KeyboardInterrupt:
        print("\n✓ Dashboard stopped")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
