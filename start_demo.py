#!/usr/bin/env python3
"""
PhishShield - One-Click Demo Launch Script
Starts the unified API and Web Dashboard
"""

import subprocess
import time
import sys
import os
from pathlib import Path

def print_banner():
    print("\n" + "="*70)
    print("   PhishShield - Unified AI Phishing Detector")
    print("   Starting Demo Environment")
    print("="*70 + "\n")

def print_section(title):
    print(f"\n{'─'*70}")
    print(f"  {title}")
    print(f"{'─'*70}\n")

def check_venv():
    """Check if virtual environment is activated"""
    venv_path = Path('.venv')
    if not venv_path.exists():
        print("❌ Virtual environment not found!")
        print("   Run: python -m venv .venv && source .venv/bin/activate")
        sys.exit(1)
    print("✓ Virtual environment found")

def start_api():
    """Start Unified API server which also serves the web dashboard"""
    print_section("Starting Unified API Server & Web Dashboard")
    print("📡 Launching FastAPI server on http://localhost:8000\n")
    
    cmd = "source .venv/bin/activate && python backend/api.py"
    process = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait for startup
    time.sleep(3)
    
    if process.poll() is None:
        print("✓ Unified API Server started successfully")
        print("  📚 OpenAPI Docs:  http://localhost:8000/docs")
        print("  🔍 Health Check:  http://localhost:8000/health")
        return process
    else:
        print("❌ API Server failed to start")
        stdout, stderr = process.communicate()
        print("STDERR:", stderr.decode())
        sys.exit(1)

def start_dashboard():
    """Start static HTTP server for dashboard on port 8501"""
    print("📡 Launching Dashboard on http://127.0.0.1:8501\n")
    
    cmd = "cd dashboard && python3 -m http.server 8501"
    process = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    time.sleep(2)
    if process.poll() is None:
        print("✓ Web Dashboard started successfully")
        print("  🌐 Web Dashboard: http://127.0.0.1:8501/index.html")
        return process
    else:
        print("❌ Dashboard Server failed to start")
        sys.exit(1)

def print_next_steps():
    """Print instructions for using the system"""
    print_section("System Ready - Faculty Presentation Guide")
    
    print("""
1️⃣  SERVER RUNNING
   • Unified Backend is active on port 8000.
   • Chrome & Edge extensions can connect to http://localhost:8000

2️⃣  WEB DASHBOARD (Full Screen Report)
   • Open: http://127.0.0.1:8501/index.html
   • Used for full analysis of emails and showcasing the pipeline.

3️⃣  BROWSER EXTENSION
   • Load unpacked extension from `chrome-extension` in both Chrome or Edge.
   • Open an email in Gmail to see the "Mini Mail UI" inline card.
   • Click "Full Analysis" to be taken to the Web Dashboard.

4️⃣  INTERACTIVE API TESTING
   • Open: http://localhost:8000/docs
   • Test phishing detection in real-time with /predict

5️⃣  DEMO EXAMPLES

   Phishing Email:
   {
     "subject": "URGENT: Verify Your Account!",
     "from_email": "verify@secure-bank-ru.com",
     "body": "Click link to verify: https://bit.ly/verify"
   }

   Legitimate Email:
   {
     "subject": "Meeting reminder",
     "from_email": "boss@company.com",
     "body": "Reminder: Q1 planning at 2 PM tomorrow"
   }

6️⃣  KEEP RUNNING
   Press Ctrl+C to stop the servers.
    """)

def main():
    """Main demo launcher"""
    print_banner()
    
    print_section("Checking Prerequisites")
    check_venv()
    print("✓ All checks passed!\n")
    
    # Start servers
    api_process = start_api()
    dash_process = start_dashboard()
    
    print_next_steps()
    
    print_section("🎬 Systems Ready for Presentation!")
    
    try:
        # Keep running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n⏹️  Shutting down services...")
        api_process.terminate()
        dash_process.terminate()
        print("✓ All services stopped")
        print("Thank you for using PhishShield!\n")

if __name__ == '__main__':
    main()
