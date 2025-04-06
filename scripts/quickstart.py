#!/usr/bin/env python
"""
PhishShield Quick Start - Complete Setup & Training
Orchestrates: downloading datasets, training models, and validation
"""

import os
import sys
import subprocess
import argparse
import time
from pathlib import Path
from typing import Callable

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_header(title: str):
    """Print formatted header"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{title:^70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}\n")


def print_step(step_num: int, title: str, description: str = ""):
    """Print step header"""
    print(f"{Colors.BOLD}{Colors.BLUE}[Step {step_num}] {title}{Colors.END}")
    if description:
        print(f"  {description}")


def print_success(message: str):
    """Print success message"""
    print(f"{Colors.GREEN}✓ {message}{Colors.END}")


def print_error(message: str):
    """Print error message"""
    print(f"{Colors.RED}✗ {message}{Colors.END}")


def print_warning(message: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠ {message}{Colors.END}")


def print_info(message: str):
    """Print info message"""
    print(f"  {Colors.BLUE}→{Colors.END} {message}")


def run_command(cmd: list, description: str = "", check: bool = True) -> bool:
    """Run shell command and report status"""
    try:
        print_info(f"Running: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=False,
            text=True,
            check=check
        )
        
        return result.returncode == 0
    
    except subprocess.CalledProcessError as e:
        print_error(f"Command failed: {e}")
        return False
    except Exception as e:
        print_error(f"Error: {e}")
        return False


def check_environment() -> bool:
    """Check if Python environment is properly set up"""
    print_step(1, "Environment Check", "Verifying Python setup...")
    
    try:
        # Check Python version
        version_info = sys.version_info
        print_info(f"Python {version_info.major}.{version_info.minor}.{version_info.micro}")
        
        # Check venv
        if sys.prefix == sys.base_prefix:
            print_warning("Virtual environment not active - activate with:")
            print(f"  {Colors.YELLOW}source .venv/bin/activate{Colors.END}")
            return False
        
        print_success("Virtual environment active")
        
        # Check required modules
        required_modules = [
            "numpy", "pandas", "sklearn", "torch",
            "transformers", "spacy", "fastapi"
        ]
        
        missing = []
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing.append(module)
        
        if missing:
            print_error(f"Missing modules: {', '.join(missing)}")
            print_info("Run: pip install -r requirements.txt")
            return False
        
        print_success("All required modules found")
        return True
        
    except Exception as e:
        print_error(f"Environment check failed: {e}")
        return False


def download_datasets() -> bool:
    """Download training datasets"""
    print_step(2, "Download Datasets", "Obtaining training data...")
    
    script_path = Path("scripts/download_datasets.py")
    if not script_path.exists():
        print_error(f"Script not found: {script_path}")
        return False
    
    print_info("This may take 10-30 minutes depending on connection speed")
    print_info("You will be prompted for each dataset")
    
    # Ask user confirmation
    response = input(f"\n{Colors.YELLOW}Continue with downloads? (y/n): {Colors.END}").strip().lower()
    if response != 'y':
        print_warning("Skipping dataset download")
        return True  # Not a fatal error
    
    return run_command(
        [sys.executable, str(script_path)],
        "Downloading datasets"
    )


def train_baseline_models(use_sample: bool = False) -> bool:
    """Train baseline models"""
    print_step(3, "Train Models", "Training TF-IDF + Logistic Regression...")
    
    script_path = Path("scripts/train_models.py")
    if not script_path.exists():
        print_error(f"Script not found: {script_path}")
        return False
    
    cmd = [sys.executable, str(script_path)]
    if use_sample:
        cmd.append("--sample")
        print_info("Using sample dataset for quick training")
    
    return run_command(cmd, "Training models")


def validate_models() -> bool:
    """Validate trained models"""
    print_step(4, "Validate Models", "Checking if models are trained...")
    
    model_dir = Path("results/models")
    expected_models = [
        "baseline_tfidf_logreg.pkl",
        "baseline_tfidf_rf.pkl"
    ]
    
    found_models = []
    for model in expected_models:
        model_path = model_dir / model
        if model_path.exists():
            size_mb = model_path.stat().st_size / (1024 * 1024)
            print_success(f"Found: {model} ({size_mb:.1f}MB)")
            found_models.append(model)
        else:
            print_warning(f"Not found: {model}")
    
    if found_models:
        print_success(f"Models ready for inference ({len(found_models)} found)")
        return True
    else:
        print_error("No trained models found - training may have failed")
        return False


def run_quick_test() -> bool:
    """Run integration tests"""
    print_step(5, "Quick Test", "Running integration tests...")
    
    script_path = Path("scripts/test_quick.py")
    if not script_path.exists():
        print_warning("Test script not found, skipping")
        return True
    
    return run_command(
        [sys.executable, str(script_path)],
        "Running integration tests"
    )


def show_next_steps():
    """Display next steps after setup"""
    print_header("Setup Complete! Next Steps")
    
    print(f"{Colors.BOLD}1. Start the API Server:{Colors.END}")
    print(f"   {Colors.CYAN}python scripts/run_api.py{Colors.END}")
    print(f"   → API will run on http://localhost:8000")
    print(f"   → OpenAPI docs: http://localhost:8000/docs\n")
    
    print(f"{Colors.BOLD}2. Start the Web Dashboard:{Colors.END}")
    print(f"   {Colors.CYAN}streamlit run scripts/streamlit_app.py{Colors.END}")
    print(f"   → Dashboard will run on http://localhost:8501\n")
    
    print(f"{Colors.BOLD}3. Test with a Sample Email:{Colors.END}")
    print(f"   {Colors.CYAN}curl -X POST http://localhost:8000/predict \\{Colors.END}")
    print(f"   {Colors.CYAN}  -H 'Content-Type: application/json' \\{Colors.END}")
    print(f"   {Colors.CYAN}  -d '{{{Colors.END}")
    print(f"   {Colors.CYAN}    \"subject\": \"Verify Your Account\",{Colors.END}")
    print(f"   {Colors.CYAN}    \"from_email\": \"noreply@bank-secure.ru\",{Colors.END}")
    print(f"   {Colors.CYAN}    \"body\": \"Click to verify: https://bit.ly/verify\",{Colors.END}")
    print(f"   {Colors.CYAN}    \"urls\": [\"https://bit.ly/verify\"]{Colors.END}")
    print(f"   {Colors.CYAN}  }}'{Colors.END}\n")
    
    print(f"{Colors.BOLD}4. Monitor Progress:{Colors.END}")
    print(f"   Check logs in: {Colors.CYAN}logs/{Colors.END}")
    print(f"   View metrics in: {Colors.CYAN}results/metrics/{Colors.END}\n")
    
    print(f"{Colors.BOLD}Documentation:{Colors.END}")
    print(f"   • System Architecture: {Colors.CYAN}SYSTEM_ARCHITECTURE.md{Colors.END}")
    print(f"   • API Reference: {Colors.CYAN}src/deployment/api.py{Colors.END}")
    print(f"   • Integration Roadmap: {Colors.CYAN}INTEGRATION_ROADMAP.md{Colors.END}\n")


def main():
    """Main orchestration function"""
    parser = argparse.ArgumentParser(
        description="PhishShield Quick Start - Setup & Training"
    )
    parser.add_argument(
        "--skip-download",
        action="store_true",
        help="Skip dataset download (use existing data)"
    )
    parser.add_argument(
        "--sample-only",
        action="store_true",
        help="Train on sample data only (faster)"
    )
    parser.add_argument(
        "--skip-test",
        action="store_true",
        help="Skip validation tests"
    )
    
    args = parser.parse_args()
    
    # Print welcome
    print_header("PhishShield Quick Start")
    print(f"Welcome to PhishShield Setup!")
    print(f"This script will help you:")
    print(f"  1. Download training datasets")
    print(f"  2. Train baseline models")
    print(f"  3. Validate training")
    print(f"  4. Run integration tests")
    
    try:
        # Step 1: Environment check
        if not check_environment():
            print_error("Environment check failed - please fix issues above")
            return 1
        
        # Step 2: Download datasets (optional)
        if not args.skip_download:
            if not download_datasets():
                print_warning("Dataset download failed/skipped - proceeding with sample data")
        else:
            print_info("Skipping dataset download (--skip-download)")
        
        # Step 3: Train models
        if not train_baseline_models(use_sample=args.sample_only):
            print_error("Model training failed")
            return 1
        
        # Step 4: Validate models
        if not validate_models():
            print_warning("Model validation incomplete - check training output")
        
        # Step 5: Quick test
        if not args.skip_test:
            if not run_quick_test():
                print_warning("Some tests failed - check output above")
        
        # Show next steps
        show_next_steps()
        
        print_header("All Done! 🎉")
        return 0
        
    except KeyboardInterrupt:
        print_error("\n\nSetup interrupted by user")
        return 1
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
