#!/usr/bin/env python
"""
Complete Training Orchestrator with Data Adaptation
Handles data conversion and model training in one command
"""

import os
import sys
import subprocess
from pathlib import Path
import pandas as pd
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def print_header(title: str):
    """Print formatted header"""
    print(f"\n{'='*70}")
    print(f"{title:^70}")
    print(f"{'='*70}\n")


def run_data_adapter():
    """Run the data adapter to convert CSV formats"""
    print_header("STEP 1: Data Adaptation")
    
    adapter_script = Path("scripts/data_adapter.py")
    if not adapter_script.exists():
        logger.error(f"Data adapter not found: {adapter_script}")
        return False
    
    logger.info("Converting datasets to unified format...")
    
    try:
        result = subprocess.run(
            [sys.executable, str(adapter_script)],
            check=True,
            capture_output=False
        )
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        logger.error(f"Data adaptation failed: {e}")
        return False


def verify_adapted_data():
    """Verify adapted data exists"""
    adapted_file = Path("data/processed/emails_unified.csv")
    
    if not adapted_file.exists():
        logger.error(f"Adapted data not found: {adapted_file}")
        return False
    
    df = pd.read_csv(adapted_file)
    logger.info(f"✓ Verified adapted dataset: {len(df)} emails")
    return True


def run_model_training():
    """Run the model trainer"""
    print_header("STEP 2: Model Training")
    
    trainer_script = Path("scripts/train_models.py")
    if not trainer_script.exists():
        logger.error(f"Trainer not found: {trainer_script}")
        return False
    
    logger.info("Training baseline models...")
    
    try:
        result = subprocess.run(
            [sys.executable, str(trainer_script)],
            check=True,
            capture_output=False
        )
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        logger.error(f"Model training failed: {e}")
        return False


def show_completion_status():
    """Show training completion status"""
    print_header("TRAINING COMPLETE ✓")
    
    models_dir = Path("results/models")
    metrics_dir = Path("results/metrics")
    
    print("📂 Generated Files:")
    print(f"  Models: {models_dir}/")
    if models_dir.exists():
        for model_file in models_dir.glob("*.pkl"):
            size_mb = model_file.stat().st_size / (1024 * 1024)
            print(f"    ✓ {model_file.name} ({size_mb:.1f}MB)")
    
    print(f"\n  Metrics: {metrics_dir}/")
    if metrics_dir.exists():
        for metric_file in metrics_dir.glob("*"):
            print(f"    ✓ {metric_file.name}")
    
    print("\n🎯 Next Steps:")
    print("  1. Start API server:")
    print("     python scripts/run_api.py")
    print("\n  2. Start web dashboard:")
    print("     streamlit run scripts/streamlit_app.py")
    print("\n  3. Test predictions:")
    print("     curl -X POST http://localhost:8000/health")


def main():
    """Main orchestration"""
    print_header("PhishShield Complete Training Pipeline")
    
    print("This will:")
    print("  1. Convert your CSVs to unified format")
    print("  2. Extract features")
    print("  3. Train baseline models")
    print()
    
    try:
        # Step 1: Data adaptation
        logger.info("Starting data adaptation...")
        if not run_data_adapter():
            logger.error("Data adaptation failed")
            return 1
        
        # Verify adapted data
        if not verify_adapted_data():
            logger.error("Data verification failed")
            return 1
        
        # Step 2: Model training
        logger.info("Starting model training...")
        if not run_model_training():
            logger.error("Model training failed")
            return 1
        
        # Show completion status
        show_completion_status()
        
        return 0
        
    except KeyboardInterrupt:
        logger.error("\n✗ Training interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
