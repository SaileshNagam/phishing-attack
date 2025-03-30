#!/usr/bin/env python
"""
Training Script Wrapper for PhishShield
Trains baseline models and evaluates performance
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Main training entry point"""
    parser = argparse.ArgumentParser(
        description="Train PhishShield baseline models"
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Train on sample dataset (quick testing)"
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default="data/raw",
        help="Path to raw data directory"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="results/models",
        help="Path to save trained models"
    )
    parser.add_argument(
        "--metrics-dir",
        type=str,
        default="results/metrics",
        help="Path to save evaluation metrics"
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Test set size (0.0-1.0)"
    )
    
    args = parser.parse_args()
    
    # Print startup info
    print("\n" + "="*70)
    print("PhishShield Model Trainer")
    print("="*70)
    
    print(f"\nConfiguration:")
    print(f"  Data Directory: {args.data_dir}")
    print(f"  Models Directory: {args.output_dir}")
    print(f"  Metrics Directory: {args.metrics_dir}")
    print(f"  Test Size: {args.test_size * 100:.0f}%")
    print(f"  Dataset: {'Sample' if args.sample else 'Full'}")
    
    # Create output directories
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    Path(args.metrics_dir).mkdir(parents=True, exist_ok=True)
    logger.info(f"✓ Output directories created")
    
    print("\n" + "="*70)
    print("TRAINING PROCESS")
    print("="*70)
    
    try:
        # Import trainer module
        from src.models.trainer import train_baseline_models
        
        logger.info("Starting model training...")
        
        # Train models
        results = train_baseline_models(
            data_dir=args.data_dir,
            output_dir=args.output_dir,
            metrics_dir=args.metrics_dir,
            test_size=args.test_size,
            use_sample=args.sample
        )
        
        # Print results
        print("\n" + "="*70)
        print("TRAINING COMPLETE")
        print("="*70)
        print("\n✓ Models trained successfully!")
        print(f"\nResults:")
        if results:
            for model_name, metrics in results.items():
                print(f"\n  {model_name}:")
                if isinstance(metrics, dict):
                    for metric, value in metrics.items():
                        if isinstance(value, float):
                            print(f"    • {metric}: {value:.4f}")
                        else:
                            print(f"    • {metric}: {value}")
        
        print("\nNext steps:")
        print("  1. Start API server:")
        print("     python scripts/run_api.py")
        print("  2. Start dashboard:")
        print("     streamlit run scripts/streamlit_app.py")
        print("  3. Test predictions:")
        print("     curl -X POST http://localhost:8000/health")
        
        return 0
        
    except ImportError as e:
        logger.error(f"✗ Failed to import trainer module: {e}")
        logger.info("\nTo use this script, ensure trainer.py is implemented in src/models/")
        return 1
    except Exception as e:
        logger.error(f"✗ Training failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
