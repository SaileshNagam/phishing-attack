#!/usr/bin/env python
"""
Dataset Downloader for PhishShield
Downloads training datasets: Enron, SpamAssassin, and PhishTank
"""

import os
import sys
import tarfile
import zipfile
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DatasetDownloader:
    """Downloads and extracts datasets for model training"""
    
    def __init__(self, data_dir: str = "data/raw"):
        """Initialize downloader with data directory"""
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Data directory: {self.data_dir}")
    
    def download_file(self, url: str, dest_file: Path, chunk_size: int = 8192) -> bool:
        """Download file with progress tracking"""
        try:
            if dest_file.exists():
                logger.info(f"✓ File already exists: {dest_file}")
                return True
            
            logger.info(f"Downloading from: {url}")
            logger.info(f"Saving to: {dest_file}")
            
            def progress_hook(block_num, block_size, total_size):
                """Show download progress"""
                downloaded = block_num * block_size
                if total_size > 0:
                    percent = min(100, int(100.0 * downloaded / total_size))
                    size_mb = total_size / (1024 * 1024)
                    print(f"\r  Progress: {percent}% ({downloaded / (1024 * 1024):.1f}MB / {size_mb:.1f}MB)", end='', flush=True)
                else:
                    print(f"\r  Downloaded: {downloaded / (1024 * 1024):.1f}MB", end='', flush=True)
            
            urllib.request.urlretrieve(url, dest_file, progress_hook)
            print()  # Newline after progress
            logger.info(f"✓ Download complete: {dest_file}")
            return True
            
        except urllib.error.URLError as e:
            logger.error(f"✗ Download failed: {e}")
            return False
        except Exception as e:
            logger.error(f"✗ Unexpected error: {e}")
            return False
    
    def extract_tar(self, tar_file: Path, extract_to: Path) -> bool:
        """Extract tar or tar.gz file"""
        try:
            if not tar_file.exists():
                logger.error(f"✗ File not found: {tar_file}")
                return False
            
            logger.info(f"Extracting: {tar_file}")
            extract_to.mkdir(parents=True, exist_ok=True)
            
            with tarfile.open(tar_file, 'r:*') as tar:
                tar.extractall(path=extract_to)
            
            logger.info(f"✓ Extraction complete: {extract_to}")
            return True
            
        except Exception as e:
            logger.error(f"✗ Extraction failed: {e}")
            return False
    
    def extract_zip(self, zip_file: Path, extract_to: Path) -> bool:
        """Extract zip file"""
        try:
            if not zip_file.exists():
                logger.error(f"✗ File not found: {zip_file}")
                return False
            
            logger.info(f"Extracting: {zip_file}")
            extract_to.mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                zip_ref.extractall(path=extract_to)
            
            logger.info(f"✓ Extraction complete: {extract_to}")
            return True
            
        except Exception as e:
            logger.error(f"✗ Extraction failed: {e}")
            return False
    
    def download_enron(self) -> bool:
        """Download Enron email corpus (~2GB, legitimate emails)"""
        logger.info("\n" + "="*60)
        logger.info("DATASET 1: Enron Corpus")
        logger.info("="*60)
        logger.info("Size: ~2GB | Emails: ~500K | Type: Legitimate")
        
        enron_dir = self.data_dir / "enron"
        
        # Check if already extracted
        if (enron_dir / "maildir").exists():
            logger.info("✓ Enron dataset already extracted")
            return True
        
        # Download tar file
        url = "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz"
        tar_file = self.data_dir / "enron_mail_20150507.tar.gz"
        
        if not self.download_file(url, tar_file):
            logger.warning("⚠ Enron download skipped (optional for training)")
            return False
        
        # Extract
        if self.extract_tar(tar_file, enron_dir):
            logger.info("✓ Enron corpus ready")
            return True
        return False
    
    def download_spamassassin(self) -> bool:
        """Download SpamAssassin corpus (~500MB, spam/phishing)"""
        logger.info("\n" + "="*60)
        logger.info("DATASET 2: SpamAssassin Public Corpus")
        logger.info("="*60)
        logger.info("Size: ~500MB | Emails: ~5K | Type: Spam/Phishing")
        
        spam_dir = self.data_dir / "spamassassin"
        
        # Check if already extracted
        if len(list(spam_dir.glob("*"))) > 0:
            logger.info("✓ SpamAssassin dataset already extracted")
            return True
        
        spam_dir.mkdir(parents=True, exist_ok=True)
        
        # Multiple dataset URLs
        urls = [
            "https://spamassassin.apache.org/publiccorpus/20021010_spam.tar.bz2",
            "https://spamassassin.apache.org/publiccorpus/20030228_spam.tar.bz2",
        ]
        
        success = False
        for url in urls:
            filename = url.split('/')[-1]
            tar_file = spam_dir / filename
            
            if self.download_file(url, tar_file):
                if self.extract_tar(tar_file, spam_dir):
                    success = True
        
        if success:
            logger.info("✓ SpamAssassin corpus ready")
            return True
        else:
            logger.warning("⚠ SpamAssassin download skipped (optional for training)")
            return False
    
    def download_phishtank(self) -> bool:
        """Download PhishTank dataset (~600K phishing URLs)"""
        logger.info("\n" + "="*60)
        logger.info("DATASET 3: PhishTank Database")
        logger.info("="*60)
        logger.info("Size: ~50MB | URLs: ~600K | Type: Phishing URLs")
        
        csv_file = self.data_dir / "phishtank.csv"
        
        if csv_file.exists():
            logger.info("✓ PhishTank dataset already downloaded")
            return True
        
        # PhishTank requires registration for API access, use public CSV snapshot
        url = "https://data.phishtank.com/data/online-valid.csv"
        
        if self.download_file(url, csv_file):
            logger.info("✓ PhishTank database ready")
            return True
        else:
            logger.warning("⚠ PhishTank download skipped (optional for training)")
            return False
    
    def create_sample_dataset(self) -> bool:
        """Create small sample dataset for quick testing"""
        logger.info("\n" + "="*60)
        logger.info("CREATING: Sample Dataset (for testing)")
        logger.info("="*60)
        
        sample_dir = self.data_dir / "sample"
        sample_dir.mkdir(parents=True, exist_ok=True)
        
        # Create sample emails CSV
        sample_emails = sample_dir / "sample_emails.csv"
        if not sample_emails.exists():
            sample_data = """id,subject,from_email,body,label
1,Verify Your Account,noreply@bankscam.ru,Click here to verify,1
2,Meeting Tomorrow at 3PM,john@company.com,Let's discuss project status,0
3,URGENT: Confirm Identity,noreply@paypal-verify.com,Your account has been suspended,1
4,Project Update,manager@company.com,Here's the latest status report,0
5,Prize Winner!,admin@lottery-fake.com,Congratulations you won 1 million,1"""
            sample_emails.write_text(sample_data)
            logger.info(f"✓ Created sample emails: {sample_emails}")
        
        # Create sample URLs CSV
        sample_urls = sample_dir / "sample_urls.csv"
        if not sample_urls.exists():
            urls_data = """url,label,category
https://bit.ly/verify123,1,phishing
https://www.google.com,0,benign
https://paypal-verify.ru,1,phishing
https://github.com,0,benign
https://amazon-account-update.com,1,phishing"""
            sample_urls.write_text(urls_data)
            logger.info(f"✓ Created sample URLs: {sample_urls}")
        
        return True
    
    def check_disk_space(self) -> bool:
        """Check if enough disk space available"""
        import shutil
        stat = shutil.disk_usage("/")
        free_gb = stat.free / (1024**3)
        
        logger.info(f"\nDisk space available: {free_gb:.1f}GB")
        
        if free_gb < 5:
            logger.warning(f"⚠ Warning: <5GB free space, downloads may fail")
            return False
        return True
    
    def validate_datasets(self) -> dict:
        """Validate downloaded datasets"""
        logger.info("\n" + "="*60)
        logger.info("VALIDATION: Checking Datasets")
        logger.info("="*60)
        
        results = {
            "enron": (self.data_dir / "enron" / "maildir").exists(),
            "spamassassin": len(list((self.data_dir / "spamassassin").glob("*"))) > 0,
            "phishtank": (self.data_dir / "phishtank.csv").exists(),
            "sample": (self.data_dir / "sample" / "sample_emails.csv").exists()
        }
        
        for name, exists in results.items():
            status = "✓" if exists else "✗"
            logger.info(f"{status} {name.upper()}: {'Ready' if exists else 'Not found'}")
        
        return results


def main():
    """Main entry point"""
    print("\n" + "="*60)
    print("PhishShield Dataset Downloader")
    print("="*60)
    
    downloader = DatasetDownloader()
    
    # Check disk space
    if not downloader.check_disk_space():
        print("\n⚠ Warning: Limited disk space. Proceeding with caution...")
    
    # Download datasets
    print("\nStarting downloads... (this may take 10-30 minutes)")
    print("You can interrupt with Ctrl+C\n")
    
    try:
        # Always create sample dataset (fast, no download)
        downloader.create_sample_dataset()
        
        # Optional: Download full datasets
        print("\nAttempting to download full datasets...")
        enron_ok = downloader.download_enron()
        spam_ok = downloader.download_spamassassin()
        phish_ok = downloader.download_phishtank()
        
        # Validate
        results = downloader.validate_datasets()
        
        # Summary
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        
        ready = []
        if results["sample"]:
            ready.append("Sample Dataset (Ready for quick testing)")
        if results["enron"]:
            ready.append("Enron Corpus (~500K emails)")
        if results["spamassassin"]:
            ready.append("SpamAssassin (~5K emails)")
        if results["phishtank"]:
            ready.append("PhishTank (~600K URLs)")
        
        if ready:
            print("\n✓ Ready to train on:")
            for item in ready:
                print(f"  • {item}")
        
        print("\nNext steps:")
        print("  1. Train models: python -m src.models.trainer")
        print("  2. Start API: python scripts/run_api.py")
        print("  3. View dashboard: streamlit run scripts/streamlit_app.py")
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("\n\n✗ Download interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"\n✗ Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
