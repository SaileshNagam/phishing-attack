#!/usr/bin/env python
"""
Data Adapter for PhishShield
Converts different CSV formats to unified training format
"""

import pandas as pd
import re
from pathlib import Path
from typing import Tuple, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EmailDataAdapter:
    """Adapts various email dataset formats to training format"""
    
    @staticmethod
    def extract_email_fields(raw_email: str) -> dict:
        """Extract subject, from, body from raw email text"""
        try:
            lines = raw_email.split('\n')
            subject = ""
            from_email = ""
            body_lines = []
            in_body = False
            
            for line in lines:
                if line.startswith('Subject:'):
                    subject = line.replace('Subject:', '').strip()
                elif line.startswith('From:'):
                    from_email = line.replace('From:', '').strip()
                elif line.strip() == '' and not in_body:
                    in_body = True
                elif in_body:
                    body_lines.append(line)
            
            body = '\n'.join(body_lines).strip()
            
            # Fallback if parsing fails
            if not subject:
                subject = raw_email[:100] if len(raw_email) > 100 else raw_email
            if not from_email:
                from_email = "unknown@email.com"
            if not body:
                body = raw_email
            
            return {
                'subject': subject,
                'from_email': from_email,
                'body': body
            }
        except Exception as e:
            logger.warning(f"Error parsing email: {e}")
            return {
                'subject': 'Unknown',
                'from_email': 'unknown@email.com',
                'body': raw_email[:500] if len(raw_email) > 500 else raw_email
            }
    
    @staticmethod
    def extract_urls(text: str) -> list:
        """Extract URLs from text"""
        url_pattern = r'https?://[^\s]+'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        return urls
    
    @staticmethod
    def load_emails_csv(filepath: str) -> pd.DataFrame:
        """Load emails.csv format (file, message)"""
        logger.info(f"Loading emails.csv: {filepath}")
        
        try:
            df = pd.read_csv(filepath, nrows=10000)  # Limit to 10k for memory
            
            records = []
            for idx, row in df.iterrows():
                if idx % 1000 == 0:
                    logger.info(f"  Processing row {idx}...")
                
                raw_email = row.get('message', '') or row.get(1, '')
                fields = EmailDataAdapter.extract_email_fields(str(raw_email))
                urls = EmailDataAdapter.extract_urls(str(raw_email))
                
                records.append({
                    'subject': fields['subject'],
                    'from_email': fields['from_email'],
                    'body': fields['body'],
                    'urls': ','.join(urls) if urls else '',
                    'label': 0  # Enron is legitimate
                })
            
            logger.info(f"✓ Loaded {len(records)} emails from emails.csv")
            return pd.DataFrame(records)
        
        except Exception as e:
            logger.error(f"Error loading emails.csv: {e}")
            return pd.DataFrame()
    
    @staticmethod
    def load_spam_assassin_csv(filepath: str) -> pd.DataFrame:
        """Load spam_assassin.csv format (text, target)"""
        logger.info(f"Loading spam_assassin.csv: {filepath}")
        
        try:
            df = pd.read_csv(filepath, nrows=10000)  # Limit to 10k for memory
            
            records = []
            for idx, row in df.iterrows():
                if idx % 1000 == 0:
                    logger.info(f"  Processing row {idx}...")
                
                raw_email = row.get('text', '') or row.get(0, '')
                label = int(row.get('target', 0))
                
                fields = EmailDataAdapter.extract_email_fields(str(raw_email))
                urls = EmailDataAdapter.extract_urls(str(raw_email))
                
                records.append({
                    'subject': fields['subject'],
                    'from_email': fields['from_email'],
                    'body': fields['body'],
                    'urls': ','.join(urls) if urls else '',
                    'label': label
                })
            
            logger.info(f"✓ Loaded {len(records)} emails from spam_assassin.csv")
            return pd.DataFrame(records)
        
        except Exception as e:
            logger.error(f"Error loading spam_assassin.csv: {e}")
            return pd.DataFrame()
    
    @staticmethod
    def load_sample_csv(filepath: str) -> pd.DataFrame:
        """Load pre-formatted sample.csv"""
        logger.info(f"Loading sample CSV: {filepath}")
        
        try:
            df = pd.read_csv(filepath)
            logger.info(f"✓ Loaded {len(df)} samples")
            return df
        except Exception as e:
            logger.error(f"Error loading sample: {e}")
            return pd.DataFrame()
    
    @staticmethod
    def combine_datasets(data_dir: str = "data/raw") -> pd.DataFrame:
        """Combine all available datasets"""
        logger.info(f"Combining datasets from {data_dir}")
        
        data_path = Path(data_dir)
        all_dfs = []
        
        # Load sample data
        sample_file = data_path / "sample_emails.csv"
        if sample_file.exists():
            sample_df = EmailDataAdapter.load_sample_csv(str(sample_file))
            if not sample_df.empty:
                all_dfs.append(sample_df)
        
        # Load emails.csv
        emails_file = data_path / "emails.csv"
        if emails_file.exists():
            emails_df = EmailDataAdapter.load_emails_csv(str(emails_file))
            if not emails_df.empty:
                all_dfs.append(emails_df)
        
        # Load spam_assassin.csv
        spam_file = data_path / "spam_assassin.csv"
        if spam_file.exists():
            spam_df = EmailDataAdapter.load_spam_assassin_csv(str(spam_file))
            if not spam_df.empty:
                all_dfs.append(spam_df)
        
        if not all_dfs:
            logger.error("No datasets found!")
            return pd.DataFrame()
        
        combined = pd.concat(all_dfs, ignore_index=True)
        logger.info(f"✓ Combined {len(combined)} total emails")
        logger.info(f"  Phishing: {(combined['label'] == 1).sum()}")
        logger.info(f"  Legitimate: {(combined['label'] == 0).sum()}")
        
        return combined
    
    @staticmethod
    def save_for_training(df: pd.DataFrame, output_file: str = "data/processed/emails_unified.csv"):
        """Save combined dataset for training"""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        df.to_csv(output_file, index=False)
        logger.info(f"✓ Saved unified dataset: {output_file}")
        
        return output_file


def main():
    """Main entry point"""
    print("\n" + "="*70)
    print("Email Data Adapter")
    print("="*70 + "\n")
    
    # Combine all datasets
    combined_df = EmailDataAdapter.combine_datasets("data/raw")
    
    if combined_df.empty:
        print("✗ No data loaded!")
        return 1
    
    # Save unified format
    output_file = EmailDataAdapter.save_for_training(
        combined_df,
        "data/processed/emails_unified.csv"
    )
    
    print("\n✓ Data preparation complete!")
    print(f"\nNext step: Train models")
    print(f"  python scripts/train_models.py")
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
