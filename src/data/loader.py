"""
Email data loader and parser
Handles loading emails from various formats and extracting components
"""

import json
import re
from email import message_from_string, policy
from email.header import decode_header
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class Email:
    """Email data structure"""
    id: str
    headers: Dict[str, str]
    subject: str
    from_email: str
    to_email: str
    body: str
    urls: List[str]
    attachments: List[Dict]
    timestamp: str
    source: str  # Which dataset this came from
    label: Optional[int] = None  # 0: legitimate, 1: phishing
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict())


class EmailParser:
    """Parse email from various formats"""
    
    @staticmethod
    def parse_eml(eml_content: str) -> Email:
        """Parse .eml format email"""
        msg = message_from_string(eml_content, policy=policy.default)
        
        # Extract headers
        headers = {}
        for key in msg.keys():
            value = msg[key]
            if isinstance(value, str):
                headers[key.lower()] = value
            else:
                headers[key.lower()] = str(value)
        
        # Decode subject
        subject = EmailParser._decode_header(msg.get('Subject', ''))
        from_email = EmailParser._decode_header(msg.get('From', ''))
        to_email = EmailParser._decode_header(msg.get('To', ''))
        
        # Extract body
        body = ""
        if msg.is_multipart():
            for part in msg.iter_parts():
                if part.get_content_type() == 'text/plain':
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        body = payload.decode('utf-8', errors='ignore')
                    else:
                        body = payload
                    break
        else:
            payload = msg.get_payload(decode=True)
            if isinstance(payload, bytes):
                body = payload.decode('utf-8', errors='ignore')
            else:
                body = payload or ""
        
        # Extract attachments
        attachments = []
        if msg.is_multipart():
            for part in msg.iter_parts():
                filename = part.get_filename()
                if filename:
                    attachments.append({
                        'filename': filename,
                        'content_type': part.get_content_type(),
                        'size': len(part.get_payload(decode=True)) if part.get_payload(decode=True) else 0
                    })
        
        # Extract URLs
        urls = EmailParser._extract_urls(body)
        
        return Email(
            id=headers.get('message-id', 'unknown'),
            headers=headers,
            subject=subject,
            from_email=from_email,
            to_email=to_email,
            body=body,
            urls=urls,
            attachments=attachments,
            timestamp=headers.get('date', ''),
            source='eml'
        )
    
    @staticmethod
    def parse_json(json_data: Dict) -> Email:
        """Parse JSON format email"""
        return Email(
            id=json_data.get('id', 'unknown'),
            headers=json_data.get('headers', {}),
            subject=json_data.get('subject', ''),
            from_email=json_data.get('from', ''),
            to_email=json_data.get('to', ''),
            body=json_data.get('body', ''),
            urls=json_data.get('urls', []),
            attachments=json_data.get('attachments', []),
            timestamp=json_data.get('timestamp', ''),
            source=json_data.get('source', 'json'),
            label=json_data.get('label')
        )
    
    @staticmethod
    def _decode_header(header_str: str) -> str:
        """Decode email header with encoding"""
        try:
            if not header_str:
                return ""
            
            decoded_parts = []
            for part, encoding in decode_header(header_str):
                if isinstance(part, bytes):
                    try:
                        part = part.decode(encoding or 'utf-8')
                    except:
                        part = part.decode('utf-8', errors='ignore')
                decoded_parts.append(part)
            
            return ''.join(decoded_parts)
        except Exception as e:
            logger.warning(f"Failed to decode header: {e}")
            return str(header_str)
    
    @staticmethod
    def _extract_urls(text: str) -> List[str]:
        """Extract URLs from text"""
        url_pattern = r'https?://[^\s\)<>"\]]*'
        urls = re.findall(url_pattern, text)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_urls = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        
        return unique_urls


class EmailDataLoader:
    """Load emails from various sources"""
    
    def __init__(self):
        self.parser = EmailParser()
    
    def load_directory(self, directory_path: str, format: str = 'eml') -> List[Email]:
        """
        Load all emails from a directory
        
        Args:
            directory_path: Path to directory containing emails
            format: Email format ('eml', 'txt', 'json')
        
        Returns:
            List of Email objects
        """
        directory = Path(directory_path)
        emails = []
        
        if format == 'eml':
            file_pattern = '*.eml'
        elif format == 'txt':
            file_pattern = '*.txt'
        elif format == 'json':
            file_pattern = '*.json'
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        for file_path in directory.glob(file_pattern):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                if format == 'eml' or format == 'txt':
                    email = self.parser.parse_eml(content)
                elif format == 'json':
                    email = self.parser.parse_json(json.loads(content))
                
                emails.append(email)
            except Exception as e:
                logger.warning(f"Failed to load {file_path}: {e}")
                continue
        
        logger.info(f"Loaded {len(emails)} emails from {directory_path}")
        return emails
    
    def load_json_lines(self, jsonl_path: str) -> List[Email]:
        """
        Load emails from JSON Lines format (one JSON object per line)
        
        Args:
            jsonl_path: Path to JSONL file
        
        Returns:
            List of Email objects
        """
        emails = []
        
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    data = json.loads(line)
                    email = self.parser.parse_json(data)
                    emails.append(email)
                except Exception as e:
                    logger.warning(f"Failed to parse line {line_num} in {jsonl_path}: {e}")
                    continue
        
        logger.info(f"Loaded {len(emails)} emails from {jsonl_path}")
        return emails
    
    def save_emails(self, emails: List[Email], output_path: str, format: str = 'jsonl'):
        """
        Save emails to file
        
        Args:
            emails: List of Email objects
            output_path: Path to save file
            format: Output format ('jsonl' or 'json')
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format == 'jsonl':
            with open(output_path, 'w', encoding='utf-8') as f:
                for email in emails:
                    f.write(email.to_json() + '\n')
        elif format == 'json':
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump([email.to_dict() for email in emails], f, indent=2)
        
        logger.info(f"Saved {len(emails)} emails to {output_path}")


def load_sample_email() -> Email:
    """Create a sample email for testing"""
    sample_eml = """From: sender@example.com
To: recipient@company.com
Subject: Urgent: Verify Your Account
Date: Mon, 12 Mar 2024 10:00:00 +0000
Message-ID: <sample@example.com>

Please verify your account by clicking the link below:
https://bit.ly/verify_account

Click here: <a href="https://malicious-site.com/phishing">Verify Now</a>

Thank you,
Bank Support Team
"""
    return EmailParser.parse_eml(sample_eml)


if __name__ == "__main__":
    # Test the parser
    sample = load_sample_email()
    print(f"Subject: {sample.subject}")
    print(f"From: {sample.from_email}")
    print(f"URLs found: {sample.urls}")
    print(f"JSON: {sample.to_json()}")
