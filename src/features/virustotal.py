"""
VirusTotal API Integration for Live URL Scanning
Provides real-time URL reputation checks against VirusTotal's database
"""

import requests
import time
import logging
from typing import Dict, Optional
from dataclasses import dataclass
from pathlib import Path
import os

logger = logging.getLogger(__name__)


@dataclass
class VirusTotalResult:
    """Result from VirusTotal URL scan"""
    url: str
    is_malicious: bool
    malicious_count: int
    suspicious_count: int
    harmless_count: int
    undetected_count: int
    total_engines: int
    threat_names: list
    reputation_score: int
    last_analysis_date: str
    error: Optional[str] = None


class VirusTotalClient:
    """
    VirusTotal API v3 client for URL scanning

    Usage:
        client = VirusTotalClient()  # Uses VIRUSTOTAL_API_KEY env var
        result = client.check_url("https://malicious.com/phishing")

    Get free API key: https://www.virustotal.com/gui/join-us
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None, rate_limit: float = 1.0):
        """
        Initialize VirusTotal client

        Args:
            api_key: VirusTotal API key (reads from VIRUSTOTAL_API_KEY env if None)
            rate_limit: Seconds between requests (free tier: 4 req/min = 0.25 min)
        """
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.rate_limit = rate_limit
        self._last_request_time = 0.0

        if not self.api_key:
            logger.warning(
                "VirusTotal API key not set. Set VIRUSTOTAL_API_KEY environment variable. "
                "URL scanning will be skipped."
            )

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Optional[dict]:
        """Make authenticated request to VirusTotal API"""
        if not self.api_key:
            return None

        # Rate limiting
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

        url = f"{self.BASE_URL}/{endpoint}"

        try:
            response = requests.request(method, url, headers=headers, **kwargs, timeout=10)
            self._last_request_time = time.time()

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            elif response.status_code == 429:
                logger.warning("VirusTotal rate limit exceeded")
                return None
            else:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                return None

        except requests.RequestException as e:
            logger.error(f"VirusTotal request failed: {e}")
            return None

    def check_url(self, url: str, force_scan: bool = False) -> VirusTotalResult:
        """
        Check a URL's reputation via VirusTotal

        Args:
            url: URL to check
            force_scan: If True, submit URL for scanning (may delay results)

        Returns:
            VirusTotalResult with reputation data
        """
        if not self.api_key:
            return VirusTotalResult(
                url=url,
                is_malicious=False,
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                total_engines=0,
                threat_names=[],
                reputation_score=0,
                last_analysis_date="",
                error="API key not configured"
            )

        # Submit URL for analysis (or get existing report)
        endpoint = f"urls/{self._get_url_id(url)}"

        # If forcing a new scan, submit first
        if force_scan:
            self._submit_url(url)

        data = self._make_request("GET", endpoint)

        if not data:
            # Try to submit and get pending result
            self._submit_url(url)
            time.sleep(2)  # Wait for processing
            data = self._make_request("GET", endpoint)

        if not data:
            return VirusTotalResult(
                url=url,
                is_malicious=False,
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                total_engines=0,
                threat_names=[],
                reputation_score=0,
                last_analysis_date="",
                error="URL not found in VirusTotal database"
            )

        return self._parse_response(url, data)

    def _get_url_id(self, url: str) -> str:
        """Get URL ID (base64 encoded) for VirusTotal API"""
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        return url_id

    def _submit_url(self, url: str) -> bool:
        """Submit URL for VirusTotal scanning"""
        data = {"url": url}
        response = self._make_request("POST", "urls", data=data)
        return response is not None

    def _parse_response(self, url: str, data: dict) -> VirusTotalResult:
        """Parse VirusTotal API response"""
        try:
            attributes = data.get("data", {}).get("attributes", {})

            last_analysis_stats = attributes.get("last_analysis_stats", {})
            last_analysis_results = attributes.get("last_analysis_results", {})

            malicious = last_analysis_stats.get("malicious", 0)
            suspicious = last_analysis_stats.get("suspicious", 0)
            harmless = last_analysis_stats.get("harmless", 0)
            undetected = last_analysis_stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected + last_analysis_stats.get("timeout", 0)

            # Extract threat names
            threat_names = [
                result["engine_name"]
                for result in last_analysis_results.values()
                if result.get("category") in ["malicious", "malware"]
            ]

            # Reputation score (-100 to 100)
            reputation = attributes.get("reputation", 0)

            # Last analysis date
            last_analysis_date = attributes.get("last_analysis_date", "")

            # Consider malicious if any engine flags it
            is_malicious = malicious > 0 or suspicious > 3

            return VirusTotalResult(
                url=url,
                is_malicious=is_malicious,
                malicious_count=malicious,
                suspicious_count=suspicious,
                harmless_count=harmless,
                undetected_count=undetected,
                total_engines=total,
                threat_names=threat_names[:10],  # Top 10 threats
                reputation_score=reputation,
                last_analysis_date=str(last_analysis_date) if last_analysis_date else "",
                error=None
            )

        except Exception as e:
            logger.error(f"Failed to parse VirusTotal response: {e}")
            return VirusTotalResult(
                url=url,
                is_malicious=False,
                malicious_count=0,
                suspicious_count=0,
                harmless_count=0,
                undetected_count=0,
                total_engines=0,
                threat_names=[],
                reputation_score=0,
                last_analysis_date="",
                error=str(e)
            )

    def check_domain(self, domain: str) -> Optional[Dict]:
        """
        Get domain reputation (uses /domains endpoint)

        Note: Domain endpoint requires VirusTotal Intelligence subscription
        for full data. Basic tier may have limited access.
        """
        if not self.api_key:
            return None

        endpoint = f"domains/{domain}"
        data = self._make_request("GET", endpoint)

        return data


class VirusTotalIntegration:
    """
    Integrates VirusTotal scanning into the phishing detection pipeline
    Provides background checking for URLs found in emails
    """

    def __init__(self, api_key: Optional[str] = None):
        self.client = VirusTotalClient(api_key=api_key)
        self.cache: Dict[str, VirusTotalResult] = {}
        self.cache_ttl = 3600  # Cache results for 1 hour

    def check_url(self, url: str, use_cache: bool = True) -> VirusTotalResult:
        """
        Check URL with VirusTotal (with caching)

        Args:
            url: URL to check
            use_cache: Whether to use cached results

        Returns:
            VirusTotalResult
        """
        # Check cache first
        if use_cache and url in self.cache:
            return self.cache[url]

        # Query VirusTotal
        result = self.client.check_url(url)

        # Cache successful results
        if not result.error:
            self.cache[url] = result

        return result

    def check_urls(self, urls: list, use_cache: bool = True) -> Dict[str, VirusTotalResult]:
        """
        Check multiple URLs

        Args:
            urls: List of URLs to check
            use_cache: Whether to use cached results

        Returns:
            Dictionary mapping URL to VirusTotalResult
        """
        results = {}
        for url in urls:
            results[url] = self.check_url(url, use_cache=use_cache)
        return results

    def get_url_risk_score(self, url: str) -> float:
        """
        Get URL risk score (0.0 = safe, 1.0 = malicious)

        Combines VirusTotal stats into a single score
        """
        result = self.check_url(url)

        if result.error:
            return 0.0  # Can't verify, assume neutral

        total = result.total_engines
        if total == 0:
            return 0.0

        # Weighted score: malicious = 1.0, suspicious = 0.5
        weighted = (result.malicious_count * 1.0 + result.suspicious_count * 0.5) / total

        return min(1.0, weighted * 2)  # Scale up for visibility

    def add_to_pipeline(self, email_features: Dict) -> Dict:
        """
        Add VirusTotal analysis to email features

        This would be called during feature extraction to enrich
        the URL analysis with live VirusTotal data

        Args:
            email_features: Dictionary of existing email features

        Returns:
            Updated features with VirusTotal results
        """
        urls = email_features.get("urls", [])

        if not urls:
            return email_features

        vt_results = self.check_urls(urls)

        # Add VirusTotal summary to features
        email_features["virustotal"] = {
            "urls_checked": len(urls),
            "malicious_detected": any(r.is_malicious for r in vt_results.values()),
            "max_risk_score": max(self.get_url_risk_score(u) for u in urls),
            "details": {
                url: {
                    "malicious": r.is_malicious,
                    "malicious_count": r.malicious_count,
                    "suspicious_count": r.suspicious_count,
                    "threats": r.threat_names
                }
                for url, r in vt_results.items()
            }
        }

        return email_features


# Convenience function for quick URL checks
def check_url_safety(url: str, api_key: Optional[str] = None) -> dict:
    """
    Quick check if a URL is safe via VirusTotal

    Returns:
        dict with keys: is_safe, risk_level, details
    """
    client = VirusTotalClient(api_key=api_key)
    result = client.check_url(url)

    if result.error:
        return {
            "is_safe": None,
            "risk_level": "UNKNOWN",
            "details": result.error
        }

    if result.is_malicious:
        risk_level = "CRITICAL" if result.malicious_count > 5 else "HIGH"
    elif result.suspicious_count > 0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "is_safe": not result.is_malicious,
        "risk_level": risk_level,
        "details": {
            "malicious_engines": result.malicious_count,
            "suspicious_engines": result.suspicious_count,
            "total_engines": result.total_engines,
            "threats": result.threat_names,
            "reputation": result.reputation_score
        }
    }


if __name__ == "__main__":
    import os
    import json

    # Check if API key is available
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        print("VIRUSTOTAL_API_KEY not set. To enable live URL scanning:")
        print("1. Get free API key from https://www.virustotal.com")
        print("2. Run: export VIRUSTOTAL_API_KEY='your-key-here'")
        print("\nTesting with mock data...")

    # Test URLs
    test_urls = [
        "https://bit.ly/verify123",
        "https://google.com",
        "https://evil.com/phishing",
    ]

    integration = VirusTotalIntegration(api_key=api_key)

    for url in test_urls:
        result = integration.check_url(url)
        print(f"\nURL: {url}")
        print(f"  Malicious: {result.is_malicious}")
        print(f"  Malicious engines: {result.malicious_count}/{result.total_engines}")
        print(f"  Suspicious engines: {result.suspicious_count}")
        print(f"  Threats: {result.threat_names[:3]}")
        print(f"  Risk score: {integration.get_url_risk_score(url):.2f}")
        if result.error:
            print(f"  Error: {result.error}")
