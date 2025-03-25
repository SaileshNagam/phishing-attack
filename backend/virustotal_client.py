"""
PhishShield VirusTotal Client — Secure API v3 Integration

Uses httpx for HTTP requests to the VirusTotal API v3.

Security rules:
  - API key loaded ONLY from environment variable VIRUSTOTAL_API_KEY
  - API key is NEVER logged, returned in responses, or exposed to frontend
  - Graceful skip if API key is missing
  - Safe handling of 404, 429 (rate limit), timeouts, and HTTP errors
"""

import os
import base64
import logging
import datetime
from typing import Optional

import httpx


logger = logging.getLogger("PhishShield-VT")

# ─── Constants ──────────────────────────────────────────────────────────────────

_VT_BASE_URL = "https://www.virustotal.com/api/v3"
_DEFAULT_TIMEOUT = 15.0  # seconds
_VT_GUI_BASE = "https://www.virustotal.com/gui/url"


# ─── Client ─────────────────────────────────────────────────────────────────────

class VirusTotalClient:
    """
    Synchronous VirusTotal API v3 client.
    All methods return clean dicts; never raise on API issues.
    """

    def __init__(self):
        self._api_key: Optional[str] = os.environ.get("VIRUSTOTAL_API_KEY", "").strip() or None
        if self._api_key:
            logger.info("VirusTotal API key loaded from environment.")
        else:
            logger.warning("VIRUSTOTAL_API_KEY not set. VirusTotal scans will be skipped.")

    @property
    def available(self) -> bool:
        return self._api_key is not None

    def _headers(self) -> dict:
        return {"x-apikey": self._api_key, "Accept": "application/json"}

    def _skip_result(self, reason: str = "no_api_key") -> dict:
        return {"skipped": True, "reason": reason}

    # ── Domain Report ───────────────────────────────────────────────────────

    def get_domain_report(self, domain: str) -> dict:
        """
        GET /domains/{domain}
        Returns domain reputation stats or skip/error dict.
        """
        if not self.available:
            return self._skip_result("no_api_key")

        url = f"{_VT_BASE_URL}/domains/{domain}"
        try:
            with httpx.Client(timeout=_DEFAULT_TIMEOUT) as client:
                resp = client.get(url, headers=self._headers())

            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "skipped": False,
                    "domain": domain,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": attrs.get("reputation", 0),
                    "categories": attrs.get("categories", {}),
                }

            if resp.status_code == 404:
                return {"skipped": False, "domain": domain, "error": "not_found",
                        "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}

            if resp.status_code == 429:
                logger.warning("VirusTotal rate limit hit for domain: %s", domain)
                return {"skipped": False, "domain": domain, "error": "rate_limit",
                        "result_unknown": True, "malicious": 0, "suspicious": 0}

            logger.warning("VT domain report HTTP %d for %s", resp.status_code, domain)
            return {"skipped": False, "domain": domain, "error": f"http_{resp.status_code}",
                    "result_unknown": True, "malicious": 0, "suspicious": 0}

        except httpx.TimeoutException:
            logger.warning("VT domain report timeout for %s", domain)
            return {"skipped": False, "domain": domain, "error": "timeout",
                    "result_unknown": True, "malicious": 0, "suspicious": 0}
        except Exception as e:
            logger.error("VT domain report error for %s: %s", domain, str(e))
            return {"skipped": False, "domain": domain, "error": "exception",
                    "result_unknown": True, "malicious": 0, "suspicious": 0}

    # ── URL Scan Submission ─────────────────────────────────────────────────

    def submit_url_scan(self, target_url: str) -> dict:
        """
        POST /urls — submit a URL for scanning.
        Returns the analysis ID or skip/error dict.
        """
        if not self.available:
            return self._skip_result("no_api_key")

        url = f"{_VT_BASE_URL}/urls"
        try:
            with httpx.Client(timeout=_DEFAULT_TIMEOUT) as client:
                resp = client.post(url, headers=self._headers(), data={"url": target_url})

            if resp.status_code == 200:
                data = resp.json()
                analysis_id = data.get("data", {}).get("id", "")
                return {"skipped": False, "analysis_id": analysis_id, "submitted": True}

            if resp.status_code == 429:
                logger.warning("VT rate limit on URL submit: %s", target_url)
                return {"skipped": False, "error": "rate_limit", "submitted": False, "result_unknown": True}

            logger.warning("VT URL submit HTTP %d for %s", resp.status_code, target_url)
            return {"skipped": False, "error": f"http_{resp.status_code}", "submitted": False}

        except httpx.TimeoutException:
            logger.warning("VT URL submit timeout for %s", target_url)
            return {"skipped": False, "error": "timeout", "submitted": False, "result_unknown": True}
        except Exception as e:
            logger.error("VT URL submit error for %s: %s", target_url, str(e))
            return {"skipped": False, "error": "exception", "submitted": False}

    # ── URL Analysis Result ─────────────────────────────────────────────────

    def get_url_analysis(self, analysis_id: str) -> dict:
        """
        GET /analyses/{id} — get the result of a submitted URL scan.
        """
        if not self.available:
            return self._skip_result("no_api_key")

        if not analysis_id:
            return {"skipped": False, "error": "no_analysis_id", "malicious": 0, "suspicious": 0}

        url = f"{_VT_BASE_URL}/analyses/{analysis_id}"
        try:
            with httpx.Client(timeout=_DEFAULT_TIMEOUT) as client:
                resp = client.get(url, headers=self._headers())

            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("stats", {})
                status = attrs.get("status", "unknown")
                return {
                    "skipped": False,
                    "status": status,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                }

            if resp.status_code == 404:
                return {"skipped": False, "error": "not_found", "malicious": 0, "suspicious": 0}

            if resp.status_code == 429:
                logger.warning("VT rate limit on analysis: %s", analysis_id)
                return {"skipped": False, "error": "rate_limit",
                        "result_unknown": True, "malicious": 0, "suspicious": 0}

            logger.warning("VT analysis HTTP %d for %s", resp.status_code, analysis_id)
            return {"skipped": False, "error": f"http_{resp.status_code}",
                    "result_unknown": True, "malicious": 0, "suspicious": 0}

        except httpx.TimeoutException:
            logger.warning("VT analysis timeout for %s", analysis_id)
            return {"skipped": False, "error": "timeout",
                    "result_unknown": True, "malicious": 0, "suspicious": 0}
        except Exception as e:
            logger.error("VT analysis error for %s: %s", analysis_id, str(e))
            return {"skipped": False, "error": "exception",
                    "result_unknown": True, "malicious": 0, "suspicious": 0}

    # ── URL ID Encoding ─────────────────────────────────────────────────────

    @staticmethod
    def get_url_id(url: str) -> str:
        """
        Generate a VirusTotal URL ID from a URL.
        VT uses base64url encoding of the URL (without padding).
        """
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    # ── Normalized VT Response ──────────────────────────────────────────────

    def normalize_vt_response(self, url: str, analysis_id: str, raw_result: dict,
                            queued_at: Optional[str] = None,
                            completed_at: Optional[str] = None) -> dict:
        """
        Normalize a VirusTotal analysis result into PhishShield format.

        Returns standardized dict with:
          - url, domain, status, analysis_id
          - queued_at, completed_at, queue_time_ms, total_time_ms
          - stats (malicious, suspicious, harmless, undetected, timeout)
          - risk_level, flagged_engines, permalink, raw_available
        """
        # Extract basic info from raw result
        status = raw_result.get("status", "unknown")
        stats = raw_result.get("stats", {})

        # Extract domain from URL
        try:
            domain = url.split("://")[-1].split("/")[0]
        except:
            domain = "unknown"

        # Calculate timing
        queue_time_ms = 0
        total_time_ms = 0
        if queued_at and completed_at:
            try:
                q_dt = datetime.datetime.fromisoformat(queued_at.replace("Z", "+00:00"))
                c_dt = datetime.datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
                queue_time_ms = int((c_dt - q_dt).total_seconds() * 1000)
                total_time_ms = queue_time_ms
            except:
                pass

        # Extract flagged engines
        flagged_engines = []
        if status == "completed":
            last_analysis = raw_result.get("last_analysis_results", {})
            for engine_name, result_data in last_analysis.items():
                if isinstance(result_data, dict):
                    category = result_data.get("category", "")
                    if category in ["malicious", "suspicious"]:
                        flagged_engines.append({
                            "engine_name": engine_name,
                            "category": category,
                            "result": result_data.get("engine_name", "")
                        })

        # Determine risk level
        risk_level = self._calculate_risk_level(
            stats.get("malicious", 0),
            stats.get("suspicious", 0),
            status
        )

        # Build normalized response
        return {
            "url": url,
            "domain": domain,
            "status": status,
            "analysis_id": analysis_id,
            "queued_at": queued_at,
            "completed_at": completed_at,
            "queue_time_ms": queue_time_ms,
            "total_time_ms": total_time_ms,
            "stats": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "timeout": stats.get("timeout", 0),
            },
            "risk_level": risk_level,
            "flagged_engines": flagged_engines[:10],  # Top 10 flagged engines
            "permalink": f"{_VT_GUI_BASE}/{self.get_url_id(url)}",
            "raw_available": status == "completed",
        }

    @staticmethod
    def _calculate_risk_level(malicious: int, suspicious: int, status: str) -> str:
        """Map VT detection counts to risk level."""
        if status in ["failed", "rate_limited"]:
            return "UNKNOWN"
        if status == "queued" or status == "processing":
            return "UNKNOWN"
        if malicious >= 5 or suspicious >= 8:
            return "CRITICAL"
        if malicious >= 2 or suspicious >= 4:
            return "HIGH"
        if malicious >= 1 or suspicious >= 1:
            return "MEDIUM"
        return "LOW"


# ─── Module-level singleton ─────────────────────────────────────────────────────

vt_client = VirusTotalClient()
