"""
PhishShield External Scanner — Background DNS + VirusTotal Orchestrator

This module runs as a FastAPI BackgroundTask. For each URL:
  1. Extract domain
  2. Run enhanced DNS scan (A, AAAA, MX, NS, TXT, SPF, DMARC via dnspython)
  3. Get VirusTotal domain report
  4. Submit URL to VirusTotal for scanning
  5. Wait for VirusTotal analysis
  6. Calculate per-URL risk score
  7. Store results

Risk scores are supportive signals only — they do NOT override ML verdicts.
"""

import os
import time
import logging
import datetime
from typing import List, Optional

import dns.resolver
import dns.exception

from url_tools import extract_domain
from virustotal_client import vt_client
from external_scan_store import (
    update_scan,
    cache_url_result,
    get_cached_url_result,
)


logger = logging.getLogger("PhishShield-ExtScan")

# ─── Configuration ──────────────────────────────────────────────────────────────

VT_ANALYSIS_WAIT = int(os.environ.get("VT_ANALYSIS_WAIT_SECONDS", "8"))


# ─── Enhanced DNS Scanner (using dnspython) ─────────────────────────────────────

def _dns_query(domain: str, rdtype: str, timeout: float = 4.0) -> List[str]:
    """Run a single DNS query. Returns list of record strings or empty list."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, rdtype)
        return [str(rdata) for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []


def enhanced_dns_scan(domain: str) -> dict:
    """
    Full DNS scan for a domain using dnspython.
    Returns A, AAAA, MX, NS, TXT records plus SPF and DMARC status.
    Never crashes — all failures return empty records.
    """
    result = {
        "domain": domain,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "spf_record": None,
        "dmarc_record": None,
        "has_spf": False,
        "has_dmarc": False,
    }

    try:
        result["a_records"] = _dns_query(domain, "A")
        result["aaaa_records"] = _dns_query(domain, "AAAA")
        result["mx_records"] = _dns_query(domain, "MX")
        result["ns_records"] = _dns_query(domain, "NS")
        result["txt_records"] = _dns_query(domain, "TXT")

        # Extract SPF from TXT records
        for txt in result["txt_records"]:
            if "v=spf1" in txt.lower():
                result["spf_record"] = txt
                result["has_spf"] = True
                break

        # Check _dmarc.domain for DMARC record
        dmarc_records = _dns_query(f"_dmarc.{domain}", "TXT")
        for txt in dmarc_records:
            if "v=dmarc1" in txt.lower():
                result["dmarc_record"] = txt
                result["has_dmarc"] = True
                break

    except Exception as e:
        logger.error("Enhanced DNS scan error for %s: %s", domain, str(e))

    return result


# ─── Risk Scoring ───────────────────────────────────────────────────────────────

def calculate_url_risk_score(dns_result: dict, vt_domain: dict, vt_analysis: dict) -> int:
    """
    Calculate external risk score for a single URL (0–100).

    DNS scoring:
      - Missing A + AAAA records: +30
      - Missing NS:              +10
      - Missing MX:              +5
      - Missing SPF:             +5
      - Missing DMARC:           +5

    VirusTotal scoring:
      - Each malicious detection: +20 (max +60)
      - Each suspicious detection: +10 (max +30)
      - Rate limit / error:        result_unknown flag (don't treat as safe)
    """
    score = 0

    # DNS scoring
    if not dns_result.get("a_records") and not dns_result.get("aaaa_records"):
        score += 30
    if not dns_result.get("ns_records"):
        score += 10
    if not dns_result.get("mx_records"):
        score += 5
    if not dns_result.get("has_spf"):
        score += 5
    if not dns_result.get("has_dmarc"):
        score += 5

    # VirusTotal domain scoring
    if not vt_domain.get("skipped"):
        malicious = vt_domain.get("malicious", 0)
        suspicious = vt_domain.get("suspicious", 0)
        score += min(60, malicious * 20)
        score += min(30, suspicious * 10)

    # VirusTotal URL analysis scoring (additive from domain)
    if not vt_analysis.get("skipped"):
        malicious = vt_analysis.get("malicious", 0)
        suspicious = vt_analysis.get("suspicious", 0)
        score += min(60, malicious * 20)
        score += min(30, suspicious * 10)

    return min(100, score)


def get_risk_label(score: int) -> str:
    """Convert a numeric risk score to a human-readable label."""
    if score >= 75:
        return "high_external_risk"
    elif score >= 40:
        return "medium_external_risk"
    elif score >= 15:
        return "low_external_risk"
    else:
        return "no_major_external_warning"


# ─── Background Scan Orchestrator ───────────────────────────────────────────────

def run_external_scan(scan_id: str, urls: List[str]):
    """
    Background task entry point. Called by FastAPI BackgroundTasks.
    Scans each URL with DNS + VirusTotal, computes risk, stores result.
    """
    try:
        # Mark as running
        update_scan(scan_id, status="running")
        logger.info("External scan started: %s (%d URLs)", scan_id, len(urls))

        all_results = []
        max_risk = 0

        for url in urls:
            try:
                url_result = _scan_single_url(url)
                all_results.append(url_result)
                max_risk = max(max_risk, url_result.get("risk_score", 0))
            except Exception as e:
                logger.error("Error scanning URL %s: %s", url, str(e))
                all_results.append({
                    "url": url,
                    "domain": extract_domain(url) or "unknown",
                    "dns": {},
                    "virustotal_domain": {},
                    "virustotal_url": {},
                    "risk_score": 0,
                    "risk_label": "no_major_external_warning",
                    "error": str(e),
                })

        # Store final result
        update_scan(
            scan_id,
            status="completed",
            results=all_results,
            external_risk_score=max_risk,
            risk_label=get_risk_label(max_risk),
        )
        logger.info("External scan completed: %s — score=%d label=%s",
                     scan_id, max_risk, get_risk_label(max_risk))

    except Exception as e:
        logger.error("External scan FAILED: %s — %s", scan_id, str(e))
        update_scan(
            scan_id,
            status="failed",
            error=str(e),
        )


def _scan_single_url(url: str) -> dict:
    """
    Scan a single URL: DNS + VirusTotal domain + VirusTotal URL analysis.

    DEPRECATED: Use submit_urls_for_vt_scan() + poll_vt_analyses() for non-blocking flow.
    This method blocks waiting for VT analysis (not recommended for real-time use).
    """
    domain = extract_domain(url) or "unknown"

    # Check URL cache first
    cached = get_cached_url_result(url)
    if cached:
        logger.info("Cache hit for URL: %s", url)
        return cached

    # 1. Enhanced DNS scan
    dns_result = enhanced_dns_scan(domain) if domain != "unknown" else {}

    # 2. VirusTotal domain report
    vt_domain = vt_client.get_domain_report(domain) if domain != "unknown" else {"skipped": True, "reason": "no_domain"}

    # 3. Submit URL to VirusTotal
    vt_submission = vt_client.submit_url_scan(url)

    # 4. Wait for analysis if submission succeeded
    vt_analysis: dict = {"skipped": True, "reason": "no_submission"}
    if vt_submission.get("submitted") and vt_submission.get("analysis_id"):
        time.sleep(VT_ANALYSIS_WAIT)
        vt_analysis = vt_client.get_url_analysis(vt_submission["analysis_id"])

    # 5. Calculate risk score
    risk_score = calculate_url_risk_score(dns_result, vt_domain, vt_analysis)
    risk_label = get_risk_label(risk_score)

    # Build result
    url_result = {
        "url": url,
        "domain": domain,
        "dns": dns_result,
        "virustotal_domain": vt_domain,
        "virustotal_url": vt_analysis,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "error": None,
    }

    # Cache the result
    cache_url_result(url, url_result)

    return url_result


# ─── Non-Blocking VirusTotal Submission ──────────────────────────────────────

def submit_urls_for_vt_scan(urls: List[str]) -> List[dict]:
    """
    Submit multiple URLs to VirusTotal for scanning WITHOUT blocking.

    Returns immediately with queued status and analysis_ids.
    Caller should poll get_vt_analyses() to check completion.

    Returns list of:
    {
        "url": str,
        "analysis_id": str or None,
        "status": "queued" or "failed",
        "queued_at": ISO timestamp,
        "error": str or None
    }
    """
    from external_scan_store import save_vt_result, save_vt_submission

    results = []
    now = datetime.datetime.utcnow().isoformat()

    for url in urls:
        try:
            # Submit to VirusTotal
            submission = vt_client.submit_url_scan(url)

            if submission.get("submitted") and submission.get("analysis_id"):
                analysis_id = submission["analysis_id"]

                # Save submission tracking
                save_vt_submission(url, analysis_id)

                # Create queued VT result
                queued_result = {
                    "url": url,
                    "domain": extract_domain(url) or "unknown",
                    "status": "queued",
                    "analysis_id": analysis_id,
                    "queued_at": now,
                    "completed_at": None,
                    "queue_time_ms": 0,
                    "total_time_ms": 0,
                    "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "timeout": 0},
                    "risk_level": "UNKNOWN",
                    "flagged_engines": [],
                    "permalink": f"https://www.virustotal.com/gui/url/{vt_client.get_url_id(url)}",
                    "raw_available": False,
                }

                # Cache the queued state
                save_vt_result(url, queued_result)

                results.append({
                    "url": url,
                    "analysis_id": analysis_id,
                    "status": "queued",
                    "queued_at": now,
                    "error": None,
                })
                logger.info("Submitted URL to VT: %s (analysis_id: %s)", url, analysis_id)
            else:
                error_msg = submission.get("error", "unknown")
                results.append({
                    "url": url,
                    "analysis_id": None,
                    "status": "failed",
                    "queued_at": None,
                    "error": error_msg,
                })
                logger.warning("Failed to submit URL to VT: %s (%s)", url, error_msg)

        except Exception as e:
            logger.error("Exception submitting URL %s: %s", url, str(e))
            results.append({
                "url": url,
                "analysis_id": None,
                "status": "failed",
                "queued_at": None,
                "error": str(e),
            })

    return results


def poll_vt_analyses(analysis_ids: List[str]) -> List[dict]:
    """
    Poll VirusTotal for analysis results.

    Returns list of normalized VT results (from cache or API).
    Results may have status: queued, processing, completed, failed, rate_limited
    """
    from external_scan_store import get_vt_result

    results = []
    now = datetime.datetime.utcnow().isoformat()

    for analysis_id in analysis_ids:
        try:
            # Get latest analysis status
            vt_response = vt_client.get_url_analysis(analysis_id)

            if vt_response.get("skipped"):
                logger.warning("VT analysis skipped for %s: %s", analysis_id, vt_response.get("reason"))
                results.append({
                    "analysis_id": analysis_id,
                    "status": "failed",
                    "error": vt_response.get("reason", "unknown"),
                })
                continue

            if vt_response.get("error"):
                if vt_response.get("error") == "rate_limit":
                    results.append({
                        "analysis_id": analysis_id,
                        "status": "rate_limited",
                        "error": "VirusTotal rate limited",
                    })
                else:
                    results.append({
                        "analysis_id": analysis_id,
                        "status": "failed",
                        "error": vt_response.get("error"),
                    })
                continue

            # Parse response
            status = vt_response.get("status", "unknown")
            results.append({
                "analysis_id": analysis_id,
                "status": status,
                "stats": vt_response.get("stats", {}),
            })

            logger.info("Polled VT analysis %s: status=%s", analysis_id, status)

        except Exception as e:
            logger.error("Exception polling VT analysis %s: %s", analysis_id, str(e))
            results.append({
                "analysis_id": analysis_id,
                "status": "failed",
                "error": str(e),
            })

    return results
