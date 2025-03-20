"""
PhishShield DNS Resolver — Live Domain Verification

Performs per-URL DNS resolution with:
- socket-based A record lookup
- 3-second timeout per domain
- In-memory result caching (5 min TTL)
- Per-domain status: resolved / unresolved / timeout / error
- Response time measurement

DNS resolution is ONE signal — a resolved domain can still be phishing.
"""

import socket
import time
import re
from urllib.parse import urlparse
from typing import List, Optional
from dataclasses import dataclass, field, asdict


# ─── Cache ──────────────────────────────────────────────────────────────────────

_dns_cache: dict = {}
_DNS_CACHE_TTL = 300  # 5 minutes


def _cache_get(domain: str) -> Optional[dict]:
    entry = _dns_cache.get(domain)
    if entry and time.time() - entry["ts"] < _DNS_CACHE_TTL:
        return entry["result"]
    if entry:
        del _dns_cache[domain]
    return None


def _cache_set(domain: str, result: dict):
    _dns_cache[domain] = {"result": result, "ts": time.time()}


# ─── Domain Extraction ──────────────────────────────────────────────────────────

def extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL, handling edge cases."""
    try:
        if not url:
            return None
        cleaned = url.strip()
        if not cleaned.startswith(("http://", "https://")):
            cleaned = "https://" + cleaned
        parsed = urlparse(cleaned)
        domain = parsed.hostname
        if domain:
            return domain.lower().rstrip(".")
        return None
    except Exception:
        return None


def extract_domains_from_urls(urls: List[str]) -> List[str]:
    """Extract unique domains from a list of URLs."""
    domains = set()
    for url in urls:
        d = extract_domain(url)
        if d:
            domains.add(d)
    return list(domains)


# ─── DNS Resolution ─────────────────────────────────────────────────────────────

def resolve_single_domain(domain: str, timeout: float = 3.0) -> dict:
    """
    Resolve a single domain. Returns structured result.
    
    DNS status values:
    - resolved: A record found
    - unresolved: No A record / NXDOMAIN
    - timeout: Lookup exceeded timeout
    - error: Unexpected error
    """
    cached = _cache_get(domain)
    if cached:
        return {**cached, "from_cache": True}

    start = time.time()
    result = {
        "domain": domain,
        "resolves": False,
        "ip": None,
        "dns_status": "error",
        "response_time_ms": 0,
        "from_cache": False,
    }

    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        ip = socket.gethostbyname(domain)
        elapsed = (time.time() - start) * 1000

        result["resolves"] = True
        result["ip"] = ip
        result["dns_status"] = "resolved"
        result["response_time_ms"] = round(elapsed, 1)

    except socket.gaierror:
        result["dns_status"] = "unresolved"
        result["response_time_ms"] = round((time.time() - start) * 1000, 1)

    except socket.timeout:
        result["dns_status"] = "timeout"
        result["response_time_ms"] = round(timeout * 1000, 1)

    except Exception as e:
        result["dns_status"] = "error"
        result["response_time_ms"] = round((time.time() - start) * 1000, 1)

    finally:
        socket.setdefaulttimeout(old_timeout)

    _cache_set(domain, result)
    return result


def resolve_domains(urls: List[str]) -> List[dict]:
    """
    Resolve all unique domains extracted from URLs.
    Returns a list of DNS result dicts.
    """
    domains = extract_domains_from_urls(urls)
    results = []
    for domain in domains:
        r = resolve_single_domain(domain)
        results.append(r)
    return results


def resolve_sender_domain(sender_email: str) -> Optional[dict]:
    """Resolve the sender's email domain."""
    if not sender_email or "@" not in sender_email:
        return None
    domain = sender_email.split("@")[-1].strip(">").strip().lower()
    if not domain:
        return None
    return resolve_single_domain(domain)


# ─── Summary Helpers ────────────────────────────────────────────────────────────

def dns_summary(results: List[dict]) -> dict:
    """Generate a summary of DNS resolution results."""
    total = len(results)
    resolved = sum(1 for r in results if r["resolves"])
    unresolved = sum(1 for r in results if r["dns_status"] == "unresolved")
    timed_out = sum(1 for r in results if r["dns_status"] == "timeout")
    errors = sum(1 for r in results if r["dns_status"] == "error")

    return {
        "total_domains": total,
        "resolved": resolved,
        "unresolved": unresolved,
        "timed_out": timed_out,
        "errors": errors,
        "all_resolved": resolved == total and total > 0,
    }
