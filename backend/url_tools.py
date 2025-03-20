"""
PhishShield URL Tools — Extraction, Normalization & Safety Filtering

Provides:
  - URL extraction from raw email body text
  - Normalization (scheme injection, deduplication)
  - Private/internal target blocking (localhost, RFC-1918, link-local, etc.)
  - Domain extraction from URLs

Used by the external scanner to prepare URLs before DNS + VirusTotal checks.
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Optional, Set


# ─── URL Regex ──────────────────────────────────────────────────────────────────
# Matches http(s) URLs and bare www. domains in free-form text.
_URL_PATTERN = re.compile(
    r'(?:https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+)',
    re.IGNORECASE,
)


# ─── Private / Blocked Hostnames ────────────────────────────────────────────────
_BLOCKED_HOSTNAMES: Set[str] = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
}


# ─── Public API ─────────────────────────────────────────────────────────────────

def extract_urls_from_text(text: str) -> List[str]:
    """Extract raw URL strings from free-form text (email body, subject, etc.)."""
    if not text:
        return []
    return _URL_PATTERN.findall(text)


def normalize_url(url: str) -> Optional[str]:
    """
    Normalize a URL string:
      - Strip whitespace
      - Add https:// if starts with www.
      - Reject unsupported schemes (only http/https allowed)
      - Strip trailing punctuation artifacts from regex extraction
    Returns None if the URL is invalid or unsupported.
    """
    if not url:
        return None

    cleaned = url.strip().rstrip(".,;:!?)>]}'\"")

    # Add scheme for bare www. URLs
    if cleaned.lower().startswith("www."):
        cleaned = "https://" + cleaned

    # Only allow http and https
    try:
        parsed = urlparse(cleaned)
        if parsed.scheme not in ("http", "https"):
            return None
        if not parsed.hostname:
            return None
    except Exception:
        return None

    return cleaned


def extract_domain(url: str) -> Optional[str]:
    """Extract the hostname (domain) from a URL string."""
    try:
        normalized = normalize_url(url)
        if not normalized:
            return None
        parsed = urlparse(normalized)
        domain = parsed.hostname
        if domain:
            return domain.lower().rstrip(".")
        return None
    except Exception:
        return None


def is_private_target(hostname: str) -> bool:
    """
    Check if a hostname or IP resolves to a private, loopback, link-local,
    multicast, or reserved address that should NEVER be sent to external
    scanning services.
    """
    if not hostname:
        return True

    hostname_lower = hostname.lower().rstrip(".")

    # Block known private hostnames
    if hostname_lower in _BLOCKED_HOSTNAMES:
        return True

    # Check if hostname is an IP address
    try:
        addr = ipaddress.ip_address(hostname_lower)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )
    except ValueError:
        pass  # Not an IP — it's a domain name, which is fine

    return False


def deduplicate_urls(urls: List[str]) -> List[str]:
    """Deduplicate URLs preserving order."""
    seen: Set[str] = set()
    result: List[str] = []
    for url in urls:
        lower = url.lower()
        if lower not in seen:
            seen.add(lower)
            result.append(url)
    return result


def prepare_urls_for_scanning(
    request_urls: Optional[List[str]],
    body_text: str = "",
) -> List[str]:
    """
    Master function: Extract URLs from request + body, normalize, deduplicate,
    and filter out private/internal targets.

    Returns a clean list of scannable URLs.
    """
    raw_urls: List[str] = []

    # Collect from request payload
    if request_urls:
        raw_urls.extend(request_urls)

    # Collect from email body text
    body_urls = extract_urls_from_text(body_text)
    raw_urls.extend(body_urls)

    # Normalize
    normalized: List[str] = []
    for url in raw_urls:
        n = normalize_url(url)
        if n:
            normalized.append(n)

    # Deduplicate
    unique = deduplicate_urls(normalized)

    # Filter out private/internal targets
    safe: List[str] = []
    for url in unique:
        domain = extract_domain(url)
        if domain and not is_private_target(domain):
            safe.append(url)

    return safe
