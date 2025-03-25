"""
PhishShield External Scan Store — In-Memory Result Storage

Stores background DNS + VirusTotal scan results keyed by scan_id.
Also maintains a per-URL result cache with configurable TTL.

Designed for demo/development use. Can be replaced with Redis later.
"""

import os
import time
import datetime
from typing import Optional, List, Dict, Any


# ─── Configuration ──────────────────────────────────────────────────────────

EXTERNAL_SCAN_CACHE_TTL = int(os.environ.get("EXTERNAL_SCAN_CACHE_TTL_SECONDS", "3600"))
VT_COMPLETED_CACHE_TTL = 86400  # 24 hours for completed VT reports


# ─── Scan Record Schema ────────────────────────────────────────────────────

def _new_scan_record(scan_id: str, urls: List[str]) -> dict:
    now = datetime.datetime.utcnow().isoformat()
    return {
        "scan_id": scan_id,
        "status": "queued",       # queued → running → completed | failed
        "urls": urls,
        "results": [],
        "external_risk_score": 0,
        "risk_label": "no_major_external_warning",
        "error": None,
        "created_at": now,
        "updated_at": now,
    }


# ─── In-Memory Store ───────────────────────────────────────────────────────

_scan_store: Dict[str, dict] = {}
_SCAN_TTL = 7200  # 2 hours — prune old entries

# ─── VT-specific stores ────────────────────────────────────────────────────
# Maps URL → VT normalized result for real VirusTotal data
_vt_url_results: Dict[str, dict] = {}  # Keyed by normalized URL
_vt_submission_ids: Dict[str, str] = {}  # Maps URL → analysis_id for tracking


def create_scan(scan_id: str, urls: List[str]) -> dict:
    """Create a new external scan record with status=queued."""
    record = _new_scan_record(scan_id, urls)
    _scan_store[scan_id] = record
    _prune_expired()
    return record


def get_scan(scan_id: str) -> Optional[dict]:
    """Retrieve an external scan record by ID. Returns None if not found/expired."""
    entry = _scan_store.get(scan_id)
    if not entry:
        return None
    age = (datetime.datetime.utcnow() -
           datetime.datetime.fromisoformat(entry["created_at"])).total_seconds()
    if age > _SCAN_TTL:
        del _scan_store[scan_id]
        return None
    return entry


def update_scan(scan_id: str, **kwargs) -> Optional[dict]:
    """Update fields on an existing scan record."""
    entry = _scan_store.get(scan_id)
    if not entry:
        return None
    for key, value in kwargs.items():
        if key in entry:
            entry[key] = value
    entry["updated_at"] = datetime.datetime.utcnow().isoformat()
    return entry


def _prune_expired():
    """Remove scans older than _SCAN_TTL."""
    now = datetime.datetime.utcnow()
    expired = []
    for sid, entry in _scan_store.items():
        age = (now - datetime.datetime.fromisoformat(entry["created_at"])).total_seconds()
        if age > _SCAN_TTL:
            expired.append(sid)
    for sid in expired:
        del _scan_store[sid]


# ─── VirusTotal Result Cache ────────────────────────────────────────────────

def save_vt_result(url: str, vt_result: dict) -> None:
    """
    Cache a VirusTotal normalized result for a URL.
    Determines TTL based on completion status.
    """
    normalized_url = url.lower()
    status = vt_result.get("status", "unknown")

    # Use 24-hour TTL for completed reports, 1 hour for others
    ttl = VT_COMPLETED_CACHE_TTL if status == "completed" else EXTERNAL_SCAN_CACHE_TTL

    _vt_url_results[normalized_url] = {
        "result": vt_result,
        "ts": time.time(),
        "ttl": ttl,
    }


def get_vt_result(url: str) -> Optional[dict]:
    """
    Retrieve cached VT result for a URL if it's still valid.
    Returns None if not found or expired.
    """
    normalized_url = url.lower()
    entry = _vt_url_results.get(normalized_url)
    if not entry:
        return None

    age = time.time() - entry["ts"]
    if age > entry.get("ttl", EXTERNAL_SCAN_CACHE_TTL):
        del _vt_url_results[normalized_url]
        return None

    return entry["result"]


def save_vt_submission(url: str, analysis_id: str) -> None:
    """Track a VirusTotal URL submission by analysis_id."""
    _vt_submission_ids[url.lower()] = analysis_id


def get_vt_submission_id(url: str) -> Optional[str]:
    """Retrieve tracked analysis_id for a URL."""
    return _vt_submission_ids.get(url.lower())


def clear_vt_cache():
    """Clear all VT caches (for testing)."""
    _vt_url_results.clear()
    _vt_submission_ids.clear()


# ─── Per-URL Result Cache (Old Format - Deprecated) ───────────────────────

_url_cache: Dict[str, dict] = {}


def cache_url_result(url: str, result: dict):
    """Cache a per-URL external scan result."""
    _url_cache[url.lower()] = {
        "result": result,
        "ts": time.time(),
    }


def get_cached_url_result(url: str) -> Optional[dict]:
    """Get a cached URL result if it exists and is within TTL."""
    entry = _url_cache.get(url.lower())
    if not entry:
        return None
    if time.time() - entry["ts"] > EXTERNAL_SCAN_CACHE_TTL:
        del _url_cache[url.lower()]
        return None
    return entry["result"]
