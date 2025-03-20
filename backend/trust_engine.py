"""
PhishShield Trust Engine — Verified Sender Intelligence

SECURITY PRINCIPLES:
1. Trust is ONE signal among many — NEVER forces a "safe" verdict alone
2. Exact domain matching only — no keyword/brand-name matching
3. Brand impersonation detection catches lookalikes
4. Sender ↔ Reply-To ↔ URL domain cross-verification
5. Trust score is a bounded contribution to the overall phishing probability
"""

import re
from urllib.parse import urlparse as _urlparse
from typing import List, Optional, Dict


# ─── Domain Helper ──────────────────────────────────────────────────────────────

def _extract_domain(url: str) -> Optional[str]:
    """Extract domain from a URL string safely."""
    try:
        if not url:
            return None
        c = url.strip()
        if not c.startswith(("http://", "https://")):
            c = "https://" + c
        d = _urlparse(c).hostname
        return d.lower().rstrip(".") if d else None
    except Exception:
        return None


# ─── Trusted Domain Registry ────────────────────────────────────────────────────

TRUSTED_DOMAINS: Dict[str, dict] = {
    # Google
    "google.com":        {"subdomains": ["mail", "accounts", "support", "ads", "cloud", "workspace", "meet", "drive", "docs", "calendar"], "category": "tech"},
    "gmail.com":         {"subdomains": [], "category": "tech"},
    "googlemail.com":    {"subdomains": [], "category": "tech"},
    "youtube.com":       {"subdomains": ["studio", "music"], "category": "tech"},
    # Microsoft
    "microsoft.com":     {"subdomains": ["support", "account", "office", "teams", "azure", "outlook", "onedrive"], "category": "tech"},
    "outlook.com":       {"subdomains": [], "category": "tech"},
    "hotmail.com":       {"subdomains": [], "category": "tech"},
    "live.com":          {"subdomains": [], "category": "tech"},
    "office365.com":     {"subdomains": [], "category": "tech"},
    "office.com":        {"subdomains": [], "category": "tech"},
    # Apple
    "apple.com":         {"subdomains": ["support", "id", "icloud", "store"], "category": "tech"},
    "icloud.com":        {"subdomains": [], "category": "tech"},
    # Amazon
    "amazon.com":        {"subdomains": ["aws", "support", "seller"], "category": "ecommerce"},
    "amazon.in":         {"subdomains": ["aws", "support", "seller"], "category": "ecommerce"},
    "amazon.co.uk":      {"subdomains": [], "category": "ecommerce"},
    "amazonaws.com":     {"subdomains": ["s3", "ec2", "ses", "sns"], "category": "cloud"},
    # Banks — India
    "sbi.co.in":         {"subdomains": ["onlinesbi", "retail"], "category": "bank"},
    "onlinesbi.sbi":     {"subdomains": [], "category": "bank"},
    "hdfcbank.com":      {"subdomains": ["netbanking"], "category": "bank"},
    "icicibank.com":     {"subdomains": ["infinity"], "category": "bank"},
    "axisbank.com":      {"subdomains": ["omni"], "category": "bank"},
    "kotak.com":         {"subdomains": ["netbanking"], "category": "bank"},
    "rbi.org.in":        {"subdomains": [], "category": "bank"},
    # Banks — Global
    "paypal.com":        {"subdomains": ["www"], "category": "finance"},
    "stripe.com":        {"subdomains": ["dashboard"], "category": "finance"},
    "chase.com":         {"subdomains": ["secure"], "category": "bank"},
    "bankofamerica.com": {"subdomains": ["secure"], "category": "bank"},
    "wellsfargo.com":    {"subdomains": ["www"], "category": "bank"},
    # Social
    "facebook.com":      {"subdomains": ["m", "business"], "category": "social"},
    "meta.com":          {"subdomains": ["about"], "category": "social"},
    "instagram.com":     {"subdomains": [], "category": "social"},
    "twitter.com":       {"subdomains": [], "category": "social"},
    "x.com":             {"subdomains": [], "category": "social"},
    "linkedin.com":      {"subdomains": ["www"], "category": "social"},
    # Other Tech
    "github.com":        {"subdomains": ["support"], "category": "tech"},
    "dropbox.com":       {"subdomains": ["www"], "category": "tech"},
    "zoom.us":           {"subdomains": ["us02web", "us04web"], "category": "tech"},
    "slack.com":         {"subdomains": [], "category": "tech"},
    "notion.so":         {"subdomains": [], "category": "tech"},
}

# ── Government Domain Patterns ──────────────────────────────────────────────────

GOV_DOMAIN_PATTERNS = [
    r"\.gov$", r"\.gov\.in$", r"\.gov\.uk$", r"\.gov\.au$",
    r"\.gc\.ca$", r"\.gov\.sg$", r"\.nic\.in$",
    r"\.edu$", r"\.edu\.in$", r"\.ac\.in$", r"\.mil$",
]

# ── Brand Impersonation Patterns ────────────────────────────────────────────────

BRAND_IMPERSONATION_PATTERNS = [
    (r"g[o0]{2}g[l1]e|go+g[l1]e|goog[l1]e[.\-]|googie|g00gle", "google"),
    (r"gma[i1l][l1]|gmai[l1][.\-]", "gmail"),
    (r"micros[o0]ft|micr[o0]s[o0]ft|microsft|micr0soft", "microsoft"),
    (r"[o0]ut[l1][o0]{2}k|outl00k", "outlook"),
    (r"app[l1]e[.\-]|app[l1]e[0-9]|aple[.\-]|appl[e3]", "apple"),
    (r"[i1]c[l1][o0]ud|ic[l1]oud", "icloud"),
    (r"amaz[o0]n[.\-]|amazn|amaz0n", "amazon"),
    (r"paypa[l1][.\-]|pay-?pa[l1]|payp[a@][l1]", "paypal"),
    (r"sbi[.\-]co|sbi-online|on[l1]inesbi", "sbi"),
    (r"hdfc[.\-]bank|hdfcb[a@]nk", "hdfc"),
    (r"[i1]c[i1]c[i1]bank|icicib[a@]nk", "icici"),
    (r"face[b6]o{1,2}k|faceb00k|facbook", "facebook"),
    (r"[l1]inked[i1]n|linkedln|l[i1]nkedin", "linkedin"),
    (r"secure-?bank|bank-?login|bank-?verify|bank-?update", "generic_bank"),
    (r"login-?secure|verify-?account|account-?update", "generic_phishing"),
]


# ─── Core Helpers ───────────────────────────────────────────────────────────────

def _get_base_domain(domain: str) -> str:
    """Extract registrable base domain. e.g. mail.google.com → google.com"""
    if not domain:
        return ""
    parts = domain.lower().rstrip(".").split(".")
    cc_slds = {"co", "com", "org", "net", "ac", "gov", "edu"}
    if len(parts) >= 3 and parts[-2] in cc_slds:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _get_subdomain(domain: str, base: str) -> str:
    """Get the subdomain prefix."""
    if domain == base:
        return ""
    if domain.endswith("." + base):
        return domain[:-(len(base) + 1)]
    return ""


# ─── Public Functions ───────────────────────────────────────────────────────────

def is_trusted_domain(domain: str) -> dict:
    """Check if a domain matches the trusted registry."""
    if not domain:
        return {"trusted": False, "base_domain": "", "category": "", "match_type": "none"}

    domain_lower = domain.lower().rstrip(".")
    base = _get_base_domain(domain_lower)

    if base in TRUSTED_DOMAINS:
        entry = TRUSTED_DOMAINS[base]
        subdomain = _get_subdomain(domain_lower, base)
        if not subdomain:
            return {"trusted": True, "base_domain": base, "category": entry["category"], "match_type": "exact"}
        sub_parts = subdomain.split(".")
        first_sub = sub_parts[-1]
        if first_sub in entry["subdomains"] or subdomain in entry["subdomains"]:
            return {"trusted": True, "base_domain": base, "category": entry["category"], "match_type": "subdomain"}
        return {"trusted": False, "base_domain": base, "category": entry["category"], "match_type": "unknown_subdomain"}

    for pattern in GOV_DOMAIN_PATTERNS:
        if re.search(pattern, domain_lower):
            return {"trusted": True, "base_domain": base, "category": "government", "match_type": "gov_pattern"}

    return {"trusted": False, "base_domain": base, "category": "", "match_type": "none"}


def detect_brand_impersonation(domain: str) -> list:
    """Check if a domain impersonates a known brand."""
    if not domain:
        return []
    domain_lower = domain.lower()
    base = _get_base_domain(domain_lower)
    if base in TRUSTED_DOMAINS:
        return []  # Actual trusted domain, not impersonation
    detections = []
    for pattern, brand in BRAND_IMPERSONATION_PATTERNS:
        if re.search(pattern, domain_lower, re.IGNORECASE):
            detections.append({
                "brand": brand,
                "domain": domain,
                "pattern": "typosquatting/homograph",
                "severity": "critical",
            })
    return detections


def cross_check_domains(sender_email: str, reply_to: str, urls: list) -> dict:
    """Cross-check sender domain against reply-to and URL domains."""
    result = {
        "sender_domain": "",
        "reply_to_domain": "",
        "url_domains": [],
        "sender_reply_to_mismatch": False,
        "sender_url_mismatch": False,
        "mismatched_url_domains": [],
        "warnings": [],
    }

    if sender_email and "@" in sender_email:
        result["sender_domain"] = sender_email.split("@")[-1].strip(">").strip().lower()
    if reply_to and "@" in reply_to:
        result["reply_to_domain"] = reply_to.split("@")[-1].strip(">").strip().lower()

    for url in (urls or []):
        d = _extract_domain(url)
        if d:
            result["url_domains"].append(d)

    # Sender vs Reply-To
    if result["sender_domain"] and result["reply_to_domain"]:
        sender_base = _get_base_domain(result["sender_domain"])
        reply_base = _get_base_domain(result["reply_to_domain"])
        if sender_base != reply_base:
            result["sender_reply_to_mismatch"] = True
            result["warnings"].append(
                f"Sender domain ({result['sender_domain']}) differs from Reply-To ({result['reply_to_domain']})"
            )

    # Sender vs URL domains
    if result["sender_domain"]:
        sender_base = _get_base_domain(result["sender_domain"])
        for url_domain in result["url_domains"]:
            url_base = _get_base_domain(url_domain)
            if url_base != sender_base and url_base not in TRUSTED_DOMAINS:
                result["sender_url_mismatch"] = True
                result["mismatched_url_domains"].append(url_domain)
        if result["mismatched_url_domains"]:
            result["warnings"].append(
                f"URL domains {result['mismatched_url_domains']} don't match sender ({result['sender_domain']})"
            )

    return result


def evaluate_trust(sender_email: str, reply_to: str, urls: list) -> dict:
    """
    Evaluate overall trust for an email.
    Returns trust_score (0.0–1.0) plus detailed signals.
    Trust is ONE signal — never forces a safe verdict alone.
    """
    trust_signals = []
    warnings = []
    trust_score = 0.0

    # 1. Sender domain trust
    sender_domain = ""
    if sender_email and "@" in sender_email:
        sender_domain = sender_email.split("@")[-1].strip(">").strip().lower()

    sender_trust = is_trusted_domain(sender_domain)

    if sender_trust["trusted"]:
        trust_score += 0.4
        trust_signals.append(f"Sender domain '{sender_domain}' is a verified {sender_trust['category']} domain")
    elif sender_trust["match_type"] == "unknown_subdomain":
        trust_score += 0.1
        warnings.append(f"Sender uses unrecognized subdomain of trusted domain: {sender_domain}")

    # 2. Brand impersonation check
    all_impersonations = []
    sender_imps = detect_brand_impersonation(sender_domain)
    all_impersonations.extend(sender_imps)

    for url in (urls or []):
        d = _extract_domain(url)
        if d:
            url_imps = detect_brand_impersonation(d)
            all_impersonations.extend(url_imps)

    if all_impersonations:
        trust_score = max(0.0, trust_score - 0.3)
        for imp in all_impersonations:
            warnings.append(f"Brand impersonation detected: '{imp['domain']}' mimics {imp['brand']}")

    # 3. Cross-domain verification
    cross = cross_check_domains(sender_email, reply_to, urls)
    if cross["sender_reply_to_mismatch"]:
        trust_score = max(0.0, trust_score - 0.2)
        warnings.extend(cross["warnings"])
    if cross["sender_url_mismatch"] and not sender_trust["trusted"]:
        trust_score = max(0.0, trust_score - 0.1)

    # 4. Reply-To trust
    if reply_to and "@" in reply_to:
        reply_to_domain = reply_to.split("@")[-1].strip(">").strip().lower()
        reply_trust = is_trusted_domain(reply_to_domain)
        if reply_trust["trusted"] and sender_trust["trusted"]:
            trust_score += 0.1
            trust_signals.append(f"Reply-To domain '{reply_to_domain}' is also verified")
        elif reply_trust["trusted"] and not sender_trust["trusted"]:
            warnings.append(f"Reply-To is trusted ({reply_to_domain}) but sender is not — suspicious")

    # 5. URL domain trust
    trusted_url_count = 0
    for url in (urls or []):
        d = _extract_domain(url)
        if d:
            url_trust = is_trusted_domain(d)
            if url_trust["trusted"]:
                trusted_url_count += 1
    if trusted_url_count > 0 and sender_trust["trusted"]:
        trust_score += 0.1
        trust_signals.append(f"{trusted_url_count} URL(s) point to verified domains")

    # Clamp
    trust_score = round(max(0.0, min(1.0, trust_score)), 3)

    return {
        "trust_score": trust_score,
        "is_trusted_sender": sender_trust["trusted"],
        "sender_trust": sender_trust,
        "brand_impersonation": all_impersonations,
        "cross_check": cross,
        "trust_signals": trust_signals,
        "warnings": warnings,
    }
