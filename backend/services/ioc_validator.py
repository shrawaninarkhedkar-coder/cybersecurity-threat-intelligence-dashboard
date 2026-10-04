"""
IOC Validation Engine
Defensive Cybersecurity Education & SOC Analytics Platform

Performs strict syntactic and format validation on potential threat indicators
(IPv4, IPv6, Domain, URL, MD5, SHA-1, SHA-256, CVE ID).

IMPORTANT NOTE:
Validation answers "Is this syntactically a valid indicator format?"
It does NOT assert malice or execute network connections.
"""

import ipaddress
import re
from urllib.parse import urlparse

# Regular Expressions for indicator validation
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
)
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")
CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

def is_valid_ipv4(value: str) -> bool:
    """Validate IPv4 address format."""
    try:
        ip = ipaddress.IPv4Address(value.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False

def is_valid_ipv6(value: str) -> bool:
    """Validate IPv6 address format."""
    try:
        ip = ipaddress.IPv6Address(value.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False

def is_valid_domain(value: str) -> bool:
    """Validate domain name syntax."""
    val = value.strip().lower()
    if len(val) > 253 or len(val) < 3:
        return False
    # Allow .invalid top level domain for defensive simulation
    if val.endswith(".invalid") or val.endswith(".example") or val.endswith(".test"):
        parts = val.split(".")
        return all(len(p) > 0 and re.match(r"^[a-zA-Z0-9-]+$", p) for p in parts)
    return bool(DOMAIN_REGEX.match(val))

def is_valid_url(value: str) -> bool:
    """Validate URL syntax without initiating network requests."""
    val = value.strip()
    try:
        parsed = urlparse(val)
        if parsed.scheme.lower() not in ("http", "https"):
            return False
        if not parsed.netloc:
            return False
        return True
    except Exception:
        return False

def is_valid_hash(value: str) -> tuple[bool, str]:
    """Validate MD5, SHA-1, or SHA-256 hash syntax."""
    val = value.strip()
    if SHA256_REGEX.match(val):
        return True, "SHA-256"
    elif SHA1_REGEX.match(val):
        return True, "SHA-1"
    elif MD5_REGEX.match(val):
        return True, "MD5"
    return False, "UNKNOWN"

def is_valid_cve(value: str) -> bool:
    """Validate CVE identifier syntax (CVE-YYYY-NNNN+)."""
    return bool(CVE_REGEX.match(value.strip().upper()))

def is_valid_email(value: str) -> bool:
    """Validate email address syntax."""
    return bool(EMAIL_REGEX.match(value.strip()))

def validate_indicator(value: str, expected_type: str = None) -> dict:
    """
    Unified validation routine returning syntax correctness,
    detected indicator type, normalized string, and analysis notes.
    """
    if not value or not isinstance(value, str):
        return {
            "valid": False,
            "indicator_type": "UNKNOWN",
            "normalized_value": "",
            "validation_notes": "Empty or non-string indicator value supplied."
        }

    raw = value.strip()

    # Check IPv4
    if is_valid_ipv4(raw):
        detected_type = "IP ADDRESS"
        notes = "Valid IPv4 address syntax."
        # Add context for RFC 5737 documentation / lab IPs
        if raw.startswith("192.0.2.") or raw.startswith("198.51.100.") or raw.startswith("203.0.113."):
            notes += " Reserved RFC 5737 safe documentation/lab prefix."
        return {
            "valid": True,
            "indicator_type": detected_type,
            "normalized_value": raw,
            "validation_notes": notes
        }

    # Check IPv6
    if is_valid_ipv6(raw):
        detected_type = "IPV6"
        notes = "Valid IPv6 address syntax."
        if raw.lower().startswith("2001:db8:"):
            notes += " Reserved RFC 3849 safe documentation prefix."
        return {
            "valid": True,
            "indicator_type": detected_type,
            "normalized_value": raw.lower(),
            "validation_notes": notes
        }

    # Check CVE ID
    if is_valid_cve(raw):
        return {
            "valid": True,
            "indicator_type": "CVE ID",
            "normalized_value": raw.upper(),
            "validation_notes": "Valid Common Vulnerabilities and Exposures (CVE) format."
        }

    # Check Hashes
    is_hash, hash_type = is_valid_hash(raw)
    if is_hash:
        return {
            "valid": True,
            "indicator_type": "FILE HASH",
            "normalized_value": raw.lower(),
            "validation_notes": f"Valid cryptographic {hash_type} hexadecimal format."
        }

    # Check URL
    if is_valid_url(raw):
        return {
            "valid": True,
            "indicator_type": "URL",
            "normalized_value": raw,
            "validation_notes": "Valid HTTP/HTTPS URL format."
        }

    # Check Email
    if is_valid_email(raw):
        return {
            "valid": True,
            "indicator_type": "EMAIL/SENDER DOMAIN",
            "normalized_value": raw.lower(),
            "validation_notes": "Valid email address format."
        }

    # Check Domain
    if is_valid_domain(raw):
        return {
            "valid": True,
            "indicator_type": "DOMAIN",
            "normalized_value": raw.lower(),
            "validation_notes": "Valid Fully Qualified Domain Name (FQDN) syntax."
        }

    return {
        "valid": False,
        "indicator_type": "INVALID",
        "normalized_value": raw,
        "validation_notes": "Unrecognized indicator format. Does not match IP, Domain, URL, Hash, or CVE syntax."
    }
