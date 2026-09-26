"""
CyberVerify AI
Module 5 - Evidence Processing & Correlation

This module processes the structured evidence produced by
Module 4 and extracts common indicators and relationships.

Module 4:
    Digital Evidence Extraction

Module 5:
    Evidence Processing & Correlation
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------

URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"`]+",
    re.IGNORECASE,
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

SHA256_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)

IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\b"
)


# ---------------------------------------------------------------------------
# Basic helpers
# ---------------------------------------------------------------------------

def _unique(values: list[str]) -> list[str]:
    """Remove duplicates while preserving original order."""
    seen: set[str] = set()
    result: list[str] = []

    for value in values:
        if not value:
            continue

        value = str(value).strip()

        if not value:
            continue

        key = value.lower()

        if key not in seen:
            seen.add(key)
            result.append(value)

    return result


def _is_valid_ip(value: str) -> bool:
    """Return True when value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _extract_urls(text: str) -> list[str]:
    """Extract HTTP/HTTPS URLs from text."""
    if not text:
        return []

    urls: list[str] = []

    for match in URL_PATTERN.findall(text):
        # Remove common punctuation that can follow a URL in text.
        cleaned = match.rstrip(".,;:!?)]}")

        if cleaned:
            urls.append(cleaned)

    return _unique(urls)


def _extract_emails(text: str) -> list[str]:
    """Extract email addresses from text."""
    if not text:
        return []

    return _unique(EMAIL_PATTERN.findall(text))


def _extract_ips(text: str) -> list[str]:
    """Extract valid IP addresses from text."""
    if not text:
        return []

    candidates = IP_PATTERN.findall(text)

    return _unique(
        [candidate for candidate in candidates if _is_valid_ip(candidate)]
    )


def _extract_domains(text: str) -> list[str]:
    """Extract domain names from text."""
    if not text:
        return []

    domains: list[str] = []

    for candidate in DOMAIN_PATTERN.findall(text):
        # Ignore values that are actually IPv4 addresses.
        if not _is_valid_ip(candidate):
            domains.append(candidate.lower().rstrip("."))

    return _unique(domains)


# ---------------------------------------------------------------------------
# Recursive text extraction
# ---------------------------------------------------------------------------

def _flatten_values(value: Any) -> list[str]:
    """
    Convert nested dictionaries/lists into searchable text values.

    This allows Module 5 to work with different evidence structures
    produced by URL, email, APK and QR analysis.
    """

    values: list[str] = []

    if value is None:
        return values

    if isinstance(value, str):
        values.append(value)
        return values

    if isinstance(value, (int, float, bool)):
        values.append(str(value))
        return values

    if isinstance(value, dict):
        for key, item in value.items():
            values.append(str(key))
            values.extend(_flatten_values(item))

        return values

    if isinstance(value, (list, tuple, set)):
        for item in value:
            values.extend(_flatten_values(item))

        return values

    return values


# ---------------------------------------------------------------------------
# Evidence normalization
# ---------------------------------------------------------------------------

def normalize_evidence(
    evidence: dict[str, Any] | None,
    evidence_type: str | None = None,
) -> dict[str, Any]:
    """
    Normalize extracted evidence into a predictable structure.

    Module 4 remains responsible for extracting the evidence.
    Module 5 prepares that evidence for correlation.
    """

    evidence = evidence or {}

    normalized_type = (
        evidence_type
        or evidence.get("evidenceType")
        or evidence.get("type")
        or "unknown"
    )

    normalized_type = str(normalized_type).lower()

    return {
        "evidenceType": normalized_type,
        "sha256": evidence.get("sha256"),
        "filename": evidence.get("filename"),
        "contentType": evidence.get("contentType"),
        "size": evidence.get("size"),
        "raw": evidence,
    }


# ---------------------------------------------------------------------------
# Indicator extraction
# ---------------------------------------------------------------------------

def extract_indicators(
    evidence: dict[str, Any] | None,
) -> dict[str, list[str]]:
    """
    Extract common investigation indicators from evidence.

    Indicators:
        - URLs
        - domains
        - IP addresses
        - email addresses
        - SHA-256 hashes
    """

    evidence = evidence or {}

    text_parts = _flatten_values(evidence)
    combined_text = "\n".join(text_parts)

    urls = _extract_urls(combined_text)
    domains = _extract_domains(combined_text)
    ips = _extract_ips(combined_text)
    emails = _extract_emails(combined_text)

    hashes: list[str] = []

    for match in SHA256_PATTERN.findall(combined_text):
        hashes.append(match.lower())

    # Explicit SHA-256 fields should also be captured.
    for key in ("sha256", "hash", "fileHash", "file_hash"):
        value = evidence.get(key)

        if isinstance(value, str) and SHA256_PATTERN.fullmatch(value.strip()):
            hashes.append(value.strip().lower())

    return {
        "urls": _unique(urls),
        "domains": _unique(domains),
        "ipAddresses": _unique(ips),
        "emailAddresses": _unique(emails),
        "sha256": _unique(hashes),
    }


# ---------------------------------------------------------------------------
# Relationship creation
# ---------------------------------------------------------------------------

def build_relationships(
    evidence: dict[str, Any] | None,
    indicators: dict[str, list[str]] | None = None,
) -> list[dict[str, Any]]:
    """
    Build simple relationships between the evidence and its indicators.

    Examples:
        Evidence -> SHA-256
        Evidence -> URL
        URL -> Domain
        URL -> IP
        Email -> Domain
    """

    evidence = evidence or {}
    indicators = indicators or extract_indicators(evidence)

    relationships: list[dict[str, Any]] = []

    evidence_type = str(
        evidence.get("evidenceType")
        or evidence.get("type")
        or "unknown"
    )

    sha256 = evidence.get("sha256")

    if sha256:
        relationships.append(
            {
                "source": evidence_type,
                "relationship": "identified_by",
                "targetType": "sha256",
                "target": str(sha256),
            }
        )

    # Evidence -> URL
    for url in indicators.get("urls", []):
        relationships.append(
            {
                "source": evidence_type,
                "relationship": "contains_url",
                "targetType": "url",
                "target": url,
            }
        )

        # URL -> Domain
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname

            if hostname:
                relationships.append(
                    {
                        "source": url,
                        "relationship": "resolves_to_domain",
                        "targetType": "domain",
                        "target": hostname.lower(),
                    }
                )

        except ValueError:
            pass

    # Evidence -> Domain
    for domain in indicators.get("domains", []):
        relationships.append(
            {
                "source": evidence_type,
                "relationship": "references_domain",
                "targetType": "domain",
                "target": domain,
            }
        )

    # Evidence -> IP
    for ip in indicators.get("ipAddresses", []):
        relationships.append(
            {
                "source": evidence_type,
                "relationship": "references_ip",
                "targetType": "ip",
                "target": ip,
            }
        )

    # Evidence -> Email
    for email in indicators.get("emailAddresses", []):
        relationships.append(
            {
                "source": evidence_type,
                "relationship": "contains_email",
                "targetType": "email",
                "target": email,
            }
        )

    return relationships


# ---------------------------------------------------------------------------
# Main processing function
# ---------------------------------------------------------------------------

def process_evidence(
    evidence: dict[str, Any] | None,
    evidence_type: str | None = None,
) -> dict[str, Any]:
    """
    Main Module 5 entry point.

    Takes evidence extracted by Module 4 and returns:
        - normalized evidence
        - extracted indicators
        - relationships
        - processing summary
    """

    normalized = normalize_evidence(
        evidence=evidence,
        evidence_type=evidence_type,
    )

    indicators = extract_indicators(
        normalized["raw"],
    )

    relationships = build_relationships(
        normalized["raw"],
        indicators,
    )

    total_indicators = sum(
        len(values)
        for values in indicators.values()
    )

    return {
        "evidenceType": normalized["evidenceType"],
        "normalizedEvidence": {
            "sha256": normalized["sha256"],
            "filename": normalized["filename"],
            "contentType": normalized["contentType"],
            "size": normalized["size"],
        },
        "indicators": indicators,
        "relationships": relationships,
        "summary": {
            "totalIndicators": total_indicators,
            "totalRelationships": len(relationships),
            "processed": True,
        },
    }