"""
CyberVerify AI
Module 5 — Evidence Processing & Correlation

Purpose:
    Process the digital evidence produced by Module 4.

Pipeline:
    Module 4 Evidence Extraction
        ↓
    Normalization
        ↓
    Indicator Extraction
        ↓
    Evidence Correlation
        ↓
    Relationship Mapping
        ↓
    Investigation Summary

This module does NOT calculate the CTDE Trust Score.
It prepares structured forensic evidence for later modules.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse


# ============================================================================
# REGEX PATTERNS
# ============================================================================

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
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b"
)


# ============================================================================
# BASIC HELPERS
# ============================================================================

def _unique(values: list[str]) -> list[str]:
    """Remove duplicates while preserving order."""

    seen: set[str] = set()
    result: list[str] = []

    for value in values:
        value = str(value).strip()

        if not value:
            continue

        if value not in seen:
            seen.add(value)
            result.append(value)

    return result


def _is_valid_ip(value: str) -> bool:
    """Return True when value is a valid IPv4/IPv6 address."""

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _clean_url(value: str) -> str:
    """Remove common trailing punctuation from extracted URLs."""

    return value.rstrip(".,;:!?)]}\"'")


# ============================================================================
# INDICATOR EXTRACTION
# ============================================================================

def _extract_urls(text: str) -> list[str]:
    """Extract HTTP/HTTPS URLs."""

    if not text:
        return []

    return _unique(
        [
            _clean_url(match)
            for match in URL_PATTERN.findall(text)
        ]
    )


def _extract_emails(text: str) -> list[str]:
    """Extract email addresses."""

    if not text:
        return []

    return _unique(
        [
            match.lower()
            for match in EMAIL_PATTERN.findall(text)
        ]
    )


def _extract_ips(text: str) -> list[str]:
    """Extract valid IP addresses."""

    if not text:
        return []

    results: list[str] = []

    for match in IP_PATTERN.findall(text):
        if _is_valid_ip(match):
            results.append(match)

    return _unique(results)


def _extract_domains(text: str) -> list[str]:
    """
    Extract domains while avoiding obvious false positives.

    Domains belonging to URLs are also collected here because
    Module 5 is responsible for correlation.
    """

    if not text:
        return []

    results: list[str] = []

    for match in DOMAIN_PATTERN.findall(text):
        domain = match.lower().strip(".,;:!?)]}\"'")

        if not domain:
            continue

        # Ignore obvious file-like values.
        if domain.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp")):
            continue

        # Ignore pure IP addresses.
        if _is_valid_ip(domain):
            continue

        results.append(domain)

    return _unique(results)


def _extract_hashes(text: str) -> list[str]:
    """Extract SHA-256 hashes."""

    if not text:
        return []

    return _unique(
        [
            match.lower()
            for match in SHA256_PATTERN.findall(text)
        ]
    )


# ============================================================================
# RECURSIVE VALUE FLATTENER
# ============================================================================

def _flatten_values(value: Any) -> list[str]:
    """
    Recursively flatten dictionaries/lists into text values.

    This allows Module 5 to process structures such as:

        {
            "collection": {...},
            "extracted": {...}
        }

    without changing Module 4's original structure.
    """

    values: list[str] = []

    if value is None:
        return values

    if isinstance(value, dict):

        for key, item in value.items():

            # Preserve the key itself because some forensic indicators
            # can be represented by field names.
            if isinstance(key, str):
                values.append(key)

            values.extend(_flatten_values(item))

    elif isinstance(value, (list, tuple, set)):

        for item in value:
            values.extend(_flatten_values(item))

    else:
        values.append(str(value))

    return values


# ============================================================================
# NORMALIZATION
# ============================================================================

def normalize_evidence(
    digital_evidence: dict[str, Any],
) -> dict[str, Any]:
    """
    Normalize common forensic metadata.

    Supports both Module 4 structures:

        root-level metadata

    and:

        digitalEvidence["collection"]
    """

    collection = digital_evidence.get(
        "collection",
        {},
    )

    if not isinstance(collection, dict):
        collection = {}

    def first_value(*keys: str) -> Any:
        for key in keys:

            if key in digital_evidence:
                value = digital_evidence.get(key)

                if value not in (None, ""):
                    return value

            if key in collection:
                value = collection.get(key)

                if value not in (None, ""):
                    return value

        return None

    return {
        "sha256": first_value(
            "sha256",
            "hash",
            "fileHash",
            "file_hash",
        ),
        "filename": first_value(
            "filename",
            "fileName",
            "name",
        ),
        "contentType": first_value(
            "contentType",
            "content_type",
            "mimeType",
            "mime_type",
        ),
        "size": first_value(
            "size",
            "sizeBytes",
            "fileSize",
            "file_size",
        ),
    }


# ============================================================================
# INDICATOR EXTRACTION
# ============================================================================

def extract_indicators(
    digital_evidence: dict[str, Any],
) -> dict[str, list[str]]:
    """
    Extract forensic indicators from Module 4 evidence.

    Indicators:
        - URLs
        - domains
        - IP addresses
        - email addresses
        - SHA-256 hashes
    """

    flattened = _flatten_values(
        digital_evidence
    )

    combined_text = " ".join(flattened)

    urls = _extract_urls(
        combined_text
    )

    emails = _extract_emails(
        combined_text
    )

    ips = _extract_ips(
        combined_text
    )

    domains = _extract_domains(
        combined_text
    )

    hashes = _extract_hashes(
        combined_text
    )

    # ------------------------------------------------------------------------
    # Explicit URL hostname extraction
    # ------------------------------------------------------------------------

    for url in urls:

        try:
            parsed = urlparse(url)

            hostname = (
                parsed.hostname
                or ""
            ).lower()

            if hostname and not _is_valid_ip(hostname):
                domains.append(hostname)

        except Exception:
            pass

    # ------------------------------------------------------------------------
    # Explicit email-domain extraction
    # ------------------------------------------------------------------------

    for email in emails:

        if "@" in email:

            domain = (
                email.split("@", 1)[1]
                .lower()
                .strip()
            )

            if domain:
                domains.append(domain)

    # ------------------------------------------------------------------------
    # Explicit Module 4 SHA-256 metadata
    # ------------------------------------------------------------------------

    normalized = normalize_evidence(
        digital_evidence
    )

    sha256 = normalized.get("sha256")

    if sha256:
        sha256_text = str(sha256).strip().lower()

        if SHA256_PATTERN.fullmatch(
            sha256_text
        ):
            hashes.append(
                sha256_text
            )

    return {
        "urls": _unique(urls),
        "domains": _unique(domains),
        "ipAddresses": _unique(ips),
        "emailAddresses": _unique(emails),
        "sha256": _unique(hashes),
    }


# ============================================================================
# RELATIONSHIP BUILDING
# ============================================================================

def build_relationships(
    indicators: dict[str, list[str]],
    evidence_type: str | None = None,
    normalized: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """
    Build relationships between extracted forensic indicators.

    Examples:

        URL → domain

        Email → domain

        Evidence → SHA-256

        Evidence → URL

        Evidence → IP
    """

    relationships: list[dict[str, str]] = []

    evidence_type = (
        evidence_type or "unknown"
    ).lower()

    # ------------------------------------------------------------------------
    # Evidence → SHA-256
    # ------------------------------------------------------------------------

    for sha256 in indicators.get(
        "sha256",
        [],
    ):

        relationships.append(
            {
                "source": evidence_type,
                "relationship": "identified_by_sha256",
                "targetType": "sha256",
                "target": sha256,
            }
        )

    # ------------------------------------------------------------------------
    # Evidence → URL
    # ------------------------------------------------------------------------

    for url in indicators.get(
        "urls",
        [],
    ):

        relationships.append(
            {
                "source": evidence_type,
                "relationship": "contains_url",
                "targetType": "url",
                "target": url,
            }
        )

    # ------------------------------------------------------------------------
    # URL → Domain
    # ------------------------------------------------------------------------

    for url in indicators.get(
        "urls",
        [],
    ):

        try:
            hostname = (
                urlparse(url).hostname
                or ""
            ).lower()

            if hostname:

                target_type = (
                    "ip"
                    if _is_valid_ip(hostname)
                    else "domain"
                )

                relationships.append(
                    {
                        "source": url,
                        "relationship": (
                            "resolves_to_ip"
                            if target_type == "ip"
                            else "resolves_to_domain"
                        ),
                        "targetType": target_type,
                        "target": hostname,
                    }
                )

        except Exception:
            continue

    # ------------------------------------------------------------------------
    # Evidence → Domain
    # ------------------------------------------------------------------------

    for domain in indicators.get(
        "domains",
        [],
    ):

        relationships.append(
            {
                "source": evidence_type,
                "relationship": "references_domain",
                "targetType": "domain",
                "target": domain,
            }
        )

    # ------------------------------------------------------------------------
    # Evidence → IP
    # ------------------------------------------------------------------------

    for ip in indicators.get(
        "ipAddresses",
        [],
    ):

        relationships.append(
            {
                "source": evidence_type,
                "relationship": "references_ip",
                "targetType": "ip",
                "target": ip,
            }
        )

    # ------------------------------------------------------------------------
    # Evidence → Email
    # ------------------------------------------------------------------------

    for email in indicators.get(
        "emailAddresses",
        [],
    ):

        relationships.append(
            {
                "source": evidence_type,
                "relationship": "contains_email",
                "targetType": "email",
                "target": email,
            }
        )

        if "@" in email:

            domain = (
                email.split("@", 1)[1]
                .lower()
                .strip()
            )

            if domain:

                relationships.append(
                    {
                        "source": email,
                        "relationship": "belongs_to_domain",
                        "targetType": "domain",
                        "target": domain,
                    }
                )

    # ------------------------------------------------------------------------
    # Remove duplicate relationships
    # ------------------------------------------------------------------------

    unique_relationships: list[
        dict[str, str]
    ] = []

    seen: set[
        tuple[str, str, str, str]
    ] = set()

    for relationship in relationships:

        key = (
            relationship.get(
                "source",
                "",
            ),
            relationship.get(
                "relationship",
                "",
            ),
            relationship.get(
                "targetType",
                "",
            ),
            relationship.get(
                "target",
                "",
            ),
        )

        if key not in seen:

            seen.add(key)

            unique_relationships.append(
                relationship
            )

    return unique_relationships


# ============================================================================
# INVESTIGATION SUMMARY
# ============================================================================

def _build_summary(
    evidence_type: str,
    indicators: dict[str, list[str]],
    relationships: list[dict[str, str]],
) -> dict[str, Any]:

    total_indicators = sum(
        len(values)
        for values in indicators.values()
    )

    return {
        "processed": True,
        "evidenceType": evidence_type,
        "totalIndicators": total_indicators,
        "totalRelationships": len(
            relationships
        ),
        "indicatorTypes": {
            "urls": len(
                indicators.get(
                    "urls",
                    [],
                )
            ),
            "domains": len(
                indicators.get(
                    "domains",
                    [],
                )
            ),
            "ipAddresses": len(
                indicators.get(
                    "ipAddresses",
                    [],
                )
            ),
            "emailAddresses": len(
                indicators.get(
                    "emailAddresses",
                    [],
                )
            ),
            "sha256": len(
                indicators.get(
                    "sha256",
                    [],
                )
            ),
        },
        "description": (
            "Digital evidence was normalized, "
            "indicators were extracted, and "
            "relationships were correlated."
        ),
    }


# ============================================================================
# MAIN MODULE 5 PROCESSOR
# ============================================================================

def process_evidence(
    digital_evidence: dict[str, Any],
    evidence_type: str | None = None,
) -> dict[str, Any]:
    """
    Main Module 5 entry point.

    Input:
        Module 4 digitalEvidence

    Output:
        normalized evidence
        indicators
        relationships
        summary
    """

    if not isinstance(
        digital_evidence,
        dict,
    ):
        return {
            "processed": False,
            "evidenceType": (
                evidence_type
                or "unknown"
            ),
            "normalizedEvidence": {},
            "indicators": {
                "urls": [],
                "domains": [],
                "ipAddresses": [],
                "emailAddresses": [],
                "sha256": [],
            },
            "relationships": [],
            "summary": {
                "processed": False,
                "totalIndicators": 0,
                "totalRelationships": 0,
            },
            "error": (
                "Digital evidence must be a dictionary."
            ),
        }

    resolved_type = (
        evidence_type
        or digital_evidence.get(
            "evidenceType"
        )
        or "unknown"
    )

    normalized = normalize_evidence(
        digital_evidence
    )

    indicators = extract_indicators(
        digital_evidence
    )

    relationships = build_relationships(
        indicators,
        evidence_type=resolved_type,
        normalized=normalized,
    )

    summary = _build_summary(
        resolved_type,
        indicators,
        relationships,
    )

    return {
        "processed": True,
        "evidenceType": resolved_type,
        "normalizedEvidence": normalized,
        "indicators": indicators,
        "relationships": relationships,
        "summary": summary,
    }


def correlate_with_prior_investigations(
    current_indicators: dict[str, Any],
    prior_investigations: list[Any],
) -> dict[str, Any]:
    """Match this evidence's indicators against prior investigations.

    The caller must scope ``prior_investigations`` to the authenticated user.
    Historical rows from before Module 5 are processed on demand when possible.
    """
    indicator_types = (
        "urls",
        "domains",
        "ipAddresses",
        "emailAddresses",
        "sha256",
    )

    current_values: dict[str, dict[str, str]] = {}
    for indicator_type in indicator_types:
        values = current_indicators.get(indicator_type, [])
        if not isinstance(values, list):
            continue
        current_values[indicator_type] = {
            str(value).strip().casefold(): str(value).strip()
            for value in values
            if str(value).strip()
        }

    matches: list[dict[str, Any]] = []
    cross_relationships: list[dict[str, str]] = []

    for investigation in prior_investigations:
        result_data = getattr(investigation, "result_json", None)
        if not isinstance(result_data, dict):
            continue

        prior_processing = result_data.get("evidenceProcessing")
        prior_indicators = (
            prior_processing.get("indicators")
            if isinstance(prior_processing, dict)
            else None
        )

        if not isinstance(prior_indicators, dict):
            digital_evidence = result_data.get("digitalEvidence")
            if isinstance(digital_evidence, dict):
                processing_evidence = dict(digital_evidence)
                evidence_panel = result_data.get("evidencePanel")
                sha256 = (
                    evidence_panel.get("sha256Hash")
                    if isinstance(evidence_panel, dict)
                    else None
                )
                if sha256:
                    collection = processing_evidence.get("collection")
                    collection = (
                        dict(collection)
                        if isinstance(collection, dict)
                        else {}
                    )
                    collection.setdefault("sha256", sha256)
                    processing_evidence["collection"] = collection

                prior_processing = process_evidence(
                    processing_evidence,
                    evidence_type=getattr(
                        investigation,
                        "evidence_type",
                        "unknown",
                    ),
                )
                prior_indicators = prior_processing.get("indicators", {})

        if not isinstance(prior_indicators, dict):
            continue

        matching_indicators: list[dict[str, str]] = []
        for indicator_type in indicator_types:
            current_type_values = current_values.get(indicator_type, {})
            prior_values = prior_indicators.get(indicator_type, [])
            if not isinstance(prior_values, list):
                continue

            prior_keys = {
                str(value).strip().casefold()
                for value in prior_values
                if str(value).strip()
            }
            for key in current_type_values.keys() & prior_keys:
                matching_indicators.append(
                    {
                        "type": indicator_type,
                        "value": current_type_values[key],
                    }
                )

        if not matching_indicators:
            continue

        case_id = str(getattr(investigation, "case_id", ""))
        investigation_id = str(getattr(investigation, "id", ""))
        created_at = getattr(investigation, "created_at", None)
        evidence_type = str(
            getattr(investigation, "evidence_type", "unknown")
        )
        risk_level = str(getattr(investigation, "risk_level", "unknown"))

        matches.append(
            {
                "caseId": case_id,
                "investigationId": investigation_id,
                "evidenceType": evidence_type,
                "riskLevel": risk_level,
                "createdAt": (
                    created_at.isoformat()
                    if hasattr(created_at, "isoformat")
                    else None
                ),
                "matchingIndicators": matching_indicators,
            }
        )

        for indicator in matching_indicators:
            cross_relationships.append(
                {
                    "source": f"{indicator['type']}:{indicator['value']}",
                    "relationship": "also_seen_in_prior_investigation",
                    "targetType": "investigation",
                    "target": case_id,
                    "indicatorType": indicator["type"],
                    "indicator": indicator["value"],
                }
            )

    return {
        "matches": matches,
        "relationships": cross_relationships,
        "matchCount": len(matches),
        "indicatorMatchCount": len(cross_relationships),
    }
