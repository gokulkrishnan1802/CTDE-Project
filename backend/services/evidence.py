"""
CyberVerify AI - Digital Evidence Extraction Engine (Module 4)

Purpose:
    Normalize and collect evidence from supported investigation inputs before
    CTDE/risk scoring. This module is intentionally separate from the UI and
    from the final risk decision.

Supported evidence:
    - website / URL
    - email headers
    - APK bytes
    - QR image bytes

Design:
    Input -> Evidence Extraction -> normalized evidence dictionary
    The existing evidence-specific analyzers remain responsible for deep
    analysis. This module provides a common forensic evidence layer around
    them.
"""

from __future__ import annotations

import hashlib
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


# ---------------------------------------------------------------------------
# Common helpers
# ---------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    """Return SHA-256 for an in-memory evidence object."""
    digest = hashlib.sha256()
    digest.update(data)
    return digest.hexdigest()


def file_evidence_metadata(
    data: bytes,
    filename: str | None = None,
    content_type: str | None = None,
) -> dict[str, Any]:
    """Build common metadata for uploaded binary evidence."""
    name = Path(filename).name if filename else None

    return {
        "filename": name,
        "contentType": content_type,
        "sizeBytes": len(data),
        "sha256": sha256_bytes(data),
    }


# ---------------------------------------------------------------------------
# Website / URL evidence
# ---------------------------------------------------------------------------

def extract_url_evidence(value: str) -> dict[str, Any]:
    """
    Extract structural evidence from a URL.

    This function does not decide whether the URL is safe or malicious.
    """
    raw = (value or "").strip()

    candidate = raw
    if candidate and "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)

    hostname = (parsed.hostname or "").lower() or None
    scheme = (parsed.scheme or "").lower() or None

    query_keys: list[str] = []
    if parsed.query:
        query_keys = sorted(set(parse_qs(parsed.query, keep_blank_values=True)))

    suspicious_structure: list[str] = []

    if hostname:
        if "@" in parsed.netloc:
            suspicious_structure.append("URL contains user-info syntax")

        if hostname.startswith("xn--") or ".xn--" in hostname:
            suspicious_structure.append("Domain contains an IDN/punycode label")

    if parsed.username or parsed.password:
        suspicious_structure.append("URL contains embedded credentials")

    return {
        "input": raw,
        "normalizedUrl": candidate if parsed.netloc else raw,
        "scheme": scheme,
        "hostname": hostname,
        "port": parsed.port,
        "path": parsed.path or "/",
        "queryPresent": bool(parsed.query),
        "queryKeys": query_keys,
        "fragmentPresent": bool(parsed.fragment),
        "isHttps": scheme == "https",
        "hasCredentials": bool(parsed.username or parsed.password),
        "suspiciousStructureIndicators": suspicious_structure,
    }


# ---------------------------------------------------------------------------
# Email header evidence
# ---------------------------------------------------------------------------

_EMAIL_URL_RE = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE,
)


def _header_value(message: Any, name: str) -> str | None:
    value = message.get(name)
    if value is None:
        return None
    return str(value).strip() or None


def extract_email_header_evidence(raw_headers: str) -> dict[str, Any]:
    """
    Extract forensic metadata from raw email headers.

    This does not replace SPF/DKIM/DMARC verification. Those checks remain
    part of the email analysis service.
    """
    raw = (raw_headers or "").strip()

    if not raw:
        return {
            "valid": False,
            "error": "Email headers are empty",
            "headers": {},
            "receivedChain": [],
            "urls": [],
        }

    message = BytesParser(policy=policy.default).parsebytes(
        raw.encode("utf-8", errors="replace")
    )

    important_names = [
        "From",
        "To",
        "Cc",
        "Reply-To",
        "Return-Path",
        "Subject",
        "Date",
        "Message-ID",
        "Authentication-Results",
    ]

    headers = {
        name: _header_value(message, name)
        for name in important_names
        if _header_value(message, name) is not None
    }

    received_chain = [
        str(value).strip()
        for name, value in message.raw_items()
        if name.lower() == "received"
    ]

    urls = sorted(
        set(
            url.rstrip(").,;")
            for url in _EMAIL_URL_RE.findall(raw)
        )
    )

    return {
        "valid": True,
        "headers": headers,
        "receivedChain": received_chain,
        "receivedHopCount": len(received_chain),
        "urls": urls,
        "urlCount": len(urls),
        "hasAuthenticationResults": bool(
            _header_value(message, "Authentication-Results")
        ),
        "hasReplyTo": bool(_header_value(message, "Reply-To")),
        "hasReturnPath": bool(_header_value(message, "Return-Path")),
    }


# ---------------------------------------------------------------------------
# APK evidence
# ---------------------------------------------------------------------------

def extract_apk_evidence(
    apk_bytes: bytes,
    filename: str | None = None,
) -> dict[str, Any]:
    """
    Add common evidence metadata and delegate APK-specific extraction to the
    existing apk_svc.analyze_apk_bytes implementation.

    The existing APK analyzer remains the source of manifest/permission/
    certificate details, so this wrapper does not duplicate that logic.
    """
    if not apk_bytes:
        raise ValueError("APK evidence is empty")

    result: dict[str, Any] = {
        "evidence": file_evidence_metadata(
            apk_bytes,
            filename=filename,
            content_type="application/vnd.android.package-archive",
        )
    }

    try:
        from services.apk_svc import analyze_apk_bytes
        analysis = analyze_apk_bytes(
            apk_bytes,
            filename or "evidence.apk",
        )

        if isinstance(analysis, dict):
            result["apkAnalysis"] = analysis
        else:
            result["apkAnalysis"] = {
                "raw": analysis,
            }

    except ImportError:
        # Keeps this module importable even if APK dependencies are not
        # installed. The existing APK endpoint can still use apk_svc directly.
        result["apkAnalysis"] = {
            "status": "unavailable",
            "reason": "APK analysis service is not available",
        }

    except Exception as exc:
        # Extraction should report the limitation rather than silently
        # converting a failed analyzer into a malicious/safe verdict.
        result["apkAnalysis"] = {
            "status": "error",
            "reason": str(exc),
        }

    return result


# ---------------------------------------------------------------------------
# QR evidence
# ---------------------------------------------------------------------------

def extract_qr_evidence(
    image_bytes: bytes,
    filename: str | None = None,
) -> dict[str, Any]:
    """
    Add common image evidence metadata and delegate QR decoding to qr_svc.

    The decoded value is evidence. It is not itself a trust decision.
    """
    if not image_bytes:
        raise ValueError("QR evidence is empty")

    result: dict[str, Any] = {
        "evidence": file_evidence_metadata(
            image_bytes,
            filename=filename,
        )
    }

    try:
        from services.qr_svc import decode_qr_bytes

        decoded = decode_qr_bytes(image_bytes)

        result["decodedContent"] = decoded
        result["decoded"] = bool(decoded)

    except ImportError:
        result["decoded"] = False
        result["decodedContent"] = None
        result["status"] = "unavailable"
        result["reason"] = "QR decoding service is not available"

    except Exception as exc:
        result["decoded"] = False
        result["decodedContent"] = None
        result["status"] = "error"
        result["reason"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Unified dispatcher
# ---------------------------------------------------------------------------

def extract_evidence(
    evidence_type: str,
    value: str | None = None,
    file_bytes: bytes | None = None,
    filename: str | None = None,
    content_type: str | None = None,
) -> dict[str, Any]:
    """
    Unified Module-4 dispatcher.

    Returns extracted evidence only. CTDE/risk classification must happen
    after this stage.
    """
    kind = (evidence_type or "").strip().lower()

    if kind in {"website", "url", "domain", "login-page"}:
        return {
            "evidenceType": kind,
            "source": "text",
            "extracted": extract_url_evidence(value or ""),
        }

    if kind in {"email", "email-header", "email_headers"}:
        return {
            "evidenceType": "email",
            "source": "text",
            "extracted": extract_email_header_evidence(value or ""),
        }

    if kind == "apk":
        if file_bytes is None:
            raise ValueError("APK file bytes are required")
        result = extract_apk_evidence(file_bytes, filename)
        result["evidenceType"] = "apk"
        result["source"] = "file"
        if content_type:
            result["evidence"]["contentType"] = content_type
        return result

    if kind in {"qr", "qr-code"}:
        if file_bytes is None:
            raise ValueError("QR image bytes are required")
        result = extract_qr_evidence(file_bytes, filename)
        result["evidenceType"] = "qr"
        result["source"] = "file"
        if content_type:
            result["evidence"]["contentType"] = content_type
        return result

    if kind in {"sender", "sms"}:
        return {
            "evidenceType": kind,
            "source": "text",
            "extracted": {
                "sender": (value or "").strip(),
            },
        }

    raise ValueError(f"Unsupported evidence type: {evidence_type}")
