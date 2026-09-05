"""
CyberTrust Decision Engine (CTDE)
Email Investigation Service

Analyzes:
- Sender/domain
- SPF
- DKIM
- DMARC
- From / Reply-To / Return-Path
- Received headers and IP addresses
- Message-ID
- Authentication-Results
- Received-SPF
- DKIM-Signature
- Spoofing indicators
- Suspicious keywords
- DNS/MX evidence
- Email header forensic risk
"""

import logging
import re
from email import policy
from email.parser import Parser
from typing import Optional

from schemas import EmailData
from services.dns import (
    lookup_dns,
    has_spf,
    has_dmarc,
    get_dmarc_policy,
)
from utils.validators import extract_domain
from utils.helpers import sha256_of_string


logger = logging.getLogger(__name__)


# ============================================================================
# CONSTANTS
# ============================================================================

FREEMAIL_PROVIDERS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "icloud.com",
    "protonmail.com",
    "aol.com",
    "mail.com",
    "zoho.com",
}


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "paypal",
    "amazon",
    "apple",
    "microsoft",
    "support",
    "helpdesk",
    "admin",
    "noreply",
    "service",
    "billing",
    "invoice",
]


# ============================================================================
# BASIC EMAIL INVESTIGATION
# ============================================================================

def investigate_email(email_or_domain: str) -> dict:
    """
    Investigate an email address or sender domain.

    Supports the normal CTDE email/sender workflow.
    """

    value = email_or_domain.strip()

    if not value:
        raise ValueError("Email address or domain cannot be empty.")

    # ------------------------------------------------------------
    # Determine sender email + domain
    # ------------------------------------------------------------

    if "@" in value:
        sender_email = value.lower()
        domain = extract_domain(sender_email)
        local_part = sender_email.split("@")[0]
    else:
        domain = value.lower()
        sender_email = f"unknown@{domain}"
        local_part = "unknown"

    if not domain:
        raise ValueError("Unable to determine email domain.")

    # ------------------------------------------------------------
    # SPF
    # ------------------------------------------------------------

    try:
        spf_status = (
            "Pass"
            if has_spf(domain)
            else "Fail — no SPF record found"
        )
    except Exception as exc:
        logger.warning("SPF lookup failed for %s: %s", domain, exc)
        spf_status = "Unknown — SPF lookup failed"

    # ------------------------------------------------------------
    # DMARC
    # ------------------------------------------------------------

    dmarc_status, dmarc_policy = _check_dmarc(domain)

    # ------------------------------------------------------------
    # DKIM
    # ------------------------------------------------------------

    dkim_status = _check_dkim(domain)

    # ------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------

    try:
        dns_data = lookup_dns(domain)
    except Exception as exc:
        logger.warning("DNS lookup failed for %s: %s", domain, exc)
        dns_data = None

    # ------------------------------------------------------------
    # Provider / spoofing
    # ------------------------------------------------------------

    is_freemail = domain in FREEMAIL_PROVIDERS

    spoof_risk = _detect_spoofing(
        domain,
        local_part,
        spf_status,
        dmarc_status,
    )

    suspicious_keywords = _find_suspicious_keywords(
        domain,
        local_part,
    )

    reply_to = _analyze_reply_to(
        sender_email,
        domain,
    )

    mx_exists = bool(getattr(dns_data, "mx", []))

    # ------------------------------------------------------------
    # Structured EmailData
    # ------------------------------------------------------------

    email_data = EmailData(
        spf=spf_status,
        dkim=dkim_status,
        dmarc=dmarc_status,
        replyToAnalysis=reply_to,
        senderDomain=domain,
        spoofDetection=spoof_risk,
    )

    sha = sha256_of_string(value)

    return {
        "email": sender_email,
        "domain": domain,
        "localPart": local_part,
        "emailData": email_data,
        "isFreemail": is_freemail,
        "dmarcPolicy": dmarc_policy,
        "suspiciousKeywords": suspicious_keywords,
        "mxExists": mx_exists,
        "dns": dns_data,
        "sha256": sha,
    }


# ============================================================================
# RAW EMAIL HEADER FORENSIC ANALYSIS
# ============================================================================

def investigate_email_headers(raw_headers: str) -> dict:
    """
    Perform forensic analysis of raw email headers.

    Supports headers copied from:
    - Gmail
    - Outlook
    - Thunderbird
    - Mail clients
    - .eml files

    The function analyzes:
    - From
    - Reply-To
    - Return-Path
    - Subject
    - Message-ID
    - Received
    - Authentication-Results
    - Received-SPF
    - DKIM-Signature
    - SPF
    - DKIM
    - DMARC
    - spoofing indicators
    - suspicious keywords
    - MX/DNS evidence
    """

    raw_headers = raw_headers.strip()

    if not raw_headers:
        raise ValueError("Email headers are empty.")

    # ------------------------------------------------------------
    # Parse headers
    # ------------------------------------------------------------

    try:
        message = Parser(
            policy=policy.default
        ).parsestr(raw_headers)

    except Exception as exc:
        logger.exception("Failed to parse email headers")

        raise ValueError(
            f"Unable to parse email headers: {exc}"
        )

    # ------------------------------------------------------------
    # Read important headers
    # ------------------------------------------------------------

    from_header = str(
        message.get("From", "")
    )

    reply_to = str(
        message.get("Reply-To", "")
    )

    return_path = str(
        message.get("Return-Path", "")
    )

    message_id = str(
        message.get("Message-ID", "")
    )

    subject = str(
        message.get("Subject", "")
    )

    received_headers = [
        str(value)
        for value in message.get_all("Received", [])
    ]

    authentication_results = str(
        message.get("Authentication-Results", "")
    )

    received_spf = str(
        message.get("Received-SPF", "")
    )

    dkim_signature = str(
        message.get("DKIM-Signature", "")
    )

    # ------------------------------------------------------------
    # Extract sender information
    # ------------------------------------------------------------

    from_email = _extract_email_address(
        from_header
    )

    sender_domain = ""

    if from_email and "@" in from_email:
        sender_domain = (
            from_email.split("@")[-1]
            .lower()
            .strip()
        )

    # ------------------------------------------------------------
    # Reply-To
    # ------------------------------------------------------------

    reply_to_email = _extract_email_address(
        reply_to
    )

    reply_to_domain = ""

    if reply_to_email and "@" in reply_to_email:
        reply_to_domain = (
            reply_to_email.split("@")[-1]
            .lower()
            .strip()
        )

    # ------------------------------------------------------------
    # Return-Path
    # ------------------------------------------------------------

    return_path_email = _extract_email_address(
        return_path
    )

    return_path_domain = ""

    if return_path_email and "@" in return_path_email:
        return_path_domain = (
            return_path_email.split("@")[-1]
            .lower()
            .strip()
        )

    # ------------------------------------------------------------
    # Authentication results
    # ------------------------------------------------------------

    spf_result = _extract_auth_result(
        authentication_results,
        "spf",
    )

    dkim_result = _extract_auth_result(
        authentication_results,
        "dkim",
    )

    dmarc_result = _extract_auth_result(
        authentication_results,
        "dmarc",
    )

    # ------------------------------------------------------------
    # Fallback to Received-SPF
    # ------------------------------------------------------------

    if spf_result == "unknown" and received_spf:
        spf_result = _extract_first_word_result(
            received_spf
        )

    # ------------------------------------------------------------
    # DKIM signature presence
    # ------------------------------------------------------------

    if dkim_result == "unknown":
        if dkim_signature:
            dkim_result = "present"
        else:
            dkim_result = "unknown"

    # ------------------------------------------------------------
    # DMARC policy from DNS
    # ------------------------------------------------------------

    dmarc_policy = "unknown"

    if sender_domain:
        try:
            _, dmarc_policy = _check_dmarc(
                sender_domain
            )
        except Exception as exc:
            logger.warning(
                "DMARC policy lookup failed for %s: %s",
                sender_domain,
                exc,
            )

    # ------------------------------------------------------------
    # Received IP extraction
    # ------------------------------------------------------------

    received_ips = _extract_received_ips(
        received_headers
    )

    # ------------------------------------------------------------
    # Suspicious keywords
    # ------------------------------------------------------------

    local_part = ""

    if from_email and "@" in from_email:
        local_part = from_email.split("@")[0]

    suspicious_keywords = _find_suspicious_keywords(
        sender_domain,
        local_part,
        subject,
    )

    # ------------------------------------------------------------
    # Spoofing indicators
    # ------------------------------------------------------------

    spoofing_indicators = _header_spoofing_indicators(
        from_email=from_email,
        reply_to_email=reply_to_email,
        return_path_email=return_path_email,
        message_id=message_id,
        received_headers=received_headers,
        spf_result=spf_result,
        dkim_result=dkim_result,
        dmarc_result=dmarc_result,
    )

    # ------------------------------------------------------------
    # DNS / MX
    # ------------------------------------------------------------

    mx_exists = False
    dns_data = None

    if sender_domain:

        try:
            dns_data = lookup_dns(
                sender_domain
            )

            mx_exists = bool(
                getattr(
                    dns_data,
                    "mx",
                    []
                )
            )

        except Exception as exc:
            logger.warning(
                "DNS lookup failed for %s: %s",
                sender_domain,
                exc,
            )

    # ------------------------------------------------------------
    # Calculate header risk
    # ------------------------------------------------------------

    risk_level = _calculate_header_risk(
        spf_result=spf_result,
        dkim_result=dkim_result,
        dmarc_result=dmarc_result,
        spoofing_indicators=spoofing_indicators,
        suspicious_keywords=suspicious_keywords,
        reply_to_domain=reply_to_domain,
        sender_domain=sender_domain,
        return_path_domain=return_path_domain,
    )

    # ------------------------------------------------------------
    # SHA256
    # ------------------------------------------------------------

    sha = sha256_of_string(
        raw_headers
    )

    # ------------------------------------------------------------
    # Final forensic result
    # ------------------------------------------------------------

    return {
        "email": from_email,
        "domain": sender_domain,
        "localPart": local_part,

        "replyTo": reply_to_email,
        "returnPath": return_path_email,

        "replyToDomain": reply_to_domain,
        "returnPathDomain": return_path_domain,

        "subject": subject,
        "messageId": message_id,

        "receivedHeaders": received_headers,
        "receivedIps": received_ips,

        "authenticationResults": authentication_results,
        "receivedSpf": received_spf,
        "dkimSignature": dkim_signature,

        "spfResult": spf_result,
        "dkimResult": dkim_result,
        "dmarcResult": dmarc_result,
        "dmarcPolicy": dmarc_policy,

        "spoofingIndicators": spoofing_indicators,
        "suspiciousKeywords": suspicious_keywords,

        "mxExists": mx_exists,

        "riskLevel": risk_level,

        "dns": dns_data,

        "sha256": sha,
    }


# ============================================================================
# EMAIL ADDRESS EXTRACTION
# ============================================================================

def _extract_email_address(value: str) -> str:
    """
    Extract a plain email address from a header.

    Examples:

        Security Team <security@example.com>

        <security@example.com>

        security@example.com
    """

    if not value:
        return ""

    match = re.search(
        r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}',
        value,
    )

    if match:
        return match.group(0).lower()

    return ""


# ============================================================================
# SPF / DMARC / DKIM
# ============================================================================

def _check_dmarc(
    domain: str,
) -> tuple[str, str]:
    """
    Check whether a domain has DMARC and obtain its policy.
    """

    try:
        if not has_dmarc(domain):
            return (
                "Fail — no DMARC record found",
                "none",
            )

        policy_value = get_dmarc_policy(
            domain
        )

        if not policy_value:
            policy_value = "unknown"

        return (
            f"Pass — DMARC policy: {policy_value}",
            str(policy_value),
        )

    except Exception as exc:
        logger.warning(
            "DMARC lookup failed for %s: %s",
            domain,
            exc,
        )

        return (
            "Unknown — DMARC lookup failed",
            "unknown",
        )


def _check_dkim(
    domain: str,
) -> str:
    """
    DKIM cannot be fully validated without
    the actual DKIM selector/signature.

    For domain-only investigation we therefore
    report whether a DKIM-related DNS record
    can be discovered.
    """

    try:
        dns_data = lookup_dns(domain)

        txt_records = getattr(
            dns_data,
            "txt",
            []
        )

        for record in txt_records:

            record_text = str(
                record
            ).lower()

            if "dkim" in record_text:
                return "Pass — DKIM evidence found"

        return "Unknown — DKIM selector not provided"

    except Exception as exc:
        logger.warning(
            "DKIM lookup failed for %s: %s",
            domain,
            exc,
        )

        return "Unknown — DKIM lookup failed"


# ============================================================================
# SPOOFING DETECTION
# ============================================================================

def _detect_spoofing(
    domain: str,
    local_part: str,
    spf: str,
    dmarc: str,
) -> str:
    """
    Basic sender spoofing assessment.
    """

    indicators = []

    spf_lower = spf.lower()
    dmarc_lower = dmarc.lower()

    if "fail" in spf_lower:
        indicators.append(
            "SPF failure"
        )

    if "fail" in dmarc_lower:
        indicators.append(
            "DMARC failure"
        )

    if domain in FREEMAIL_PROVIDERS:
        indicators.append(
            "Freemail provider"
        )

    suspicious = _find_suspicious_keywords(
        domain,
        local_part,
    )

    if suspicious:
        indicators.append(
            "Suspicious sender keywords"
        )

    if not indicators:
        return "No obvious spoofing indicators detected"

    return "; ".join(
        indicators
    )


# ============================================================================
# RAW HEADER SPOOFING ANALYSIS
# ============================================================================

def _header_spoofing_indicators(
    from_email: str,
    reply_to_email: str,
    return_path_email: str,
    message_id: str,
    received_headers: list[str],
    spf_result: str,
    dkim_result: str,
    dmarc_result: str,
) -> list[str]:

    indicators = []

    # ------------------------------------------------------------
    # SPF
    # ------------------------------------------------------------

    if spf_result.lower() in {
        "fail",
        "softfail",
        "permerror",
    }:
        indicators.append(
            f"SPF result: {spf_result}"
        )

    # ------------------------------------------------------------
    # DKIM
    # ------------------------------------------------------------

    if dkim_result.lower() in {
        "fail",
        "permerror",
    }:
        indicators.append(
            f"DKIM result: {dkim_result}"
        )

    # ------------------------------------------------------------
    # DMARC
    # ------------------------------------------------------------

    if dmarc_result.lower() in {
        "fail",
        "permerror",
    }:
        indicators.append(
            f"DMARC result: {dmarc_result}"
        )

    # ------------------------------------------------------------
    # Reply-To mismatch
    # ------------------------------------------------------------

    if (
        from_email
        and reply_to_email
        and from_email.lower()
        != reply_to_email.lower()
    ):
        from_domain = (
            from_email.split("@")[-1]
            .lower()
        )

        reply_domain = (
            reply_to_email.split("@")[-1]
            .lower()
        )

        if from_domain != reply_domain:
            indicators.append(
                "Reply-To domain differs from From domain"
            )

    # ------------------------------------------------------------
    # Return-Path mismatch
    # ------------------------------------------------------------

    if (
        from_email
        and return_path_email
    ):

        from_domain = (
            from_email.split("@")[-1]
            .lower()
        )

        return_domain = (
            return_path_email.split("@")[-1]
            .lower()
        )

        if from_domain != return_domain:
            indicators.append(
                "Return-Path domain differs from From domain"
            )

    # ------------------------------------------------------------
    # Message-ID
    # ------------------------------------------------------------

    if not message_id:
        indicators.append(
            "Missing Message-ID"
        )

    # ------------------------------------------------------------
    # Received chain
    # ------------------------------------------------------------

    if not received_headers:
        indicators.append(
            "No Received headers found"
        )

    return indicators


# ============================================================================
# AUTHENTICATION-RESULTS PARSING
# ============================================================================

def _extract_auth_result(
    authentication_results: str,
    mechanism: str,
) -> str:
    """
    Extract SPF/DKIM/DMARC result from:

    Authentication-Results:
        example.com;
        spf=pass;
        dkim=pass;
        dmarc=pass
    """

    if not authentication_results:
        return "unknown"

    pattern = (
        rf"\b{re.escape(mechanism)}"
        r"\s*=\s*"
        r"([a-zA-Z]+)"
    )

    match = re.search(
        pattern,
        authentication_results,
        re.IGNORECASE,
    )

    if not match:
        return "unknown"

    return _normalize_auth_value(
        match.group(1)
    )


def _normalize_auth_value(
    value: str,
) -> str:

    if not value:
        return "unknown"

    normalized = value.strip().lower()

    aliases = {
        "passed": "pass",
        "failed": "fail",
    }

    return aliases.get(
        normalized,
        normalized,
    )


def _extract_first_word_result(
    value: str,
) -> str:
    """
    Extract the first authentication result
    from Received-SPF or similar fields.
    """

    if not value:
        return "unknown"

    match = re.search(
        r"\b(pass|fail|softfail|neutral|none|"
        r"temperror|permerror)\b",
        value,
        re.IGNORECASE,
    )

    if not match:
        return "unknown"

    return _normalize_auth_value(
        match.group(1)
    )


# ============================================================================
# RECEIVED HEADER / IP ANALYSIS
# ============================================================================

def _extract_received_ips(
    received_headers: list[str],
) -> list[str]:

    ips = []

    ipv4_pattern = (
        r"\b"
        r"(?:\d{1,3}\.){3}"
        r"\d{1,3}"
        r"\b"
    )

    for header in received_headers:

        matches = re.findall(
            ipv4_pattern,
            header,
        )

        for ip in matches:

            if ip not in ips:
                ips.append(ip)

    return ips


# ============================================================================
# SUSPICIOUS KEYWORDS
# ============================================================================

def _find_suspicious_keywords(
    domain: str,
    local_part: str,
    subject: Optional[str] = None,
) -> list[str]:

    text_parts = [
        domain or "",
        local_part or "",
        subject or "",
    ]

    combined = " ".join(
        text_parts
    ).lower()

    found = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword.lower() in combined:

            if keyword not in found:
                found.append(
                    keyword
                )

    return found


# ============================================================================
# REPLY-TO ANALYSIS
# ============================================================================

def _analyze_reply_to(
    sender_email: str,
    domain: str,
) -> str:

    if not sender_email:
        return "Unable to determine sender"

    if "@" not in sender_email:
        return "Invalid sender address"

    sender_domain = (
        sender_email.split("@")[-1]
        .lower()
    )

    if sender_domain == domain.lower():
        return (
            "Reply-To domain matches sender domain"
        )

    return (
        "Potential Reply-To domain mismatch"
    )


# ============================================================================
# HEADER RISK CALCULATION
# ============================================================================

def _calculate_header_risk(
    spf_result: str,
    dkim_result: str,
    dmarc_result: str,
    spoofing_indicators: list[str],
    suspicious_keywords: list[str],
    reply_to_domain: str,
    sender_domain: str,
    return_path_domain: str,
) -> str:

    risk_points = 0

    # ------------------------------------------------------------
    # SPF
    # ------------------------------------------------------------

    if spf_result.lower() == "pass":
        risk_points -= 1

    elif spf_result.lower() in {
        "fail",
        "softfail",
        "permerror",
    }:
        risk_points += 3

    # ------------------------------------------------------------
    # DKIM
    # ------------------------------------------------------------

    if dkim_result.lower() == "pass":
        risk_points -= 1

    elif dkim_result.lower() in {
        "fail",
        "permerror",
    }:
        risk_points += 3

    # ------------------------------------------------------------
    # DMARC
    # ------------------------------------------------------------

    if dmarc_result.lower() == "pass":
        risk_points -= 2

    elif dmarc_result.lower() in {
        "fail",
        "permerror",
    }:
        risk_points += 4

    # ------------------------------------------------------------
    # Spoofing
    # ------------------------------------------------------------

    risk_points += (
        len(spoofing_indicators) * 2
    )

    # ------------------------------------------------------------
    # Suspicious keywords
    # ------------------------------------------------------------

    risk_points += min(
        len(suspicious_keywords),
        5,
    )

    # ------------------------------------------------------------
    # Reply-To mismatch
    # ------------------------------------------------------------

    if (
        reply_to_domain
        and sender_domain
        and reply_to_domain != sender_domain
    ):
        risk_points += 3

    # ------------------------------------------------------------
    # Return-Path mismatch
    # ------------------------------------------------------------

    if (
        return_path_domain
        and sender_domain
        and return_path_domain != sender_domain
    ):
        risk_points += 3

    # ------------------------------------------------------------
    # Final classification
    # ------------------------------------------------------------

    if risk_points >= 8:
        return "Dangerous"

    if risk_points >= 4:
        return "Suspicious"

    return "Safe"