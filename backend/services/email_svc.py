"""
Email investigation service.
Analyzes SPF, DKIM, DMARC, headers, and spoofing indicators.
"""
import re
import logging
from typing import Optional

from schemas import EmailData
from services.dns import lookup_dns, has_spf, has_dmarc, get_dmarc_policy
from utils.validators import extract_domain, is_valid_domain
from utils.helpers import sha256_of_string

logger = logging.getLogger(__name__)

FREEMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "icloud.com", "protonmail.com", "aol.com", "mail.com", "zoho.com",
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "paypal", "amazon", "apple", "microsoft", "support", "helpdesk",
    "admin", "noreply", "service", "billing", "invoice",
]


def investigate_email(email_or_domain: str) -> dict:
    """
    Investigate an email address or sender domain.
    Returns structured evidence for trust scoring.
    """
    # Extract domain from email
    if "@" in email_or_domain:
        sender_email = email_or_domain.strip().lower()
        domain = extract_domain(sender_email)
        local_part = sender_email.split("@")[0]
    else:
        domain = email_or_domain.strip().lower()
        sender_email = f"unknown@{domain}"
        local_part = "unknown"

    spf_status = "Pass" if has_spf(domain) else "Fail — no SPF record found"
    dmarc_status, dmarc_policy = _check_dmarc(domain)
    dkim_status = _check_dkim(domain)
    dns_data = lookup_dns(domain)
    is_freemail = domain in FREEMAIL_PROVIDERS
    spoof_risk = _detect_spoofing(domain, local_part, spf_status, dmarc_status)
    suspicious_keywords = _find_suspicious_keywords(domain, local_part)
    reply_to = _analyze_reply_to(sender_email, domain)
    mx_exists = bool(dns_data.mx)

    email_data = EmailData(
        spf=spf_status,
        dkim=dkim_status,
        dmarc=dmarc_status,
        replyToAnalysis=reply_to,
        senderDomain=domain,
        spoofDetection=spoof_risk,
    )

    sha = sha256_of_string(email_or_domain)

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


def _check_dmarc(domain: str) -> tuple[str, str]:
    if has_dmarc(domain):
        policy = get_dmarc_policy(domain)
        if policy == "reject":
            return f"Pass — policy: reject (strict)", "reject"
        elif policy == "quarantine":
            return f"Pass — policy: quarantine", "quarantine"
        else:
            return f"Weak — policy: none (monitoring only)", "none"
    return "Fail — no DMARC record found", "missing"


def _check_dkim(domain: str) -> str:
    """
    DKIM selector lookup — tries common selectors.
    Full DKIM validation requires the actual email headers.
    """
    import dns.resolver
    common_selectors = ["default", "google", "mail", "k1", "s1", "s2", "selector1", "selector2"]
    for selector in common_selectors:
        try:
            dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT", lifetime=4)
            return f"Pass — DKIM key found (selector: {selector})"
        except Exception:
            continue
    return "Unknown — no common DKIM selectors found (requires raw email headers to verify)"


def _detect_spoofing(domain: str, local_part: str, spf: str, dmarc: str) -> str:
    indicators = []
    if "Fail" in spf:
        indicators.append("missing SPF")
    if "Fail" in dmarc or "missing" in dmarc.lower():
        indicators.append("missing DMARC")
    if any(kw in domain for kw in ["secure", "login", "verify", "support"]):
        indicators.append("deceptive domain keywords")
    if any(kw in local_part for kw in ["noreply", "admin", "support", "billing"]):
        indicators.append("sensitive local-part keyword")
    if indicators:
        return f"Potential spoofing risk — {', '.join(indicators)}"
    return "No spoofing indicators detected"


def _find_suspicious_keywords(domain: str, local_part: str) -> list[str]:
    combined = f"{local_part} {domain}".lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in combined]


def _analyze_reply_to(sender: str, domain: str) -> str:
    return f"Sender domain: {domain} — reply-to analysis requires raw email headers"
