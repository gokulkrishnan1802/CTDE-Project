"""
Risk Engine — Deterministic trust score calculator.
Computes trust score 0-100 from weighted evidence.
Never generates random scores.
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RiskFactor:
    label: str
    positive: bool
    points: int


@dataclass
class RiskResult:
    score: int
    risk_level: str  # Safe | Suspicious | Dangerous
    factors: list[RiskFactor] = field(default_factory=list)
    confidence: int = 90


def score_to_risk_level(score: int) -> str:
    if score <= 40:
        return "Dangerous"
    if score <= 60:
        return "Suspicious"
    return "Safe"


# ── Evidence type-specific scorers ───────────────────────────────────────────

def score_url(evidence: dict) -> RiskResult:
    factors: list[RiskFactor] = []
    score = 60  # neutral baseline

    whois = evidence.get("whois")
    ssl = evidence.get("ssl")
    dns = evidence.get("dns")
    reputation = evidence.get("reputation")
    brand = evidence.get("brand")
    url_analysis = evidence.get("urlAnalysis")
    website = evidence.get("website", {})

    # --- WHOIS / Domain age ---
    if whois:
        age = whois.domainAge
        if "Unknown" not in age:
            if "year" in age:
                years = int(age.split()[0])
                if years >= 5:
                    score += 15; factors.append(RiskFactor("Established domain (5+ years)", True, 15))
                elif years >= 2:
                    score += 8; factors.append(RiskFactor("Moderately aged domain (2+ years)", True, 8))
                elif years >= 1:
                    score += 2; factors.append(RiskFactor("Young domain (1-2 years)", True, 2))
                else:
                    score -= 10; factors.append(RiskFactor("Very new domain (< 1 year)", False, -10))
            elif "month" in age:
                months = int(age.split()[0])
                if months < 3:
                    score -= 20; factors.append(RiskFactor("Newly registered domain (< 3 months)", False, -20))
                else:
                    score -= 8; factors.append(RiskFactor("Recently registered domain (< 12 months)", False, -8))
            elif "day" in age:
                score -= 25; factors.append(RiskFactor("Very newly registered domain (days old)", False, -25))

    # --- SSL ---
    if ssl:
        if "Valid" in ssl.sslStatus:
            score += 15; factors.append(RiskFactor("Valid TLS/SSL certificate", True, 15))
            if "TLSv1.3" in ssl.tlsVersion:
                score += 5; factors.append(RiskFactor("Modern TLS 1.3 protocol", True, 5))
            elif "TLSv1.2" in ssl.tlsVersion:
                score += 2; factors.append(RiskFactor("TLS 1.2 protocol", True, 2))
        elif "Not available" in ssl.sslStatus:
            score -= 20; factors.append(RiskFactor("No valid SSL certificate", False, -20))
        elif "Expired" in ssl.sslStatus:
            score -= 15; factors.append(RiskFactor("Expired SSL certificate", False, -15))

    # --- Reputation ---
    if reputation:
        if reputation.overall == "malicious":
            score -= 40; factors.append(RiskFactor("Flagged malicious by reputation sources", False, -40))
        elif reputation.overall == "suspicious":
            score -= 20; factors.append(RiskFactor("Flagged suspicious by reputation sources", False, -20))
        else:
            # Only add points if we actually checked (not skipped)
            checked = not all("not configured" in s.lower() for s in [
                reputation.virusTotal, reputation.googleSafeBrowsing,
                reputation.urlScan, reputation.abuseIpdb
            ])
            if checked:
                score += 20; factors.append(RiskFactor("Clean reputation — no blocklist detections", True, 20))

    # --- Brand impersonation ---
    if brand:
        if brand.brandName != "None" and brand.confidence > 60:
            score -= 25; factors.append(RiskFactor(f"Brand impersonation: {brand.brandName}", False, -25))
        elif brand.brandName == "None":
            score += 10; factors.append(RiskFactor("No brand impersonation detected", True, 10))

    # --- URL analysis ---
    if url_analysis:
        if url_analysis.ipAddressDetection:
            score -= 15; factors.append(RiskFactor("IP address used in URL (no domain)", False, -15))
        if url_analysis.encodedCharacters:
            score -= 5; factors.append(RiskFactor("URL contains encoded/obfuscated characters", False, -5))
        if url_analysis.suspiciousParameters:
            score -= 8; factors.append(RiskFactor(f"Suspicious URL parameters: {', '.join(url_analysis.suspiciousParameters)}", False, -8))
        if url_analysis.redirectCount > 3:
            score -= 10; factors.append(RiskFactor(f"Excessive redirects ({url_analysis.redirectCount})", False, -10))
        if not url_analysis.httpsStatus:
            score -= 10; factors.append(RiskFactor("No HTTPS — plain HTTP only", False, -10))

    # --- Website evidence ---
    domain = website.get("domain", "")
    from utils.helpers import is_suspicious_tld
    if domain and is_suspicious_tld(domain):
        score -= 10; factors.append(RiskFactor(f"Suspicious TLD ({domain.split('.')[-1]})", False, -10))

    security_headers = website.get("securityHeaders", {})
    present = sum(1 for v in security_headers.values() if v != "MISSING")
    if present >= 5:
        score += 8; factors.append(RiskFactor(f"Good security headers ({present}/7 present)", True, 8))
    elif present <= 1:
        score -= 5; factors.append(RiskFactor(f"Poor security headers ({present}/7 present)", False, -5))

    # --- DNS ---
    if dns and dns.aRecord:
        factors.append(RiskFactor("Domain resolves correctly (DNS A record found)", True, 0))
    elif dns and not dns.aRecord:
        score -= 10; factors.append(RiskFactor("Domain does not resolve (no DNS A record)", False, -10))

    score = max(0, min(100, score))
    return RiskResult(score=score, risk_level=score_to_risk_level(score), factors=factors)


def score_email(evidence: dict) -> RiskResult:
    factors: list[RiskFactor] = []
    score = 60

    email_data = evidence.get("emailData")
    is_freemail = evidence.get("isFreemail", False)
    suspicious_kw = evidence.get("suspiciousKeywords", [])
    mx_exists = evidence.get("mxExists", True)
    dmarc_policy = evidence.get("dmarcPolicy", "missing")

    if email_data:
        if "Pass" in email_data.spf:
            score += 15; factors.append(RiskFactor("SPF record present and valid", True, 15))
        else:
            score -= 15; factors.append(RiskFactor("SPF record missing or invalid", False, -15))

        if "Pass" in email_data.dmarc:
            score += 10; factors.append(RiskFactor("DMARC policy configured", True, 10))
            if dmarc_policy == "reject":
                score += 5; factors.append(RiskFactor("DMARC policy: reject (strict)", True, 5))
        else:
            score -= 10; factors.append(RiskFactor("DMARC policy missing or weak", False, -10))

        if "Pass" in email_data.dkim:
            score += 15; factors.append(RiskFactor("DKIM selector found", True, 15))
        else:
            factors.append(RiskFactor("DKIM not verified (requires raw email headers)", True, 0))

        if "Potential spoofing" in email_data.spoofDetection:
            score -= 20; factors.append(RiskFactor("Spoofing indicators detected", False, -20))

    if is_freemail:
        score -= 5; factors.append(RiskFactor("Sender uses free email provider", False, -5))

    if suspicious_kw:
        score -= min(len(suspicious_kw) * 5, 20)
        factors.append(RiskFactor(f"Suspicious keywords in address: {', '.join(suspicious_kw[:3])}", False, -min(len(suspicious_kw) * 5, 20)))

    if not mx_exists:
        score -= 15; factors.append(RiskFactor("No MX record — domain cannot receive email", False, -15))

    score = max(0, min(100, score))
    return RiskResult(score=score, risk_level=score_to_risk_level(score), factors=factors)


def score_apk(evidence: dict) -> RiskResult:
    factors: list[RiskFactor] = []
    apk_risk = evidence.get("riskScore", 50)
    dangerous = evidence.get("dangerousPermissions", [])
    flags = evidence.get("malwareFlags", [])

    # Convert APK risk score (0-100 bad) to trust score (0-100 good)
    score = 100 - apk_risk

    for f in flags[:5]:
        factors.append(RiskFactor(f"Malware indicator: {f}", False, 0))

    if dangerous:
        factors.append(RiskFactor(f"{len(dangerous)} dangerous permissions declared", len(dangerous) < 4, 0))

    if not flags and len(dangerous) < 4:
        factors.append(RiskFactor("No high-severity malware indicators detected", True, 0))

    score = max(0, min(100, score))
    return RiskResult(score=score, risk_level=score_to_risk_level(score), factors=factors)


def score_qr(evidence: dict, website_score: Optional[RiskResult] = None) -> RiskResult:
    factors: list[RiskFactor] = []
    risk_indicators = evidence.get("riskIndicators", [])
    redirects = evidence.get("redirects", [])

    if website_score:
        score = website_score.score
        factors = website_score.factors[:]
    else:
        score = 60

    for ind in risk_indicators:
        score -= 10
        factors.append(RiskFactor(f"QR risk: {ind}", False, -10))

    if not risk_indicators:
        score += 5; factors.append(RiskFactor("No QR-specific risk indicators", True, 5))

    score = max(0, min(100, score))
    return RiskResult(score=score, risk_level=score_to_risk_level(score), factors=factors)


def score_sender(evidence: dict) -> RiskResult:
    # Sender is treated similarly to email
    return score_email(evidence)
