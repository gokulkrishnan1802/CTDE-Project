"""
Investigation router.
POST /analyze — main investigation endpoint (called by the frontend).
Dispatches to the correct service pipeline based on evidenceType.
"""
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session

from auth import get_optional_user
from database import get_db
from models import User, Investigation
from schemas import AnalyzeRequest, AnalysisResponse, EvidencePanelData, ScoreBreakdown, MitreTechnique
from utils.validators import normalize_url, extract_domain
from utils.helpers import sha256_of_string

from services.domain import investigate_domain
from services.ssl import check_ssl
from services.dns import lookup_dns
from services.whois_svc import lookup_whois
from services.website import investigate_website
from services.reputation import check_reputation
from services.email_svc import investigate_email
from services.qr_svc import investigate_qr
from services.apk_svc import analyze_apk_bytes
from services.risk_engine import (
    score_url, score_email, score_apk, score_qr, score_sender,
    RiskFactor, RiskResult,
)
from services.ai import generate_explanation

logger = logging.getLogger(__name__)
router = APIRouter(tags=["investigation"])


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze(
    req: AnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_user),
):
    evidence_type = req.evidenceType.lower()
    evidence_value = req.evidenceValue.strip()

    if not evidence_value:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="evidenceValue cannot be empty")

    try:
        if evidence_type == "url":
            result = await _pipeline_url(evidence_value)
        elif evidence_type == "email":
            result = await _pipeline_email(evidence_value)
        elif evidence_type == "apk":
            result = await _pipeline_apk_string(evidence_value)
        elif evidence_type == "qr":
            result = await _pipeline_qr(evidence_value)
        elif evidence_type == "sender":
            result = await _pipeline_sender(evidence_value)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported evidenceType: {evidence_type}")
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Investigation pipeline error for %s '%s': %s", evidence_type, evidence_value, exc)
        raise HTTPException(status_code=500, detail=f"Investigation failed: {exc}")

    # Persist if user is authenticated
    if current_user:
        try:
            inv = Investigation(
                case_id=_generate_case_id(db),
                user_id=current_user.id,
                evidence_type=evidence_type,
                evidence_value=evidence_value,
                trust_score=result.trustScore,
                risk_level=result.riskLevel,
                confidence=result.confidence,
                result_json=result.model_dump(),
            )
            db.add(inv)
            db.commit()
        except Exception as exc:
            logger.warning("Failed to persist investigation: %s", exc)
            db.rollback()

    return result


# ── URL pipeline ──────────────────────────────────────────────────────────────

async def _pipeline_url(url: str) -> AnalysisResponse:
    url = normalize_url(url)
    parsed = urlparse(url)
    domain = parsed.hostname or extract_domain(url)

    # Collect all evidence concurrently
    import asyncio
    website_task = investigate_website(url)
    reputation_task = check_reputation(url)
    domain_info = investigate_domain(domain)  # sync

    website, reputation = await asyncio.gather(website_task, reputation_task)

    whois_data = domain_info["whois"]
    dns_data = domain_info["dns"]
    ssl_data = check_ssl(domain)
    brand_data = website["brand"]
    url_analysis = website["urlAnalysis"]
    ip = domain_info["ip"]
    hosting = domain_info["hosting"]
    country = domain_info["country"]

    # Score
    risk_evidence = {
        "whois": whois_data,
        "ssl": ssl_data,
        "dns": dns_data,
        "reputation": reputation,
        "brand": brand_data,
        "urlAnalysis": url_analysis,
        "website": website,
    }
    risk_result = score_url(risk_evidence)

    # Build evidence strings
    ev_summary = (
        f"URL investigation of {url}. "
        f"Domain: {domain} | IP: {ip} | Hosting: {hosting} | Country: {country}. "
        f"SSL: {ssl_data.sslStatus} | WHOIS Age: {whois_data.domainAge} | "
        f"Reputation: {reputation.overall.upper()}."
    )

    identity = (
        f"Domain '{domain}' registered via {whois_data.registrar}. "
        f"Registration date: {whois_data.registrationDate}. "
        f"Domain age: {whois_data.domainAge}. "
        f"Status: {whois_data.whoisStatus}."
    )

    domain_verif = (
        f"Domain resolves {'correctly' if dns_data.aRecord else 'incorrectly — no A record found'}. "
        f"A records: {', '.join(dns_data.aRecord[:3]) or 'None'}. "
        f"NS: {', '.join(dns_data.ns[:2]) or 'None'}. "
        f"DNSSEC: {'Enabled' if domain_info.get('hasDnssec') else 'Not configured'}."
    )

    cert_text = (
        f"{ssl_data.sslStatus} — Issued by: {ssl_data.issuer}. "
        f"TLS Version: {ssl_data.tlsVersion}. "
        f"Valid from {ssl_data.validFrom} to {ssl_data.validUntil}. "
        f"Subject: {ssl_data.subject}."
    )

    whois_text = (
        f"Registrar: {whois_data.registrar}. "
        f"Created: {whois_data.registrationDate}. "
        f"Expires: {whois_data.expiryDate}. "
        f"Country: {whois_data.country}. "
        f"Status: {whois_data.whoisStatus}."
    )

    brand_text = brand_data.evidence if brand_data else "No brand impersonation analysis available."

    url_analysis_text = (
        f"URL length: {url_analysis.urlLength} chars. "
        f"HTTPS: {'Yes' if url_analysis.httpsStatus else 'No'}. "
        f"Redirects: {url_analysis.redirectCount}. "
        f"IP in URL: {'Yes' if url_analysis.ipAddressDetection else 'No'}. "
        f"Encoded characters: {'Yes' if url_analysis.encodedCharacters else 'No'}. "
        f"Suspicious params: {', '.join(url_analysis.suspiciousParameters) or 'None'}."
    )

    rep_text = (
        f"{reputation.virusTotal}. "
        f"{reputation.googleSafeBrowsing}. "
        f"{reputation.urlScan}. "
        f"{reputation.abuseIpdb}."
    )

    mitre = _map_mitre_url(risk_result, brand_data, url_analysis, reputation)
    recs = _recommendations_url(risk_result, ssl_data, whois_data, reputation, brand_data)

    # AI explanation
    ai_context = {
        "evidenceType": "url",
        "evidenceValue": url,
        "trustScore": risk_result.score,
        "riskLevel": risk_result.risk_level,
        "scoreFactors": [{"label": f.label, "positive": f.positive} for f in risk_result.factors],
        "whoisData": whois_data.model_dump() if whois_data else {},
        "sslData": ssl_data.model_dump() if ssl_data else {},
        "reputationData": reputation.model_dump() if reputation else {},
        "brandData": brand_data.model_dump() if brand_data else {},
    }
    ai_texts = await generate_explanation(ai_context)

    evidence_panel = EvidencePanelData(
        originalUrl=url,
        resolvedUrl=website.get("finalUrl", url),
        ipAddress=ip,
        hostingProvider=hosting,
        country=country,
        registrar=whois_data.registrar,
        sslStatus=ssl_data.sslStatus,
        whoisStatus=whois_data.whoisStatus,
        sha256Hash=sha256_of_string(url),
    )

    return AnalysisResponse(
        evidenceType="url",
        evidenceValue=url,
        evidenceSummary=ev_summary,
        identityVerification=identity,
        domainVerification=domain_verif,
        certificateValidation=cert_text,
        whoisInfo=whois_text,
        brandImpersonation=brand_text,
        urlAnalysis=url_analysis_text,
        reputationAnalysis=rep_text,
        trustScore=risk_result.score,
        riskLevel=risk_result.risk_level,
        confidence=90,
        reasonBehindDecision=_reason_text(risk_result),
        investigationStory=ai_texts["investigationStory"],
        mitreMapping=[t["id"] + " — " + t["name"] for t in mitre],
        aiSummary=ai_texts["aiSummary"],
        aiExplanation=ai_texts["aiExplanation"],
        recommendations=recs,
        scoreBreakdown=[ScoreBreakdown(label=f.label, positive=f.positive, points=f.points) for f in risk_result.factors],
        mitreTechniques=[MitreTechnique(techniqueId=t["id"], techniqueName=t["name"], description=t["desc"]) for t in mitre],
        whois=whois_data,
        ssl=ssl_data,
        dns=dns_data,
        reputation=reputation,
        brand=brand_data,
        urlAnalysisStructured=url_analysis,
        evidencePanel=evidence_panel,
    )


# ── Email pipeline ────────────────────────────────────────────────────────────

async def _pipeline_email(email_str: str) -> AnalysisResponse:
    email_evidence = investigate_email(email_str)
    domain = email_evidence["domain"]
    email_data = email_evidence["emailData"]
    dns_data = email_evidence["dns"]

    reputation = await check_reputation(email_str)
    risk_result = score_email(email_evidence)

    identity = (
        f"Email address: {email_evidence['email']}. "
        f"Sender domain: {domain}. "
        f"Free email provider: {'Yes' if email_evidence['isFreemail'] else 'No'}."
    )

    sender_verif = (
        f"SPF: {email_data.spf}. "
        f"DKIM: {email_data.dkim}. "
        f"DMARC: {email_data.dmarc}. "
        f"Spoofing detection: {email_data.spoofDetection}. "
        f"MX records: {'Found' if email_evidence['mxExists'] else 'Missing'}."
    )

    kw = email_evidence.get("suspiciousKeywords", [])
    url_analysis_text = (
        f"Suspicious keywords in address: {', '.join(kw) if kw else 'None'}. "
        f"Domain: {domain}."
    )

    ev_summary = (
        f"Email investigation of '{email_str}'. "
        f"Domain: {domain}. "
        f"SPF: {email_data.spf.split(' — ')[0]}. "
        f"DMARC: {email_data.dmarc.split(' — ')[0]}. "
        f"Spoofing risk: {email_data.spoofDetection.split(' — ')[0]}."
    )

    mitre = _map_mitre_email(risk_result, email_data)
    recs = _recommendations_email(risk_result, email_data, email_evidence["isFreemail"])

    ai_context = {
        "evidenceType": "email",
        "evidenceValue": email_str,
        "trustScore": risk_result.score,
        "riskLevel": risk_result.risk_level,
        "scoreFactors": [{"label": f.label, "positive": f.positive} for f in risk_result.factors],
    }
    ai_texts = await generate_explanation(ai_context)

    evidence_panel = EvidencePanelData(
        originalUrl=email_str,
        resolvedUrl=f"@{domain}",
        ipAddress=email_evidence.get("ip", "N/A"),
        hostingProvider="N/A",
        country="N/A",
        registrar="N/A",
        sslStatus="N/A",
        whoisStatus="N/A",
        sha256Hash=email_evidence["sha256"],
    )

    # WHOIS for the sender domain
    whois_data = lookup_whois(domain)
    ssl_data = check_ssl(domain)

    return AnalysisResponse(
        evidenceType="email",
        evidenceValue=email_str,
        evidenceSummary=ev_summary,
        identityVerification=identity,
        domainVerification=f"Sender domain: {domain}. MX records: {', '.join(dns_data.mx[:2]) or 'None found'}.",
        certificateValidation=f"Domain SSL: {ssl_data.sslStatus}.",
        whoisInfo=f"Registrar: {whois_data.registrar}. Domain age: {whois_data.domainAge}. Country: {whois_data.country}.",
        brandImpersonation=f"Keywords found: {', '.join(kw) if kw else 'None detected'}.",
        urlAnalysis=url_analysis_text,
        senderVerification=sender_verif,
        reputationAnalysis=f"{reputation.virusTotal}. {reputation.googleSafeBrowsing}.",
        trustScore=risk_result.score,
        riskLevel=risk_result.risk_level,
        confidence=85,
        reasonBehindDecision=_reason_text(risk_result),
        investigationStory=ai_texts["investigationStory"],
        mitreMapping=[t["id"] + " — " + t["name"] for t in mitre],
        aiSummary=ai_texts["aiSummary"],
        aiExplanation=ai_texts["aiExplanation"],
        recommendations=recs,
        scoreBreakdown=[ScoreBreakdown(label=f.label, positive=f.positive, points=f.points) for f in risk_result.factors],
        email=email_data,
        whois=whois_data,
        ssl=ssl_data,
        dns=dns_data,
        reputation=reputation,
        evidencePanel=evidence_panel,
    )


# ── APK pipeline (string / package name input) ────────────────────────────────

async def _pipeline_apk_string(apk_value: str) -> AnalysisResponse:
    """
    Handle APK analysis when only a filename/package name is provided (no binary).
    Binary APK analysis is handled via a file upload endpoint.
    """
    sha = sha256_of_string(apk_value)

    apk_evidence = {
        "sha256": sha,
        "filename": apk_value,
        "permissions": [],
        "dangerousPermissions": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "networkUrls": [],
        "signingCertificate": "Unknown — no binary provided",
        "malwareFlags": [],
        "malwareDetection": "Static analysis requires APK binary upload",
        "riskScore": 50,
    }

    from schemas import APKData
    apk_data = APKData(
        sha256=sha,
        permissions=[],
        dangerousPermissions=[],
        receivers=[],
        services=[],
        activities=[],
        malwareDetection="Static analysis requires APK binary upload. Please use the file upload endpoint.",
        riskScore=50,
    )

    risk_result = score_apk(apk_evidence)
    reputation = await check_reputation(apk_value)
    mitre = _map_mitre_apk(apk_evidence)
    recs = ["Upload the actual APK binary for full static analysis.", "Verify the app source and publisher.", "Check Google Play Store listing for the app."]
    ai_context = {"evidenceType": "apk", "evidenceValue": apk_value, "trustScore": risk_result.score, "riskLevel": risk_result.risk_level, "scoreFactors": []}
    ai_texts = await generate_explanation(ai_context)

    return AnalysisResponse(
        evidenceType="apk",
        evidenceValue=apk_value,
        evidenceSummary=f"APK investigation of '{apk_value}'. SHA256: {sha[:16]}... Static analysis requires binary upload.",
        identityVerification=f"Package/filename: {apk_value}. Publisher identity cannot be verified without the binary.",
        domainVerification="N/A for APK",
        certificateValidation="Signing certificate: Unknown — binary not provided.",
        whoisInfo="N/A for APK",
        brandImpersonation="Brand check requires binary analysis.",
        urlAnalysis="N/A for APK",
        apkPermissionAnalysis="Static permission analysis requires the APK binary. Upload the .apk file for full analysis.",
        reputationAnalysis=f"{reputation.virusTotal}. {reputation.googleSafeBrowsing}.",
        trustScore=risk_result.score,
        riskLevel=risk_result.risk_level,
        confidence=50,
        reasonBehindDecision=_reason_text(risk_result),
        investigationStory=ai_texts["investigationStory"],
        mitreMapping=[t["id"] + " — " + t["name"] for t in mitre],
        aiSummary=ai_texts["aiSummary"],
        aiExplanation=ai_texts["aiExplanation"],
        recommendations=recs,
        scoreBreakdown=[ScoreBreakdown(label=f.label, positive=f.positive, points=f.points) for f in risk_result.factors],
        apk=apk_data,
        reputation=reputation,
        evidencePanel=EvidencePanelData(
            originalUrl=apk_value, resolvedUrl="N/A", ipAddress="N/A",
            hostingProvider="N/A", country="N/A", registrar="N/A",
            sslStatus="N/A", whoisStatus="N/A", sha256Hash=sha,
        ),
    )


# ── QR pipeline ───────────────────────────────────────────────────────────────

async def _pipeline_qr(content: str) -> AnalysisResponse:
    qr_evidence = await investigate_qr(content)
    qr_data = qr_evidence["qrData"]
    resolved_url = qr_evidence["resolvedUrl"]

    # If QR resolves to a URL, run full URL investigation
    url_result: AnalysisResponse | None = None
    if qr_evidence["isUrl"]:
        try:
            url_result = await _pipeline_url(resolved_url)
        except Exception as exc:
            logger.warning("QR URL pipeline failed: %s", exc)

    if url_result:
        # Overlay QR-specific data onto URL result
        import asyncio
        risk_result = score_qr(qr_evidence, None)
        qr_verif = (
            f"QR decoded content: {content}. "
            f"Resolved to: {resolved_url}. "
            f"Redirects: {len(qr_evidence['redirects'])}. "
            f"QR risk level: {qr_data.qrRiskLevel}."
        )
        url_result.evidenceType = "qr"
        url_result.evidenceValue = content
        url_result.qrVerification = qr_verif
        url_result.qr = qr_data
        url_result.trustScore = max(0, min(100, url_result.trustScore - len(qr_evidence["riskIndicators"]) * 10))
        url_result.riskLevel = _score_to_risk(url_result.trustScore)
        return url_result

    # QR content is not a URL
    risk_result = score_qr(qr_evidence)
    ai_context = {"evidenceType": "qr", "evidenceValue": content, "trustScore": risk_result.score, "riskLevel": risk_result.risk_level, "scoreFactors": []}
    ai_texts = await generate_explanation(ai_context)
    sha = sha256_of_string(content)

    return AnalysisResponse(
        evidenceType="qr",
        evidenceValue=content,
        evidenceSummary=f"QR code investigation. Decoded content: {content[:100]}. No URL destination detected.",
        identityVerification="QR does not contain a URL — identity verification not applicable.",
        domainVerification="N/A",
        certificateValidation="N/A",
        whoisInfo="N/A",
        brandImpersonation="N/A",
        urlAnalysis=f"Content length: {len(content)} chars. Redirects: {len(qr_evidence['redirects'])}.",
        qrVerification=f"Decoded: {content}. Risk: {qr_data.qrRiskLevel}.",
        reputationAnalysis="Reputation check not applicable for non-URL QR content.",
        trustScore=risk_result.score,
        riskLevel=risk_result.risk_level,
        confidence=80,
        reasonBehindDecision=_reason_text(risk_result),
        investigationStory=ai_texts["investigationStory"],
        mitreMapping=["T1566.002 — Phishing via QR Code"],
        aiSummary=ai_texts["aiSummary"],
        aiExplanation=ai_texts["aiExplanation"],
        recommendations=["Verify the source of the QR code.", "Do not scan QR codes from unknown sources.", "Use a QR scanner that previews the URL before opening."],
        qr=qr_data,
        evidencePanel=EvidencePanelData(
            originalUrl=content, resolvedUrl=resolved_url, ipAddress="N/A",
            hostingProvider="N/A", country="N/A", registrar="N/A",
            sslStatus="N/A", whoisStatus="N/A", sha256Hash=sha,
        ),
    )


# ── Sender pipeline ───────────────────────────────────────────────────────────

async def _pipeline_sender(sender: str) -> AnalysisResponse:
    result = await _pipeline_email(sender)
    result.evidenceType = "sender"
    return result


# ── MITRE ATT&CK mappings ─────────────────────────────────────────────────────

def _map_mitre_url(risk: RiskResult, brand, url_analysis, reputation) -> list[dict]:
    techniques = []
    if brand and brand.confidence > 60 and brand.brandName != "None":
        techniques.append({"id": "T1566.002", "name": "Phishing: Spearphishing Link", "desc": "Attacker used a link impersonating a legitimate brand."})
    if url_analysis and url_analysis.ipAddressDetection:
        techniques.append({"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "desc": "URL uses raw IP address to bypass domain-based detection."})
    if url_analysis and url_analysis.redirectCount > 2:
        techniques.append({"id": "T1036", "name": "Masquerading", "desc": "Multiple redirects used to obscure the final destination."})
    if reputation and reputation.overall == "malicious":
        techniques.append({"id": "T1583.001", "name": "Acquire Infrastructure: Domains", "desc": "Domain flagged as malicious by threat intelligence."})
    if not techniques:
        techniques.append({"id": "T1598.003", "name": "Phishing for Information: Spearphishing Link", "desc": "URL requires monitoring — no confirmed active techniques."})
    return techniques


def _map_mitre_email(risk: RiskResult, email_data) -> list[dict]:
    techniques = [{"id": "T1566.001", "name": "Phishing: Spearphishing Attachment", "desc": "Email-based phishing vector."}]
    if email_data and "Fail" in email_data.spf:
        techniques.append({"id": "T1534", "name": "Internal Spearphishing", "desc": "Missing SPF enables email spoofing."})
    if email_data and "Potential spoofing" in email_data.spoofDetection:
        techniques.append({"id": "T1656", "name": "Impersonation", "desc": "Sender identity indicators suggest impersonation."})
    return techniques


def _map_mitre_apk(apk_evidence: dict) -> list[dict]:
    techniques = [{"id": "T1476", "name": "Deliver Malicious App via Other Means", "desc": "APK delivered outside official app stores."}]
    flags = apk_evidence.get("malwareFlags", [])
    if any("SMS" in f for f in flags):
        techniques.append({"id": "T1412", "name": "Capture SMS Messages", "desc": "App requests SMS read/receive permissions."})
    if any("overlay" in f.lower() for f in flags):
        techniques.append({"id": "T1417", "name": "Input Capture", "desc": "Overlay attack capability detected."})
    return techniques


# ── Recommendation builders ───────────────────────────────────────────────────

def _recommendations_url(risk: RiskResult, ssl, whois, reputation, brand) -> list[str]:
    recs = []
    if risk.risk_level == "Dangerous":
        recs.append("Do NOT visit or interact with this URL — it shows multiple high-risk indicators.")
        recs.append("Report this URL to Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/")
    if ssl and "Not available" in ssl.sslStatus:
        recs.append("This site does not use HTTPS — any data entered would be transmitted in plaintext.")
    if whois and ("month" in whois.domainAge or "day" in whois.domainAge):
        recs.append("Treat newly registered domains with caution — they are commonly used in phishing.")
    if brand and brand.confidence > 60 and brand.brandName != "None":
        recs.append(f"This domain impersonates '{brand.brandName}'. Visit the official {brand.brandName} website directly via a bookmark.")
    if reputation and reputation.overall == "malicious":
        recs.append("This URL is flagged by threat intelligence sources — block it at the network level.")
    if not recs:
        recs.append("Continue monitoring for any changes in domain registration or reputation.")
        recs.append("Verify the URL matches the official domain before entering sensitive information.")
    return recs


def _recommendations_email(risk: RiskResult, email_data, is_freemail: bool) -> list[str]:
    recs = []
    if "Fail" in email_data.spf:
        recs.append("The sender's domain has no SPF record — emails from this domain can be spoofed. Exercise caution.")
    if "Fail" in email_data.dmarc or "missing" in email_data.dmarc.lower():
        recs.append("The sender's domain lacks DMARC policy — spoofed emails may reach inboxes.")
    if "Potential spoofing" in email_data.spoofDetection:
        recs.append("Spoofing indicators detected — verify sender identity through an independent channel before responding.")
    if is_freemail:
        recs.append("Free email provider used — legitimate businesses typically use corporate domain email.")
    if risk.risk_level == "Dangerous":
        recs.append("Do NOT click links or download attachments from this sender without independent verification.")
    if not recs:
        recs.append("Email authentication checks passed. Continue exercising standard email security hygiene.")
    return recs


# ── Helpers ───────────────────────────────────────────────────────────────────

def _reason_text(risk: RiskResult) -> str:
    if not risk.factors:
        return f"Trust Score: {risk.score}/100. No evidence factors were collected."
    neg = [f.label for f in risk.factors if not f.positive]
    pos = [f.label for f in risk.factors if f.positive]
    parts = []
    if neg:
        parts.append(f"Risk factors: {'; '.join(neg[:3])}")
    if pos:
        parts.append(f"Trust factors: {'; '.join(pos[:3])}")
    return " | ".join(parts) + f". Final score: {risk.score}/100."


def _score_to_risk(score: int) -> str:
    if score <= 40:
        return "Dangerous"
    if score <= 60:
        return "Suspicious"
    return "Safe"


def _generate_case_id(db: Session) -> str:
    count = db.query(Investigation).count()
    year = datetime.now(timezone.utc).year
    return f"CTDE-{year}-{str(count + 1).zfill(4)}"
