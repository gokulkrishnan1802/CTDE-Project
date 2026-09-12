"""
Investigation router.
POST /analyze — main investigation endpoint (called by the frontend).
Dispatches to the correct service pipeline based on evidenceType.
"""
import io
import os
import zipfile
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import (  # pyright: ignore[reportMissingImports]
    APIRouter,
    HTTPException,
    Depends,
    status,
    UploadFile,
    File,
)
from services.qr_svc import decode_qr_bytes
from sqlalchemy.orm import Session  # pyright: ignore[reportMissingImports]

from auth import get_optional_user
from database import get_db
from models import User, Investigation

from schemas import (
    AnalyzeRequest,
    EmailHeaderRequest,
    AnalysisResponse,
    EvidencePanelData,
    ScoreBreakdown,
    MitreTechnique,
)

from utils.validators import normalize_url, extract_domain
from utils.helpers import sha256_of_string

from services.domain import investigate_domain ,lookup_whois
from services.ssl import check_ssl
from services.website import investigate_website
from services.reputation import check_reputation
from services.email_svc import (
    investigate_email,
    investigate_email_headers,
)
from services.qr_svc import investigate_qr
from services.apk_svc import analyze_apk_bytes

from services.risk_engine import (
    score_url,
    score_email,
    score_apk,
    score_qr,
    score_sender,
    RiskResult,
)

from services.ai import generate_explanation


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analyze", tags=["investigation"])


# ══════════════════════════════════════════════════════════════════════════════
# MAIN ANALYSIS ENDPOINT
# ══════════════════════════════════════════════════════════════════════════════

@router.post("", response_model=AnalysisResponse)
async def analyze(
    req: AnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_user),
):
    evidence_type = req.evidenceType.lower()
    evidence_value = req.evidenceValue.strip()

    if not evidence_value:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="evidenceValue cannot be empty",
        )

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
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported evidenceType: {evidence_type}",
            )

    except HTTPException:
        raise

    except Exception as exc:
        logger.exception(
            "Investigation pipeline error for %s '%s': %s",
            evidence_type,
            evidence_value,
            exc,
        )

        raise HTTPException(
            status_code=500,
            detail=f"Investigation failed: {exc}",
        )

    # ── Persist authenticated investigation ──────────────────────────────────

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
            logger.warning(
                "Failed to persist investigation: %s",
                exc,
            )
            db.rollback()

    return result
# ══════════════════════════════════════════════════════════════════════════════
# RAW EMAIL HEADER ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/email", response_model=AnalysisResponse)
async def analyze_email_headers(
    req: EmailHeaderRequest,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_user),
):
    raw_headers = req.rawHeaders
    """
    Analyze raw email headers.

    Expected input:
        From:
        Reply-To:
        Return-Path:
        Received:
        Authentication-Results:
        Received-SPF:
        DKIM-Signature:
        Message-ID:
        Subject:

    This endpoint performs forensic header analysis rather than
    only checking an email address/domain.
    """

    raw_headers = raw_headers.strip()

    if not raw_headers:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Email headers cannot be empty.",
        )

    try:
        header_evidence = investigate_email_headers(
            raw_headers
        )

        sender_email = header_evidence.get(
            "email",
            ""
        )

        sender_domain = header_evidence.get(
            "domain",
            ""
        )

        if not sender_email and not sender_domain:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unable to identify sender from email headers.",
            )

        # --------------------------------------------------------------
        # Build the normal CTDE email evidence structure.
        #
        # This keeps the existing risk engine compatible while adding
        # raw-header forensic evidence.
        # --------------------------------------------------------------

        if sender_email:
            try:
                base_email = investigate_email(
                    sender_email
                )
            except Exception:
                base_email = investigate_email(
                    sender_domain
                )
        else:
            base_email = investigate_email(
                sender_domain
            )

        # --------------------------------------------------------------
        # Replace authentication values with the actual header results.
        # --------------------------------------------------------------

        email_data = base_email["emailData"]

        email_data.spf = (
            f"Header result: "
            f"{header_evidence.get('spfResult', 'unknown')}"
        )

        email_data.dkim = (
            f"Header result: "
            f"{header_evidence.get('dkimResult', 'unknown')}"
        )

        email_data.dmarc = (
            f"Header result: "
            f"{header_evidence.get('dmarcResult', 'unknown')}"
        )

        spoof_indicators = header_evidence.get(
            "spoofingIndicators",
            [],
        )

        if spoof_indicators:
            email_data.spoofDetection = (
                "Potential spoofing risk — "
                + "; ".join(spoof_indicators)
            )
        else:
            email_data.spoofDetection = (
                "No major header spoofing indicators detected"
            )

        reply_to = header_evidence.get(
            "replyTo",
            ""
        )

        if reply_to:
            email_data.replyToAnalysis = (
                f"Reply-To: {reply_to}. "
                f"Reply-To domain: "
                f"{header_evidence.get('replyToDomain', 'unknown')}."
            )
        else:
            email_data.replyToAnalysis = (
                "No Reply-To header found."
            )

        # --------------------------------------------------------------
        # Merge raw-header evidence into CTDE evidence.
        # --------------------------------------------------------------

        email_evidence = dict(base_email)

        email_evidence.update({
            "email": sender_email,
            "domain": sender_domain,

            "headerAnalysis": header_evidence,

            "spfResult": header_evidence.get(
                "spfResult",
                "unknown",
            ),

            "dkimResult": header_evidence.get(
                "dkimResult",
                "unknown",
            ),

            "dmarcResult": header_evidence.get(
                "dmarcResult",
                "unknown",
            ),

            "spoofingIndicators": spoof_indicators,

            "receivedIps": header_evidence.get(
                "receivedIps",
                [],
            ),

            "replyTo": reply_to,

            "returnPath": header_evidence.get(
                "returnPath",
                "",
            ),

            "messageId": header_evidence.get(
                "messageId",
                "",
            ),

            "emailData": email_data,
        })

        # --------------------------------------------------------------
        # Reputation
        # --------------------------------------------------------------

        try:
            reputation = await check_reputation(
                sender_email or sender_domain
            )
        except Exception as exc:
            logger.warning(
                "Email header reputation lookup failed: %s",
                exc,
            )
            reputation = None

        # --------------------------------------------------------------
        # --------------------------------------------------------------
        # CTDE RISK ENGINE — RAW EMAIL HEADER SCORING
        # --------------------------------------------------------------

        spf_result = str(
            header_evidence.get("spfResult", "unknown")
        ).lower()

        dkim_result = str(
            header_evidence.get("dkimResult", "unknown")
        ).lower()

        dmarc_result = str(
            header_evidence.get("dmarcResult", "unknown")
        ).lower()

        header_score = 100
        header_factors = []

        # SPF
        if spf_result == "pass":
            header_factors.append(
                ScoreBreakdown(
                    label="SPF authentication passed",
                    positive=True,
                    points=0,
                )
            )
        elif spf_result == "fail":
            header_score -= 15
            header_factors.append(
                ScoreBreakdown(
                    label="SPF authentication failed",
                    positive=False,
                    points=-15,
                )
            )
        else:
            header_score -= 5
            header_factors.append(
                ScoreBreakdown(
                    label="SPF result unavailable",
                    positive=False,
                    points=-5,
                )
            )

        # DKIM
        if dkim_result == "pass":
            header_factors.append(
                ScoreBreakdown(
                    label="DKIM authentication passed",
                    positive=True,
                    points=0,
                )
            )
        elif dkim_result == "fail":
            header_score -= 15
            header_factors.append(
                ScoreBreakdown(
                    label="DKIM authentication failed",
                    positive=False,
                    points=-15,
                )
            )
        else:
            header_score -= 5
            header_factors.append(
                ScoreBreakdown(
                    label="DKIM result unavailable",
                    positive=False,
                    points=-5,
                )
            )

        # DMARC
        if dmarc_result == "pass":
            header_factors.append(
                ScoreBreakdown(
                    label="DMARC authentication passed",
                    positive=True,
                    points=0,
                )
            )
        elif dmarc_result == "fail":
            header_score -= 20
            header_factors.append(
                ScoreBreakdown(
                    label="DMARC authentication failed",
                    positive=False,
                    points=-20,
                )
            )
        else:
            header_score -= 5
            header_factors.append(
                ScoreBreakdown(
                    label="DMARC result unavailable",
                    positive=False,
                    points=-5,
                )
            )

        # Additional forensic penalties
        header_penalty = 0

        for indicator in spoof_indicators:
            indicator_lower = str(indicator).lower()

            if (
                "spf authentication: fail" in indicator_lower
                or "dkim authentication: fail" in indicator_lower
                or "dmarc authentication: fail" in indicator_lower
            ):
                continue

            if (
                "reply-to domain" in indicator_lower
                or "return-path domain" in indicator_lower
            ):
                header_penalty += 10
                header_factors.append(
                    ScoreBreakdown(
                        label=indicator,
                        positive=False,
                        points=-10,
                    )
                )

            elif "missing message-id" in indicator_lower:
                header_penalty += 5
                header_factors.append(
                    ScoreBreakdown(
                        label=indicator,
                        positive=False,
                        points=-5,
                    )
                )

            elif "no received headers" in indicator_lower:
                header_penalty += 5
                header_factors.append(
                    ScoreBreakdown(
                        label=indicator,
                        positive=False,
                        points=-5,
                    )
                )

            else:
                header_penalty += 5
                header_factors.append(
                    ScoreBreakdown(
                        label=indicator,
                        positive=False,
                        points=-5,
                    )
                )

        # Final score
        final_score = max(
            0,
            min(
                100,
                header_score - header_penalty,
            ),
        )

        final_risk = _score_to_risk(final_score)

        score_factors = header_factors
        # --------------------------------------------------------------
        # SCORE BREAKDOWN
        # --------------------------------------------------------------

     
        # --------------------------------------------------------------
        # MITRE ATT&CK
        # --------------------------------------------------------------

        mitre = _map_mitre_email_headers(
            header_evidence
        )

        # --------------------------------------------------------------
        # RECOMMENDATIONS
        # --------------------------------------------------------------

        recommendations = (
            _recommendations_email_headers(
                header_evidence,
                final_risk,
            )
        )

        # --------------------------------------------------------------
        # AI EXPLANATION
        # --------------------------------------------------------------

        ai_context = {
            "evidenceType": "email",
            "evidenceValue": sender_email,

            "trustScore": final_score,
            "riskLevel": final_risk,

            "scoreFactors": [
                {
                    "label": factor.label,
                    "positive": factor.positive,
                    "points": factor.points,
                }
                for factor in score_factors
            ],

            "emailHeaderEvidence": header_evidence,
        }

        ai_texts = await generate_explanation(
            ai_context
        )

        # --------------------------------------------------------------
        # HUMAN-READABLE FORENSIC SUMMARY
        # --------------------------------------------------------------

        received_ips = header_evidence.get(
            "receivedIps",
            [],
        )

        evidence_summary = (
            f"Email header forensic investigation. "
            f"Sender: {sender_email or 'Unknown'}. "
            f"Domain: {sender_domain or 'Unknown'}. "
            f"SPF: {header_evidence.get('spfResult', 'unknown')}. "
            f"DKIM: {header_evidence.get('dkimResult', 'unknown')}. "
            f"DMARC: {header_evidence.get('dmarcResult', 'unknown')}. "
            f"Received IPs: {len(received_ips)}. "
            f"Spoofing indicators: "
            f"{len(spoof_indicators)}."
        )

        identity = (
            f"From: "
            f"{sender_email or 'Not detected'}. "
            f"Return-Path: "
            f"{header_evidence.get('returnPath') or 'Not detected'}. "
            f"Reply-To: "
            f"{header_evidence.get('replyTo') or 'Not detected'}."
        )

        domain_verification = (
            f"Sender domain: "
            f"{sender_domain or 'Unknown'}. "
            f"DMARC policy: "
            f"{header_evidence.get('dmarcPolicy', 'unknown')}. "
            f"MX records: "
            f"{'Found' if email_evidence.get('mxExists') else 'Missing'}."
        )

        authentication_text = (
            f"SPF: "
            f"{header_evidence.get('spfResult', 'unknown')}. "
            f"DKIM: "
            f"{header_evidence.get('dkimResult', 'unknown')}. "
            f"DMARC: "
            f"{header_evidence.get('dmarcResult', 'unknown')}."
        )

        spoofing_text = (
            "; ".join(spoof_indicators)
            if spoof_indicators
            else "No major spoofing indicators detected."
        )

        received_text = (
            ", ".join(received_ips)
            if received_ips
            else "No public IPv4 addresses extracted."
        )

        message_text = (
            f"Message-ID: "
            f"{header_evidence.get('messageId') or 'Missing'}. "
            f"Subject: "
            f"{header_evidence.get('subject') or 'Not available'}. "
            f"Received IPs: {received_text}."
        )

        # --------------------------------------------------------------
        # WHOIS / SSL
        # --------------------------------------------------------------

        whois_data = None
        ssl_data = None

        if sender_domain:

            try:
                whois_data = lookup_whois(
                    sender_domain
                )
            except Exception as exc:
                logger.warning(
                    "WHOIS lookup failed: %s",
                    exc,
                )

            try:
                ssl_data = check_ssl(
                    sender_domain
                )
            except Exception as exc:
                logger.warning(
                    "SSL lookup failed: %s",
                    exc,
                )

        # --------------------------------------------------------------
        # FINAL EVIDENCE PANEL
        # --------------------------------------------------------------

        evidence_panel = EvidencePanelData(
            originalUrl=sender_email or sender_domain,
            resolvedUrl=(
                f"mail://{sender_domain}"
                if sender_domain
                else "N/A"
            ),
            ipAddress=(
                received_ips[0]
                if received_ips
                else "N/A"
            ),
            hostingProvider="Email infrastructure",
            country="N/A",
            registrar=(
                whois_data.registrar
                if whois_data
                else "N/A"
            ),
            sslStatus=(
                ssl_data.sslStatus
                if ssl_data
                else "N/A"
            ),
            whoisStatus=(
                whois_data.whoisStatus
                if whois_data
                else "N/A"
            ),
            sha256Hash=header_evidence[
                "sha256"
            ],
        )

        # --------------------------------------------------------------
        # FINAL RESPONSE
        # --------------------------------------------------------------

        return AnalysisResponse(
            evidenceType="email",
            evidenceValue=(
                sender_email
                or sender_domain
                or "raw-email-header"
            ),

            evidenceSummary=evidence_summary,

            identityVerification=identity,

            domainVerification=domain_verification,

            certificateValidation=(
                f"Sender-domain SSL: "
                f"{ssl_data.sslStatus if ssl_data else 'N/A'}."
            ),

            whoisInfo=(
                f"Registrar: "
                f"{whois_data.registrar if whois_data else 'N/A'}. "
                f"Domain age: "
                f"{whois_data.domainAge if whois_data else 'N/A'}."
            ),

            brandImpersonation=(
                "Header-based brand impersonation requires "
                "additional message/body analysis."
            ),

            urlAnalysis=message_text,

            senderVerification=authentication_text,

            reputationAnalysis=(
                f"{reputation.virusTotal}. "
                f"{reputation.googleSafeBrowsing}."
                if reputation
                else "Threat reputation lookup unavailable."
            ),

            trustScore=final_score,

            riskLevel=final_risk,

            confidence=90,

            reasonBehindDecision=(
                f"Header forensic analysis detected "
                f"{len(spoof_indicators)} spoofing indicators. "
                f"Final CTDE Trust Score: "
                f"{final_score}/100."
            ),

            investigationStory=(
                ai_texts["investigationStory"]
            ),

            mitreMapping=[
                technique["id"]
                + " — "
                + technique["name"]
                for technique in mitre
            ],

            aiSummary=ai_texts["aiSummary"],

            aiExplanation=ai_texts["aiExplanation"],

            recommendations=recommendations,

            scoreBreakdown=score_factors,

            mitreTechniques=[
                MitreTechnique(
                    techniqueId=technique["id"],
                    techniqueName=technique["name"],
                    description=technique["desc"],
                )
                for technique in mitre
            ],

            email=email_data,

            whois=whois_data,

            ssl=ssl_data,

            dns=email_evidence.get(
                "dns"
            ),

            reputation=reputation,

            evidencePanel=evidence_panel,
        )

    except HTTPException:
        raise

    except Exception as exc:

        logger.exception(
            "Email header investigation failed"
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                f"Email header analysis failed: {exc}"
            ),
        )

# ══════════════════════════════════════════════════════════════════════════════
# URL PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

async def _pipeline_url(url: str) -> AnalysisResponse:
    url = normalize_url(url)

    parsed = urlparse(url)
    domain = parsed.hostname or extract_domain(url)

    # ──────────────────────────────────────────────────────────────────────────
    # DOMAIN EVIDENCE FIRST
    #
    # Reputation analysis uses the resolved IP for AbuseIPDB.
    # Therefore domain_info must exist BEFORE check_reputation().
    # ──────────────────────────────────────────────────────────────────────────

    domain_info = investigate_domain(domain)

    import asyncio

    website_task = investigate_website(url)

    reputation_task = check_reputation(
        url,
        ip=domain_info.get("ip"),
    )

    website, reputation = await asyncio.gather(
        website_task,
        reputation_task,
    )

    # ──────────────────────────────────────────────────────────────────────────
    # STRUCTURED EVIDENCE
    # ──────────────────────────────────────────────────────────────────────────

    whois_data = domain_info["whois"]
    dns_data = domain_info["dns"]
    ssl_data = check_ssl(domain)

    brand_data = website["brand"]
    url_analysis = website["urlAnalysis"]

    ip = domain_info["ip"]
    hosting = domain_info["hosting"]
    country = domain_info["country"]

    # ──────────────────────────────────────────────────────────────────────────
    # RISK ENGINE
    # ──────────────────────────────────────────────────────────────────────────

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

    # ──────────────────────────────────────────────────────────────────────────
    # EVIDENCE SUMMARY
    # ──────────────────────────────────────────────────────────────────────────

    ev_summary = (
        f"URL investigation of {url}. "
        f"Domain: {domain} | "
        f"IP: {ip} | "
        f"Hosting: {hosting} | "
        f"Country: {country}. "
        f"SSL: {ssl_data.sslStatus} | "
        f"WHOIS Age: {whois_data.domainAge} | "
        f"Reputation: {reputation.overall.upper()}."
    )

    identity = (
        f"Domain '{domain}' registered via {whois_data.registrar}. "
        f"Registration date: {whois_data.registrationDate}. "
        f"Domain age: {whois_data.domainAge}. "
        f"Status: {whois_data.whoisStatus}."
    )

    domain_verif = (
        f"Domain resolves "
        f"{'correctly' if dns_data.aRecord else 'incorrectly — no A record found'}. "
        f"A records: {', '.join(dns_data.aRecord[:3]) or 'None'}. "
        f"NS: {', '.join(dns_data.ns[:2]) or 'None'}. "
        f"DNSSEC: "
        f"{'Enabled' if domain_info.get('hasDnssec') else 'Not configured'}."
    )

    cert_text = (
        f"{ssl_data.sslStatus} — "
        f"Issued by: {ssl_data.issuer}. "
        f"TLS Version: {ssl_data.tlsVersion}. "
        f"Valid from {ssl_data.validFrom} "
        f"to {ssl_data.validUntil}. "
        f"Subject: {ssl_data.subject}."
    )

    whois_text = (
        f"Registrar: {whois_data.registrar}. "
        f"Created: {whois_data.registrationDate}. "
        f"Expires: {whois_data.expiryDate}. "
        f"Country: {whois_data.country}. "
        f"Status: {whois_data.whoisStatus}."
    )

    brand_text = (
        brand_data.evidence
        if brand_data
        else "No brand impersonation analysis available."
    )

    url_analysis_text = (
        f"URL length: {url_analysis.urlLength} chars. "
        f"HTTPS: {'Yes' if url_analysis.httpsStatus else 'No'}. "
        f"Redirects: {url_analysis.redirectCount}. "
        f"IP in URL: "
        f"{'Yes' if url_analysis.ipAddressDetection else 'No'}. "
        f"Encoded characters: "
        f"{'Yes' if url_analysis.encodedCharacters else 'No'}. "
        f"Suspicious params: "
        f"{', '.join(url_analysis.suspiciousParameters) or 'None'}."
    )

    rep_text = (
        f"{reputation.virusTotal}. "
        f"{reputation.googleSafeBrowsing}. "
        f"{reputation.urlScan}. "
        f"{reputation.abuseIpdb}."
    )

    # ──────────────────────────────────────────────────────────────────────────
    # MITRE ATT&CK
    # ──────────────────────────────────────────────────────────────────────────

    mitre = _map_mitre_url(
        risk_result,
        brand_data,
        url_analysis,
        reputation,
    )

    # ──────────────────────────────────────────────────────────────────────────
    # RECOMMENDATIONS
    # ──────────────────────────────────────────────────────────────────────────

    recs = _recommendations_url(
        risk_result,
        ssl_data,
        whois_data,
        reputation,
        brand_data,
    )

    # ──────────────────────────────────────────────────────────────────────────
    # AI EXPLANATION
    # ──────────────────────────────────────────────────────────────────────────

    ai_context = {
        "evidenceType": "url",
        "evidenceValue": url,
        "trustScore": risk_result.score,
        "riskLevel": risk_result.risk_level,
        "scoreFactors": [
            {
                "label": factor.label,
                "positive": factor.positive,
                "points": factor.points,
            }
            for factor in risk_result.factors
        ],
        "whoisData": (
            whois_data.model_dump()
            if whois_data
            else {}
        ),
        "sslData": (
            ssl_data.model_dump()
            if ssl_data
            else {}
        ),
        "reputationData": (
            reputation.model_dump()
            if reputation
            else {}
        ),
        "brandData": (
            brand_data.model_dump()
            if brand_data
            else {}
        ),
    }

    ai_texts = await generate_explanation(ai_context)

    # ──────────────────────────────────────────────────────────────────────────
    # EVIDENCE PANEL
    # ──────────────────────────────────────────────────────────────────────────

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

    # ──────────────────────────────────────────────────────────────────────────
    # FINAL RESPONSE
    #
    # IMPORTANT:
    # scoreBreakdown comes DIRECTLY from risk_result.factors.
    # No hardcoded frontend score factors should be used.
    # ──────────────────────────────────────────────────────────────────────────

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
        mitreMapping=[
            technique["id"] + " — " + technique["name"]
            for technique in mitre
        ],

        aiSummary=ai_texts["aiSummary"],
        aiExplanation=ai_texts["aiExplanation"],
        recommendations=recs,

        # ACTUAL BACKEND RISK FACTORS
        scoreBreakdown=[
            ScoreBreakdown(
                label=factor.label,
                positive=factor.positive,
                points=factor.points,
            )
            for factor in risk_result.factors
        ],

        mitreTechniques=[
            MitreTechnique(
                techniqueId=technique["id"],
                techniqueName=technique["name"],
                description=technique["desc"],
            )
            for technique in mitre
        ],

        whois=whois_data,
        ssl=ssl_data,
        dns=dns_data,
        reputation=reputation,
        brand=brand_data,
        urlAnalysisStructured=url_analysis,

        evidencePanel=evidence_panel,
    )


# ══════════════════════════════════════════════════════════════════════════════
# EMAIL PIPELINE
# ══════════════════════════════════════════════════════════════════════════════
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
        f"Free email provider: "
        f"{'Yes' if email_evidence['isFreemail'] else 'No'}."
    )

    sender_verif = (
        f"SPF: {email_data.spf}. "
        f"DKIM: {email_data.dkim}. "
        f"DMARC: {email_data.dmarc}. "
        f"Spoofing detection: {email_data.spoofDetection}. "
        f"MX records: "
        f"{'Found' if email_evidence['mxExists'] else 'Missing'}."
    )

    kw = email_evidence.get(
        "suspiciousKeywords",
        [],
    )

    url_analysis_text = (
        f"Suspicious keywords in address: "
        f"{', '.join(kw) if kw else 'None'}. "
        f"Domain: {domain}."
    )

    ev_summary = (
        f"Email investigation of '{email_str}'. "
        f"Domain: {domain}. "
        f"SPF: {email_data.spf.split(' — ')[0]}. "
        f"DMARC: {email_data.dmarc.split(' — ')[0]}. "
        f"Spoofing risk: "
        f"{email_data.spoofDetection.split(' — ')[0]}."
    )

    mitre = _map_mitre_email(
        risk_result,
        email_data,
    )

    recs = _recommendations_email(
        risk_result,
        email_data,
        email_evidence["isFreemail"],
    )

    # --------------------------------------------------------------
    # AI EXPLANATION
    # --------------------------------------------------------------

    ai_context = {
        "evidenceType": "email",
        "evidenceValue": email_str,
        "trustScore": risk_result.score,
        "riskLevel": risk_result.risk_level,
        "scoreFactors": [
            {
                "label": factor.label,
                "positive": factor.positive,
                "points": factor.points,
            }
            for factor in risk_result.factors
        ],
    }

    ai_texts = await generate_explanation(
        ai_context
    )

    # --------------------------------------------------------------
    # EVIDENCE PANEL
    # --------------------------------------------------------------

    evidence_panel = EvidencePanelData(
        originalUrl=email_str,
        resolvedUrl=f"@{domain}",
        ipAddress=email_evidence.get(
            "ip",
            "N/A",
        ),
        hostingProvider="N/A",
        country="N/A",
        registrar="N/A",
        sslStatus="N/A",
        whoisStatus="N/A",
        sha256Hash=email_evidence["sha256"],
    )

    # --------------------------------------------------------------
    # WHOIS / SSL
    # --------------------------------------------------------------

    whois_data = lookup_whois(domain)
    ssl_data = check_ssl(domain)

    # --------------------------------------------------------------
    # FINAL RESPONSE
    # --------------------------------------------------------------

    return AnalysisResponse(
        evidenceType="email",
        evidenceValue=email_str,

        evidenceSummary=ev_summary,
        identityVerification=identity,

        domainVerification=(
            f"Sender domain: {domain}. "
            f"MX records: "
            f"{', '.join(dns_data.mx[:2]) or 'None found'}."
        ),

        certificateValidation=(
            f"Domain SSL: {ssl_data.sslStatus}."
        ),

        whoisInfo=(
            f"Registrar: {whois_data.registrar}. "
            f"Domain age: {whois_data.domainAge}. "
            f"Country: {whois_data.country}."
        ),

        brandImpersonation=(
            f"Keywords found: "
            f"{', '.join(kw) if kw else 'None detected'}."
        ),

        urlAnalysis=url_analysis_text,
        senderVerification=sender_verif,

        reputationAnalysis=(
            f"{reputation.virusTotal}. "
            f"{reputation.googleSafeBrowsing}."
        ),

        trustScore=risk_result.score,
        riskLevel=risk_result.risk_level,
        confidence=85,

        reasonBehindDecision=_reason_text(
            risk_result
        ),

        investigationStory=(
            ai_texts["investigationStory"]
        ),

        mitreMapping=[
            technique["id"] + " — " + technique["name"]
            for technique in mitre
        ],

        aiSummary=ai_texts["aiSummary"],
        aiExplanation=ai_texts["aiExplanation"],
        recommendations=recs,

        # ACTUAL BACKEND RISK FACTORS
        scoreBreakdown=[
            ScoreBreakdown(
                label=factor.label,
                positive=factor.positive,
                points=factor.points,
            )
            for factor in risk_result.factors
        ],

        email=email_data,
        whois=whois_data,
        ssl=ssl_data,
        dns=dns_data,
        reputation=reputation,

        evidencePanel=evidence_panel,
    )
# ══════════════════════════════════════════════════════════════════════════════
# APK PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

async def _pipeline_apk_string(apk_value: str) -> AnalysisResponse:
    """
    Handle APK analysis when only a filename/package name is provided.

    Full static analysis requires the actual APK binary.
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
        "malwareDetection": (
            "Static analysis requires APK binary upload"
        ),
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
        malwareDetection=(
            "Static analysis requires APK binary upload. "
            "Please use the file upload endpoint."
        ),
        riskScore=50,
    )

    risk_result = score_apk(apk_evidence)

    reputation = await check_reputation(apk_value)

    mitre = _map_mitre_apk(apk_evidence)

    recs = [
        "Upload the actual APK binary for full static analysis.",
        "Verify the app source and publisher.",
        "Check Google Play Store listing for the app.",
    ]

    ai_context = {
        "evidenceType": "apk",
        "evidenceValue": apk_value,
        "trustScore": risk_result.score,
        "riskLevel": risk_result.risk_level,
        "scoreFactors": [
            {
                "label": factor.label,
                "positive": factor.positive,
                "points": factor.points,
            }
            for factor in risk_result.factors
        ],
    }

    ai_texts = await generate_explanation(ai_context)

    return AnalysisResponse(
        evidenceType="apk",
        evidenceValue=apk_value,

        evidenceSummary=(
            f"APK investigation of '{apk_value}'. "
            f"SHA256: {sha[:16]}... "
            f"Static analysis requires binary upload."
        ),

        identityVerification=(
            f"Package/filename: {apk_value}. "
            f"Publisher identity cannot be verified without the binary."
        ),

        domainVerification="N/A for APK",

        certificateValidation=(
            "Signing certificate: Unknown — binary not provided."
        ),

        whoisInfo="N/A for APK",

        brandImpersonation=(
            "Brand check requires binary analysis."
        ),

        urlAnalysis="N/A for APK",

        apkPermissionAnalysis=(
            "Static permission analysis requires the APK binary. "
            "Upload the .apk file for full analysis."
        ),

        reputationAnalysis=(
            f"{reputation.virusTotal}. "
            f"{reputation.googleSafeBrowsing}."
        ),

        trustScore=risk_result.score,
riskLevel=risk_result.risk_level,
confidence=50,
        reasonBehindDecision=_reason_text(risk_result),

        investigationStory=ai_texts["investigationStory"],

        mitreMapping=[
            technique["id"] + " — " + technique["name"]
            for technique in mitre
        ],

        aiSummary=ai_texts["aiSummary"],
        aiExplanation=ai_texts["aiExplanation"],
        recommendations=recs,

        # ACTUAL BACKEND RISK FACTORS
        scoreBreakdown=[
            ScoreBreakdown(
                label=factor.label,
                positive=factor.positive,
                points=factor.points,
            )
            for factor in risk_result.factors
        ],

        apk=apk_data,
        reputation=reputation,

        evidencePanel=EvidencePanelData(
            originalUrl=apk_value,
            resolvedUrl="N/A",
            ipAddress="N/A",
            hostingProvider="N/A",
            country="N/A",
            registrar="N/A",
            sslStatus="N/A",
            whoisStatus="N/A",
            sha256Hash=sha,
        ),
    )


# ══════════════════════════════════════════════════════════════════════════════
# APK FILE UPLOAD ENDPOINT
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/apk", response_model=AnalysisResponse)
async def analyze_apk_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_user),
):
    """
    Analyze an uploaded Android APK binary.

    The actual APK bytes are passed to the existing APK forensic service.
    This endpoint is separate from POST /analyze because APK analysis
    requires multipart file upload rather than JSON evidenceValue.
    """

    # ── APK file validation ───────────────────────────────────────────────
    MAX_APK_SIZE = 150 * 1024 * 1024  # 150 MB

    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="APK filename is required.",
        )

    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please upload a valid .apk file.",
        )

    apk_bytes = await file.read()

    if not apk_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded APK file is empty.",
        )

    if len(apk_bytes) > MAX_APK_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="APK file is too large. Maximum allowed size is 150 MB.",
        )

    # APK files use the ZIP container format.
    try:
        with zipfile.ZipFile(io.BytesIO(apk_bytes)) as apk_zip:
            if apk_zip.testzip() is not None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="The APK file is corrupted.",
                )

            if "AndroidManifest.xml" not in apk_zip.namelist():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid APK file. AndroidManifest.xml is missing.",
                )
    except zipfile.BadZipFile:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid APK file. The uploaded file is not a valid APK package.",
        )

    try:
        apk_evidence = analyze_apk_bytes(
            apk_bytes,
            file.filename,
        )

        from schemas import APKData

        risk_result = score_apk(apk_evidence)

        reputation = None
        try:
            reputation = await check_reputation(file.filename)
        except Exception as exc:
            logger.warning("APK reputation lookup failed: %s", exc)

        mitre = _map_mitre_apk(apk_evidence)

        recommendations = []
        if apk_evidence.get("malwareFlags"):
            recommendations.append(
                "Do not install or execute this APK until its source and behavior are verified."
            )
        if apk_evidence.get("dangerousPermissions"):
            recommendations.append(
                "Review the requested Android permissions and confirm they are required by the app."
            )
        if not recommendations:
            recommendations.append(
                "Verify the APK source, publisher, and signing certificate before installation."
            )

        ai_context = {
            "evidenceType": "apk",
            "evidenceValue": file.filename,
            "trustScore": risk_result.score,
            "riskLevel": risk_result.risk_level,
            "scoreFactors": [
                {
                    "label": factor.label,
                    "positive": factor.positive,
                    "points": factor.points,
                }
                for factor in risk_result.factors
            ],
            "apkEvidence": apk_evidence,
        }

        ai_texts = await generate_explanation(ai_context)

        apk_data = APKData(
            sha256=apk_evidence.get("sha256", ""),
            permissions=apk_evidence.get("permissions", []),
            dangerousPermissions=apk_evidence.get("dangerousPermissions", []),
            receivers=apk_evidence.get("receivers", []),
            services=apk_evidence.get("services", []),
            activities=apk_evidence.get("activities", []),
            malwareDetection=apk_evidence.get(
                "malwareDetection",
                "Unknown",
            ),
            riskScore=apk_evidence.get("riskScore", risk_result.score),
        )

        reputation_text = (
            f"{reputation.virusTotal}. {reputation.googleSafeBrowsing}."
            if reputation
            else "Threat reputation lookup unavailable."
        )

        result = AnalysisResponse(
            evidenceType="apk",
            evidenceValue=file.filename,
            evidenceSummary=(
                f"APK forensic investigation of '{file.filename}'. "
                f"SHA-256: {apk_evidence.get('sha256', '')}. "
                f"Permissions: {len(apk_evidence.get('permissions', []))}. "
                f"Dangerous permissions: "
                f"{len(apk_evidence.get('dangerousPermissions', []))}."
            ),
            identityVerification=(
                f"APK filename: {file.filename}. "
                f"Signing information: "
                f"{apk_evidence.get('signingCertificate', 'Unknown')}."
            ),
            domainVerification="N/A for APK",
            certificateValidation=(
                f"Signing certificate: "
                f"{apk_evidence.get('signingCertificate', 'Unknown')}."
            ),
            whoisInfo="N/A for APK",
            brandImpersonation="Static APK brand impersonation analysis not available.",
            urlAnalysis=(
                f"Network URLs extracted: "
                f"{len(apk_evidence.get('networkUrls', []))}."
            ),
            apkPermissionAnalysis=(
                f"Permissions: {len(apk_evidence.get('permissions', []))}. "
                f"Dangerous permissions: "
                f"{len(apk_evidence.get('dangerousPermissions', []))}. "
                f"Malware indicators: "
                f"{len(apk_evidence.get('malwareFlags', []))}."
            ),
            reputationAnalysis=reputation_text,
            trustScore=risk_result.score,
            riskLevel=risk_result.risk_level,
            confidence=85 if apk_evidence.get("permissions") is not None else 50,
            reasonBehindDecision=_reason_text(risk_result),
            investigationStory=ai_texts["investigationStory"],
            mitreMapping=[
                technique["id"] + " — " + technique["name"]
                for technique in mitre
            ],
            aiSummary=ai_texts["aiSummary"],
            aiExplanation=ai_texts["aiExplanation"],
            recommendations=recommendations,
            scoreBreakdown=[
                ScoreBreakdown(
                    label=factor.label,
                    positive=factor.positive,
                    points=factor.points,
                )
                for factor in risk_result.factors
            ],
            mitreTechniques=[
                MitreTechnique(
                    techniqueId=technique["id"],
                    techniqueName=technique["name"],
                    description=technique["desc"],
                )
                for technique in mitre
            ],
            apk=apk_data,
            reputation=reputation,
            evidencePanel=EvidencePanelData(
                originalUrl=file.filename,
                resolvedUrl="N/A",
                ipAddress="N/A",
                hostingProvider="N/A",
                country="N/A",
                registrar="N/A",
                sslStatus="N/A",
                whoisStatus="N/A",
                sha256Hash=apk_evidence.get("sha256", ""),
            ),
        )

        if current_user:
            try:
                inv = Investigation(
                    case_id=_generate_case_id(db),
                    user_id=current_user.id,
                    evidence_type="apk",
                    evidence_value=file.filename,
                    trust_score=result.trustScore,
                    risk_level=result.riskLevel,
                    confidence=result.confidence,
                    result_json=result.model_dump(),
                )
                db.add(inv)
                db.commit()
            except Exception as exc:
                logger.warning("Failed to persist APK investigation: %s", exc)
                db.rollback()

        return result

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("APK file analysis failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"APK analysis failed: {exc}",
        )


# ══════════════════════════════════════════════════════════════════════════════
# QR PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

async def _pipeline_qr(content: str) -> AnalysisResponse:
    qr_evidence = await investigate_qr(content)

    qr_data = qr_evidence["qrData"]
    resolved_url = qr_evidence["resolvedUrl"]

    url_result: AnalysisResponse | None = None

    # ──────────────────────────────────────────────────────────────────────────
    # QR → URL → FULL URL INVESTIGATION
    # ──────────────────────────────────────────────────────────────────────────

    if qr_evidence["isUrl"]:
        try:
            url_result = await _pipeline_url(resolved_url)

        except Exception as exc:
            logger.warning(
                "QR URL pipeline failed: %s",
                exc,
            )

    if url_result:

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

        # Apply QR-specific penalties to the existing URL score.
        qr_penalty = (
            len(qr_evidence["riskIndicators"]) * 10
        )

        url_result.trustScore = max(
            0,
            min(
                100,
                url_result.trustScore - qr_penalty,
            ),
        )

        url_result.riskLevel = _score_to_risk(
            url_result.trustScore
        )

        return url_result

    # ──────────────────────────────────────────────────────────────────────────
    # QR CONTENT IS NOT A URL
    # ──────────────────────────────────────────────────────────────────────────

    risk_result = score_qr(qr_evidence)

    ai_context = {
        "evidenceType": "qr",
        "evidenceValue": content,
        "trustScore": risk_result.score,
        "riskLevel": risk_result.risk_level,
        "scoreFactors": [
            {
                "label": factor.label,
                "positive": factor.positive,
                "points": factor.points,
            }
            for factor in risk_result.factors
        ],
    }

    ai_texts = await generate_explanation(ai_context)

    sha = sha256_of_string(content)

    return AnalysisResponse(
        evidenceType="qr",
        evidenceValue=content,

        evidenceSummary=(
            f"QR code investigation. "
            f"Decoded content: {content[:100]}. "
            f"No URL destination detected."
        ),

        identityVerification=(
            "QR does not contain a URL — "
            "identity verification not applicable."
        ),

        domainVerification="N/A",
        certificateValidation="N/A",
        whoisInfo="N/A",
        brandImpersonation="N/A",

        urlAnalysis=(
            f"Content length: {len(content)} chars. "
            f"Redirects: {len(qr_evidence['redirects'])}."
        ),

        qrVerification=(
            f"Decoded: {content}. "
            f"Risk: {qr_data.qrRiskLevel}."
        ),

        reputationAnalysis=(
            "Reputation check not applicable for non-URL QR content."
        ),

       trustScore=risk_result.score,
        riskLevel=risk_result.risk_level,
        confidence=80,

        reasonBehindDecision=_reason_text(risk_result),

        investigationStory=ai_texts["investigationStory"],

        mitreMapping=[
            "T1566.002 — Phishing via QR Code"
        ],

        aiSummary=ai_texts["aiSummary"],
        aiExplanation=ai_texts["aiExplanation"],

        recommendations=[
            "Verify the source of the QR code.",
            "Do not scan QR codes from unknown sources.",
            "Use a QR scanner that previews the URL before opening.",
        ],

        # ACTUAL BACKEND RISK FACTORS
        scoreBreakdown=[
            ScoreBreakdown(
                label=factor.label,
                positive=factor.positive,
                points=factor.points,
            )
            for factor in risk_result.factors
        ],

        qr=qr_data,

        evidencePanel=EvidencePanelData(
            originalUrl=content,
            resolvedUrl=resolved_url,
            ipAddress="N/A",
            hostingProvider="N/A",
            country="N/A",
            registrar="N/A",
            sslStatus="N/A",
            whoisStatus="N/A",
            sha256Hash=sha,
        ),
    )


# ══════════════════════════════════════════════════════════════════════════════
# SENDER PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

async def _pipeline_sender(sender: str) -> AnalysisResponse:
    result = await _pipeline_email(sender)

    result.evidenceType = "sender"

    return result


# ══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK — URL
# ══════════════════════════════════════════════════════════════════════════════

def _map_mitre_url(
    risk: RiskResult,
    brand,
    url_analysis,
    reputation,
) -> list[dict]:

    techniques = []

    if (
        brand
        and brand.confidence > 60
        and brand.brandName != "None"
    ):
        techniques.append(
            {
                "id": "T1566.002",
                "name": "Phishing: Spearphishing Link",
                "desc": (
                    "Attacker used a link impersonating "
                    "a legitimate brand."
                ),
            }
        )

    if (
        url_analysis
        and url_analysis.ipAddressDetection
    ):
        techniques.append(
            {
                "id": "T1071.001",
                "name": "Application Layer Protocol: Web Protocols",
                "desc": (
                    "URL uses raw IP address to bypass "
                    "domain-based detection."
                ),
            }
        )

    if (
        url_analysis
        and url_analysis.redirectCount > 2
    ):
        techniques.append(
            {
                "id": "T1036",
                "name": "Masquerading",
                "desc": (
                    "Multiple redirects used to obscure "
                    "the final destination."
                ),
            }
        )

    if (
        reputation
        and reputation.overall == "malicious"
    ):
        techniques.append(
            {
                "id": "T1583.001",
                "name": "Acquire Infrastructure: Domains",
                "desc": (
                    "Domain flagged as malicious "
                    "by threat intelligence."
                ),
            }
        )

    if not techniques:
        techniques.append(
            {
                "id": "T1598.003",
                "name": "Phishing for Information: Spearphishing Link",
                "desc": (
                    "URL requires monitoring — "
                    "no confirmed active techniques."
                ),
            }
        )

    return techniques


# ══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK — EMAIL
# ══════════════════════════════════════════════════════════════════════════════

def _map_mitre_email(
    risk: RiskResult,
    email_data,
) -> list[dict]:

    techniques = [
        {
            "id": "T1566.001",
            "name": "Phishing: Spearphishing Attachment",
            "desc": "Email-based phishing vector.",
        }
    ]

    if (
        email_data
        and "Fail" in email_data.spf
    ):
        techniques.append(
            {
                "id": "T1534",
                "name": "Internal Spearphishing",
                "desc": (
                    "Missing SPF enables email spoofing."
                ),
            }
        )

    if (
        email_data
        and "Potential spoofing"
        in email_data.spoofDetection
    ):
        techniques.append(
            {
                "id": "T1656",
                "name": "Impersonation",
                "desc": (
                    "Sender identity indicators "
                    "suggest impersonation."
                ),
            }
        )

    return techniques


# ══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK — APK
# ══════════════════════════════════════════════════════════════════════════════

def _map_mitre_apk(
    apk_evidence: dict,
) -> list[dict]:

    techniques = [
        {
            "id": "T1476",
            "name": "Deliver Malicious App via Other Means",
            "desc": (
                "APK delivered outside official app stores."
            ),
        }
    ]

    flags = apk_evidence.get(
        "malwareFlags",
        [],
    )

    if any("SMS" in f for f in flags):
        techniques.append(
            {
                "id": "T1412",
                "name": "Capture SMS Messages",
                "desc": (
                    "App requests SMS read/receive permissions."
                ),
            }
        )

    if any(
        "overlay" in f.lower()
        for f in flags
    ):
        techniques.append(
            {
                "id": "T1417",
                "name": "Input Capture",
                "desc": (
                    "Overlay attack capability detected."
                ),
            }
        )

    return techniques


# ══════════════════════════════════════════════════════════════════════════════
# RECOMMENDATIONS — URL
# ══════════════════════════════════════════════════════════════════════════════

def _recommendations_url(
    risk: RiskResult,
    ssl,
    whois,
    reputation,
    brand,
) -> list[str]:

    recs = []

    if risk.risk_level == "Dangerous":
        recs.append(
            "Do NOT visit or interact with this URL — "
            "it shows multiple high-risk indicators."
        )

        recs.append(
            "Report this URL to Google Safe Browsing: "
            "https://safebrowsing.google.com/"
            "safebrowsing/report_phish/"
        )

    if ssl and "Not available" in ssl.sslStatus:
        recs.append(
            "This site does not use HTTPS — "
            "any data entered would be transmitted in plaintext."
        )

    if whois and (
        "month" in whois.domainAge
        or "day" in whois.domainAge
    ):
        recs.append(
            "Treat newly registered domains with caution — "
            "they are commonly used in phishing."
        )

    if (
        brand
        and brand.confidence > 60
        and brand.brandName != "None"
    ):
        recs.append(
            f"This domain impersonates '{brand.brandName}'. "
            f"Visit the official {brand.brandName} website "
            f"directly via a bookmark."
        )

    if (
        reputation
        and reputation.overall == "malicious"
    ):
        recs.append(
            "This URL is flagged by threat intelligence "
            "sources — block it at the network level."
        )

    if not recs:
        recs.append(
            "Continue monitoring for any changes in "
            "domain registration or reputation."
        )

        recs.append(
            "Verify the URL matches the official domain "
            "before entering sensitive information."
        )

    return recs


# ══════════════════════════════════════════════════════════════════════════════
# RECOMMENDATIONS — EMAIL
# ══════════════════════════════════════════════════════════════════════════════

def _recommendations_email(
    risk: RiskResult,
    email_data,
    is_freemail: bool,
) -> list[str]:

    recs = []

    if "Fail" in email_data.spf:
        recs.append(
            "The sender's domain has no SPF record — "
            "emails from this domain can be spoofed. "
            "Exercise caution."
        )

    if (
        "Fail" in email_data.dmarc
        or "missing" in email_data.dmarc.lower()
    ):
        recs.append(
            "The sender's domain lacks DMARC policy — "
            "spoofed emails may reach inboxes."
        )

    if "Potential spoofing" in email_data.spoofDetection:
        recs.append(
            "Spoofing indicators detected — "
            "verify sender identity through an independent "
            "channel before responding."
        )

    if is_freemail:
        recs.append(
            "Free email provider used — legitimate businesses "
            "typically use corporate domain email."
        )

    if risk.risk_level == "Dangerous":
        recs.append(
            "Do NOT click links or download attachments "
            "from this sender without independent verification."
        )

    if not recs:
        recs.append(
            "Email authentication checks passed. "
            "Continue exercising standard email security hygiene."
        )

    return recs


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK — RAW EMAIL HEADERS
# ══════════════════════════════════════════════════════════════════════════════

def _map_mitre_email_headers(
    header_evidence: dict,
) -> list[dict]:

    techniques = []

    indicators = header_evidence.get(
        "spoofingIndicators",
        [],
    )

    spf = header_evidence.get(
        "spfResult",
        "unknown",
    )

    dkim = header_evidence.get(
        "dkimResult",
        "unknown",
    )

    dmarc = header_evidence.get(
        "dmarcResult",
        "unknown",
    )

    # Email phishing
    techniques.append(
        {
            "id": "T1566.001",
            "name": "Phishing: Spearphishing Attachment",
            "desc": (
                "Email-based delivery can be used "
                "as a phishing vector."
            ),
        }
    )

    # Spoofing / impersonation
    if indicators:
        techniques.append(
            {
                "id": "T1036",
                "name": "Masquerading",
                "desc": (
                    "Email header inconsistencies "
                    "may indicate sender impersonation "
                    "or identity masquerading."
                ),
            }
        )

    # Authentication failures
    if spf == "fail":
        techniques.append(
            {
                "id": "T1656",
                "name": "Impersonation",
                "desc": (
                    "SPF authentication failed, "
                    "which may support sender spoofing."
                ),
            }
        )

    if dmarc == "fail":
        techniques.append(
            {
                "id": "T1656",
                "name": "Impersonation",
                "desc": (
                    "DMARC authentication failed, "
                    "indicating possible domain impersonation."
                ),
            }
        )

    if dkim == "fail":
        techniques.append(
            {
                "id": "T1566",
                "name": "Phishing",
                "desc": (
                    "DKIM authentication failed "
                    "during email authentication analysis."
                ),
            }
        )

    # Reply-To mismatch
    if any(
        "Reply-To domain"
        in indicator
        for indicator in indicators
    ):
        techniques.append(
            {
                "id": "T1071.003",
                "name": "Mail Protocols",
                "desc": (
                    "Reply-To routing differs from "
                    "the visible sender domain."
                ),
            }
        )

    return techniques


# ══════════════════════════════════════════════════════════════════════════════
# EMAIL HEADER RECOMMENDATIONS
# ══════════════════════════════════════════════════════════════════════════════

def _recommendations_email_headers(
    header_evidence: dict,
    risk_level: str,
) -> list[str]:

    recommendations = []

    indicators = header_evidence.get(
        "spoofingIndicators",
        [],
    )

    spf = header_evidence.get(
        "spfResult",
        "unknown",
    )

    dkim = header_evidence.get(
        "dkimResult",
        "unknown",
    )

    dmarc = header_evidence.get(
        "dmarcResult",
        "unknown",
    )

    # SPF
    if spf == "fail":
        recommendations.append(
            "SPF authentication failed. "
            "Do not trust the sender identity solely "
            "from the visible From address."
        )

    # DKIM
    if dkim == "fail":
        recommendations.append(
            "DKIM authentication failed. "
            "Treat the message as potentially modified "
            "or spoofed."
        )

    # DMARC
    if dmarc == "fail":
        recommendations.append(
            "DMARC authentication failed. "
            "Verify the sender through an independent "
            "communication channel."
        )

    # Reply-To
    if any(
        "Reply-To domain"
        in indicator
        for indicator in indicators
    ):
        recommendations.append(
            "Reply-To domain differs from the From domain. "
            "Do not reply or provide sensitive information "
            "until the sender is verified."
        )

    # Return-Path
    if any(
        "Return-Path domain"
        in indicator
        for indicator in indicators
    ):
        recommendations.append(
            "Return-Path differs from the visible sender "
            "domain. Investigate the mail infrastructure "
            "before trusting the message."
        )

    # High risk
    if risk_level == "Dangerous":
        recommendations.append(
            "Do NOT click links, open attachments, "
            "or provide credentials from this email."
        )

    elif risk_level == "Suspicious":
        recommendations.append(
            "Treat this email as suspicious and verify "
            "the sender through an independent channel."
        )

    # Default
    if not recommendations:
        recommendations.append(
            "No major authentication or spoofing "
            "indicators were detected. Continue normal "
            "email security practices."
        )

    return recommendations
def _reason_text(risk: RiskResult) -> str:

    if not risk.factors:
        return (
            f"Trust Score: {risk.score}/100. "
            f"No evidence factors were collected."
        )

    negative = [
        factor.label
        for factor in risk.factors
        if not factor.positive
    ]

    positive = [
        factor.label
        for factor in risk.factors
        if factor.positive
    ]

    parts = []

    if negative:
        parts.append(
            f"Risk factors: {'; '.join(negative[:3])}"
        )

    if positive:
        parts.append(
            f"Trust factors: {'; '.join(positive[:3])}"
        )

    return (
        " | ".join(parts)
        + f". Final score: {risk.score}/100."
    )


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

@router.post("/qr", response_model=AnalysisResponse)
async def analyze_qr_image(
    file: UploadFile = File(...)
):
    """
    Analyze an uploaded QR-code image.

    Validation performed before QR analysis:
    - filename check
    - supported image format check
    - empty file check
    - file size check
    - QR readability check
    """

    # ── Supported QR image formats ─────────────────────────────────────
    ALLOWED_QR_TYPES = {
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/webp": ".webp",
    }

    MAX_QR_SIZE = 10 * 1024 * 1024  # 10 MB

    # ── Filename validation ────────────────────────────────────────────
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="QR image filename is required."
        )

    extension = os.path.splitext(file.filename)[1].lower()

    allowed_extensions = {".png", ".jpg", ".jpeg", ".webp"}

    if extension not in allowed_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported QR image format. Use PNG, JPG, JPEG, or WEBP."
        )

    # ── MIME type validation ───────────────────────────────────────────
    if file.content_type not in ALLOWED_QR_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported QR image type. Use PNG, JPG, JPEG, or WEBP."
        )

    # JPEG can use both .jpg and .jpeg
    expected_extension = ALLOWED_QR_TYPES[file.content_type]

    if extension != expected_extension:
        if not (
            file.content_type == "image/jpeg"
            and extension == ".jpeg"
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Image extension does not match its file type."
            )

    # ── Read file ──────────────────────────────────────────────────────
    image_bytes = await file.read()

    if not image_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded QR image is empty."
        )

    # ── Size validation ────────────────────────────────────────────────
    if len(image_bytes) > MAX_QR_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="QR image is too large. Maximum allowed size is 10 MB."
        )

    # ── Actual QR validation ───────────────────────────────────────────
    # This checks whether the uploaded image contains a readable QR code.
    decoded_content = decode_qr_bytes(image_bytes)

    if not decoded_content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No readable QR code found in the uploaded image."
        )

    # ── Continue with existing CTDE QR pipeline ────────────────────────
    try:
        result = await _pipeline_qr(decoded_content)

        return result

    except Exception as exc:
        logger.exception("QR image analysis failed")

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"QR analysis failed: {str(exc)}"
        )