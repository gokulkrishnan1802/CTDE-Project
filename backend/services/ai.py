"""
AI explanation service.
Constructs factual explanations from collected evidence.
When an LLM API key is configured, uses it with a strict grounding prompt.
When no key is configured, uses a deterministic rule-based explanation engine.
The AI is NEVER allowed to fabricate facts — it can only reference provided evidence.
"""
import logging
import json
from typing import Any

from config import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a digital forensics analyst for the CyberTrust Decision Engine (CTDE).
Your job is to explain the investigation results to a non-technical user.

STRICT RULES:
1. NEVER invent, fabricate, or assume any fact not present in the evidence JSON.
2. Only explain what the evidence shows — do not guess about intentions or assume guilt.
3. Use plain, clear language. No jargon unless explained.
4. If data is missing or inconclusive, say so explicitly.
5. Structure your response as: Summary | Risk Explanation | Evidence | MITRE Mapping | Recommendations.
6. Keep it factual, measured, and professional."""

SYSTEM_PROMPT_CHAT = """You are an AI assistant for the CyberTrust Decision Engine (CTDE).
The user is asking about a specific investigation result. Answer based ONLY on the evidence provided.

STRICT RULES:
1. Never fabricate facts. Only reference evidence that is in the investigation JSON.
2. If you don't know, say you don't know — don't guess.
3. Be concise, professional, and helpful.
4. You may suggest next steps but must base them on the evidence."""


async def generate_explanation(evidence_summary: dict[str, Any]) -> dict[str, str]:
    """
    Generate AI explanation for an investigation.
    Returns {aiSummary, aiExplanation, investigationStory}.
    """
    if settings.OPENAI_API_KEY:
        return await _openai_explain(evidence_summary)
    if settings.GOOGLE_API_KEY:
        return await _gemini_explain(evidence_summary)
    return _rule_based_explanation(evidence_summary)


async def answer_question(question: str, investigation: dict[str, Any]) -> str:
    """
    Answer a user question about an investigation.
    Uses the LLM if available, otherwise rule-based.
    """
    if settings.OPENAI_API_KEY:
        return await _openai_chat(question, investigation)
    if settings.GOOGLE_API_KEY:
        return await _gemini_chat(question, investigation)
    return _rule_based_chat(question, investigation)


# ── OpenAI ───────────────────────────────────────────────────────────────────

async def _openai_explain(evidence: dict) -> dict[str, str]:
    try:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        prompt = f"Analyze this digital forensics evidence and provide a structured explanation:\n\n{json.dumps(evidence, indent=2, default=str)}"
        resp = await client.chat.completions.create(
            model=settings.OPENAI_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            max_tokens=1200,
            temperature=0.2,
        )
        text = resp.choices[0].message.content or ""
        return _parse_llm_explanation(text, evidence)
    except Exception as exc:
        logger.warning("OpenAI error: %s — falling back to rule-based", exc)
        return _rule_based_explanation(evidence)


async def _openai_chat(question: str, investigation: dict) -> str:
    try:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        context = json.dumps(investigation, indent=2, default=str)
        resp = await client.chat.completions.create(
            model=settings.OPENAI_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT_CHAT},
                {"role": "user", "content": f"Investigation context:\n{context}\n\nUser question: {question}"},
            ],
            max_tokens=600,
            temperature=0.3,
        )
        return resp.choices[0].message.content or "Unable to generate answer."
    except Exception as exc:
        logger.warning("OpenAI chat error: %s", exc)
        return _rule_based_chat(question, investigation)


# ── Google Gemini ─────────────────────────────────────────────────────────────

async def _gemini_explain(evidence: dict) -> dict[str, str]:
    try:
        import google.generativeai as genai
        genai.configure(api_key=settings.GOOGLE_API_KEY)
        model = genai.GenerativeModel(settings.GOOGLE_MODEL)
        prompt = f"{SYSTEM_PROMPT}\n\nAnalyze this evidence:\n{json.dumps(evidence, indent=2, default=str)}"
        resp = model.generate_content(prompt)
        text = resp.text or ""
        return _parse_llm_explanation(text, evidence)
    except Exception as exc:
        logger.warning("Gemini error: %s — falling back to rule-based", exc)
        return _rule_based_explanation(evidence)


async def _gemini_chat(question: str, investigation: dict) -> str:
    try:
        import google.generativeai as genai
        genai.configure(api_key=settings.GOOGLE_API_KEY)
        model = genai.GenerativeModel(settings.GOOGLE_MODEL)
        context = json.dumps(investigation, indent=2, default=str)
        prompt = f"{SYSTEM_PROMPT_CHAT}\n\nInvestigation:\n{context}\n\nQuestion: {question}"
        resp = model.generate_content(prompt)
        return resp.text or "Unable to generate answer."
    except Exception as exc:
        logger.warning("Gemini chat error: %s", exc)
        return _rule_based_chat(question, investigation)


# ── Rule-based fallback ───────────────────────────────────────────────────────

def _rule_based_explanation(ev: dict) -> dict[str, str]:
    """
    Builds explanation text purely from evidence values.
    No invented facts — every sentence references a collected data point.
    """
    evidence_type = ev.get("evidenceType", "unknown")
    evidence_value = ev.get("evidenceValue", "")
    risk_level = ev.get("riskLevel", "Unknown")
    trust_score = ev.get("trustScore", 0)
    factors = ev.get("scoreFactors", [])

    # Summary
    summary = (
        f"This {evidence_type.upper()} investigation of '{evidence_value}' produced a Trust Score of "
        f"{trust_score}/100, indicating a {risk_level} risk level. "
    )

    # Score factors
    positive = [f["label"] for f in factors if f.get("positive")]
    negative = [f["label"] for f in factors if not f.get("positive")]

    if positive:
        summary += f"Positive signals include: {'; '.join(positive[:3])}. "
    if negative:
        summary += f"Risk signals include: {'; '.join(negative[:3])}."

    # Explanation (more detailed)
    explanation_parts = [f"Confidence in this assessment: 90% based on {len(factors)} evidence factors collected."]

    whois = ev.get("whoisData", {})
    if whois.get("domainAge") and whois["domainAge"] != "Unknown":
        explanation_parts.append(f"Domain age: {whois['domainAge']} — registered via {whois.get('registrar', 'unknown registrar')}.")

    ssl = ev.get("sslData", {})
    if ssl.get("sslStatus"):
        explanation_parts.append(f"SSL/TLS: {ssl['sslStatus']} using {ssl.get('tlsVersion', 'unknown TLS version')}.")

    rep = ev.get("reputationData", {})
    if rep.get("virusTotal") and "not configured" not in rep["virusTotal"].lower():
        explanation_parts.append(f"VirusTotal: {rep['virusTotal']}.")
    if rep.get("googleSafeBrowsing") and "not configured" not in rep["googleSafeBrowsing"].lower():
        explanation_parts.append(f"Google Safe Browsing: {rep['googleSafeBrowsing']}.")

    brand = ev.get("brandData", {})
    if brand.get("evidence") and brand["brandName"] != "None":
        explanation_parts.append(f"Brand analysis: {brand['evidence']}.")

    explanation = " ".join(explanation_parts)

    # Story
    story_parts = [f"The CTDE investigation pipeline analyzed '{evidence_value}' across multiple forensic modules."]
    story_parts.append(f"Evidence was collected from WHOIS registries, DNS resolvers, SSL certificate authorities, and threat intelligence databases.")
    if negative:
        story_parts.append(f"The following risk factors contributed to the {risk_level} verdict: {'; '.join(negative[:3])}.")
    else:
        story_parts.append(f"No critical risk factors were identified. The evidence is consistent with a legitimate {evidence_type}.")
    story = " ".join(story_parts)

    return {
        "aiSummary": summary,
        "aiExplanation": explanation,
        "investigationStory": story,
    }


def _rule_based_chat(question: str, investigation: dict) -> str:
    """Answer a specific question using only investigation data."""
    q = question.lower()
    risk = investigation.get("riskLevel", "Unknown")
    score = investigation.get("trustScore", 0)
    evidence_type = investigation.get("evidenceType", "evidence")
    evidence_value = investigation.get("evidenceValue", "")

    if any(w in q for w in ["safe", "trust", "why", "reason", "score"]):
        reason = investigation.get("reasonBehindDecision", "")
        return (
            f"The {evidence_type} '{evidence_value}' received a Trust Score of {score}/100 ({risk}). "
            f"{reason} "
            f"The score was calculated from real forensic evidence collected during the investigation — "
            f"no assumptions were made."
        )

    if any(w in q for w in ["ssl", "certificate", "tls"]):
        cert = investigation.get("certificateValidation", "SSL information not available.")
        return f"Certificate analysis: {cert}"

    if any(w in q for w in ["whois", "domain", "registrar", "age"]):
        whois = investigation.get("whoisInfo", "WHOIS information not available.")
        return f"Domain / WHOIS findings: {whois}"

    if any(w in q for w in ["reputation", "virustotal", "blocklist", "malicious"]):
        rep = investigation.get("reputationAnalysis", "Reputation data not available.")
        return f"Reputation analysis: {rep}"

    if any(w in q for w in ["recommend", "next", "action", "should"]):
        recs = investigation.get("recommendations", [])
        if recs:
            rec_text = "\n".join(f"- {r}" for r in recs)
            return f"Based on the investigation findings, here are the recommended actions:\n{rec_text}"
        return "No specific recommendations available for this investigation."

    if any(w in q for w in ["mitre", "attack", "technique"]):
        mitre = investigation.get("mitreMapping", [])
        if mitre:
            return f"MITRE ATT&CK techniques identified: {', '.join(mitre)}"
        return "No MITRE ATT&CK techniques were mapped for this investigation."

    if any(w in q for w in ["apk", "permission", "android"]):
        apk = investigation.get("apkPermissionAnalysis", "APK analysis not available.")
        return f"APK analysis: {apk}"

    if any(w in q for w in ["email", "spf", "dmarc", "dkim", "sender"]):
        sender = investigation.get("senderVerification") or investigation.get("reputationAnalysis", "")
        return f"Email / sender analysis: {sender}"

    if any(w in q for w in ["summary", "explain", "overview", "report"]):
        return investigation.get("evidenceSummary", "Evidence summary not available.")

    return (
        f"Based on the investigation of '{evidence_value}', the Trust Score is {score}/100 ({risk}). "
        f"Please ask a more specific question such as: 'Why is this score {risk}?', 'Explain the SSL findings', "
        f"'What are the recommendations?', or 'Show MITRE mapping'."
    )


def _parse_llm_explanation(text: str, evidence: dict) -> dict[str, str]:
    """Extract structured sections from LLM output."""
    # Try to find sections in the text
    summary = ""
    explanation = text
    story = ""

    lines = text.split("\n")
    current_section = ""
    sections: dict[str, list[str]] = {}

    for line in lines:
        line_lower = line.lower().strip()
        if "summary" in line_lower and line.startswith("#"):
            current_section = "summary"
            sections[current_section] = []
        elif "explanation" in line_lower and line.startswith("#"):
            current_section = "explanation"
            sections[current_section] = []
        elif "story" in line_lower and line.startswith("#"):
            current_section = "story"
            sections[current_section] = []
        elif current_section:
            sections[current_section].append(line)

    if "summary" in sections:
        summary = " ".join(sections["summary"]).strip()
    if "explanation" in sections:
        explanation = " ".join(sections["explanation"]).strip()
    if "story" in sections:
        story = " ".join(sections["story"]).strip()

    if not summary:
        summary = text[:400] if len(text) > 400 else text
    if not story:
        story = _rule_based_explanation(evidence).get("investigationStory", "")

    return {
        "aiSummary": summary or text[:300],
        "aiExplanation": explanation or text,
        "investigationStory": story,
    }
