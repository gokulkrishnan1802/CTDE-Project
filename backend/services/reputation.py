"""
Reputation analysis service.
Queries VirusTotal, URLScan.io, AbuseIPDB, Google Safe Browsing.
All API keys are optional — graceful fallback when absent.
"""
import logging
import base64
from typing import Optional

import httpx

from config import settings
from schemas import ReputationData

logger = logging.getLogger(__name__)


async def check_reputation(value: str, ip: Optional[str] = None) -> ReputationData:
    """Aggregate reputation data from all available sources."""
    vt_result = await _virustotal(value)
    urlscan_result = await _urlscan(value)
    gsb_result = await _google_safe_browsing(value)
    abuseipdb_result = await _abuseipdb(ip) if ip else "Not checked (no IP)"

    # Compute overall verdict
    malicious_signals = 0
    suspicious_signals = 0

    if "malicious" in vt_result.lower():
        malicious_signals += 2
    elif "suspicious" in vt_result.lower():
        suspicious_signals += 1

    if "malicious" in urlscan_result.lower() or "phishing" in urlscan_result.lower():
        malicious_signals += 1
    elif "suspicious" in urlscan_result.lower():
        suspicious_signals += 1

    if "unsafe" in gsb_result.lower() or "phishing" in gsb_result.lower() or "malware" in gsb_result.lower():
        malicious_signals += 2

    if "reported" in abuseipdb_result.lower() or "abusive" in abuseipdb_result.lower():
        malicious_signals += 1

    if malicious_signals >= 2:
        overall = "malicious"
    elif malicious_signals >= 1 or suspicious_signals >= 1:
        overall = "suspicious"
    else:
        overall = "clean"

    # Parse VT vendor count from result string
    vendor_count = 0
    detection_ratio = "0/0"
    if "/" in vt_result:
        parts = [p.strip() for p in vt_result.split() if "/" in p]
        if parts:
            detection_ratio = parts[0]
            try:
                num, denom = detection_ratio.split("/")
                vendor_count = int(num)
            except Exception:
                pass

    return ReputationData(
        virusTotal=vt_result,
        urlScan=urlscan_result,
        phishTank="Not checked (no API key configured)",
        abuseIpdb=abuseipdb_result,
        googleSafeBrowsing=gsb_result,
        vendorCount=vendor_count,
        detectionRatio=detection_ratio,
        overall=overall,
    )


async def _virustotal(value: str) -> str:
    if not settings.VIRUSTOTAL_API_KEY:
        return "VirusTotal: API key not configured — skipped"
    try:
        encoded = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as client:
            resp = await client.get(f"https://www.virustotal.com/api/v3/urls/{encoded}", headers=headers)
            if resp.status_code == 404:
                # URL not yet scanned — submit and return pending
                post_resp = await client.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": value},
                )
                if post_resp.status_code == 200:
                    return "VirusTotal: Submitted for analysis — no cached result"
                return "VirusTotal: Not previously scanned"
            if resp.status_code != 200:
                return f"VirusTotal: API returned {resp.status_code}"
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1
            if malicious > 0:
                return f"VirusTotal: {malicious}/{total} vendors flagged as malicious"
            elif suspicious > 0:
                return f"VirusTotal: {suspicious}/{total} vendors flagged as suspicious"
            return f"VirusTotal: Clean — 0/{total} detections"
    except Exception as exc:
        logger.warning("VirusTotal error: %s", exc)
        return f"VirusTotal: Request failed — {exc}"


async def _urlscan(value: str) -> str:
    if not settings.URLSCAN_API_KEY:
        return "URLScan.io: API key not configured — skipped"
    try:
        headers = {"API-Key": settings.URLSCAN_API_KEY, "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as client:
            # Try search first
            search_resp = await client.get(
                f"https://urlscan.io/api/v1/search/?q=page.url:{value}&size=1",
                headers=headers,
            )
            if search_resp.status_code == 200:
                results = search_resp.json().get("results", [])
                if results:
                    verdict = results[0].get("verdicts", {}).get("overall", {})
                    score = verdict.get("score", 0)
                    malicious = verdict.get("malicious", False)
                    if malicious:
                        return f"URLScan.io: Flagged as malicious (score {score})"
                    if score > 50:
                        return f"URLScan.io: Suspicious (score {score})"
                    return f"URLScan.io: Clean (score {score})"
            return "URLScan.io: No previous scan found"
    except Exception as exc:
        logger.warning("URLScan error: %s", exc)
        return f"URLScan.io: Request failed — {exc}"


async def _google_safe_browsing(value: str) -> str:
    if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
        return "Google Safe Browsing: API key not configured — skipped"
    try:
        payload = {
            "client": {"clientId": "ctde", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": value}],
            },
        }
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as client:
            resp = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}",
                json=payload,
            )
            if resp.status_code != 200:
                return f"Google Safe Browsing: API returned {resp.status_code}"
            data = resp.json()
            matches = data.get("matches", [])
            if matches:
                threat_types = list({m.get("threatType", "") for m in matches})
                return f"Google Safe Browsing: UNSAFE — {', '.join(threat_types)}"
            return "Google Safe Browsing: Safe — no threats detected"
    except Exception as exc:
        logger.warning("GSB error: %s", exc)
        return f"Google Safe Browsing: Request failed — {exc}"


async def _abuseipdb(ip: str) -> str:
    if not settings.ABUSEIPDB_API_KEY:
        return "AbuseIPDB: API key not configured — skipped"
    try:
        headers = {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as client:
            resp = await client.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                headers=headers,
            )
            if resp.status_code != 200:
                return f"AbuseIPDB: API returned {resp.status_code}"
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            reports = data.get("totalReports", 0)
            if score > 50:
                return f"AbuseIPDB: High abuse confidence {score}% ({reports} reports)"
            if score > 10:
                return f"AbuseIPDB: Low-moderate abuse confidence {score}% ({reports} reports)"
            return f"AbuseIPDB: Clean — {score}% confidence score ({reports} reports)"
    except Exception as exc:
        logger.warning("AbuseIPDB error: %s", exc)
        return f"AbuseIPDB: Request failed — {exc}"
