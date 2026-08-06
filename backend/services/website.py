"""
Website investigation service.
Collects HTTP headers, redirects, security headers, and brand impersonation signals.
"""
import re
import logging
from typing import Optional
from urllib.parse import urlparse

import httpx

from config import settings
from utils.validators import normalize_url, is_ip_address, extract_domain
from utils.helpers import sha256_of_string, is_suspicious_tld
from schemas import URLAnalysisData, BrandData

logger = logging.getLogger(__name__)

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
]

KNOWN_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook", "instagram",
    "netflix", "bank", "chase", "wellsfargo", "citibank", "hdfc", "icici",
    "sbi", "axis", "twitter", "linkedin", "dropbox", "adobe",
]


async def investigate_website(url: str) -> dict:
    """
    Perform comprehensive website investigation.
    Returns structured evidence for all analysis modules.
    """
    url = normalize_url(url.strip())
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    sha = sha256_of_string(url)

    headers_result, status_code, redirect_chain, final_url, response_headers = await _fetch_http(url)
    url_analysis = _analyze_url(url, redirect_chain)
    security_headers = _check_security_headers(response_headers)
    brand = _detect_brand_impersonation(domain)
    https_status = url.startswith("https://")

    return {
        "originalUrl": url,
        "finalUrl": final_url,
        "domain": domain,
        "statusCode": status_code,
        "redirectChain": redirect_chain,
        "responseHeaders": response_headers,
        "securityHeaders": security_headers,
        "urlAnalysis": url_analysis,
        "brand": brand,
        "httpsStatus": https_status,
        "sha256": sha,
        "fetchError": headers_result,
    }


async def _fetch_http(url: str) -> tuple[str, Optional[int], list[str], str, dict]:
    """Fetch URL and collect redirect chain and response headers."""
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            max_redirects=settings.HTTP_MAX_REDIRECTS,
            timeout=settings.HTTP_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (CTDE Security Scanner/1.0)"},
            verify=True,
        ) as client:
            resp = await client.get(url)
            chain = [str(r.url) for r in resp.history]
            headers = dict(resp.headers)
            return "OK", resp.status_code, chain, str(resp.url), headers
    except httpx.SSLError:
        return "SSL verification failed", None, [], url, {}
    except httpx.ConnectError:
        return "Connection refused or host unreachable", None, [], url, {}
    except httpx.TimeoutException:
        return "Request timed out", None, [], url, {}
    except Exception as exc:
        return str(exc), None, [], url, {}


def _analyze_url(url: str, redirects: list[str]) -> URLAnalysisData:
    parsed = urlparse(url)
    domain = parsed.hostname or ""

    # Detect encoded characters
    encoded = bool(re.search(r"%[0-9A-Fa-f]{2}", url))

    # Suspicious query parameters
    suspicious_params = []
    if parsed.query:
        for param in parsed.query.split("&"):
            key = param.split("=")[0].lower()
            if key in {"redirect", "url", "next", "goto", "return", "redir", "target", "dest"}:
                suspicious_params.append(key)

    return URLAnalysisData(
        redirectCount=len(redirects),
        urlLength=len(url),
        encodedCharacters=encoded,
        suspiciousParameters=suspicious_params,
        ipAddressDetection=is_ip_address(domain),
        httpsStatus=url.startswith("https://"),
    )


def _check_security_headers(headers: dict) -> dict:
    return {
        h: headers.get(h, "MISSING")
        for h in SECURITY_HEADERS
    }


def _detect_brand_impersonation(domain: str) -> BrandData:
    """
    Heuristic brand impersonation detection.
    Checks if domain contains known brand names but doesn't belong to them.
    """
    domain_lower = domain.lower()
    # Remove TLD for matching
    domain_core = ".".join(domain_lower.split(".")[:-1]) if "." in domain_lower else domain_lower

    for brand in KNOWN_BRANDS:
        if brand in domain_core:
            # Check if it IS the official domain (exact TLD match)
            official_domains = {
                "paypal": "paypal.com", "amazon": "amazon.com", "apple": "apple.com",
                "microsoft": "microsoft.com", "google": "google.com", "facebook": "facebook.com",
                "instagram": "instagram.com", "netflix": "netflix.com",
            }
            official = official_domains.get(brand, f"{brand}.com")
            if domain_lower == official or domain_lower.endswith(f".{official}"):
                # It IS the legitimate brand domain
                return BrandData(
                    brandName=brand.capitalize(),
                    confidence=5.0,
                    evidence=f"Domain matches official {brand} domain",
                    visualSimilarity=1.0,
                    domainSimilarity=1.0,
                )
            # It contains the brand name but isn't the official domain
            similarity = len(brand) / len(domain_core) * 100
            return BrandData(
                brandName=brand.capitalize(),
                confidence=min(70 + similarity, 95),
                evidence=f"Domain '{domain}' contains brand name '{brand}' but is not the official domain '{official}'",
                visualSimilarity=round(similarity / 100, 2),
                domainSimilarity=round(similarity / 100, 2),
            )

    return BrandData(
        brandName="None",
        confidence=0.0,
        evidence="No known brand impersonation detected",
        visualSimilarity=0.0,
        domainSimilarity=0.0,
    )
