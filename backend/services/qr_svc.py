"""
QR Code investigation service.
Decodes QR image or processes a pre-decoded URL, then runs website investigation.
"""
import logging
from typing import Optional

import httpx

from schemas import QRData
from utils.helpers import sha256_of_string
from utils.validators import normalize_url

logger = logging.getLogger(__name__)


def decode_qr_bytes(image_bytes: bytes) -> Optional[str]:
    """Decode a QR code from raw image bytes using pyzbar."""
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode
        import io
        image = Image.open(io.BytesIO(image_bytes))
        decoded = decode(image)
        if decoded:
            return decoded[0].data.decode("utf-8")
    except ImportError:
        logger.warning("pyzbar/Pillow not installed — QR image decoding unavailable")
    except Exception as exc:
        logger.warning("QR decode error: %s", exc)
    return None


async def investigate_qr(content: str) -> dict:
    """
    Investigate QR content.
    If content is a URL, follows redirects and collects evidence.
    Returns structured QR evidence.
    """
    content = content.strip()
    sha = sha256_of_string(content)

    # Determine if it's a URL
    is_url = content.startswith(("http://", "https://")) or ("." in content and "/" in content)
    url = normalize_url(content) if not content.startswith(("http://", "https://")) else content

    redirects: list[str] = []
    resolved_url = url

    if is_url:
        redirects, resolved_url = await _follow_redirects(url)

    # Assess QR risk based on content
    risk_indicators = _assess_qr_risk(content, redirects)
    if risk_indicators:
        qr_risk = "High — " + "; ".join(risk_indicators)
    else:
        qr_risk = "Low — content appears benign"

    qr_data = QRData(
        decodedUrl=content,
        redirects=redirects,
        reputation=f"Resolved to: {resolved_url}" if resolved_url != url else "No redirects",
        qrRiskLevel=qr_risk,
    )

    return {
        "originalContent": content,
        "resolvedUrl": resolved_url,
        "isUrl": is_url,
        "redirects": redirects,
        "qrData": qr_data,
        "riskIndicators": risk_indicators,
        "sha256": sha,
    }


async def _follow_redirects(url: str) -> tuple[list[str], str]:
    """Follow HTTP redirects and return the chain + final URL."""
    chain: list[str] = []
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            max_redirects=10,
            timeout=10,
        ) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0 CTDE/1.0"})
            # Collect redirect history
            for r in resp.history:
                chain.append(str(r.url))
            return chain, str(resp.url)
    except Exception as exc:
        logger.warning("QR redirect follow error for %s: %s", url, exc)
        return [], url


def _assess_qr_risk(content: str, redirects: list[str]) -> list[str]:
    indicators = []
    content_lower = content.lower()

    suspicious_keywords = ["login", "verify", "account", "secure", "update", "paypal", "bank", "wallet"]
    for kw in suspicious_keywords:
        if kw in content_lower:
            indicators.append(f"suspicious keyword: '{kw}'")
            break

    if len(redirects) > 2:
        indicators.append(f"excessive redirects ({len(redirects)} hops)")

    if any(r != redirects[0] for r in redirects[1:]) if len(redirects) > 1 else False:
        indicators.append("cross-domain redirect chain")

    # IP-based URL in QR
    import re
    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", content):
        indicators.append("IP address URL (no domain)")

    if len(content) > 200:
        indicators.append("unusually long QR content")

    return indicators
