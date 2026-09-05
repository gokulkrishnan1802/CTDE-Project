"""
QR Code investigation service.

Decodes QR images and investigates the decoded content.

Decoder strategy:
1. pyzbar / ZBar - primary decoder
2. OpenCV QRCodeDetector - fallback decoder
3. Multiple image preprocessing attempts for difficult QR images

The decoded content can then be investigated as a URL or as
non-URL QR content by the CTDE investigation pipeline.
"""

import io
import logging
import re
from typing import Optional

import httpx

from schemas import QRData
from utils.helpers import sha256_of_string
from utils.validators import normalize_url

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# QR IMAGE DECODER
# ──────────────────────────────────────────────────────────────────────────────

def decode_qr_bytes(image_bytes: bytes) -> Optional[str]:
    """
    Decode a QR code from raw image bytes.

    Decoder order:
        1. pyzbar / ZBar
        2. OpenCV QRCodeDetector

    OpenCV also tries multiple preprocessing methods so that QR images
    containing logos, compression, scaling, or mild image noise have
    a better chance of decoding.
    """

    if not image_bytes:
        logger.warning("QR decoder received empty image bytes")
        return None

    # ──────────────────────────────────────────────────────────────────────
    # METHOD 1: pyzbar / ZBar
    # ──────────────────────────────────────────────────────────────────────

    try:
        from PIL import Image
        from pyzbar.pyzbar import decode

        image = Image.open(io.BytesIO(image_bytes))

        # Normal image
        decoded = decode(image)

        if decoded:
            for result in decoded:
                try:
                    data = result.data.decode("utf-8").strip()

                    if data:
                        logger.info(
                            "QR decoded successfully using pyzbar: %s",
                            data,
                        )
                        return data

                except UnicodeDecodeError:
                    logger.warning(
                        "QR payload was not valid UTF-8"
                    )

        # Try grayscale image
        grayscale = image.convert("L")
        decoded = decode(grayscale)

        if decoded:
            for result in decoded:
                try:
                    data = result.data.decode("utf-8").strip()

                    if data:
                        logger.info(
                            "QR decoded successfully using pyzbar "
                            "grayscale: %s",
                            data,
                        )
                        return data

                except UnicodeDecodeError:
                    logger.warning(
                        "QR grayscale payload was not valid UTF-8"
                    )

    except ImportError:
        logger.warning(
            "pyzbar/Pillow unavailable. "
            "Falling back to OpenCV."
        )

    except Exception as exc:
        logger.warning(
            "pyzbar QR decoding failed: %s. "
            "Trying OpenCV fallback.",
            exc,
        )

    # ──────────────────────────────────────────────────────────────────────
    # METHOD 2: OpenCV fallback
    # ──────────────────────────────────────────────────────────────────────

    try:
        import cv2
        import numpy as np

        image_array = np.frombuffer(
            image_bytes,
            dtype=np.uint8,
        )

        image = cv2.imdecode(
            image_array,
            cv2.IMREAD_COLOR,
        )

        if image is None:
            logger.warning(
                "OpenCV could not read the uploaded image"
            )
            return None

        detector = cv2.QRCodeDetector()

        # Store different versions of the image.
        images_to_try = []

        # 1. Original
        images_to_try.append(image)

        # 2. Grayscale
        gray = cv2.cvtColor(
            image,
            cv2.COLOR_BGR2GRAY,
        )
        images_to_try.append(gray)

        # 3. 2x enlarged original
        enlarged = cv2.resize(
            image,
            None,
            fx=2,
            fy=2,
            interpolation=cv2.INTER_CUBIC,
        )
        images_to_try.append(enlarged)

        # 4. 2x enlarged grayscale
        enlarged_gray = cv2.resize(
            gray,
            None,
            fx=2,
            fy=2,
            interpolation=cv2.INTER_CUBIC,
        )
        images_to_try.append(enlarged_gray)

        # 5. OTSU threshold
        _, otsu = cv2.threshold(
            gray,
            0,
            255,
            cv2.THRESH_BINARY + cv2.THRESH_OTSU,
        )
        images_to_try.append(otsu)

        # 6. Adaptive threshold
        adaptive = cv2.adaptiveThreshold(
            gray,
            255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY,
            31,
            5,
        )
        images_to_try.append(adaptive)

        # 7. Sharpened grayscale
        blurred = cv2.GaussianBlur(
            gray,
            (0, 0),
            3,
        )

        sharpened = cv2.addWeighted(
            gray,
            1.5,
            blurred,
            -0.5,
            0,
        )

        images_to_try.append(sharpened)

        # Try every image version
        for index, candidate in enumerate(images_to_try, start=1):

            try:
                data, points, _ = detector.detectAndDecode(
                    candidate
                )

                if data and data.strip():
                    decoded = data.strip()

                    logger.info(
                        "QR decoded successfully using OpenCV "
                        "attempt %s: %s",
                        index,
                        decoded,
                    )

                    return decoded

            except Exception as exc:
                logger.debug(
                    "OpenCV QR attempt %s failed: %s",
                    index,
                    exc,
                )

        # Try OpenCV's multi-code detector if available
        try:
            if hasattr(
                detector,
                "detectAndDecodeMulti",
            ):
                success, decoded_info, points, _ = (
                    detector.detectAndDecodeMulti(image)
                )

                if success and decoded_info:

                    for data in decoded_info:

                        if data and data.strip():
                            decoded = data.strip()

                            logger.info(
                                "QR decoded successfully using "
                                "OpenCV multi-code detector: %s",
                                decoded,
                            )

                            return decoded

        except Exception as exc:
            logger.debug(
                "OpenCV multi-code detection failed: %s",
                exc,
            )

    except ImportError:
        logger.error(
            "OpenCV/numpy is not installed. "
            "Run: pip install opencv-python numpy"
        )

    except Exception as exc:
        logger.exception(
            "OpenCV QR decoding failed: %s",
            exc,
        )

    logger.warning(
        "QR image was processed but no readable QR code was detected"
    )

    return None


# ──────────────────────────────────────────────────────────────────────────────
# QR INVESTIGATION
# ──────────────────────────────────────────────────────────────────────────────

async def investigate_qr(content: str) -> dict:
    """
    Investigate decoded QR content.

    If the QR contains a URL:
        - normalize the URL
        - follow redirects safely
        - collect destination information
        - identify suspicious indicators

    If the QR does not contain a URL:
        - perform content-based heuristic analysis
        - return the QR evidence without external URL checks
    """

    content = (content or "").strip()

    if not content:
        raise ValueError("QR content cannot be empty")

    # ──────────────────────────────────────────────────────────────────────
    # Determine whether QR content is a URL
    # ──────────────────────────────────────────────────────────────────────

    is_url = bool(
        re.match(
            r"^https?://",
            content,
            re.IGNORECASE,
        )
    )

    # Also support content that looks like a URL but has no scheme.
    if not is_url:
        is_url = bool(
            re.match(
                r"^(www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$",
                content,
                re.IGNORECASE,
            )
        )

    redirects: list[str] = []
    resolved_url = content

    # ──────────────────────────────────────────────────────────────────────
    # Suspicious QR indicators
    # ──────────────────────────────────────────────────────────────────────

    risk_indicators: list[str] = []

    # Suspicious words commonly seen in phishing URLs/content.
    suspicious_keywords = re.findall(
        r"login|verify|verification|account|secure|security|"
        r"update|confirm|password|bank|payment|wallet|"
        r"paypal|upi|reward|prize|claim",
        content,
        re.IGNORECASE,
    )

    if suspicious_keywords:
        unique_keywords = sorted(
            set(
                keyword.lower()
                for keyword in suspicious_keywords
            )
        )

        risk_indicators.append(
            "suspicious keyword in QR content"
        )

    # Raw IP address URL.
    if re.search(
        r"https?://(?:\d{1,3}\.){3}\d{1,3}"
        r"(?::\d+)?(?:/|$)",
        content,
        re.IGNORECASE,
    ):
        risk_indicators.append(
            "IP address URL — no domain name"
        )

    # Encoded URL indicators.
    if "%" in content:
        risk_indicators.append(
            "encoded characters detected in QR content"
        )

    # Very long QR payload.
    if len(content) > 200:
        risk_indicators.append(
            "unusually long QR content"
        )

    # Suspicious URL parameters.
    if is_url:
        parameter_match = re.search(
            r"[?&](redirect|url|next|return|"
            r"continue|target|dest|destination)=",
            content,
            re.IGNORECASE,
        )

        if parameter_match:
            risk_indicators.append(
                "redirect parameter detected in QR URL"
            )

    # ──────────────────────────────────────────────────────────────────────
    # Follow URL redirects
    # ──────────────────────────────────────────────────────────────────────

    if is_url:

        try:
            url = normalize_url(content)

            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=10.0,
                verify=True,
                headers={
                    "User-Agent": (
                        "CTDE-QR-Investigation/1.0"
                    )
                },
            ) as client:

                response = await client.get(url)

                resolved_url = str(
                    response.url
                )

                # Build redirect history
                for history_response in response.history:
                    history_url = str(
                        history_response.url
                    )

                    if history_url not in redirects:
                        redirects.append(history_url)

                # Include final destination if different
                if (
                    resolved_url != url
                    and resolved_url not in redirects
                ):
                    redirects.append(resolved_url)

                # Too many redirects
                if len(response.history) > 2:
                    risk_indicators.append(
                        "multiple redirects detected"
                    )

                # HTTP instead of HTTPS
                if resolved_url.lower().startswith(
                    "http://"
                ):
                    risk_indicators.append(
                        "QR resolves to an insecure HTTP URL"
                    )

        except Exception as exc:

            logger.warning(
                "QR URL resolution failed: %s",
                exc,
            )

            risk_indicators.append(
                "QR destination could not be resolved"
            )

            resolved_url = content

    # ──────────────────────────────────────────────────────────────────────
    # QR risk level
    # ──────────────────────────────────────────────────────────────────────

    indicator_count = len(risk_indicators)

    if indicator_count >= 3:
        qr_risk_level = (
            "High — multiple suspicious indicators"
        )

    elif indicator_count >= 1:
        qr_risk_level = (
            "Medium — suspicious indicators detected"
        )

    else:
        qr_risk_level = (
            "Low — no suspicious indicators detected"
        )

    # ──────────────────────────────────────────────────────────────────────
    # QR reputation summary
    # ──────────────────────────────────────────────────────────────────────

    if is_url:

        if risk_indicators:
            reputation = (
                "Heuristic analysis identified: "
                + "; ".join(risk_indicators)
            )
        else:
            reputation = (
                "No QR-specific heuristic indicators "
                "were detected. Full destination reputation "
                "is evaluated by the CTDE URL pipeline."
            )

    else:
        reputation = (
            "QR contains non-URL content. "
            "External URL reputation checks are not applicable."
        )

    # ──────────────────────────────────────────────────────────────────────
    # QRData object
    # ──────────────────────────────────────────────────────────────────────

    qr_data = QRData(
        decodedUrl=content,
        redirects=redirects,
        reputation=reputation,
        qrRiskLevel=qr_risk_level,
    )

    # ──────────────────────────────────────────────────────────────────────
    # Return complete evidence package
    # ──────────────────────────────────────────────────────────────────────

    return {
        "content": content,
        "isUrl": is_url,
        "resolvedUrl": resolved_url,
        "redirects": redirects,
        "riskIndicators": risk_indicators,
        "qrData": qr_data,
        "sha256": sha256_of_string(content),
    }