"""
APK analysis service using androguard.
Extracts permissions, activities, services, receivers, network calls, and signing info.
"""
import logging
import hashlib
from typing import Optional

logger = logging.getLogger(__name__)

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.INTERNET",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.DISABLE_KEYGUARD",
}

MALWARE_INDICATORS = [
    ("android.permission.SEND_SMS", "SMS exfiltration capability"),
    ("android.permission.RECEIVE_SMS", "SMS interception capability"),
    ("android.permission.SYSTEM_ALERT_WINDOW", "Overlay attack capability"),
    ("android.permission.INSTALL_PACKAGES", "Silent app installation capability"),
    ("android.permission.BIND_DEVICE_ADMIN", "Device administrator — high-privilege malware indicator"),
    ("android.permission.REQUEST_INSTALL_PACKAGES", "Dropper/downloader capability"),
    ("android.permission.READ_SMS", "Credential theft via OTP interception"),
    ("android.permission.DISABLE_KEYGUARD", "Screen lock bypass capability"),
]


def analyze_apk_bytes(apk_bytes: bytes, filename: str = "uploaded.apk") -> dict:
    """
    Analyze APK binary using androguard.
    Returns structured evidence.
    """
    sha256 = hashlib.sha256(apk_bytes).hexdigest()

    try:
        from androguard.core.apk import APK

        # AnalyzeAPK also builds a full DEX cross-reference/basic-block graph,
        # which can exceed the memory available on small hosted instances.
        # APK parses the manifest and metadata without constructing that graph.
        a = APK(apk_bytes, raw=True)
        return _extract_evidence(a, sha256, filename)
    except ImportError:
        logger.warning("androguard not installed — APK deep analysis unavailable")
        return _fallback_apk(sha256, filename, "androguard library not installed")
    except Exception as exc:
        logger.warning("APK analysis error: %s", exc)
        return _fallback_apk(sha256, filename, str(exc))


def analyze_apk_path(path: str) -> dict:
    """Analyze an APK from a file path."""
    with open(path, "rb") as f:
        data = f.read()
    return analyze_apk_bytes(data, path.split("/")[-1])


def _extract_evidence(a, sha256: str, filename: str) -> dict:
    permissions = list(a.get_permissions())
    dangerous = [p for p in permissions if p in DANGEROUS_PERMISSIONS]

    activities = list(a.get_activities())
    services = list(a.get_services())
    receivers = list(a.get_receivers())

    # Find network URLs
    import re
    urls: list[str] = []
    url_pattern = re.compile(r"https?://[^\s'\"<>]+")
    # Search raw DEX bytes for URL literals instead of decoding every method
    # and building Androguard's much larger DEX analysis graph.
    url_bytes_pattern = re.compile(rb"https?://[^\x00-\x20'\"<>]+")
    for dex_bytes in a.get_all_dex():
        for match in url_bytes_pattern.finditer(dex_bytes):
            url = match.group(0).decode("utf-8", errors="replace").rstrip(".,);]")
            urls.append(url)
            if len(urls) >= 20:
                break
        if len(urls) >= 20:
            break
    urls = list(dict.fromkeys(urls))

    # Certificate / signing info
    signing_cert = "Unknown"
    try:
        certs = a.get_certificates()
        if certs:
            cert = certs[0]
            signing_cert = f"SHA256: {cert.sha256.hex()[:16]}... Issuer: {cert.issuer.human_friendly}"
    except Exception:
        pass

    # Malware indicators
    malware_flags: list[str] = []
    for perm, description in MALWARE_INDICATORS:
        if perm in permissions:
            malware_flags.append(description)

    malware_detection = _summarize_malware(malware_flags, dangerous)
    risk_score = _compute_apk_risk(dangerous, malware_flags, permissions)

    return {
        "sha256": sha256,
        "filename": filename,
        "permissions": permissions,
        "dangerousPermissions": dangerous,
        "activities": activities[:20],
        "services": services[:20],
        "receivers": receivers[:20],
        "networkUrls": urls,
        "signingCertificate": signing_cert,
        "malwareFlags": malware_flags,
        "malwareDetection": malware_detection,
        "riskScore": risk_score,
    }


def _fallback_apk(sha256: str, filename: str, reason: str) -> dict:
    return {
        "sha256": sha256,
        "filename": filename,
        "permissions": [],
        "dangerousPermissions": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "networkUrls": [],
        "signingCertificate": "Unknown",
        "malwareFlags": [],
        "malwareDetection": f"Static analysis unavailable — {reason}",
        "riskScore": 50,
    }


def _summarize_malware(flags: list[str], dangerous: list[str]) -> str:
    if not flags and len(dangerous) == 0:
        return "No malware indicators detected"
    parts = []
    if flags:
        parts.append(f"{len(flags)} malware indicator(s): {'; '.join(flags[:3])}")
    if len(dangerous) > 5:
        parts.append(f"{len(dangerous)} dangerous permissions")
    return " | ".join(parts) if parts else "No malware indicators detected"


def _compute_apk_risk(dangerous: list[str], flags: list[str], all_perms: list[str]) -> int:
    """Returns 0-100 risk score."""
    score = 0
    score += min(len(dangerous) * 8, 40)
    score += min(len(flags) * 15, 45)
    if len(all_perms) > 20:
        score += 10
    return min(score, 100)
