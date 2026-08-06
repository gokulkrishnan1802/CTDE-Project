import hashlib
import socket
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse


def sha256_of_string(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def resolve_ip(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def extract_links_from_text(text: str) -> list[str]:
    url_pattern = r"https?://[^\s\"'<>]+"
    return re.findall(url_pattern, text)


def safe_get(d: dict, *keys, default="N/A") -> str:
    for key in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(key, {})
    return str(d) if d and d != {} else default


def truncate(text: str, max_len: int = 200) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def domain_age_days(creation_date) -> Optional[int]:
    if creation_date is None:
        return None
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    try:
        if isinstance(creation_date, str):
            for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%dT%H:%M:%S"):
                try:
                    creation_date = datetime.strptime(creation_date, fmt)
                    break
                except ValueError:
                    continue
        delta = datetime.now() - creation_date.replace(tzinfo=None) if hasattr(creation_date, "replace") else None
        return delta.days if delta else None
    except Exception:
        return None


def get_tld(domain: str) -> str:
    parts = domain.split(".")
    return parts[-1] if parts else ""


def is_suspicious_tld(domain: str) -> bool:
    suspicious = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "loan", "work", "racing"}
    return get_tld(domain).lower() in suspicious
