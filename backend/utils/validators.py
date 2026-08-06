import re
from urllib.parse import urlparse


def is_valid_url(value: str) -> bool:
    try:
        result = urlparse(value if value.startswith(("http://", "https://")) else f"https://{value}")
        return bool(result.scheme and result.netloc)
    except Exception:
        return False


def is_valid_email(value: str) -> bool:
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value))


def is_valid_domain(value: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value))


def extract_domain(value: str) -> str:
    """Extract bare domain from URL, email, or domain string."""
    value = value.strip()
    if "@" in value:
        return value.split("@")[-1].lower()
    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)
        host = parsed.hostname or ""
        return host.lower()
    return value.lower().split("/")[0]


def is_ip_address(value: str) -> bool:
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    return bool(re.match(ip_pattern, value))


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value.startswith(("http://", "https://")):
        return f"https://{value}"
    return value
