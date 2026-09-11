import ipaddress
import re

from urllib.parse import urlparse


# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────

ALLOWED_URL_SCHEMES = {"http", "https"}

MAX_URL_LENGTH = 2048
MAX_DOMAIN_LENGTH = 253

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


# ──────────────────────────────────────────────────────────────────────────────
# URL VALIDATION
# ──────────────────────────────────────────────────────────────────────────────

def is_valid_url(value: str) -> bool:
    """
    Validate an HTTP/HTTPS URL.

    Examples:
        https://example.com       -> True
        http://example.com        -> True
        example.com               -> True
        ftp://example.com         -> False
        example                  -> False
        https://                  -> False
    """

    if not isinstance(value, str):
        return False

    value = value.strip()

    if not value or len(value) > MAX_URL_LENGTH:
        return False

    # Add HTTPS temporarily when the user provides a bare domain.
    test_value = value

    if not test_value.startswith(("http://", "https://")):
        test_value = f"https://{test_value}"

    try:
        parsed = urlparse(test_value)

        # Only HTTP and HTTPS are supported.
        if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES:
            return False

        # A hostname is mandatory.
        if not parsed.hostname:
            return False

        # Reject whitespace inside the URL.
        if any(char.isspace() for char in value):
            return False

        # Validate hostname.
        hostname = parsed.hostname.lower().rstrip(".")

        if is_ip_address(hostname):
            return is_valid_ip(hostname)

        return is_valid_domain(hostname)

    except (ValueError, UnicodeError):
        return False


# ──────────────────────────────────────────────────────────────────────────────
# EMAIL VALIDATION
# ──────────────────────────────────────────────────────────────────────────────

def is_valid_email(value: str) -> bool:
    """
    Validate a normal email address.
    """

    if not isinstance(value, str):
        return False

    value = value.strip()

    if not value or len(value) > 254:
        return False

    return bool(EMAIL_PATTERN.fullmatch(value))


# ──────────────────────────────────────────────────────────────────────────────
# DOMAIN VALIDATION
# ──────────────────────────────────────────────────────────────────────────────

def is_valid_domain(value: str) -> bool:
    """
    Validate a normal domain name.

    Examples:
        example.com          -> True
        google.com           -> True
        sub.example.com      -> True
        example              -> False
        -example.com         -> False
    """

    if not isinstance(value, str):
        return False

    value = value.strip().lower().rstrip(".")

    if not value:
        return False

    if len(value) > MAX_DOMAIN_LENGTH:
        return False

    return bool(DOMAIN_PATTERN.fullmatch(value))


# ──────────────────────────────────────────────────────────────────────────────
# DOMAIN EXTRACTION
# ──────────────────────────────────────────────────────────────────────────────

def extract_domain(value: str) -> str:
    """
    Extract a bare domain from:
        URL
        email address
        domain string
    """

    if not isinstance(value, str):
        return ""

    value = value.strip()

    if not value:
        return ""

    # Email address
    if "@" in value:
        return value.rsplit("@", 1)[-1].lower().strip()

    # URL
    if value.startswith(("http://", "https://")):
        try:
            parsed = urlparse(value)
            return (parsed.hostname or "").lower()
        except ValueError:
            return ""

    # Bare domain
    return value.lower().split("/")[0].split(":")[0]


# ──────────────────────────────────────────────────────────────────────────────
# IP ADDRESS VALIDATION
# ──────────────────────────────────────────────────────────────────────────────

def is_ip_address(value: str) -> bool:
    """
    Check whether a value is syntactically an IPv4 or IPv6 address.
    """

    if not isinstance(value, str):
        return False

    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_valid_ip(value: str) -> bool:
    """
    Validate an IPv4 or IPv6 address.
    """

    return is_ip_address(value)


# ──────────────────────────────────────────────────────────────────────────────
# PRIVATE / LOCAL IP DETECTION
# ──────────────────────────────────────────────────────────────────────────────

def is_private_or_local_ip(value: str) -> bool:
    """
    Detect private, loopback, link-local, or otherwise non-public IP addresses.

    This is useful later when remote URL analysis is performed.
    """

    try:
        ip = ipaddress.ip_address(value.strip())

        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_unspecified
        )

    except ValueError:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# URL NORMALIZATION
# ──────────────────────────────────────────────────────────────────────────────

def normalize_url(value: str) -> str:
    """
    Normalize a URL by:
      1. Removing surrounding whitespace.
      2. Adding HTTPS when no scheme is supplied.

    Raises:
        ValueError for invalid URLs.
    """

    if not isinstance(value, str):
        raise ValueError("URL must be a string")

    value = value.strip()

    if not value:
        raise ValueError("URL cannot be empty")

    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"

    if not is_valid_url(value):
        raise ValueError("Invalid URL. Please provide a valid HTTP or HTTPS URL.")

    return value


# ──────────────────────────────────────────────────────────────────────────────
# GENERIC TEXT VALIDATION
# ──────────────────────────────────────────────────────────────────────────────

def is_valid_text(
    value: str,
    min_length: int = 1,
    max_length: int = 10000,
) -> bool:
    """
    Validate generic text input.
    """

    if not isinstance(value, str):
        return False

    value = value.strip()

    if len(value) < min_length:
        return False

    if len(value) > max_length:
        return False

    return True