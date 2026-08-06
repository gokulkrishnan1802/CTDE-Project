"""
Domain investigation service.
Aggregates WHOIS, DNS, IP, and hosting information for a domain.
"""
import logging
import socket
from typing import Optional

import httpx

from config import settings
from schemas import DNSData, WhoisData
from services.dns import lookup_dns
from services.whois_svc import lookup_whois
from utils.helpers import is_suspicious_tld

logger = logging.getLogger(__name__)

# Known hosting providers (IP prefix → name)
HOSTING_MAP = {
    "104.21.": "Cloudflare",
    "172.67.": "Cloudflare",
    "13.": "Amazon AWS",
    "52.": "Amazon AWS",
    "54.": "Amazon AWS",
    "35.": "Google Cloud",
    "34.": "Google Cloud",
    "20.": "Microsoft Azure",
    "40.": "Microsoft Azure",
    "104.18.": "Cloudflare",
    "185.199.": "GitHub Pages",
    "151.101.": "Fastly",
}


def investigate_domain(domain: str) -> dict:
    """
    Collect comprehensive domain intelligence.
    Returns a dict with all domain evidence.
    """
    domain = domain.lower().strip()

    whois_data = lookup_whois(domain)
    dns_data = lookup_dns(domain)

    ip = _resolve_ip(domain)
    hosting = _detect_hosting(ip) if ip else "Unknown"
    country = _geolocate_ip(ip) if ip else whois_data.country

    suspicious_tld = is_suspicious_tld(domain)
    newly_registered = _is_newly_registered(whois_data)
    has_dnssec = _check_dnssec(domain)

    return {
        "domain": domain,
        "ip": ip or "Unresolvable",
        "hosting": hosting,
        "country": country,
        "whois": whois_data,
        "dns": dns_data,
        "suspiciousTld": suspicious_tld,
        "newlyRegistered": newly_registered,
        "hasDnssec": has_dnssec,
    }


def _resolve_ip(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def _detect_hosting(ip: str) -> str:
    if not ip:
        return "Unknown"
    for prefix, name in HOSTING_MAP.items():
        if ip.startswith(prefix):
            return name
    return "Unknown Hosting"


def _geolocate_ip(ip: str) -> str:
    """Use ip-api.com (free, no key required) to get the country."""
    try:
        with httpx.Client(timeout=5) as client:
            resp = client.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode")
            if resp.status_code == 200:
                data = resp.json()
                return data.get("country", "Unknown")
    except Exception:
        pass
    return "Unknown"


def _is_newly_registered(whois_data: WhoisData) -> bool:
    age = whois_data.domainAge
    if "Unknown" in age:
        return False
    if "day" in age:
        days = int(age.split()[0])
        return days < 90
    if "month" in age:
        months = int(age.split()[0])
        return months < 3
    return False


def _check_dnssec(domain: str) -> bool:
    import dns.resolver
    import dns.exception
    try:
        dns.resolver.resolve(domain, "DNSKEY", lifetime=5)
        return True
    except Exception:
        return False
