"""
WHOIS lookup service using python-whois.
"""
import logging
from datetime import datetime
from typing import Optional

import whois

from schemas import WhoisData
from utils.helpers import domain_age_days

logger = logging.getLogger(__name__)


def lookup_whois(domain: str) -> WhoisData:
    """Perform a real WHOIS lookup for the domain."""
    try:
        w = whois.whois(domain)

        registrar = _first_str(w.registrar) or "Unknown"
        creation = _first_date(w.creation_date)
        expiry = _first_date(w.expiration_date)
        country = _first_str(w.country) or "Unknown"

        age_days = domain_age_days(creation)
        if age_days is not None:
            years = age_days // 365
            months = (age_days % 365) // 30
            if years > 0:
                age_str = f"{years} year{'s' if years != 1 else ''}"
                if months:
                    age_str += f" {months} month{'s' if months != 1 else ''}"
            else:
                age_str = f"{months} month{'s' if months != 1 else ''}" if months else f"{age_days} days"
        else:
            age_str = "Unknown"

        status_raw = w.status
        if isinstance(status_raw, list):
            status_str = ", ".join(str(s).split(" ")[0] for s in status_raw[:3])
        else:
            status_str = str(status_raw).split(" ")[0] if status_raw else "Unknown"

        return WhoisData(
            registrar=registrar,
            registrationDate=creation.strftime("%Y-%m-%d") if creation else "Unknown",
            expiryDate=expiry.strftime("%Y-%m-%d") if expiry else "Unknown",
            domainAge=age_str,
            country=country,
            whoisStatus=status_str or "Unknown",
        )

    except Exception as exc:
        logger.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return WhoisData(
            registrar="Lookup failed",
            registrationDate="Unknown",
            expiryDate="Unknown",
            domainAge="Unknown",
            country="Unknown",
            whoisStatus="Unknown",
        )


def _first_str(val) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    return str(val).strip() if val else None


def _first_date(val) -> Optional[datetime]:
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    if isinstance(val, datetime):
        return val
    return None
