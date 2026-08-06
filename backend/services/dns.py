"""
DNS lookup service using dnspython.
Collects A, AAAA, MX, TXT, NS, CNAME records.
"""
import logging
from typing import List

import dns.resolver
import dns.exception

from schemas import DNSData

logger = logging.getLogger(__name__)


def lookup_dns(domain: str) -> DNSData:
    """Perform full DNS record lookup for a domain."""
    return DNSData(
        aRecord=_query(domain, "A"),
        aaaaRecord=_query(domain, "AAAA"),
        mx=_query(domain, "MX"),
        txt=_query(domain, "TXT"),
        ns=_query(domain, "NS"),
        cname=_query(domain, "CNAME"),
    )


def _query(domain: str, record_type: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=8)
        results = []
        for rdata in answers:
            if record_type == "MX":
                results.append(f"{rdata.preference} {rdata.exchange}")
            elif record_type == "TXT":
                results.append(" ".join(part.decode() for part in rdata.strings))
            else:
                results.append(str(rdata))
        return results
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except dns.exception.Timeout:
        logger.warning("DNS timeout for %s %s", domain, record_type)
        return []
    except Exception as exc:
        logger.warning("DNS error for %s %s: %s", domain, record_type, exc)
        return []


def has_spf(domain: str) -> bool:
    txt_records = _query(domain, "TXT")
    return any("v=spf1" in rec for rec in txt_records)


def has_dmarc(domain: str) -> bool:
    txt_records = _query(f"_dmarc.{domain}", "TXT")
    return any("v=DMARC1" in rec for rec in txt_records)


def get_dmarc_policy(domain: str) -> str:
    txt_records = _query(f"_dmarc.{domain}", "TXT")
    for rec in txt_records:
        if "v=DMARC1" in rec:
            for part in rec.split(";"):
                part = part.strip()
                if part.startswith("p="):
                    return part[2:].strip()
    return "none"
