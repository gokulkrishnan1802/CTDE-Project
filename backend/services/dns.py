"""
DNS lookup service using dnspython.
Collects A, AAAA, MX, TXT, NS, CNAME records.
"""

import logging
from importlib import import_module
from typing import List

from schemas import DNSData

logger = logging.getLogger(__name__)


# Maximum time allowed for each DNS query
DNS_TIMEOUT = 3.0


try:
    _dns_resolver = import_module("dns.resolver")
    _dns_exception = import_module("dns.exception")
except ImportError:
    _dns_resolver = None
    _dns_exception = None


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
    """Query a single DNS record type."""

    if _dns_resolver is None:
        logger.warning("dnspython is not installed; cannot query %s %s", domain, record_type)
        return []

    try:

        resolver = _dns_resolver.Resolver()

        # Timeout for an individual nameserver attempt
        resolver.timeout = DNS_TIMEOUT

        # Overall lifetime of the query
        resolver.lifetime = DNS_TIMEOUT

        answers = resolver.resolve(
            domain,
            record_type,
        )

        results = []

        for rdata in answers:

            if record_type == "MX":

                results.append(
                    f"{rdata.preference} {rdata.exchange}"
                )

            elif record_type == "TXT":

                try:
                    results.append(
                        " ".join(
                            part.decode(
                                errors="replace"
                            )
                            for part in rdata.strings
                        )
                    )

                except Exception:

                    results.append(
                        str(rdata)
                    )

            else:

                results.append(
                    str(rdata)
                )

        return results

    except _dns_resolver.NXDOMAIN:

        return []

    except _dns_resolver.NoAnswer:

        return []

    except _dns_resolver.NoNameservers:

        logger.warning(
            "No DNS nameservers available for %s %s",
            domain,
            record_type,
        )

        return []

    except _dns_exception.Timeout:

        logger.warning(
            "DNS timeout for %s %s",
            domain,
            record_type,
        )

        return []

    except Exception as exc:

        logger.warning(
            "DNS error for %s %s: %s",
            domain,
            record_type,
            exc,
        )

        return []


def has_spf(domain: str) -> bool:
    """Check whether the domain has an SPF record."""

    txt_records = _query(
        domain,
        "TXT",
    )

    return any(
        "v=spf1" in record.lower()
        for record in txt_records
    )


def has_dmarc(domain: str) -> bool:
    """Check whether the domain has a DMARC record."""

    txt_records = _query(
        f"_dmarc.{domain}",
        "TXT",
    )

    return any(
        "v=dmarc1" in record.lower()
        for record in txt_records
    )


def get_dmarc_policy(domain: str) -> str:
    """Extract the DMARC policy."""

    txt_records = _query(
        f"_dmarc.{domain}",
        "TXT",
    )

    for record in txt_records:

        if "v=dmarc1" not in record.lower():
            continue

        for part in record.split(";"):

            part = part.strip()

            if part.lower().startswith("p="):

                return part[2:].strip()

    return "none"