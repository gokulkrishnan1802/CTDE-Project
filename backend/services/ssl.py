"""
SSL certificate analysis service.
Uses Python's stdlib ssl module for real certificate inspection.
"""
import ssl
import socket
from datetime import datetime, timezone
from typing import Optional

from schemas import SSLData


def check_ssl(hostname: str, port: int = 443) -> SSLData:
    """Fetch and inspect the TLS certificate for the given hostname."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()  # (name, protocol, bits)
                tls_version = tls_sock.version() or "Unknown"

        # Subject
        subject_dict = dict(x[0] for x in cert.get("subject", []))
        subject = subject_dict.get("commonName", hostname)

        # Issuer
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        issuer_org = issuer_dict.get("organizationName", "Unknown")
        issuer_cn = issuer_dict.get("commonName", "")
        issuer = f"{issuer_org} ({issuer_cn})" if issuer_cn else issuer_org

        # Validity dates
        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")
        not_before = _parse_ssl_date(not_before_str)
        not_after = _parse_ssl_date(not_after_str)

        now = datetime.now(timezone.utc)
        is_valid = not_before <= now <= not_after if (not_before and not_after) else False

        # SANs
        san_raw = cert.get("subjectAltName", [])
        san_list = [v for t, v in san_raw if t == "DNS"]

        # Certificate chain depth (approximated from issuer info)
        chain_info = f"{issuer} → {subject}"

        return SSLData(
            sslStatus="Valid" if is_valid else "Expired or Invalid",
            tlsVersion=tls_version,
            issuer=issuer,
            validFrom=not_before.strftime("%Y-%m-%d") if not_before else "Unknown",
            validUntil=not_after.strftime("%Y-%m-%d") if not_after else "Unknown",
            certificateChain=chain_info,
            subject=subject,
            san=san_list[:10],
        )

    except ssl.SSLCertVerificationError as exc:
        return _error_ssl(hostname, f"Certificate verification failed: {exc}")
    except ssl.SSLError as exc:
        return _error_ssl(hostname, f"SSL error: {exc}")
    except OSError as exc:
        return _error_ssl(hostname, f"Connection error: {exc}")
    except Exception as exc:
        return _error_ssl(hostname, f"Unknown error: {exc}")


def _parse_ssl_date(date_str: str) -> Optional[datetime]:
    if not date_str:
        return None
    try:
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _error_ssl(hostname: str, reason: str) -> SSLData:
    return SSLData(
        sslStatus=f"Not available — {reason}",
        tlsVersion="N/A",
        issuer="N/A",
        validFrom="N/A",
        validUntil="N/A",
        certificateChain="N/A",
        subject=hostname,
        san=[],
    )
