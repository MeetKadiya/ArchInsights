import asyncio
from datetime import datetime, timezone
import logging
import socket
import ssl
from typing import Optional, Dict, Any, List

from app.domain_scanner.models import TlsCertificateInfo

logger = logging.getLogger(__name__)


class TlsInspector:
    """
    Connects to target domain port 443 via TLS handshake to inspect
    certificates, expiry windows, SANs, and cipher configurations.
    """

    def __init__(self, timeout: float = 3.5):
        self.timeout = timeout

    async def inspect(self, domain: str, port: int = 443) -> Optional[TlsCertificateInfo]:
        """Runs TLS handshake in a background thread with timeout."""
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._inspect_sync, domain, port),
                timeout=self.timeout + 1.0,
            )
        except Exception as e:
            logger.debug(f"TLS inspection failed for {domain}:{port} - {e}")
            return None

    def _inspect_sync(self, domain: str, port: int = 443) -> Optional[TlsCertificateInfo]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # We want to inspect even self-signed or invalid certs

        with socket.create_connection((domain, port), timeout=self.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                version = ssock.version()
                cipher = ssock.cipher()
                cipher_str = cipher[0] if cipher else None

                # When verify_mode=CERT_NONE and binary_form=False, cert dictionary may be empty
                # In that case, we extract binary cert or use verified context
                if not cert:
                    # Retry with normal verification to grab cert dict
                    try:
                        ctx_verified = ssl.create_default_context()
                        with socket.create_connection((domain, port), timeout=self.timeout) as sock2:
                            with ctx_verified.wrap_socket(sock2, server_hostname=domain) as ssock2:
                                cert = ssock2.getpeercert()
                                version = ssock2.version()
                                cipher = ssock2.cipher()
                                cipher_str = cipher[0] if cipher else None
                    except Exception:
                        pass

                return self._parse_cert_dict(cert, version, cipher_str)

    def _parse_cert_dict(
        self, cert: Optional[Dict[str, Any]], version: Optional[str], cipher: Optional[str]
    ) -> TlsCertificateInfo:
        if not cert:
            return TlsCertificateInfo(
                protocol_version=version,
                cipher_suite=cipher,
                is_trusted=False,
            )

        # Parse subject & issuer
        subject_dict: Dict[str, str] = {}
        for item in cert.get("subject", []):
            for k, v in item:
                subject_dict[k] = v

        issuer_dict: Dict[str, str] = {}
        for item in cert.get("issuer", []):
            for k, v in item:
                issuer_dict[k] = v

        # Parse SANs
        san_list: List[str] = []
        for typ, val in cert.get("subjectAltName", []):
            if typ == "DNS":
                san_list.append(val)

        # Parse validity
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")
        days_remaining = None
        is_expired = False
        is_expiring_soon = False

        if not_after:
            try:
                # e.g., 'May 20 12:00:00 2026 GMT'
                dt_expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                delta = dt_expiry - now
                days_remaining = delta.days
                if days_remaining < 0:
                    is_expired = True
                elif days_remaining <= 14:
                    is_expiring_soon = True
            except Exception:
                pass

        return TlsCertificateInfo(
            issuer=issuer_dict,
            subject=subject_dict,
            san_list=san_list,
            valid_from=not_before,
            valid_to=not_after,
            days_remaining=days_remaining,
            is_expired=is_expired,
            is_expiring_soon=is_expiring_soon,
            protocol_version=version,
            cipher_suite=cipher,
            is_trusted=not is_expired,
            details={"serial_number": cert.get("serialNumber")},
        )
