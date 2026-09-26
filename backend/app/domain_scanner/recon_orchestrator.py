import asyncio
import logging
import re
from typing import Optional, Dict
from urllib.parse import urlparse
import httpx

from app.domain_scanner.models import DomainReconResult
from app.domain_scanner.dns_recon import DnsReconEngine
from app.domain_scanner.subdomain_discovery import SubdomainDiscoveryEngine
from app.domain_scanner.tls_inspector import TlsInspector
from app.domain_scanner.port_scanner import PortScannerEngine
from app.domain_scanner.fingerprint_engine import FingerprintEngine

logger = logging.getLogger(__name__)


class DomainReconOrchestrator:
    """
    Coordinates DNS discovery, subdomain enumeration, TLS certificate inspection,
    port scanning, and technology stack fingerprinting into a unified reconnaissance pipeline.
    """

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout
        self.dns_engine = DnsReconEngine(timeout=3.5)
        self.subdomain_engine = SubdomainDiscoveryEngine(timeout=3.0)
        self.tls_inspector = TlsInspector(timeout=4.0)
        self.port_scanner = PortScannerEngine(timeout=1.0)
        self.fingerprint_engine = FingerprintEngine()

    @staticmethod
    def normalize_domain(target: str) -> str:
        """Extracts clean hostname/domain from URL or bare domain string."""
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        parsed = urlparse(target)
        domain = parsed.hostname or target
        # Strip trailing dots or port if present
        domain = domain.split(":")[0].rstrip(".")
        return domain.lower()

    async def scan_domain(self, target_input: str) -> DomainReconResult:
        """
        Executes end-to-end domain reconnaissance asynchronously.
        """
        domain = self.normalize_domain(target_input)
        canonical_url = f"https://{domain}"

        # 1. Fetch HTTP/HTTPS web content and headers
        http_headers: Dict[str, str] = {}
        cookies_list = []
        html_body = ""
        http_status = None

        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=False,
            follow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36 ArchInsights/2.0"
                )
            },
        ) as client:
            try:
                resp = await client.get(f"https://{domain}")
                http_status = resp.status_code
                http_headers = dict(resp.headers)
                cookies_list = [f"{k}={v}" for k, v in resp.cookies.items()]
                html_body = resp.text
                canonical_url = str(resp.url)
            except Exception:
                try:
                    resp = await client.get(f"http://{domain}")
                    http_status = resp.status_code
                    http_headers = dict(resp.headers)
                    cookies_list = [f"{k}={v}" for k, v in resp.cookies.items()]
                    html_body = resp.text
                    canonical_url = str(resp.url)
                except Exception as e:
                    logger.debug(f"HTTP fetch failed for {domain}: {e}")

        # 2. Concurrently execute network and infrastructure probes
        dns_task = self.dns_engine.resolve_all(domain)
        subdomain_task = self.subdomain_engine.discover(domain)
        tls_task = self.tls_inspector.inspect(domain)
        port_task = self.port_scanner.scan(domain)

        dns_res, subdomains, tls_info, open_ports = await asyncio.gather(
            dns_task,
            subdomain_task,
            tls_task,
            port_task,
            return_exceptions=False,
        )

        dns_records, ip_addresses, nameservers, has_spf, has_dmarc = dns_res

        # 3. Analyze fingerprinting indicators and security headers
        technologies, sec_headers = self.fingerprint_engine.analyze(
            headers=http_headers,
            cookies=cookies_list,
            html_body=html_body,
        )

        return DomainReconResult(
            domain=domain,
            canonical_url=canonical_url,
            ip_addresses=ip_addresses,
            http_status=http_status,
            dns_records=dns_records,
            nameservers=nameservers,
            subdomains=subdomains,
            tls_info=tls_info,
            open_ports=open_ports,
            technologies=technologies,
            http_headers=http_headers,
            cookies=cookies_list,
            security_headers=sec_headers,
            has_spf=has_spf,
            has_dmarc=has_dmarc,
            raw_metadata={"body_length": len(html_body)},
        )
