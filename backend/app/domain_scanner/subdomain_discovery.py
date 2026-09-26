import asyncio
import logging
import socket
from typing import List, Set
import httpx

from app.domain_scanner.models import SubdomainInfo

logger = logging.getLogger(__name__)

COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "api",
    "app",
    "auth",
    "admin",
    "cdn",
    "dev",
    "staging",
    "status",
    "shop",
    "blog",
    "portal",
    "docs",
    "dashboard",
    "internal",
    "static",
    "assets",
    "m",
    "login",
    "accounts",
    "support",
    "cloud",
    "billing",
    "gateway",
    "secure",
    "sso",
    "help",
    "meet",
    "drive",
    "maps",
    "news",
    "play",
]


class SubdomainDiscoveryEngine:
    """
    Discovers active subdomains via Certificate Transparency (CT) logs
    and fast concurrent DNS & HTTP probing.
    """

    def __init__(self, concurrency: int = 20, timeout: float = 2.5):
        self.concurrency = concurrency
        self.timeout = timeout

    @staticmethod
    def extract_apex_domain(domain: str) -> str:
        """Extracts the base/apex domain (e.g. google.com from www.google.com)."""
        parts = domain.lower().split(".")
        if len(parts) <= 2:
            return domain
        second_level_tlds = {"co.uk", "com.au", "co.nz", "co.jp", "com.br", "org.uk", "gov.in", "ac.uk"}
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in second_level_tlds:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    async def discover(self, domain: str) -> List[SubdomainInfo]:
        """
        Discovers and probes subdomains for the target domain and its apex.
        """
        apex = self.extract_apex_domain(domain)
        candidate_names: Set[str] = set()

        # Always include the original domain itself if it is a subdomain
        if domain != apex:
            candidate_names.add(domain.lower())

        # 1. Add common standard subdomains on the apex domain
        for sub in COMMON_SUBDOMAINS:
            candidate_names.add(f"{sub}.{apex}")

        # 2. Query Certificate Transparency (crt.sh) logs asynchronously
        ct_candidates = await self._query_crt_sh(apex)
        candidate_names.update(ct_candidates)

        # Remove wildcard entries and apex domain itself
        clean_candidates = [
            s.lower().strip() for s in candidate_names
            if s and not s.startswith("*.") and (s.endswith(f".{apex}") or s == domain) and s != apex
        ]

        # Limit to top 30 candidate subdomains to maintain fast execution
        clean_candidates = sorted(list(set(clean_candidates)))[:30]

        # 3. Concurrently probe DNS and HTTP status
        semaphore = asyncio.Semaphore(self.concurrency)

        async def probe_worker(sub: str) -> Optional[SubdomainInfo]:
            async with semaphore:
                return await self._probe_subdomain(sub)

        tasks = [probe_worker(sub) for sub in clean_candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        live_subdomains = [r for r in results if isinstance(r, SubdomainInfo) and r.is_live]
        return live_subdomains

    async def _query_crt_sh(self, domain: str) -> Set[str]:
        """Queries crt.sh certificate transparency logs for subdomains."""
        found: Set[str] = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                res = await client.get(url)
                if res.status_code == 200:
                    entries = res.json()
                    for entry in entries:
                        name_val = entry.get("name_value", "")
                        for line in name_val.split("\n"):
                            line = line.strip().lower()
                            if line and domain in line and not line.startswith("*"):
                                found.add(line)
        except Exception:
            # crt.sh can sometimes be rate-limited or slow, gracefully ignore
            pass
        return found

    async def _probe_subdomain(self, subdomain: str) -> Optional[SubdomainInfo]:
        """Resolves DNS and performs lightweight HTTP check for a subdomain."""
        try:
            # Asynchronous DNS resolution via socket
            loop = asyncio.get_running_loop()
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(subdomain, None, family=socket.AF_INET),
                timeout=self.timeout
            )
            ips = list({info[4][0] for info in addr_info if info[4]})
            if not ips:
                return None

            status_code = None
            server_header = None

            # Fast HTTP probe to see if web service is responding
            try:
                async with httpx.AsyncClient(timeout=2.0, verify=False, follow_redirects=True) as client:
                    resp = await client.get(f"https://{subdomain}", timeout=2.0)
                    status_code = resp.status_code
                    server_header = resp.headers.get("server")
            except Exception:
                try:
                    async with httpx.AsyncClient(timeout=2.0, verify=False, follow_redirects=True) as client:
                        resp = await client.get(f"http://{subdomain}", timeout=2.0)
                        status_code = resp.status_code
                        server_header = resp.headers.get("server")
                except Exception:
                    pass

            return SubdomainInfo(
                subdomain=subdomain,
                ip_addresses=ips,
                status_code=status_code,
                server_header=server_header,
                is_live=True
            )
        except Exception:
            return None
