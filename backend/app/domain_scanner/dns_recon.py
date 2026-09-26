import asyncio
import logging
from typing import List, Dict, Tuple, Optional
import httpx

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from app.domain_scanner.models import DnsRecord

logger = logging.getLogger(__name__)

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]

# DNS-over-HTTPS (DoH) fallback mapping for standard numeric record types
DOH_TYPE_MAP = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}


class DnsReconEngine:
    """
    Robust DNS Reconnaissance engine supporting direct dnspython resolution
    and automatic fallback to DNS-over-HTTPS (DoH).
    """

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    async def resolve_all(self, domain: str) -> Tuple[List[DnsRecord], List[str], List[str], bool, bool]:
        """
        Resolves standard records, nameservers, IPs, and evaluates SPF/DMARC presence.
        Returns:
            (records, ip_addresses, nameservers, has_spf, has_dmarc)
        """
        records: List[DnsRecord] = []
        ip_addresses: List[str] = []
        nameservers: List[str] = []
        has_spf = False
        has_dmarc = False

        # 1. Primary resolution using dnspython if installed
        if HAS_DNSPYTHON:
            records = await asyncio.to_thread(self._resolve_dnspython, domain)

        # 2. Fallback or supplementary via DNS-over-HTTPS if dnspython produced no records or is unavailable
        if not records:
            records = await self._resolve_doh(domain)

        # 3. Resolve DMARC record (_dmarc.domain)
        dmarc_records = []
        if HAS_DNSPYTHON:
            dmarc_records = await asyncio.to_thread(self._resolve_dnspython, f"_dmarc.{domain}", ["TXT"])
        if not dmarc_records:
            dmarc_records = await self._resolve_doh_single(f"_dmarc.{domain}", "TXT")
        records.extend(dmarc_records)

        # 4. Extract derived fields
        for r in records:
            if r.record_type in ("A", "AAAA"):
                if r.value not in ip_addresses:
                    ip_addresses.append(r.value)
            elif r.record_type == "NS":
                ns_clean = r.value.rstrip(".").lower()
                if ns_clean not in nameservers:
                    nameservers.append(ns_clean)
            elif r.record_type == "TXT":
                val = r.value.strip('"\'')
                if val.lower().startswith("v=spf1"):
                    has_spf = True
                if val.lower().startswith("v=dmarc1"):
                    has_dmarc = True

        return records, ip_addresses, nameservers, has_spf, has_dmarc

    def _resolve_dnspython(self, domain: str, types: Optional[List[str]] = None) -> List[DnsRecord]:
        results: List[DnsRecord] = []
        query_types = types or RECORD_TYPES
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        for rtype in query_types:
            try:
                answers = resolver.resolve(domain, rtype)
                for ans in answers:
                    results.append(
                        DnsRecord(
                            record_type=rtype,
                            name=domain,
                            value=str(ans).strip(),
                            ttl=answers.ttl,
                        )
                    )
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoNameservers, Exception):
                continue

        return results

    async def _resolve_doh(self, domain: str) -> List[DnsRecord]:
        results: List[DnsRecord] = []
        tasks = [self._resolve_doh_single(domain, rtype) for rtype in RECORD_TYPES]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        for sublist in batch_results:
            if isinstance(sublist, list):
                results.extend(sublist)
        return results

    async def _resolve_doh_single(self, domain: str, rtype: str) -> List[DnsRecord]:
        type_num = DOH_TYPE_MAP.get(rtype, 1)
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={type_num}"
        headers = {"accept": "application/dns-json"}
        results: List[DnsRecord] = []

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.get(url, headers=headers)
                if res.status_code == 200:
                    data = res.json()
                    answers = data.get("Answer", [])
                    for ans in answers:
                        # ans format: {'name': '...', 'type': 1, 'TTL': 300, 'data': '...'}
                        data_val = str(ans.get("data", "")).strip().strip('"')
                        if data_val:
                            results.append(
                                DnsRecord(
                                    record_type=rtype,
                                    name=ans.get("name", domain).rstrip("."),
                                    value=data_val,
                                    ttl=ans.get("TTL"),
                                )
                            )
        except Exception:
            pass

        return results
