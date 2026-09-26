from __future__ import annotations

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class DnsRecord(BaseModel):
    record_type: str  # A, AAAA, CNAME, MX, TXT, NS, SOA
    name: str
    value: str
    ttl: Optional[int] = None


class TlsCertificateInfo(BaseModel):
    issuer: Dict[str, str] = Field(default_factory=dict)
    subject: Dict[str, str] = Field(default_factory=dict)
    san_list: List[str] = Field(default_factory=list)
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    days_remaining: Optional[int] = None
    is_expired: bool = False
    is_expiring_soon: bool = False  # < 14 days
    protocol_version: Optional[str] = None  # TLSv1.3, TLSv1.2, etc.
    cipher_suite: Optional[str] = None
    is_trusted: bool = True
    details: Dict[str, Any] = Field(default_factory=dict)


class SubdomainInfo(BaseModel):
    subdomain: str
    ip_addresses: List[str] = Field(default_factory=list)
    status_code: Optional[int] = None
    server_header: Optional[str] = None
    cname: Optional[str] = None
    is_live: bool = False


class PortServiceInfo(BaseModel):
    port: int
    service_name: str
    protocol: str = "tcp"
    is_open: bool = False
    banner: Optional[str] = None
    category: str = "web"  # web, database, remote_access, cache, messaging, other
    is_sensitive: bool = False  # e.g., exposed DB port or redis without firewall


class TechDetection(BaseModel):
    name: str
    category: str  # Frontend Framework, Backend Runtime, CMS, Cloud / CDN, Third-Party API, Web Server, Security, Database
    confidence: float = 1.0  # 0.0 - 1.0
    version: Optional[str] = None
    indicators: List[str] = Field(default_factory=list)
    description: Optional[str] = None


class DomainReconResult(BaseModel):
    domain: str
    canonical_url: str
    ip_addresses: List[str] = Field(default_factory=list)
    http_status: Optional[int] = None
    dns_records: List[DnsRecord] = Field(default_factory=list)
    nameservers: List[str] = Field(default_factory=list)
    subdomains: List[SubdomainInfo] = Field(default_factory=list)
    tls_info: Optional[TlsCertificateInfo] = None
    open_ports: List[PortServiceInfo] = Field(default_factory=list)
    technologies: List[TechDetection] = Field(default_factory=list)
    http_headers: Dict[str, str] = Field(default_factory=dict)
    cookies: List[str] = Field(default_factory=list)
    security_headers: Dict[str, bool] = Field(default_factory=dict)
    has_spf: bool = False
    has_dmarc: bool = False
    raw_metadata: Dict[str, Any] = Field(default_factory=dict)
