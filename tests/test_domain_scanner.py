import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.domain_scanner.models import (
    DomainReconResult,
    DnsRecord,
    SubdomainInfo,
    PortServiceInfo,
    TlsCertificateInfo,
    TechDetection,
)
from app.domain_scanner.fingerprint_engine import FingerprintEngine
from app.domain_scanner.tls_inspector import TlsInspector
from app.domain_scanner.topology_mapper import DomainTopologyMapper


client = TestClient(app)


def test_fingerprint_engine_detection():
    engine = FingerprintEngine()

    headers = {
        "Server": "cloudflare",
        "CF-Ray": "887a123bc45d-ORD",
        "X-Powered-By": "Next.js",
        "Strict-Transport-Security": "max-age=31536000",
    }
    cookies = ["__cf_bm=xyz123", "connect.sid=s%3A987"]
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <script src="https://js.stripe.com/v3/"></script>
        <script src="https://www.googletagmanager.com/gtag/js?id=G-12345"></script>
    </head>
    <body class="flex flex-col min-h-screen bg-gray-900">
        <div id="__next">
            <div data-reactroot="">Content</div>
        </div>
        <script id="__NEXT_DATA__" type="application/json">{}</script>
    </body>
    </html>
    """

    techs, sec_headers = engine.analyze(headers, cookies, html)
    tech_names = [t.name for t in techs]

    # Verify key detections
    assert "Cloudflare" in tech_names
    assert "Next.js" in tech_names
    assert "Node.js / Express" in tech_names
    assert "Stripe Payments" in tech_names
    assert "Google Analytics / GTM" in tech_names
    assert "Tailwind CSS" in tech_names

    # Verify security headers audit
    assert sec_headers["strict-transport-security"] is True
    assert sec_headers["content-security-policy"] is False
    assert sec_headers["x-frame-options"] is False


def test_tls_inspector_parsing():
    inspector = TlsInspector()

    # Mock cert dict
    mock_cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "DigiCert Inc"),),),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        "notBefore": "Jan 01 00:00:00 2026 GMT",
        "notAfter": "Dec 31 23:59:59 2026 GMT",
    }

    tls_info = inspector._parse_cert_dict(mock_cert, "TLSv1.3", "TLS_AES_256_GCM_SHA384")
    assert tls_info.protocol_version == "TLSv1.3"
    assert tls_info.issuer.get("organizationName") == "DigiCert Inc"
    assert "www.example.com" in tls_info.san_list
    assert tls_info.days_remaining is not None
    assert tls_info.is_trusted is True


def test_domain_topology_mapping_and_smell_detection():
    recon = DomainReconResult(
        domain="test-vulnerable.org",
        canonical_url="https://test-vulnerable.org",
        ip_addresses=["198.51.100.1"],
        http_status=200,
        dns_records=[
            DnsRecord(record_type="A", name="test-vulnerable.org", value="198.51.100.1", ttl=300),
            DnsRecord(record_type="NS", name="test-vulnerable.org", value="ns1.test-vulnerable.org", ttl=300),
        ],
        nameservers=["ns1.test-vulnerable.org"],
        subdomains=[
            SubdomainInfo(subdomain="api.test-vulnerable.org", ip_addresses=["198.51.100.2"], is_live=True),
        ],
        tls_info=TlsCertificateInfo(
            issuer={"organizationName": "Let's Encrypt"},
            valid_from="2026-01-01",
            valid_to="2026-04-01",
            days_remaining=5,
            is_expired=False,
            is_expiring_soon=True,
            protocol_version="TLSv1.2",
            is_trusted=True,
        ),
        open_ports=[
            PortServiceInfo(port=80, service_name="HTTP", category="web", is_open=True),
            PortServiceInfo(port=443, service_name="HTTPS", category="web", is_open=True),
            PortServiceInfo(port=3306, service_name="MySQL Database", category="database", is_open=True, is_sensitive=True),
        ],
        technologies=[
            TechDetection(name="Nginx", category="Web Server", confidence=1.0),
            TechDetection(name="PHP", category="Backend Runtime", version="8.1.2", confidence=1.0),
            TechDetection(name="WordPress CMS", category="CMS", confidence=1.0),
        ],
        http_headers={"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.1.2"},
        cookies=["PHPSESSID=abc123xyz"],
        security_headers={
            "strict-transport-security": False,
            "content-security-policy": False,
            "x-frame-options": False,
            "x-content-type-options": False,
        },
        has_spf=False,
        has_dmarc=False,
    )

    graph, antipatterns, debt, plans, ai_summary = DomainTopologyMapper.generate_topology(recon)

    # 1. Graph checks
    assert len(graph.nodes) >= 6
    assert len(graph.edges) >= 5
    node_labels = {n.label for n in graph.nodes}
    assert "Infrastructure" in node_labels
    assert "Gateway" in node_labels
    assert "Service" in node_labels
    assert "Database" in node_labels

    # 2. Smell detections
    smell_types = {ap.type for ap in antipatterns}
    assert "EXPOSED_DATABASE_PORT" in smell_types
    assert "MISSING_SECURITY_HEADERS" in smell_types
    assert "INSECURE_OR_EXPIRING_TLS" in smell_types
    assert "EMAIL_SPOOFING_VULNERABILITY" in smell_types
    assert "INFORMATION_DISCLOSURE" in smell_types

    # 3. Debt summary & AI assessment
    assert debt.debt_score > 50  # Multiple high/critical smells
    assert debt.debt_level in ("High", "Critical")
    assert ai_summary.health_grade in ("C", "D", "F")
    assert len(plans) >= 3


def test_api_domain_scan_and_report_endpoints():
    mock_recon = DomainReconResult(
        domain="example.org",
        canonical_url="https://example.org",
        ip_addresses=["93.184.216.34"],
        http_status=200,
        dns_records=[DnsRecord(record_type="A", name="example.org", value="93.184.216.34", ttl=300)],
        nameservers=["a.iana-servers.net", "b.iana-servers.net"],
        subdomains=[],
        tls_info=TlsCertificateInfo(
            issuer={"organizationName": "DigiCert"},
            days_remaining=120,
            protocol_version="TLSv1.3",
            is_trusted=True,
        ),
        open_ports=[PortServiceInfo(port=443, service_name="HTTPS", category="web", is_open=True)],
        technologies=[TechDetection(name="Nginx", category="Web Server", confidence=1.0)],
        http_headers={"Server": "nginx"},
        cookies=[],
        security_headers={"strict-transport-security": True, "content-security-policy": True},
        has_spf=True,
        has_dmarc=True,
    )

    with patch("app.domain_scanner.recon_orchestrator.DomainReconOrchestrator.scan_domain", return_value=mock_recon):
        res = client.post("/api/domain/scan", json={"domain": "example.org", "sync_to_neo4j": False})
        assert res.status_code == 200
        data = res.json()
        assert data["domain"] == "example.org"
        assert data["total_nodes"] > 0
        assert data["total_edges"] > 0
        assert "Nginx" in data["technologies_detected"]

        # Test report endpoint
        report_res = client.get("/api/domain/report")
        assert report_res.status_code == 200
        report_data = report_res.json()
        assert report_data["recon"]["domain"] == "example.org"
        assert "debt_summary" in report_data

        # Test graph endpoint returns domain nodes
        graph_res = client.get("/api/graph?level=all")
        assert graph_res.status_code == 200
        graph_data = graph_res.json()
        assert len(graph_data["nodes"]) > 0
        assert len(graph_data["links"]) > 0
