import uuid
from typing import List, Dict, Tuple, Optional, Any

from app.parser.models import CodebaseGraph, GraphNode, DependencyEdge, ModuleParseResult, CodeLocation
from app.analysis.anti_patterns import AntiPatternReport
from app.analysis.metrics_engine import ArchitecturalDebtSummary, PackageMetric
from app.analysis.refactoring import RefactoringPlan
from app.analysis.ai_copilot import CodebaseAiSummary, AiActionItem
from app.domain_scanner.models import DomainReconResult, PortServiceInfo, TechDetection


class DomainTopologyMapper:
    """
    Translates raw domain reconnaissance data into a structured architectural
    graph (nodes and edges), detects architectural & security smells, computes
    resilience debt metrics, and generates AI remediation blueprints.
    """

    @classmethod
    def generate_topology(
        cls, recon: DomainReconResult
    ) -> Tuple[CodebaseGraph, List[AntiPatternReport], ArchitecturalDebtSummary, List[RefactoringPlan], CodebaseAiSummary]:
        """
        Main transformation entrypoint:
        DomainReconResult -> (CodebaseGraph, AntiPatterns, DebtSummary, RefactoringPlans, AiSummary)
        """
        domain = recon.domain
        nodes: List[GraphNode] = []
        edges: List[DependencyEdge] = []
        modules: Dict[str, ModuleParseResult] = {}
        node_ids: set[str] = set()

        def add_node(node: GraphNode, loc: int = 25, cc: int = 2, mi: float = 85.0):
            if node.id not in node_ids:
                node_ids.add(node.id)
                node.properties["loc"] = loc
                node.properties["cyclomatic_complexity"] = cc
                node.properties["maintainability_index"] = mi
                nodes.append(node)

                # Add a corresponding ModuleParseResult so metrics engines can compute stats
                modules[node.id] = ModuleParseResult(
                    id=node.id,
                    file_path=node.properties.get("file_path", node.id),
                    name=node.name,
                    language="architecture",
                    loc=loc,
                    sloc=loc,
                    cyclomatic_complexity=cc,
                    maintainability_index=mi,
                )

        def add_edge(src: str, tgt: str, rel_type: str, props: Optional[Dict[str, Any]] = None):
            if src in node_ids and tgt in node_ids:
                edges.append(
                    DependencyEdge(
                        source=src,
                        target=tgt,
                        type=rel_type,
                        properties=props or {},
                    )
                )

        # ---------------- 1. TIER 1: Edge, DNS & Infrastructure ----------------
        dns_node_id = f"dns:{domain}"
        add_node(
            GraphNode(
                id=dns_node_id,
                label="Infrastructure",
                name=f"DNS ({domain})",
                properties={
                    "tier": "Tier 1: Edge & DNS",
                    "category": "DNS Zone Authority",
                    "nameservers": recon.nameservers,
                    "records_count": len(recon.dns_records),
                    "file_path": f"dns://{domain}",
                },
            ),
            loc=20,
            cc=1,
            mi=95.0,
        )

        # 1a. Authoritative Nameservers (up to 4)
        for ns in recon.nameservers[:4]:
            ns_clean = ns.rstrip(".").lower()
            ns_id = f"ns:{ns_clean}"
            add_node(
                GraphNode(
                    id=ns_id,
                    label="Infrastructure",
                    name=f"NS: {ns_clean}",
                    properties={
                        "tier": "Tier 1: Edge & DNS",
                        "category": "Authoritative Nameserver",
                        "host": ns_clean,
                        "file_path": f"ns://{ns_clean}",
                    },
                ),
                loc=15,
                cc=1,
                mi=92.0,
            )
            add_edge(dns_node_id, ns_id, "DELEGATED_TO")

        # 1b. Mail Exchange (MX) Relay Servers
        mx_records = [
            r.value.rstrip(".").split()[-1].lower()
            for r in recon.dns_records
            if r.record_type == "MX"
        ]
        seen_mx = set()
        unique_mx = []
        for mx in mx_records:
            if mx not in seen_mx:
                seen_mx.add(mx)
                unique_mx.append(mx)

        for mx_host in unique_mx[:3]:
            mx_id = f"mx:{mx_host}"
            add_node(
                GraphNode(
                    id=mx_id,
                    label="Infrastructure",
                    name=f"Mail Relay ({mx_host})",
                    properties={
                        "tier": "Tier 1: Messaging & Mail",
                        "category": "Mail Exchange (MX)",
                        "host": mx_host,
                        "file_path": f"smtp://{mx_host}:25",
                    },
                ),
                loc=25,
                cc=2,
                mi=90.0,
            )
            add_edge(dns_node_id, mx_id, "MX_RELAY")

        # 1c. DNS Security Policies (SPF & DMARC)
        if recon.has_spf:
            spf_id = f"policy:spf:{domain}"
            add_node(
                GraphNode(
                    id=spf_id,
                    label="Infrastructure",
                    name="SPF Policy (v=spf1)",
                    properties={
                        "tier": "Tier 1: Security & Identity",
                        "category": "Email Security Policy",
                        "status": "Configured",
                        "file_path": f"txt://{domain}#spf",
                    },
                ),
                loc=10,
                cc=1,
                mi=95.0,
            )
            add_edge(dns_node_id, spf_id, "ENFORCES_POLICY")

        if recon.has_dmarc:
            dmarc_id = f"policy:dmarc:{domain}"
            add_node(
                GraphNode(
                    id=dmarc_id,
                    label="Infrastructure",
                    name="DMARC Policy (Anti-Spoofing)",
                    properties={
                        "tier": "Tier 1: Security & Identity",
                        "category": "Domain Authentication Policy",
                        "status": "Configured",
                        "file_path": f"txt://_dmarc.{domain}",
                    },
                ),
                loc=10,
                cc=1,
                mi=95.0,
            )
            add_edge(dns_node_id, dmarc_id, "ENFORCES_POLICY")

        # 1d. Anycast Edge POP IPs
        ip_nodes = []
        for ip in recon.ip_addresses[:4]:
            ip_clean = ip.strip()
            ip_id = f"ip:{ip_clean}"
            ip_nodes.append(ip_id)
            add_node(
                GraphNode(
                    id=ip_id,
                    label="Infrastructure",
                    name=f"Edge POP ({ip_clean})",
                    properties={
                        "tier": "Tier 1: Network & Routing",
                        "category": "Anycast Network IP",
                        "ip": ip_clean,
                        "file_path": f"ip://{ip_clean}",
                    },
                ),
                loc=20,
                cc=1,
                mi=90.0,
            )
            add_edge(dns_node_id, ip_id, "RESOLVES_IP")

        # CDN / Edge Provider Node
        cdn_techs = [t for t in recon.technologies if t.category == "Cloud / CDN"]
        edge_node_id = None
        if cdn_techs:
            cdn = cdn_techs[0]
            edge_node_id = f"edge:{cdn.name.lower().replace(' ', '_')}"
            add_node(
                GraphNode(
                    id=edge_node_id,
                    label="Edge",
                    name=cdn.name,
                    properties={
                        "tier": "Tier 1: Edge & CDN",
                        "category": "CDN / WAF",
                        "indicators": cdn.indicators,
                        "file_path": f"cdn://{cdn.name}",
                    },
                ),
                loc=40,
                cc=2,
                mi=90.0,
            )
            add_edge(dns_node_id, edge_node_id, "CACHED_BY")
            for ip_id in ip_nodes:
                add_edge(ip_id, edge_node_id, "ROUTES_TO")

        # SSL / TLS Node
        tls_node_id = f"tls:{domain}"
        tls_issuer = recon.tls_info.issuer.get("organizationName", "Verified TLS Authority") if recon.tls_info else "Self/Unknown"
        tls_proto = recon.tls_info.protocol_version if recon.tls_info else "TLS"
        add_node(
            GraphNode(
                id=tls_node_id,
                label="Edge",
                name=f"SSL/TLS ({tls_proto})",
                properties={
                    "tier": "Tier 1: Edge & Security",
                    "category": "Security / TLS",
                    "issuer": tls_issuer,
                    "valid_to": recon.tls_info.valid_to if recon.tls_info else "N/A",
                    "days_remaining": recon.tls_info.days_remaining if recon.tls_info else None,
                    "file_path": f"tls://{domain}:443",
                },
            ),
            loc=20,
            cc=1,
            mi=88.0,
        )
        if edge_node_id:
            add_edge(edge_node_id, tls_node_id, "SECURED_BY")
        else:
            add_edge(dns_node_id, tls_node_id, "SECURED_BY")

        # ---------------- 2. TIER 2: Gateway, Listeners & Ingress ----------------
        root_gateway_id = f"gateway:{domain}"
        web_server_techs = [t for t in recon.technologies if t.category == "Web Server"]
        server_name = web_server_techs[0].name if web_server_techs else "HTTP Gateway / Ingress"

        add_node(
            GraphNode(
                id=root_gateway_id,
                label="Gateway",
                name=f"Ingress ({server_name})",
                properties={
                    "tier": "Tier 2: Ingress & Gateway",
                    "category": "Reverse Proxy",
                    "server": server_name,
                    "ip_addresses": recon.ip_addresses,
                    "file_path": f"ingress://{domain}",
                },
            ),
            loc=50,
            cc=3,
            mi=85.0,
        )

        if edge_node_id:
            add_edge(edge_node_id, root_gateway_id, "ROUTES_TO")
        else:
            if ip_nodes:
                for ip_id in ip_nodes:
                    add_edge(ip_id, root_gateway_id, "ROUTES_TO")
            else:
                add_edge(dns_node_id, root_gateway_id, "ROUTES_TO")

        add_edge(tls_node_id, root_gateway_id, "TERMINATES_ON")

        # Protocol Listener Nodes
        listener_http_id = f"listener:http:{domain}"
        add_node(
            GraphNode(
                id=listener_http_id,
                label="Gateway",
                name="HTTP Listener (:80 Redirect)",
                properties={
                    "tier": "Tier 2: Ingress & Gateway",
                    "category": "Protocol Listener",
                    "port": 80,
                    "action": "301 Redirect to HTTPS",
                    "file_path": f"http://{domain}:80",
                },
            ),
            loc=25,
            cc=1,
            mi=92.0,
        )
        add_edge(root_gateway_id, listener_http_id, "LISTENS_ON")

        listener_https_id = f"listener:https:{domain}"
        add_node(
            GraphNode(
                id=listener_https_id,
                label="Gateway",
                name="HTTPS Listener (:443 TLS)",
                properties={
                    "tier": "Tier 2: Ingress & Gateway",
                    "category": "Protocol Listener",
                    "port": 443,
                    "tls": tls_proto,
                    "file_path": f"https://{domain}:443",
                },
            ),
            loc=35,
            cc=2,
            mi=90.0,
        )
        add_edge(root_gateway_id, listener_https_id, "LISTENS_ON")

        # ---------------- 2b. Modular Subdomain Services ----------------
        subdomain_category_map = {
            "accounts": ("Auth & SSO Gateway", "Identity Provider", "Tier 2: Identity & Access"),
            "auth": ("Auth & SSO Gateway", "Identity Provider", "Tier 2: Identity & Access"),
            "login": ("Auth & SSO Gateway", "Identity Provider", "Tier 2: Identity & Access"),
            "sso": ("Auth & SSO Gateway", "Identity Provider", "Tier 2: Identity & Access"),
            "mail": ("Webmail Service", "Messaging Service", "Tier 3: Application Layer"),
            "email": ("Webmail Service", "Messaging Service", "Tier 3: Application Layer"),
            "webmail": ("Webmail Service", "Messaging Service", "Tier 3: Application Layer"),
            "api": ("API Gateway", "REST / Microservice API", "Tier 2: Ingress & Gateway"),
            "rest": ("API Gateway", "REST / Microservice API", "Tier 2: Ingress & Gateway"),
            "graphql": ("GraphQL Gateway", "Microservice API", "Tier 2: Ingress & Gateway"),
            "docs": ("Documentation Portal", "Knowledge Base", "Tier 3: Application Layer"),
            "support": ("Support Desk", "Knowledge & Helpdesk", "Tier 3: Application Layer"),
            "help": ("Support Desk", "Knowledge & Helpdesk", "Tier 3: Application Layer"),
            "admin": ("Admin Portal", "Administrative Console", "Tier 3: Administrative Layer"),
            "portal": ("Customer Portal", "User Dashboard", "Tier 3: Application Layer"),
            "dashboard": ("Dashboard Console", "User Dashboard", "Tier 3: Application Layer"),
            "cdn": ("Asset CDN Cluster", "Static Content Delivery", "Tier 1: Content Delivery"),
            "static": ("Asset CDN Cluster", "Static Content Delivery", "Tier 1: Content Delivery"),
            "assets": ("Asset CDN Cluster", "Static Content Delivery", "Tier 1: Content Delivery"),
            "media": ("Media Distribution", "Static Content Delivery", "Tier 1: Content Delivery"),
            "drive": ("Cloud Drive Storage", "Object Storage Service", "Tier 4: Data & Storage"),
            "storage": ("Storage Service", "Object Storage Service", "Tier 4: Data & Storage"),
            "files": ("File Service", "Object Storage Service", "Tier 4: Data & Storage"),
            "cloud": ("Cloud Infrastructure", "Cloud Compute Console", "Tier 1: Cloud & Infra"),
            "news": ("News & Media Hub", "Content Publication", "Tier 3: Application Layer"),
            "blog": ("Blog Publication", "Content Publication", "Tier 3: Application Layer"),
            "shop": ("E-Commerce Storefront", "Digital Commerce", "Tier 3: Application Layer"),
            "store": ("E-Commerce Storefront", "Digital Commerce", "Tier 3: Application Layer"),
            "meet": ("WebRTC Collaboration", "Realtime Communications", "Tier 3: Application Layer"),
            "chat": ("Realtime Chat Service", "Realtime Communications", "Tier 3: Application Layer"),
            "status": ("System Status Hub", "Observability & Uptime", "Tier 1: Monitoring"),
        }

        for sub in recon.subdomains[:14]:
            sub_prefix = sub.subdomain.split(".")[0].lower()
            name_label, cat_label, tier_label = subdomain_category_map.get(
                sub_prefix,
                (f"Service ({sub_prefix})", "Subdomain Endpoint", "Tier 2: Ingress & Gateway")
            )
            sub_id = f"subdomain:{sub.subdomain}"
            add_node(
                GraphNode(
                    id=sub_id,
                    label="Gateway" if "Gateway" in tier_label or "Ingress" in tier_label else "Service",
                    name=f"{name_label} ({sub_prefix})",
                    properties={
                        "tier": tier_label,
                        "category": cat_label,
                        "fqdn": sub.subdomain,
                        "ips": sub.ip_addresses,
                        "status_code": sub.status_code,
                        "server": sub.server_header or "",
                        "file_path": f"https://{sub.subdomain}",
                    },
                ),
                loc=45,
                cc=2,
                mi=84.0,
            )
            add_edge(root_gateway_id, sub_id, "ROUTES_SUBDOMAIN")

        # ---------------- 3. TIER 3: Application Services & Technologies ----------------
        app_node_id = f"app:{domain}"
        fe_techs = [t for t in recon.technologies if t.category == "Frontend Framework"]
        be_techs = [t for t in recon.technologies if t.category == "Backend Runtime"]
        cms_techs = [t for t in recon.technologies if t.category == "CMS"]

        fe_name = fe_techs[0].name if fe_techs else "Web Client / SPA"
        add_node(
            GraphNode(
                id=app_node_id,
                label="Service",
                name=f"Frontend ({fe_name})",
                properties={
                    "tier": "Tier 3: Application Layer",
                    "category": "Frontend Application",
                    "framework": fe_name,
                    "file_path": f"app://{domain}/frontend",
                },
            ),
            loc=120,
            cc=5,
            mi=80.0,
        )
        add_edge(listener_https_id, app_node_id, "SERVES")

        # Individual Frontend Framework / Library nodes
        for fe in fe_techs:
            fe_slug = fe.name.lower().replace(" ", "_").replace(".", "_")
            fe_id = f"fe:{fe_slug}"
            add_node(
                GraphNode(
                    id=fe_id,
                    label="Service",
                    name=f"{fe.name} (UI Stack)",
                    properties={
                        "tier": "Tier 3: Application Layer",
                        "category": "Frontend Framework",
                        "version": fe.version or "Modern",
                        "indicators": fe.indicators,
                        "file_path": f"pkg://{fe.name}",
                    },
                ),
                loc=50,
                cc=2,
                mi=88.0,
            )
            add_edge(app_node_id, fe_id, "BUILT_WITH")

        # Web Server engine nodes (e.g. GWS, Nginx, Apache)
        for srv in web_server_techs:
            srv_slug = srv.name.lower().replace(" ", "_").replace(".", "_")
            srv_id = f"server:{srv_slug}"
            add_node(
                GraphNode(
                    id=srv_id,
                    label="Service",
                    name=f"{srv.name} (Server Engine)",
                    properties={
                        "tier": "Tier 2: Ingress & Gateway",
                        "category": "Web Server Engine",
                        "version": srv.version or "Active",
                        "file_path": f"server://{srv.name}",
                    },
                ),
                loc=60,
                cc=3,
                mi=85.0,
            )
            add_edge(root_gateway_id, srv_id, "POWERED_BY")

        # Backend runtime & CMS nodes
        backend_node_id = None
        for be in (be_techs + cms_techs):
            be_slug = be.name.lower().replace(" ", "_").replace(".", "_")
            be_node_id = f"backend:{be_slug}"
            if not backend_node_id:
                backend_node_id = be_node_id
            add_node(
                GraphNode(
                    id=be_node_id,
                    label="Service",
                    name=f"{be.name} ({be.category})",
                    properties={
                        "tier": "Tier 3: Application Layer",
                        "category": be.category,
                        "runtime": be.name,
                        "version": be.version or "",
                        "file_path": f"app://{domain}/backend/{be_slug}",
                    },
                ),
                loc=160,
                cc=7,
                mi=76.0,
            )
            add_edge(app_node_id, be_node_id, "DEPENDS_ON")
            add_edge(root_gateway_id, be_node_id, "ROUTES_TO")

        # ---------------- 4. TIER 4: Data & Storage Services ----------------
        db_ports = [p for p in recon.open_ports if p.category == "database"]
        for p in db_ports:
            db_id = f"db:{p.port}"
            add_node(
                GraphNode(
                    id=db_id,
                    label="Database",
                    name=f"{p.service_name} (:{p.port})",
                    properties={
                        "tier": "Tier 4: Data & Storage",
                        "category": "Database / Store",
                        "port": p.port,
                        "banner": p.banner,
                        "is_sensitive": p.is_sensitive,
                        "file_path": f"tcp://{domain}:{p.port}",
                    },
                ),
                loc=80,
                cc=12 if p.is_sensitive else 4,
                mi=40.0 if p.is_sensitive else 85.0,
            )
            target_source = backend_node_id or app_node_id
            add_edge(target_source, db_id, "STORES_IN")

        # ---------------- 5. TIER 5: Third-Party APIs, SaaS & Analytics ----------------
        third_parties = [t for t in recon.technologies if t.category in ("Third-Party API", "Security", "Analytics")]
        for tp in third_parties:
            tp_slug = tp.name.lower().replace(" ", "_").replace(".", "_")
            tp_id = f"saas:{tp_slug}"
            add_node(
                GraphNode(
                    id=tp_id,
                    label="ThirdParty",
                    name=tp.name,
                    properties={
                        "tier": "Tier 5: Third-Party & SaaS",
                        "category": tp.category,
                        "description": tp.description,
                        "file_path": f"api://{tp.name}",
                    },
                ),
                loc=25,
                cc=2,
                mi=90.0,
            )
            add_edge(app_node_id, tp_id, "INTEGRATES_WITH")

        # Construct CodebaseGraph
        graph = CodebaseGraph(
            repository_name=f"{domain} (Domain Topology)",
            root_path=recon.canonical_url,
            nodes=nodes,
            edges=edges,
            modules=modules,
        )

        # ---------------- 6. Anti-Patterns & Risk Detection ----------------
        antipatterns = cls._detect_domain_smells(recon, graph)

        # ---------------- 7. Debt Summary Calculation ----------------
        debt_summary = cls._compute_domain_debt(graph, antipatterns, recon)

        # ---------------- 8. Refactoring / Remediation Plans ----------------
        refactoring_plans = cls._generate_remediation_plans(antipatterns, recon)

        # ---------------- 9. AI Architectural Summary ----------------
        ai_summary = cls._generate_domain_ai_summary(recon, graph, antipatterns, debt_summary, refactoring_plans)

        return graph, antipatterns, debt_summary, refactoring_plans, ai_summary

    @classmethod
    def _detect_domain_smells(cls, recon: DomainReconResult, graph: CodebaseGraph) -> List[AntiPatternReport]:
        smells: List[AntiPatternReport] = []

        # 1. Exposed Sensitive Database / Cache Ports
        for p in recon.open_ports:
            if p.is_sensitive:
                smells.append(
                    AntiPatternReport(
                        id=f"smell-port-{p.port}",
                        type="EXPOSED_DATABASE_PORT",
                        severity="CRITICAL",
                        entity_type="Infrastructure",
                        entity_id=f"db:{p.port}",
                        entity_name=f"{p.service_name} (Port {p.port})",
                        description=(
                            f"Port {p.port} ({p.service_name}) is exposed to the public Internet. "
                            f"Databases and caches must never be directly accessible from untrusted external networks."
                        ),
                        metrics={"port": p.port, "service": p.service_name},
                        refactoring_suggestion=(
                            f"Restrict port {p.port} using firewall rules (UFW/AWS Security Group) "
                            f"to only allow trusted backend application private IPs or access via VPN/bastion."
                        ),
                    )
                )

        # 2. Missing Critical Security Headers
        missing_headers = [k for k, present in recon.security_headers.items() if not present]
        if missing_headers:
            severity = "HIGH" if ("strict-transport-security" in missing_headers or "content-security-policy" in missing_headers) else "MEDIUM"
            smells.append(
                AntiPatternReport(
                    id="smell-security-headers",
                    type="MISSING_SECURITY_HEADERS",
                    severity=severity,
                    entity_type="Gateway",
                    entity_id=f"gateway:{recon.domain}",
                    entity_name=f"HTTP Ingress ({recon.domain})",
                    description=(
                        f"Missing essential HTTP defense-in-depth headers: {', '.join(missing_headers)}. "
                        f"Leaving these unconfigured exposes users to Clickjacking, XSS, and protocol downgrade attacks."
                    ),
                    metrics={"missing_headers": missing_headers, "total_missing": len(missing_headers)},
                    refactoring_suggestion=(
                        "Add Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), "
                        "X-Frame-Options, and X-Content-Type-Options headers in your reverse proxy/ingress."
                    ),
                )
            )

        # 3. Insecure or Expiring TLS
        if recon.tls_info:
            tls = recon.tls_info
            if tls.is_expired:
                smells.append(
                    AntiPatternReport(
                        id="smell-tls-expired",
                        type="INSECURE_OR_EXPIRING_TLS",
                        severity="CRITICAL",
                        entity_type="Edge",
                        entity_id=f"tls:{recon.domain}",
                        entity_name=f"SSL/TLS ({recon.domain})",
                        description=f"TLS certificate for {recon.domain} has EXPIRED! Browsers will display security warnings to all visitors.",
                        metrics={"days_remaining": tls.days_remaining},
                        refactoring_suggestion="Immediately renew SSL/TLS certificate via Let's Encrypt / Certbot or your cloud provider.",
                    )
                )
            elif tls.is_expiring_soon:
                smells.append(
                    AntiPatternReport(
                        id="smell-tls-expiring",
                        type="INSECURE_OR_EXPIRING_TLS",
                        severity="HIGH",
                        entity_type="Edge",
                        entity_id=f"tls:{recon.domain}",
                        entity_name=f"SSL/TLS ({recon.domain})",
                        description=f"TLS certificate will expire in {tls.days_remaining} days. Service disruption imminent if not renewed.",
                        metrics={"days_remaining": tls.days_remaining},
                        refactoring_suggestion="Trigger automated ACME certificate renewal workflow.",
                    )
                )

        # 4. Email Spoofing Vulnerability (Missing SPF / DMARC)
        if not recon.has_spf or not recon.has_dmarc:
            missing_dns = []
            if not recon.has_spf:
                missing_dns.append("SPF")
            if not recon.has_dmarc:
                missing_dns.append("DMARC")
            smells.append(
                AntiPatternReport(
                    id="smell-email-spoofing",
                    type="EMAIL_SPOOFING_VULNERABILITY",
                    severity="HIGH",
                    entity_type="Infrastructure",
                    entity_id=f"dns:{recon.domain}",
                    entity_name=f"DNS ({recon.domain})",
                    description=(
                        f"Missing email security records: {', '.join(missing_dns)}. "
                        f"Adversaries can forge emails using @{recon.domain} to conduct phishing campaigns."
                    ),
                    metrics={"missing_dns": missing_dns},
                    refactoring_suggestion="Publish a valid SPF TXT record and DMARC TXT record (_dmarc.domain) with a strict reject policy.",
                )
            )

        # 5. Server Information Disclosure
        server_hdr = recon.http_headers.get("server") or recon.http_headers.get("Server") or ""
        powered_by = recon.http_headers.get("x-powered-by") or recon.http_headers.get("X-Powered-By") or ""
        if any(char.isdigit() for char in server_hdr) or powered_by:
            leaked = []
            if server_hdr:
                leaked.append(f"Server: {server_hdr}")
            if powered_by:
                leaked.append(f"X-Powered-By: {powered_by}")
            smells.append(
                AntiPatternReport(
                    id="smell-info-disclosure",
                    type="INFORMATION_DISCLOSURE",
                    severity="LOW",
                    entity_type="Gateway",
                    entity_id=f"gateway:{recon.domain}",
                    entity_name=f"Ingress ({recon.domain})",
                    description=(
                        f"Headers leak internal software version details ({', '.join(leaked)}). "
                        f"Assists attackers in targeting known CVE vulnerabilities."
                    ),
                    metrics={"leaked_headers": leaked},
                    refactoring_suggestion="Disable 'server_tokens' in Nginx or configure 'expose_php = Off' and strip X-Powered-By headers.",
                )
            )

        # 6. Single Point of Failure
        if len(recon.nameservers) <= 1:
            smells.append(
                AntiPatternReport(
                    id="smell-spof-dns",
                    type="SINGLE_POINT_OF_FAILURE",
                    severity="MEDIUM",
                    entity_type="Infrastructure",
                    entity_id=f"dns:{recon.domain}",
                    entity_name=f"DNS ({recon.domain})",
                    description=f"Domain relies on {len(recon.nameservers)} nameserver. If this nameserver fails, the entire domain goes offline.",
                    metrics={"nameserver_count": len(recon.nameservers)},
                    refactoring_suggestion="Configure at least two geographically redundant nameservers across separate network providers.",
                )
            )

        return smells

    @classmethod
    def _compute_domain_debt(
        cls, graph: CodebaseGraph, antipatterns: List[AntiPatternReport], recon: DomainReconResult
    ) -> ArchitecturalDebtSummary:
        total_nodes = len(graph.nodes)
        total_edges = len(graph.edges)

        # Base debt score computed from smell severities
        penalty = 0.0
        for s in antipatterns:
            if s.severity == "CRITICAL":
                penalty += 35.0
            elif s.severity == "HIGH":
                penalty += 18.0
            elif s.severity == "MEDIUM":
                penalty += 9.0
            else:
                penalty += 3.0

        # Missing security headers penalty
        missing_sec = sum(1 for v in recon.security_headers.values() if not v)
        penalty += missing_sec * 2.5

        debt_score = min(100.0, max(0.0, round(penalty, 1)))

        if debt_score <= 15:
            level = "Low"
        elif debt_score <= 45:
            level = "Moderate"
        elif debt_score <= 75:
            level = "High"
        else:
            level = "Critical"

        # Complexity & maintainability derived from graph topology
        avg_cc = round(sum(n.properties.get("cyclomatic_complexity", 1) for n in graph.nodes) / max(1, total_nodes), 1)
        avg_mi = round(max(20.0, 100.0 - debt_score * 0.7), 1)
        total_loc = sum(n.properties.get("loc", 10) for n in graph.nodes)

        critical_hotspots = [
            {
                "id": s.entity_id,
                "name": s.entity_name,
                "type": s.type,
                "severity": s.severity,
                "complexity": 10,
                "loc": 30,
                "reasons": [s.description],
            }
            for s in antipatterns
            if s.severity in ("CRITICAL", "HIGH")
        ]

        # Group into package metrics by tier
        tiers = set(n.properties.get("tier", n.label) for n in graph.nodes)
        package_metrics = [
            PackageMetric(
                package_id=f"tier::{t.lower().replace(' ', '_')}",
                package_name=t,
                module_count=sum(1 for n in graph.nodes if n.properties.get("tier", n.label) == t),
                afferent_coupling=1,
                efferent_coupling=1,
                instability=0.5,
                abstractness=0.2,
                distance_main_sequence=0.3,
            )
            for t in tiers
        ]

        return ArchitecturalDebtSummary(
            total_modules=total_nodes,
            total_loc=total_loc,
            average_complexity=avg_cc,
            average_maintainability_index=avg_mi,
            debt_score=debt_score,
            debt_level=level,
            critical_hotspots=critical_hotspots,
            package_metrics=package_metrics,
        )

    @classmethod
    def _generate_remediation_plans(
        cls, antipatterns: List[AntiPatternReport], recon: DomainReconResult
    ) -> List[RefactoringPlan]:
        plans: List[RefactoringPlan] = []

        for ap in antipatterns:
            if ap.type == "EXPOSED_DATABASE_PORT":
                port = ap.metrics.get("port", 3306)
                diff = (
                    f"--- /etc/ufw/rules (Before: Public access)\n"
                    f"+++ /etc/ufw/rules (After: Private internal subnet only)\n"
                    f"- ALLOW 0.0.0.0/0 on port {port}\n"
                    f"+ ALLOW 10.0.0.0/16 on port {port}\n"
                    f"+ DENY 0.0.0.0/0 on port {port}\n"
                )
                plans.append(
                    RefactoringPlan(
                        id=f"plan-port-{port}",
                        target_id=ap.entity_id,
                        target_name=ap.entity_name,
                        title=f"Isolate Database Port {port} from Public Internet",
                        pattern="Private Subnet Isolation / Firewall Perimeter",
                        steps=[
                            f"Audit current connections on port {port} using netstat/ss.",
                            f"Update cloud security group or local firewall (ufw deny {port}).",
                            f"Bind database listener only to private IP address (127.0.0.1 or VPC subnet).",
                        ],
                        code_diff_preview=diff,
                        debt_reduction_pct=35,
                    )
                )

            elif ap.type == "MISSING_SECURITY_HEADERS":
                diff = (
                    f"--- /etc/nginx/conf.d/security.conf (Before)\n"
                    f"+++ /etc/nginx/conf.d/security.conf (After)\n"
                    f"+ add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
                    f"+ add_header X-Frame-Options \"DENY\" always;\n"
                    f"+ add_header X-Content-Type-Options \"nosniff\" always;\n"
                    f"+ add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
                    f"+ add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline';\" always;\n"
                )
                plans.append(
                    RefactoringPlan(
                        id="plan-security-headers",
                        target_id=ap.entity_id,
                        target_name=ap.entity_name,
                        title="Harden Reverse Proxy with Modern Security Headers",
                        pattern="HTTP Defense-in-Depth Hardening",
                        steps=[
                            "Add Strict-Transport-Security to enforce HTTPS encryption.",
                            "Set X-Frame-Options: DENY to prevent clickjacking in iframes.",
                            "Configure X-Content-Type-Options: nosniff to stop MIME type sniffing.",
                            "Deploy Content-Security-Policy to restrict unauthorized script execution.",
                        ],
                        code_diff_preview=diff,
                        debt_reduction_pct=25,
                    )
                )

            elif ap.type == "EMAIL_SPOOFING_VULNERABILITY":
                diff = (
                    f"--- DNS Zone file for {recon.domain}\n"
                    f"+++ DNS Zone file for {recon.domain}\n"
                    f"+ {recon.domain}.    IN  TXT  \"v=spf1 mx ~all\"\n"
                    f"+ _dmarc.{recon.domain}. IN  TXT  \"v=DMARC1; p=reject; rua=mailto:dmarc@{recon.domain}\"\n"
                )
                plans.append(
                    RefactoringPlan(
                        id="plan-email-spoofing",
                        target_id=ap.entity_id,
                        target_name=ap.entity_name,
                        title="Configure SPF & DMARC DNS Records",
                        pattern="Domain Email Authentication & Anti-Spoofing",
                        steps=[
                            f"Create a TXT record for {recon.domain} with authorized mail servers (SPF).",
                            f"Create a TXT record for _dmarc.{recon.domain} with a reject policy.",
                            "Verify alignment via standard DMARC lookup validators.",
                        ],
                        code_diff_preview=diff,
                        debt_reduction_pct=18,
                    )
                )

            elif ap.type == "INFORMATION_DISCLOSURE":
                diff = (
                    f"--- /etc/nginx/nginx.conf\n"
                    f"+++ /etc/nginx/nginx.conf\n"
                    f" http {{\n"
                    f"-    # server_tokens on;\n"
                    f"+    server_tokens off;\n"
                    f"+    more_clear_headers Server;\n"
                    f"+    more_clear_headers 'X-Powered-By';\n"
                    f" }}\n"
                )
                plans.append(
                    RefactoringPlan(
                        id="plan-info-disclosure",
                        target_id=ap.entity_id,
                        target_name=ap.entity_name,
                        title="Suppress Server & Runtime Fingerprinting Headers",
                        pattern="Information Disclosure Minimization",
                        steps=[
                            "Disable server_tokens directive in web server configuration.",
                            "Strip or mask X-Powered-By and Server response headers.",
                        ],
                        code_diff_preview=diff,
                        debt_reduction_pct=8,
                    )
                )

        return plans

    @classmethod
    def _generate_domain_ai_summary(
        cls,
        recon: DomainReconResult,
        graph: CodebaseGraph,
        antipatterns: List[AntiPatternReport],
        debt_summary: ArchitecturalDebtSummary,
        plans: List[RefactoringPlan],
    ) -> CodebaseAiSummary:
        debt_score = debt_summary.debt_score
        grade, color = cls._debt_to_grade(debt_score)

        if debt_score <= 15:
            headline = f"Excellent Architecture: {recon.domain} is resilient, well-isolated, and secure."
        elif debt_score <= 45:
            headline = f"Solid Foundation: {recon.domain} has minor infrastructure hardening recommendations."
        elif debt_score <= 75:
            headline = f"Attention Required: {len(antipatterns)} architectural/security vulnerabilities detected on {recon.domain}."
        else:
            headline = f"Critical Risk: Severe infrastructure exposure and misconfigurations detected on {recon.domain}."

        tech_names = [t.name for t in recon.technologies]
        tech_summary_str = ", ".join(tech_names[:6]) if tech_names else "Standard HTTP Web Server"

        simple_breakdown = (
            f"ArchInsights mapped **{len(graph.nodes)} architectural components** and **{len(graph.edges)} dependency relationships** for **{recon.domain}**. "
            f"The environment utilizes **{tech_summary_str}**, serving traffic across {len(recon.subdomains)} active subdomains. "
            f"Overall architectural debt is rated at **{debt_score}/100 ({debt_summary.debt_level})**, earning a health grade of **{grade}**."
        )

        strengths = []
        if recon.tls_info and not recon.tls_info.is_expired and not recon.tls_info.is_expiring_soon:
            strengths.append(f"Modern TLS Encryption ({recon.tls_info.protocol_version}) active with {recon.tls_info.days_remaining} days remaining.")
        if any(t.category == "Cloud / CDN" for t in recon.technologies):
            cdn = next(t.name for t in recon.technologies if t.category == "Cloud / CDN")
            strengths.append(f"Protected by {cdn} edge network for DDoS mitigation and global caching.")
        if recon.has_spf and recon.has_dmarc:
            strengths.append("SPF and DMARC anti-spoofing policies correctly configured on DNS.")
        if len(recon.subdomains) > 0:
            strengths.append(f"Discovered {len(recon.subdomains)} operational subdomains providing modular service routing.")
        if not strengths:
            strengths.append("Core HTTP service operational and responding to traffic.")

        risks = []
        for s in antipatterns[:4]:
            risks.append(f"[{s.severity}] {s.type}: {s.description}")
        if not risks:
            risks.append("No critical architectural anti-patterns or exposed sensitive services detected.")

        action_items: List[AiActionItem] = []
        for idx, p in enumerate(plans):
            matching_smell = next((s for s in antipatterns if s.entity_id == p.target_id), None)
            severity = matching_smell.severity if matching_smell else "MEDIUM"
            action_items.append(
                AiActionItem(
                    id=f"action-{idx + 1}",
                    title=p.title,
                    target_id=p.target_id,
                    target_name=p.target_name,
                    severity=severity,
                    difficulty="Easy (15 mins)" if severity in ("LOW", "MEDIUM") else "High Priority (30 mins)",
                    debt_reduction_pct=p.debt_reduction_pct,
                    plain_english_summary=matching_smell.description if matching_smell else p.title,
                    analogy="Locked Front Door vs Open Back Gate" if "PORT" in (matching_smell.type if matching_smell else "") else "Passport Validation Protocol",
                    why_it_matters=matching_smell.refactoring_suggestion if matching_smell else "Hardens security posture.",
                    action_steps=p.steps,
                    suggested_pattern=p.pattern,
                )
            )

        return CodebaseAiSummary(
            repository_name=f"{recon.domain} (External Domain)",
            health_grade=grade,
            grade_color=color,
            headline=headline,
            executive_summary=f"Automated architectural scan of {recon.canonical_url} completed with {len(antipatterns)} findings.",
            simple_breakdown=simple_breakdown,
            key_strengths=strengths,
            critical_risks=risks,
            prioritized_actions=action_items,
        )

    @staticmethod
    def _debt_to_grade(score: float) -> Tuple[str, str]:
        if score <= 15:
            return "A+", "emerald"
        if score <= 25:
            return "A", "emerald"
        if score <= 45:
            return "B", "blue"
        if score <= 65:
            return "C", "amber"
        if score <= 80:
            return "D", "crimson"
        return "F", "crimson"
