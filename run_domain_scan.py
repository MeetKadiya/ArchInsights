#!/usr/bin/env python3
"""
ArchInsights Domain Architecture Scanner & Topology Visualizer CLI
Scan, analyze, and visualize the architecture of external domains and websites.
"""

import sys
import os
import argparse
import asyncio
import json
from typing import Optional

# Ensure backend modules can be imported
sys.path.insert(0, os.path.abspath("backend"))

from app.domain_scanner.recon_orchestrator import DomainReconOrchestrator
from app.domain_scanner.topology_mapper import DomainTopologyMapper


def format_terminal_report(recon, graph, antipatterns, debt, plans, ai_summary) -> str:
    lines = []
    separator = "=" * 70
    subsep = "-" * 70

    lines.append("\n" + separator)
    lines.append(f"  ArchInsights — Domain Architecture & Topology Report")
    lines.append(f"  Target: {recon.domain} ({recon.canonical_url})")
    lines.append(separator)

    # 1. Executive Summary & Health Grade
    lines.append(f"\n[+] ARCHITECTURAL HEALTH ASSESSMENT")
    lines.append(f"    Health Grade    : {ai_summary.health_grade}")
    lines.append(f"    Debt Score      : {debt.debt_score}/100 ({debt.debt_level})")
    lines.append(f"    Headline        : {ai_summary.headline}")
    lines.append(f"    Avg CC / MI     : CC {debt.average_complexity} | MI {debt.average_maintainability_index}/100")

    # 2. Network & DNS
    lines.append(f"\n[+] DNS & NETWORK PERIMETER")
    lines.append(f"    IP Addresses    : {', '.join(recon.ip_addresses) if recon.ip_addresses else 'None resolved'}")
    lines.append(f"    Nameservers     : {', '.join(recon.nameservers) if recon.nameservers else 'N/A'}")
    lines.append(f"    DNS Records     : {len(recon.dns_records)} records resolved")
    lines.append(f"    SPF Configured  : {'YES (Safe)' if recon.has_spf else 'NO (Vulnerable to spoofing)'}")
    lines.append(f"    DMARC Policy    : {'YES (Safe)' if recon.has_dmarc else 'NO (Vulnerable to spoofing)'}")

    # 3. SSL / TLS
    lines.append(f"\n[+] SSL / TLS SECURITY POSTURE")
    if recon.tls_info:
        tls = recon.tls_info
        issuer = tls.issuer.get('organizationName', tls.issuer.get('commonName', 'Unknown'))
        lines.append(f"    Protocol        : {tls.protocol_version or 'TLS'}")
        lines.append(f"    Cipher Suite    : {tls.cipher_suite or 'Default'}")
        lines.append(f"    Issuer          : {issuer}")
        lines.append(f"    Days Remaining  : {tls.days_remaining} days (Expires: {tls.valid_to})")
        lines.append(f"    Status          : {'EXPIRED' if tls.is_expired else ('EXPIRING SOON' if tls.is_expiring_soon else 'Valid & Trusted')}")
    else:
        lines.append(f"    Status          : Port 443 TLS handshake not available")

    # 4. Open Ports & Services
    lines.append(f"\n[+] OPEN PORTS & SERVICES")
    if recon.open_ports:
        for p in recon.open_ports:
            flag = " [!] SENSITIVE / EXPOSED" if p.is_sensitive else ""
            lines.append(f"    - Port {p.port:5d} / {p.protocol.upper()} : {p.service_name} ({p.category}){flag}")
    else:
        lines.append("    No standard high-risk or external ports open to public scan.")

    # 5. Technology Stack Fingerprint
    lines.append(f"\n[+] TECHNOLOGY STACK DETECTION")
    if recon.technologies:
        for t in recon.technologies:
            ver = f" v{t.version}" if t.version else ""
            lines.append(f"    - [{t.category:18s}] {t.name}{ver} (Confidence: {int(t.confidence * 100)}%)")
    else:
        lines.append("    Generic / customized HTTP web service (signatures masked).")

    # 6. Discovered Subdomains
    lines.append(f"\n[+] ACTIVE SUBDOMAINS ({len(recon.subdomains)} discovered)")
    for sub in recon.subdomains[:8]:
        ips = f"({', '.join(sub.ip_addresses)})" if sub.ip_addresses else ""
        lines.append(f"    - {sub.subdomain:30s} {ips}")

    # 7. Architectural Smells & Vulnerabilities
    lines.append(f"\n[+] ARCHITECTURAL & SECURITY SMELLS ({len(antipatterns)} detected)")
    if antipatterns:
        for ap in antipatterns:
            lines.append(f"    - [{ap.severity:8s}] {ap.type}: {ap.entity_name}")
            lines.append(f"      Description : {ap.description}")
            lines.append(f"      Remediation : {ap.refactoring_suggestion}")
    else:
        lines.append("    None detected. Perimeter and architecture follow best security practices.")

    # 8. Prioritized Remediation Action Plan
    lines.append(f"\n[+] ACTIONABLE REFACTORING BLUEPRINT ({len(plans)} plans)")
    for i, plan in enumerate(plans, 1):
        lines.append(f"    {i}. {plan.title} [-{plan.debt_reduction_pct}% Debt]")
        lines.append(f"       Pattern: {plan.pattern}")
        for step in plan.steps:
            lines.append(f"       > {step}")

    lines.append("\n" + separator + "\n")
    return "\n".join(lines)


def generate_standalone_html(recon, graph, antipatterns, debt, plans, ai_summary) -> str:
    """Generates a self-contained interactive D3.js architecture graph HTML file."""
    graph_dict = {
        "nodes": [
            {
                "id": n.id,
                "label": n.label,
                "name": n.name,
                "loc": n.properties.get("loc", 20),
                "complexity": n.properties.get("cyclomatic_complexity", 2),
                "maintainability": n.properties.get("maintainability_index", 85.0),
                "tier": n.properties.get("tier", ""),
                "category": n.properties.get("category", ""),
            }
            for n in graph.nodes
        ],
        "links": [
            {
                "source": e.source,
                "target": e.target,
                "type": e.type,
            }
            for e in graph.edges
        ],
    }

    graph_json = json.dumps(graph_dict)
    summary_json = json.dumps({
        "domain": recon.domain,
        "grade": ai_summary.health_grade,
        "debt_score": debt.debt_score,
        "headline": ai_summary.headline,
        "smells": len(antipatterns),
    })

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ArchInsights — {recon.domain} Topology</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=Fira+Code&display=swap" rel="stylesheet">
    <style>
        body {{ margin:0; background:#070a0e; color:#f0fdf4; font-family:'Inter',sans-serif; overflow:hidden; }}
        header {{ position:absolute; top:1rem; left:1rem; z-index:10; background:rgba(12,18,24,0.88); backdrop-filter:blur(12px); padding:1rem 1.4rem; border-radius:12px; border:1px solid rgba(16,185,129,0.3); box-shadow:0 8px 30px rgba(0,0,0,0.5); }}
        h1 {{ margin:0 0 0.3rem 0; font-size:1.25rem; color:#00f5a0; }}
        .badge {{ display:inline-block; padding:0.2rem 0.6rem; border-radius:6px; font-weight:700; font-size:0.8rem; background:#10b981; color:#070a0e; }}
        svg {{ width:100vw; height:100vh; }}
        .link {{ stroke:rgba(148,163,184,0.25); stroke-width:1.5px; fill:none; }}
        .node circle {{ stroke:#10b981; stroke-width:1.5px; cursor:pointer; transition:all 0.2s; }}
        .node circle:hover {{ stroke-width:3px; filter:drop-shadow(0 0 10px #00f5a0); }}
        .node text {{ font-size:11px; fill:#cbd5e1; font-family:'Inter',sans-serif; pointer-events:none; }}
        .tooltip {{ position:absolute; display:none; background:rgba(12,18,24,0.96); border:1px solid rgba(16,185,129,0.35); border-radius:8px; padding:0.6rem 0.9rem; font-size:0.8rem; pointer-events:none; box-shadow:0 10px 25px rgba(0,0,0,0.6); }}
    </style>
</head>
<body>
    <header>
        <h1>{recon.domain}</h1>
        <div>Health Grade: <span class="badge">{ai_summary.health_grade}</span> | Debt Score: <strong>{debt.debt_score}/100</strong></div>
        <div style="font-size:0.8rem;color:#94a3b8;margin-top:0.3rem;">{len(graph.nodes)} Nodes · {len(graph.edges)} Connections · {len(antipatterns)} Smells</div>
    </header>
    <svg id="svg"></svg>
    <div class="tooltip" id="tooltip"></div>
    <script>
        const data = {graph_json};
        const width = window.innerWidth, height = window.innerHeight;
        const svg = d3.select("#svg");
        const g = svg.append("g");
        svg.call(d3.zoom().scaleExtent([0.2, 4]).on("zoom", (e) => g.attr("transform", e.transform)));

        const colorMap = {{
            Edge: '#00f5a0', Gateway: '#10b981', Service: '#38bdf8',
            Infrastructure: '#059669', Database: '#f59e0b', ThirdParty: '#a855f7'
        }};

        const simulation = d3.forceSimulation(data.nodes)
            .force("link", d3.forceLink(data.links).id(d => d.id).distance(110))
            .force("charge", d3.forceManyBody().strength(-350))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collide", d3.forceCollide(25));

        const link = g.append("g").selectAll("line").data(data.links).enter().append("line").attr("class", "link");
        const node = g.append("g").selectAll("g").data(data.nodes).enter().append("g").attr("class", "node")
            .call(d3.drag()
                .on("start", (e, d) => {{ if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }})
                .on("drag", (e, d) => {{ d.fx = e.x; d.fy = e.y; }})
                .on("end", (e, d) => {{ if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }}));

        node.append("circle").attr("r", 14).attr("fill", d => colorMap[d.label] || '#38bdf8');
        node.append("text").attr("dx", 18).attr("dy", 4).text(d => d.name);

        const tooltip = d3.select("#tooltip");
        node.on("mouseenter", (e, d) => {{
            tooltip.style("display", "block").html(`<strong>${{d.name}}</strong><br>Type: ${{d.label}}<br>Tier: ${{d.tier || 'N/A'}}<br>Category: ${{d.category || 'N/A'}}`);
        }}).on("mousemove", (e) => {{
            tooltip.style("left", (e.pageX + 15) + "px").style("top", (e.pageY + 15) + "px");
        }}).on("mouseleave", () => tooltip.style("display", "none"));

        simulation.on("tick", () => {{
            link.attr("x1", d => d.source.x).attr("y1", d => d.source.y).attr("x2", d => d.target.x).attr("y2", d => d.target.y);
            node.attr("transform", d => `translate(${{d.x}},${{d.y}})`);
        }});
    </script>
</body>
</html>"""


async def main():
    parser = argparse.ArgumentParser(description="ArchInsights External Domain Architecture Scanner & Topology Generator")
    parser.add_argument("domain", help="Target domain or URL (e.g. example.com or https://github.com)")
    parser.add_argument("--output", "-o", help="Path to write full JSON report")
    parser.add_argument("--html", help="Path to generate standalone interactive D3.js visualization HTML file")
    args = parser.parse_args()

    print(f"[*] Starting ArchInsights domain reconnaissance on: {args.domain}")
    print("[*] Probing DNS, subdomains, SSL/TLS, port listeners, and tech stack signatures...")

    orchestrator = DomainReconOrchestrator()
    recon = await orchestrator.scan_domain(args.domain)

    print("[*] Mapping architectural topology, evaluating smells, and computing resilience score...")
    graph, antipatterns, debt, plans, ai_summary = DomainTopologyMapper.generate_topology(recon)

    # Print terminal report
    report_text = format_terminal_report(recon, graph, antipatterns, debt, plans, ai_summary)
    print(report_text)

    # Export JSON if requested
    if args.output:
        data = {
            "recon": recon.model_dump(),
            "debt_summary": debt.model_dump(),
            "antipatterns": [ap.model_dump() for ap in antipatterns],
            "refactoring_plans": [rp.model_dump() for rp in plans],
            "ai_summary": ai_summary.model_dump(),
            "graph": {
                "nodes": [n.model_dump() for n in graph.nodes],
                "edges": [e.model_dump() for e in graph.edges],
            },
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[OK] Full JSON report exported to: {args.output}")

    # Generate standalone interactive HTML if requested
    if args.html:
        html_content = generate_standalone_html(recon, graph, antipatterns, debt, plans, ai_summary)
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[OK] Standalone interactive HTML visualizer exported to: {args.html}")


if __name__ == "__main__":
    asyncio.run(main())
