#!/usr/bin/env python3
"""
Antigravity Agent: Domain Architecture Reconnaissance & Topology Mapper
Orchestrates autonomous tools to inspect, diagnose, and blueprint any external domain architecture.
"""

import sys
import os
import asyncio
import json
from typing import Optional, Dict, Any

# Ensure backend and root modules can be imported
sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath("backend"))

from app.domain_scanner.recon_orchestrator import DomainReconOrchestrator
from app.domain_scanner.topology_mapper import DomainTopologyMapper
from run_domain_scan import generate_standalone_html, format_terminal_report

# Cached session state for multi-turn agent execution
AGENT_STATE: Dict[str, Any] = {
    "last_recon": None,
    "last_graph": None,
    "last_antipatterns": [],
    "last_debt": None,
    "last_plans": [],
    "last_ai_summary": None,
}


# ===================== Agent Tool Definitions =====================

async def recon_domain(domain: str) -> str:
    """Performs deep non-intrusive domain reconnaissance, DNS resolution,
    subdomain discovery, TLS certificate inspection, port scanning,
    and technology stack fingerprinting.

    Args:
        domain: Target domain or URL (e.g. "example.com" or "https://github.com").
    """
    orchestrator = DomainReconOrchestrator()
    recon = await orchestrator.scan_domain(domain)
    graph, antipatterns, debt, plans, ai_summary = DomainTopologyMapper.generate_topology(recon)

    AGENT_STATE["last_recon"] = recon
    AGENT_STATE["last_graph"] = graph
    AGENT_STATE["last_antipatterns"] = antipatterns
    AGENT_STATE["last_debt"] = debt
    AGENT_STATE["last_plans"] = plans
    AGENT_STATE["last_ai_summary"] = ai_summary

    tech_names = [t.name for t in recon.technologies]
    return (
        f"Reconnaissance completed for {recon.domain}:\n"
        f"- Canonical URL: {recon.canonical_url}\n"
        f"- IP Addresses: {', '.join(recon.ip_addresses) if recon.ip_addresses else 'None'}\n"
        f"- Subdomains found: {len(recon.subdomains)}\n"
        f"- Technologies detected: {', '.join(tech_names) if tech_names else 'Generic HTTP'}\n"
        f"- Open ports: {[p.port for p in recon.open_ports]}\n"
        f"- TLS protocol: {recon.tls_info.protocol_version if recon.tls_info else 'N/A'}\n"
        f"- SPF record: {'Configured' if recon.has_spf else 'Missing'}\n"
        f"- DMARC record: {'Configured' if recon.has_dmarc else 'Missing'}"
    )


def map_architecture(domain: str) -> str:
    """Translates discovered services and infrastructure into an architectural
    topology graph of tiers, nodes, and dependency edges.

    Args:
        domain: Target domain previously scanned.
    """
    graph = AGENT_STATE.get("last_graph")
    if not graph:
        return "Please call recon_domain first."

    lines = [f"Architectural Topology for {graph.repository_name}:"]
    lines.append(f"Total Nodes: {len(graph.nodes)} | Total Dependency Edges: {len(graph.edges)}\n")

    lines.append("Nodes by Architectural Tier:")
    for n in graph.nodes:
        tier = n.properties.get("tier", n.label)
        category = n.properties.get("category", "")
        lines.append(f"  [{n.label:14s}] {n.name:30s} (Tier: {tier}, Cat: {category})")

    lines.append("\nKey Architectural Relationships:")
    for e in graph.edges[:12]:
        lines.append(f"  {e.source} --({e.type})--> {e.target}")

    return "\n".join(lines)


def audit_security_and_smells(domain: str) -> str:
    """Audits detected architectural anti-patterns, exposed sensitive ports,
    and missing defense-in-depth headers.

    Args:
        domain: Target domain previously scanned.
    """
    antipatterns = AGENT_STATE.get("last_antipatterns", [])
    debt = AGENT_STATE.get("last_debt")
    ai_summary = AGENT_STATE.get("last_ai_summary")

    if not debt:
        return "Please call recon_domain first."

    lines = [
        f"Architectural Health Audit for {domain}:",
        f"- Health Grade : {ai_summary.health_grade}",
        f"- Debt Score   : {debt.debt_score}/100 ({debt.debt_level})",
        f"- Smells Count : {len(antipatterns)} anti-patterns detected\n",
    ]

    for ap in antipatterns:
        lines.append(f"[{ap.severity}] {ap.type}: {ap.entity_name}")
        lines.append(f"  Detail : {ap.description}")
        lines.append(f"  Fix    : {ap.refactoring_suggestion}\n")

    return "\n".join(lines)


def generate_remediation_blueprint(domain: str) -> str:
    """Generates a prioritized step-by-step refactoring action plan with code diff previews.

    Args:
        domain: Target domain previously scanned.
    """
    plans = AGENT_STATE.get("last_plans", [])
    if not plans:
        return "No remediation plans available or domain has zero debt."

    lines = [f"Remediation Blueprint for {domain}:"]
    for i, plan in enumerate(plans, 1):
        lines.append(f"\n{i}. {plan.title} (Est. Debt Reduction: -{plan.debt_reduction_pct}%)")
        lines.append(f"   Pattern: {plan.pattern}")
        lines.append("   Action Steps:")
        for step in plan.steps:
            lines.append(f"     - {step}")
        if plan.code_diff_preview:
            lines.append(f"   Configuration Blueprint:\n{plan.code_diff_preview}")

    return "\n".join(lines)


def export_architecture_report(domain: str, output_path: str = "domain_report.json", html_path: str = "domain_arch.html") -> str:
    """Exports structured JSON analysis and generates a self-contained interactive
    D3.js visualization HTML file.

    Args:
        domain: Target domain previously scanned.
        output_path: File path to save JSON report.
        html_path: File path to save interactive HTML diagram.
    """
    recon = AGENT_STATE.get("last_recon")
    graph = AGENT_STATE.get("last_graph")
    debt = AGENT_STATE.get("last_debt")
    antipatterns = AGENT_STATE.get("last_antipatterns", [])
    plans = AGENT_STATE.get("last_plans", [])
    ai_summary = AGENT_STATE.get("last_ai_summary")

    if not recon or not graph:
        return "Please call recon_domain first."

    # Export JSON
    data = {
        "domain": recon.domain,
        "canonical_url": recon.canonical_url,
        "debt_summary": debt.model_dump(),
        "ai_summary": ai_summary.model_dump(),
        "antipatterns": [ap.model_dump() for ap in antipatterns],
        "refactoring_plans": [rp.model_dump() for rp in plans],
        "technologies": [t.model_dump() for t in recon.technologies],
        "subdomains": [s.model_dump() for s in recon.subdomains],
        "open_ports": [p.model_dump() for p in recon.open_ports],
        "graph": {
            "nodes": [n.model_dump() for n in graph.nodes],
            "edges": [e.model_dump() for e in graph.edges],
        },
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    # Export interactive HTML
    html_content = generate_standalone_html(recon, graph, antipatterns, debt, plans, ai_summary)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return f"Exported successfully:\n- JSON Report: {output_path}\n- Interactive HTML Topology: {html_path}"


# ===================== Agent Execution Runner =====================

async def run_antigravity_agent(domain: str):
    """
    Executes the Antigravity Agent flow.
    Attempts to initialize Google Antigravity SDK (`google.antigravity`),
    falling back seamlessly to direct autonomous tool execution.
    """
    print(f"\n==================================================================")
    print(f"  Antigravity Agent: Initializing Domain Architecture Pipeline")
    print(f"  Target Domain: {domain}")
    print(f"==================================================================\n")

    has_sdk = False
    try:
        from google.antigravity import Agent, LocalAgentConfig
        has_sdk = True
    except ImportError:
        has_sdk = False

    if has_sdk:
        print("[*] Running with Google Antigravity SDK agent runtime...")
        tools = [
            recon_domain,
            map_architecture,
            audit_security_and_smells,
            generate_remediation_blueprint,
            export_architecture_report,
        ]
        config = LocalAgentConfig(
            tools=tools,
            system_instructions=(
                "You are an expert autonomous software architect and security engineer. "
                "Your objective is to scan, analyze, and visualize the architecture of target domains. "
                "Use recon_domain first to gather intelligence, then map the topology, audit smells, "
                "and generate a refactoring blueprint."
            ),
        )
        async with Agent(config) as agent:
            prompt = (
                f"Please perform a complete architectural reconnaissance and security audit of '{domain}'. "
                f"Identify the technology stack, map the infrastructure topology, detect code smells or risks, "
                f"and export both a JSON report and interactive HTML diagram."
            )
            response = await agent.chat(prompt)
            async for chunk in response:
                print(chunk, end="", flush=True)
            print("\n")
    else:
        print("[*] Running autonomous multi-phase reconnaissance pipeline...")
        # Step 1: Reconnaissance
        print("\n--- Phase 1: Network & Fingerprint Reconnaissance ---")
        recon_output = await recon_domain(domain)
        print(recon_output)

        # Step 2: Architecture Mapping
        print("\n--- Phase 2: Topology Generation ---")
        topo_output = map_architecture(domain)
        print(topo_output)

        # Step 3: Security & Anti-Pattern Audit
        print("\n--- Phase 3: Architectural Smells Audit ---")
        audit_output = audit_security_and_smells(domain)
        print(audit_output)

        # Step 4: Remediation Action Blueprint
        print("\n--- Phase 4: Remediation Action Blueprint ---")
        blueprint_output = generate_remediation_blueprint(domain)
        print(blueprint_output)

        # Step 5: Exporting Reports & Interactive Diagram
        json_file = f"{domain.replace('.', '_')}_report.json"
        html_file = f"{domain.replace('.', '_')}_arch.html"
        print(f"\n--- Phase 5: Artifact Generation ---")
        export_output = export_architecture_report(domain, json_file, html_file)
        print(export_output)

    print("\n[OK] Antigravity Agent workflow completed successfully.")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    asyncio.run(run_antigravity_agent(target))
