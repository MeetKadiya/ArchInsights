---
name: domain-architecture-scanner
description: "Scan, analyze, and visualize the architecture, infrastructure topology, and technology stack of external domains and websites. Detects DNS configurations, subdomains, SSL/TLS certificates, open ports/services, frontend/backend/cloud frameworks, and architectural smells."
---

# Domain Architecture Reconnaissance & Topology Scanner

This skill extends ArchInsights to scan external domains and web applications, mapping their real-world infrastructure into an interactive architectural topology force-graph comparable to codebase AST dependency visualizers.

## When to Use This Skill

Activate this skill when:
- The user requests an architectural scan or analysis of an external website or domain (e.g. `example.com`, `stripe.com`, `github.com`).
- The user asks to discover subdomains, DNS records, open ports, or SSL certificate health for a domain.
- The user asks what tech stack or cloud provider an external domain is using.
- The user wants an architectural topology diagram (nodes, edges, tiers) or infrastructure debt report for a web domain.
- The user requests recommendations or refactoring blueprints to harden domain infrastructure.

## Available Workflows & Commands

### 1. Interactive CLI Scan

Run the standalone CLI runner from the project root:

```bash
python run_domain_scan.py <domain> [--output report.json] [--html architecture.html]
```

**Examples**:
```bash
# Quick terminal scan
python run_domain_scan.py example.com

# Full scan with JSON report and interactive D3.js HTML visualization
python run_domain_scan.py example.com --output example_report.json --html example_arch.html
```

### 2. Autonomous Antigravity Agent Workflow

Run the autonomous agent pipeline directly:

```bash
python agent/domain_agent.py <domain>
```

This invokes the autonomous agent tools:
1. `recon_domain(domain)`: Scans DNS (SPF/DMARC), subdomains, TLS certificates, ports, and tech stack signatures.
2. `map_architecture(domain)`: Assembles multi-tier topology graph (`Edge`, `Gateway`, `Service`, `Infrastructure`, `Database`, `ThirdParty`).
3. `audit_security_and_smells(domain)`: Identifies architectural anti-patterns (`EXPOSED_DATABASE_PORT`, `MISSING_SECURITY_HEADERS`, `INSECURE_OR_EXPIRING_TLS`, `EMAIL_SPOOFING_VULNERABILITY`).
4. `generate_remediation_blueprint(domain)`: Generates actionable 3-phase remediation plans with configuration diffs.
5. `export_architecture_report(domain, json_path, html_path)`: Exports structured report and interactive D3 diagram.

### 3. FastAPI REST Endpoints

When running the ArchInsights backend (`python -m uvicorn app.main:app --app-dir backend --reload`):

- **Scan Domain**: `POST /api/domain/scan`
  ```json
  {
    "domain": "example.com",
    "sync_to_neo4j": false
  }
  ```
- **Fetch Full Report**: `GET /api/domain/report`
- **Interactive D3 Graph Data**: `GET /api/graph?level=all`
- **Architectural Debt & Metrics**: `GET /api/metrics`
- **AI Executive Assessment**: `GET /api/ai/summary`
- **Node Deep Dive Explanation**: `POST /api/ai/explain-node`
  ```json
  {
    "node_id": "gateway:example.com"
  }
  ```

### 4. Interactive Web Visualizer

Open [http://localhost:8000](http://localhost:8000) in your browser:
- Click **Scan Domain** in the top navbar.
- Enter any domain or pick a quick preset (`example.com`, `cloudflare.com`, `github.com`).
- The dashboard immediately renders the live D3.js force graph, tier colors, smell highlights, health grade, and AI Copilot drawer.
