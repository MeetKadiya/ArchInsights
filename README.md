# ArchInsights

> **Automated Codebase Architectural Debt Visualizer & Refactoring Copilot**

ArchInsights is an architectural analysis tool that parses multi-language source code (`Python`, `JavaScript`, `TypeScript`) into Abstract Syntax Trees (ASTs) using **Tree-sitter**, constructs dependency graphs, computes cyclomatic complexity, Halstead metrics, and maintainability indices, detects critical architectural code smells, and presents visual network graphs and plain-English AI refactoring blueprints.

---

## Key Features

- **Multi-Language AST Engine**: Built on Tree-sitter for fast AST extraction (Python, JS, TS).
- **Direct In-Memory Remote Scanning**: Scans remote GitHub repositories directly in memory without disk writes or cloning.
- **External Domain Architecture Scanner**: Performs live network reconnaissance (DNS records, subdomains, SSL/TLS certificates, open ports/services) and technology stack fingerprinting (Frontend, Backend, CMS, Cloud/CDN, Third-party APIs) across external domains and websites.
- **Multi-Tier Architecture & Topology Mapping**: Generates structured graph representations of real-world infrastructure tiers (`Edge`, `Gateway`, `Service`, `Infrastructure`, `Database`, `ThirdParty`).
- **Architectural & Security Smell Detection**: Detects Circular Dependencies, God Classes, Tight Coupling, Shotgun Surgery, Orphan/Dead Code, Exposed Database Ports, Missing Security Headers, Insecure/Expiring TLS, and Spoofing risks.
- **8-Category Anti-Pattern Filtering Suite**: Interactive filter pills with live badge counters (Critical, Cycles, God Class, Coupling, Security & Ports, Shotgun Surgery, Dead Code) featuring dynamic focus-dimming.
- **Cyber-Obsidian & Radiant Emerald UI + Multi-Theme Switcher**: Modern visual palette with 4 switchable themes (Emerald Obsidian, Solar Amber, Crimson Cyber, Nordic Frost) persisted in `localStorage`.
- **Plain-English AI Copilot**: Translates abstract metrics into intuitive analogies, risk summaries, and step-by-step 3-stage refactoring plans with code diff previews.
- **Interactive Force Graph**: Interactive D3.js force-directed visualization with hotspot highlighting and node inspectors.
- **Autonomous Antigravity Agent**: Autonomous agent workflow with dedicated tools for domain intelligence, topology generation, and remediation blueprints.
- **Optional Neo4j Sync**: Ingests nodes and dependency relationships into Neo4j graph database with APOC support.
- **Production Ready**: Fully containerized with Docker and Docker Compose.

---

## Domain Architecture Scanning

### 1. Standalone CLI Scanner
Scan any public domain or website and generate a terminal report, JSON export, and standalone interactive D3.js visualization:

```bash
# Terminal summary
python run_domain_scan.py example.com

# Full scan with JSON and interactive HTML export
python run_domain_scan.py example.com --output example_report.json --html example_arch.html
```

### 2. Autonomous Antigravity Agent
Run the autonomous Antigravity agent pipeline directly:

```bash
python agent/domain_agent.py example.com
```

### 3. Web Dashboard Scanning
1. Start the server:
   ```bash
   python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
   ```
2. Open [http://127.0.0.1:8000](http://127.0.0.1:8000)
3. Click **Scan Domain** in the navbar, enter target URL or domain, or select a preset (`example.com`, `cloudflare.com`, `github.com`).

---

## Quick Start with Docker

The fastest way to spin up ArchInsights along with Neo4j:

```bash
# 1. Clone your repository (or navigate to project root)
cd ArchInsights

# 2. Build and start containers
docker compose up --build
```

- **ArchInsights Dashboard**: [http://localhost:8000](http://localhost:8000)
- **Neo4j Browser UI**: [http://localhost:7474](http://localhost:7474)

---

## Local Setup (Without Docker)

### 1. Prerequisites
- Python 3.10+
- (Optional) Neo4j 5.x running locally

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run Application
```bash
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```
Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.

### 4. Run Test Suite
```bash
python -m pytest tests/ -v
```

---

## Project Structure

```
ArchInsights/
├── backend/app/
│   ├── parser/         # Tree-sitter multi-language AST visitors & complexity metrics
│   ├── domain_scanner/ # Domain reconnaissance, port scanning & tech stack fingerprinting
│   ├── graph/          # Neo4j client, schema, and Cypher queries
│   ├── analysis/       # Code & infrastructure smell detectors, debt scores & AI Copilot
│   ├── api/            # FastAPI REST endpoints (/scan, /domain/scan, /graph, /metrics)
│   ├── main.py         # Application entrypoint & static file mounts
│   └── config.py       # Pydantic configuration & environment settings
├── agent/              # Autonomous Antigravity Agent implementations
├── frontend/           # D3.js force-directed graph UI & AI Copilot drawer
├── tests/              # Test suite for codebase ASTs and domain reconnaissance
├── run_domain_scan.py  # Standalone CLI runner for external domain architecture mapping
├── run_self_scan.py    # Self-scan runner for codebase AST analysis
├── requirements.txt    # Python dependencies
└── docker-compose.yml  # Orchestrates ArchInsights and Neo4j
```
