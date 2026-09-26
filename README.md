# ArchInsights

> **Automated Codebase Architectural Debt Visualizer & Refactoring Copilot**

ArchInsights is an architectural analysis tool that parses multi-language source code (`Python`, `JavaScript`, `TypeScript`) into Abstract Syntax Trees (ASTs) using **Tree-sitter**, constructs dependency graphs, computes cyclomatic complexity, Halstead metrics, and maintainability indices, detects critical architectural code smells, and presents visual network graphs and plain-English AI refactoring blueprints.

---

## Key Features

- **Multi-Language AST Engine**: Built on Tree-sitter for fast AST extraction (Python, JS, TS).
- **Direct In-Memory Remote Scanning**: Scans remote GitHub repositories directly in memory without disk writes or cloning.
- **Architectural Code Smell Detection**: Detects Circular Dependencies (Tarjan's SCC), God Classes, Tight Coupling, and Hub bottlenecks.
- **Plain-English AI Copilot**: Translates abstract metrics into intuitive analogies, risk summaries, and step-by-step 3-stage refactoring plans with code diff previews.
- **Interactive Force Graph**: Interactive D3.js force-directed visualization with hotspot highlighting and node inspectors.
- **Optional Neo4j Sync**: Ingests nodes and dependency relationships into Neo4j graph database with APOC support.
- **Production Ready**: Fully containerized with Docker and Docker Compose.

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
│   ├── graph/          # Neo4j client, schema, and Cypher queries
│   ├── analysis/       # Code smell detectors, debt scores & AI Copilot engine
│   ├── api/            # FastAPI REST endpoints
│   ├── main.py         # Application entrypoint & static file mounts
│   └── config.py       # Pydantic configuration & environment settings
├── frontend/           # D3.js force-directed graph UI & AI Copilot drawer
├── tests/              # Multi-package test fixtures & integration tests
├── Dockerfile          # Multi-stage production container
├── docker-compose.yml  # Orchestrates ArchInsights and Neo4j
├── requirements.txt    # Python dependencies
└── .gitignore          # Git exclusion rules
```
