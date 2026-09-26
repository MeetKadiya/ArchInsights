import os
import re
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.parser.ast_engine import AstEngine
from app.parser.models import CodebaseGraph
from app.graph.neo4j_client import Neo4jClient
from app.analysis.anti_patterns import AntiPatternDetector, AntiPatternReport
from app.analysis.metrics_engine import MetricsEngine, ArchitecturalDebtSummary
from app.analysis.refactoring import RefactoringGenerator, RefactoringPlan
from app.analysis.ai_copilot import AiCopilotEngine, CodebaseAiSummary, NodeAiExplanation
from app.domain_scanner.recon_orchestrator import DomainReconOrchestrator
from app.domain_scanner.topology_mapper import DomainTopologyMapper
from app.domain_scanner.models import DomainReconResult

router = APIRouter()

# In-memory cached state of the latest analysis
class AppState:
    current_graph: Optional[CodebaseGraph] = None
    antipatterns: List[AntiPatternReport] = []
    debt_summary: Optional[ArchitecturalDebtSummary] = None
    refactoring_plans: List[RefactoringPlan] = []
    ai_summary: Optional[CodebaseAiSummary] = None
    neo4j_client: Neo4jClient = Neo4jClient()
    latest_domain_recon: Optional[DomainReconResult] = None
    scan_type: str = "codebase"  # "codebase" or "domain"

state = AppState()
ast_engine = AstEngine()


class ScanRequest(BaseModel):
    repo_path: str
    repo_name: Optional[str] = None
    sync_to_neo4j: bool = True


class DomainScanRequest(BaseModel):
    domain: str
    sync_to_neo4j: bool = False


@router.get("/health")
def get_health():
    neo4j_alive = state.neo4j_client.is_connected()
    if not neo4j_alive:
        # Try connecting once
        neo4j_alive = state.neo4j_client.connect()

    return {
        "status": "healthy",
        "neo4j_connected": neo4j_alive,
        "active_codebase": state.current_graph.repository_name if state.current_graph else None,
        "scanned_modules": len(state.current_graph.modules) if state.current_graph else 0,
    }


@router.post("/scan")
def scan_codebase(req: ScanRequest):
    target_path = req.repo_path.strip()
    is_git_url = (
        target_path.startswith(("https://", "http://", "git@", "ssh://"))
        or target_path.endswith(".git")
        or "github.com" in target_path
    )

    inferred_name = req.repo_name

    if is_git_url:
        try:
            graph = ast_engine.analyze_github_repository(target_path, repo_name=inferred_name)
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to scan remote repository: {str(e)}")
    else:
        if not os.path.exists(target_path):
            raise HTTPException(status_code=400, detail=f"Path does not exist: {target_path}")
        graph = ast_engine.analyze_repository(repo_path=target_path, repo_name=inferred_name)

    state.current_graph = graph
    state.scan_type = "codebase"

    # 2. Anti-pattern detection
    antipatterns = AntiPatternDetector.detect_all(graph)
    state.antipatterns = antipatterns

    # 3. Architectural Debt & Metrics
    debt_summary = MetricsEngine.compute_architectural_debt(graph, antipattern_count=len(antipatterns))
    state.debt_summary = debt_summary

    # 4. Refactoring plans
    refactoring_plans = RefactoringGenerator.generate_plans(antipatterns)
    state.refactoring_plans = refactoring_plans

    # 5. AI Copilot Architectural Summary
    state.ai_summary = AiCopilotEngine.generate_summary(
        graph=graph,
        antipatterns=antipatterns,
        debt_summary=debt_summary,
        refactoring_plans=refactoring_plans,
    )

    # 6. Optional Neo4j Sync
    neo4j_synced = False
    if req.sync_to_neo4j:
        if not state.neo4j_client.is_connected():
            state.neo4j_client.connect()

        if state.neo4j_client.is_connected():
            try:
                state.neo4j_client.ingest_codebase_graph(graph, clear_existing=True)
                neo4j_synced = True
            except Exception as e:
                print(f"[API] Error syncing to Neo4j: {e}")

    return {
        "repository": graph.repository_name,
        "modules_scanned": len(graph.modules),
        "total_nodes": len(graph.nodes),
        "total_edges": len(graph.edges),
        "antipatterns_found": len(antipatterns),
        "debt_score": debt_summary.debt_score,
        "debt_level": debt_summary.debt_level,
        "neo4j_synced": neo4j_synced,
    }


@router.post("/domain/scan")
async def scan_domain(req: DomainScanRequest):
    """
    Performs full automated reconnaissance, fingerprinting, and architectural
    topology mapping for an external domain.
    """
    target = req.domain.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Domain cannot be empty.")

    try:
        orchestrator = DomainReconOrchestrator()
        recon = await orchestrator.scan_domain(target)
        graph, antipatterns, debt_summary, refactoring_plans, ai_summary = (
            DomainTopologyMapper.generate_topology(recon)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Domain scan failed: {str(e)}")

    state.current_graph = graph
    state.antipatterns = antipatterns
    state.debt_summary = debt_summary
    state.refactoring_plans = refactoring_plans
    state.ai_summary = ai_summary
    state.latest_domain_recon = recon
    state.scan_type = "domain"

    # Optional Neo4j Sync
    neo4j_synced = False
    if req.sync_to_neo4j:
        if not state.neo4j_client.is_connected():
            state.neo4j_client.connect()

        if state.neo4j_client.is_connected():
            try:
                state.neo4j_client.ingest_codebase_graph(graph, clear_existing=True)
                neo4j_synced = True
            except Exception as e:
                print(f"[API] Error syncing domain graph to Neo4j: {e}")

    return {
        "domain": recon.domain,
        "canonical_url": recon.canonical_url,
        "total_nodes": len(graph.nodes),
        "total_edges": len(graph.edges),
        "technologies_detected": [t.name for t in recon.technologies],
        "subdomains_found": len(recon.subdomains),
        "open_ports": [p.port for p in recon.open_ports],
        "antipatterns_found": len(antipatterns),
        "debt_score": debt_summary.debt_score,
        "debt_level": debt_summary.debt_level,
        "neo4j_synced": neo4j_synced,
    }


@router.get("/domain/report")
def get_domain_report():
    """
    Returns full reconnaissance and architectural analysis for the latest scanned domain.
    """
    if not state.latest_domain_recon:
        raise HTTPException(status_code=404, detail="No domain has been scanned yet.")

    return {
        "recon": state.latest_domain_recon,
        "debt_summary": state.debt_summary,
        "antipatterns": state.antipatterns,
        "refactorings": state.refactoring_plans,
        "ai_summary": state.ai_summary,
    }


@router.get("/graph")
def get_graph_data(level: str = "module"):
    """
    Returns graph nodes and links formatted for D3.js force-directed visualization.
    'level' can be 'all', 'module', or 'package'.
    """
    if not state.current_graph:
        return {"nodes": [], "links": []}

    graph = state.current_graph

    # Identify circular dependency node IDs to tag them in D3
    cycle_node_ids = set()
    for ap in state.antipatterns:
        if ap.type == "CIRCULAR_DEPENDENCY":
            for nid in ap.metrics.get("cycle_path", []):
                cycle_node_ids.add(nid)

    # Filter nodes based on level and scan type
    if state.scan_type == "domain":
        allowed_labels = {"Edge", "Gateway", "Service", "Infrastructure", "Database", "ThirdParty", "Module", "Package"}
    else:
        allowed_labels = {"Module", "Package"} if level == "module" else {"Module", "Package", "Class", "Function"}
        if level == "package":
            allowed_labels = {"Package"}

    filtered_nodes = []
    node_id_set = set()

    for n in graph.nodes:
        if n.label in allowed_labels:
            node_id_set.add(n.id)
            filtered_nodes.append(
                {
                    "id": n.id,
                    "label": n.label,
                    "name": n.name,
                    "loc": n.properties.get("loc", 10),
                    "complexity": n.properties.get("cyclomatic_complexity", n.properties.get("wmc", 1)),
                    "maintainability": n.properties.get("maintainability_index", 80.0),
                    "is_in_cycle": n.id in cycle_node_ids,
                    "file_path": n.properties.get("file_path", ""),
                    "tier": n.properties.get("tier", ""),
                    "category": n.properties.get("category", ""),
                }
            )

    filtered_links = []
    for edge in graph.edges:
        if edge.source in node_id_set and edge.target in node_id_set:
            is_cycle_edge = (edge.type == "IMPORTS" and edge.source in cycle_node_ids and edge.target in cycle_node_ids)
            filtered_links.append(
                {
                    "source": edge.source,
                    "target": edge.target,
                    "type": edge.type,
                    "is_cycle": is_cycle_edge,
                }
            )

    return {"nodes": filtered_nodes, "links": filtered_links}


@router.get("/antipatterns", response_model=List[AntiPatternReport])
def get_antipatterns():
    return state.antipatterns


@router.get("/metrics")
def get_metrics():
    if not state.debt_summary:
        return {}
    return state.debt_summary


@router.get("/refactorings", response_model=List[RefactoringPlan])
def get_refactorings():
    return state.refactoring_plans


@router.get("/ai/summary")
def get_ai_summary():
    if not state.ai_summary and state.current_graph and state.debt_summary:
        state.ai_summary = AiCopilotEngine.generate_summary(
            graph=state.current_graph,
            antipatterns=state.antipatterns,
            debt_summary=state.debt_summary,
            refactoring_plans=state.refactoring_plans,
        )
    if not state.ai_summary:
        return {}
    return state.ai_summary


class ExplainNodeRequest(BaseModel):
    node_id: str


@router.post("/ai/explain-node")
def explain_node(req: ExplainNodeRequest):
    if not state.current_graph:
        raise HTTPException(status_code=400, detail="No active codebase scanned.")
    return AiCopilotEngine.explain_node(
        node_id=req.node_id,
        graph=state.current_graph,
        antipatterns=state.antipatterns,
        refactoring_plans=state.refactoring_plans,
    )
