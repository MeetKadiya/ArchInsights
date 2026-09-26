import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.main import app

client = TestClient(app)


def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"


def test_scan_and_graph_endpoints():
    sample_repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "sample_codebase"))
    
    # 1. Scan repo
    scan_res = client.post(
        "/api/scan",
        json={"repo_path": sample_repo, "repo_name": "TestCodebase", "sync_to_neo4j": False}
    )
    assert scan_res.status_code == 200
    scan_data = scan_res.json()
    assert scan_data["modules_scanned"] >= 4
    assert scan_data["antipatterns_found"] >= 1
    assert scan_data["debt_score"] > 0

    # 2. Get Graph Data
    graph_res = client.get("/api/graph?level=all")
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    assert len(graph_data["nodes"]) >= 4
    assert len(graph_data["links"]) >= 3
    # Verify circular dependency tagging in D3 payload
    assert any(n["is_in_cycle"] for n in graph_data["nodes"])
    assert any(l["is_cycle"] for l in graph_data["links"])

    # 3. Get Anti-patterns
    anti_res = client.get("/api/antipatterns")
    assert anti_res.status_code == 200
    anti_data = anti_res.json()
    assert len(anti_data) >= 1
    assert any(a["type"] == "CIRCULAR_DEPENDENCY" for a in anti_data)

    # 4. Get Metrics
    metrics_res = client.get("/api/metrics")
    assert metrics_res.status_code == 200
    metrics_data = metrics_res.json()
    assert metrics_data["total_modules"] >= 4
    assert "debt_score" in metrics_data

    # 5. Get Refactorings
    refactor_res = client.get("/api/refactorings")
    assert refactor_res.status_code == 200
    refactor_data = refactor_res.json()
    assert len(refactor_data) >= 1
    assert "code_diff_preview" in refactor_data[0]

    # 6. AI Summary
    ai_summary_res = client.get("/api/ai/summary")
    assert ai_summary_res.status_code == 200
    ai_data = ai_summary_res.json()
    assert "health_grade" in ai_data
    assert "executive_summary" in ai_data
    assert "simple_breakdown" in ai_data
    assert len(ai_data["prioritized_actions"]) >= 1
    assert "plain_english_summary" in ai_data["prioritized_actions"][0]
    assert "analogy" in ai_data["prioritized_actions"][0]

    # 7. AI Explain Node
    first_node_id = graph_data["nodes"][0]["id"]
    explain_res = client.post("/api/ai/explain-node", json={"node_id": first_node_id})
    assert explain_res.status_code == 200
    explain_data = explain_res.json()
    assert "diagnosis" in explain_data
    assert "role_in_architecture" in explain_data
    assert "plain_english_role" in explain_data
    assert "recommended_refactoring" in explain_data

    # 6. Verify HTML index route
    index_res = client.get("/")
    assert index_res.status_code == 200
    assert "ArchInsights" in index_res.text


def test_scan_github_url_validation():
    # Verify that remote git URLs are detected and handle errors gracefully
    res = client.post(
        "/api/scan",
        json={"repo_path": "https://github.com/nonexistent_owner_12345/nonexistent_repo_99999", "sync_to_neo4j": False}
    )
    assert res.status_code == 400
    assert "Failed to fetch GitHub repository" in res.json()["detail"] or "Failed to scan" in res.json()["detail"]
