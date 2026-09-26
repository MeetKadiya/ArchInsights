import os
import sys

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.parser.ast_engine import AstEngine
from app.analysis.anti_patterns import AntiPatternDetector
from app.analysis.metrics_engine import MetricsEngine
from app.analysis.refactoring import RefactoringGenerator


def test_ast_engine_python_parsing():
    engine = AstEngine()
    current_dir = os.path.dirname(__file__)
    sample_file = os.path.join(current_dir, "sample_codebase", "pkg_a", "order_service.py")

    result = engine.parse_file(sample_file, repo_root=os.path.join(current_dir, "sample_codebase"))
    assert result is not None
    assert result.language == "python"
    assert len(result.classes) == 1
    assert result.classes[0].name == "OrderManager"
    assert len(result.classes[0].methods) >= 9
    assert result.classes[0].wmc > 10
    assert len(result.imports) >= 2


def test_ast_engine_js_parsing():
    engine = AstEngine()
    current_dir = os.path.dirname(__file__)
    sample_file = os.path.join(current_dir, "sample_codebase", "pkg_js", "notification.js")

    result = engine.parse_file(sample_file, repo_root=os.path.join(current_dir, "sample_codebase"))
    assert result is not None
    assert result.language == "javascript"
    assert len(result.classes) == 1
    assert result.classes[0].name == "NotificationService"
    assert len(result.imports) == 1


def test_anti_pattern_circular_dependency():
    engine = AstEngine()
    sample_repo = os.path.join(os.path.dirname(__file__), "sample_codebase")
    graph = engine.analyze_repository(sample_repo, repo_name="TestRepo")

    antipatterns = AntiPatternDetector.detect_all(graph)
    cycle_reports = [ap for ap in antipatterns if ap.type == "CIRCULAR_DEPENDENCY"]

    assert len(cycle_reports) >= 1
    cycle = cycle_reports[0]
    assert cycle.severity in ("CRITICAL", "HIGH")
    assert len(cycle.metrics["cycle_path"]) == 3  # order_service -> payment_service -> shipping_service


def test_anti_pattern_god_class():
    engine = AstEngine()
    sample_repo = os.path.join(os.path.dirname(__file__), "sample_codebase")
    graph = engine.analyze_repository(sample_repo, repo_name="TestRepo")

    antipatterns = AntiPatternDetector.detect_all(graph)
    god_classes = [ap for ap in antipatterns if ap.type == "GOD_CLASS"]

    assert len(god_classes) >= 1
    assert god_classes[0].entity_name == "OrderManager"


def test_metrics_engine_and_refactoring_plans():
    engine = AstEngine()
    sample_repo = os.path.join(os.path.dirname(__file__), "sample_codebase")
    graph = engine.analyze_repository(sample_repo, repo_name="TestRepo")

    antipatterns = AntiPatternDetector.detect_all(graph)
    debt_summary = MetricsEngine.compute_architectural_debt(graph, antipattern_count=len(antipatterns))

    assert debt_summary.total_modules >= 4
    assert debt_summary.debt_score > 0
    assert len(debt_summary.package_metrics) >= 1

    plans = RefactoringGenerator.generate_plans(antipatterns)
    assert len(plans) >= 2
    assert any("Break Circular Import Cycle" in p.title for p in plans)
    assert any("Decompose God Class" in p.title for p in plans)


def test_self_scan_repository():
    engine = AstEngine()
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    graph = engine.analyze_repository(root_dir, repo_name="ArchInsights")
    assert len(graph.modules) >= 10
    assert len(graph.nodes) >= 20
    assert len(graph.edges) >= 20

