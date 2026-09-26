import sys
import os

sys.path.insert(0, os.path.abspath("backend"))

from app.parser.ast_engine import AstEngine
from app.analysis.anti_patterns import AntiPatternDetector
from app.analysis.metrics_engine import MetricsEngine

import traceback

if __name__ == "__main__":
    try:
        engine = AstEngine()
        graph = engine.analyze_repository(".", repo_name="ArchInsights")
        print(f"Total Modules Scanned: {len(graph.modules)}")
        print(f"Total Graph Nodes: {len(graph.nodes)}")
        print(f"Total Graph Edges: {len(graph.edges)}")

        antipatterns = AntiPatternDetector.detect_all(graph)
        print(f"Antipatterns Detected: {len(antipatterns)}")
        for ap in antipatterns:
            print(f"  - [{ap.severity}] {ap.type}: {ap.description}")

        debt = MetricsEngine.compute_architectural_debt(graph, len(antipatterns))
        print(f"Overall Debt Score: {debt.debt_score}/100 ({debt.debt_level})")
        print(f"Average CC: {debt.average_complexity}")
        print(f"Average MI: {debt.average_maintainability_index}")
    except Exception as e:
        traceback.print_exc()
        with open("scan_error.log", "w") as f:
            f.write(traceback.format_exc())
