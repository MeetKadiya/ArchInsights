from typing import Dict, List, Any
from pydantic import BaseModel
from app.parser.models import CodebaseGraph


class PackageMetric(BaseModel):
    package_id: str
    package_name: str
    module_count: int
    afferent_coupling: int  # Ca (Fan-in)
    efferent_coupling: int  # Ce (Fan-out)
    instability: float  # I = Ce / (Ca + Ce)
    abstractness: float  # A = abstract_classes / total_classes
    distance_main_sequence: float  # D = |A + I - 1|


class ArchitecturalDebtSummary(BaseModel):
    total_modules: int
    total_loc: int
    average_complexity: float
    average_maintainability_index: float
    debt_score: float  # 0 to 100 (higher = worse debt)
    debt_level: str  # LOW, MODERATE, HIGH, CRITICAL
    critical_hotspots: List[Dict[str, Any]]
    package_metrics: List[PackageMetric]


class MetricsEngine:
    """
    Computes Robert C. Martin's Package Coupling & Instability Metrics,
    Abstractness, Distance from the Main Sequence, and Architectural Debt Scores.
    """

    @classmethod
    def compute_package_metrics(cls, graph: CodebaseGraph) -> List[PackageMetric]:
        # Map packages to contained modules
        pkg_modules: Dict[str, List[str]] = {}
        pkg_names: Dict[str, str] = {}
        mod_to_pkg: Dict[str, str] = {}

        for node in graph.nodes:
            if node.label == "Package":
                pkg_modules[node.id] = []
                pkg_names[node.id] = node.name

        for edge in graph.edges:
            if edge.type == "CONTAINS" and edge.source.startswith("pkg::") and edge.target.startswith("mod::"):
                pkg_modules.setdefault(edge.source, []).append(edge.target)
                mod_to_pkg[edge.target] = edge.source

        # Count classes and abstract classes per package
        pkg_classes: Dict[str, int] = {p: 0 for p in pkg_modules}
        pkg_abstract_classes: Dict[str, int] = {p: 0 for p in pkg_modules}

        for node in graph.nodes:
            if node.label == "Class":
                # Find parent module
                for edge in graph.edges:
                    if edge.type == "DEFINES" and edge.target == node.id:
                        parent_pkg = mod_to_pkg.get(edge.source)
                        if parent_pkg:
                            pkg_classes[parent_pkg] = pkg_classes.get(parent_pkg, 0) + 1
                            if node.properties.get("is_abstract") or node.properties.get("is_interface"):
                                pkg_abstract_classes[parent_pkg] = pkg_abstract_classes.get(parent_pkg, 0) + 1

        # Calculate Ca and Ce per package based on cross-package imports
        ca_counts: Dict[str, set] = {p: set() for p in pkg_modules}
        ce_counts: Dict[str, set] = {p: set() for p in pkg_modules}

        for edge in graph.edges:
            if edge.type == "IMPORTS":
                src_pkg = mod_to_pkg.get(edge.source)
                tgt_pkg = mod_to_pkg.get(edge.target)
                if src_pkg and tgt_pkg and src_pkg != tgt_pkg:
                    ce_counts[src_pkg].add(tgt_pkg)
                    ca_counts[tgt_pkg].add(src_pkg)

        results: List[PackageMetric] = []
        for pkg_id, mods in pkg_modules.items():
            ca = len(ca_counts.get(pkg_id, set()))
            ce = len(ce_counts.get(pkg_id, set()))
            total_coupling = ca + ce
            instability = round(ce / total_coupling, 2) if total_coupling > 0 else 0.0

            total_cls = pkg_classes.get(pkg_id, 0)
            abstract_cls = pkg_abstract_classes.get(pkg_id, 0)
            abstractness = round(abstract_cls / total_cls, 2) if total_cls > 0 else 0.0

            # Distance from Main Sequence D = |A + I - 1|
            distance = round(abs(abstractness + instability - 1.0), 2)

            results.append(
                PackageMetric(
                    package_id=pkg_id,
                    package_name=pkg_names.get(pkg_id, pkg_id),
                    module_count=len(mods),
                    afferent_coupling=ca,
                    efferent_coupling=ce,
                    instability=instability,
                    abstractness=abstractness,
                    distance_main_sequence=distance,
                )
            )

        return results

    @classmethod
    def compute_architectural_debt(
        cls, graph: CodebaseGraph, antipattern_count: int = 0
    ) -> ArchitecturalDebtSummary:
        modules = [n for n in graph.nodes if n.label == "Module"]
        total_modules = len(modules)
        if total_modules == 0:
            return ArchitecturalDebtSummary(
                total_modules=0,
                total_loc=0,
                average_complexity=0.0,
                average_maintainability_index=100.0,
                debt_score=0.0,
                debt_level="LOW",
                critical_hotspots=[],
                package_metrics=[],
            )

        total_loc = sum(n.properties.get("loc", 0) for n in modules)
        avg_complexity = round(sum(n.properties.get("cyclomatic_complexity", 1) for n in modules) / total_modules, 2)
        avg_mi = round(sum(n.properties.get("maintainability_index", 100.0) for n in modules) / total_modules, 2)

        # Identify critical hotspots (low MI or high CC)
        hotspots = []
        for m in sorted(modules, key=lambda x: x.properties.get("maintainability_index", 100.0)):
            mi = m.properties.get("maintainability_index", 100.0)
            cc = m.properties.get("cyclomatic_complexity", 1)
            if mi < 65.0 or cc > 10:
                hotspots.append(
                    {
                        "id": m.id,
                        "name": m.name,
                        "file_path": m.properties.get("file_path"),
                        "complexity": cc,
                        "maintainability_index": mi,
                        "loc": m.properties.get("loc", 0),
                    }
                )

        pkg_metrics = cls.compute_package_metrics(graph)
        avg_distance = sum(p.distance_main_sequence for p in pkg_metrics) / max(1, len(pkg_metrics))

        # Composite Debt Score (0 to 100):
        # - Low MI contributes up to 40 points
        # - High Complexity contributes up to 20 points
        # - Distance from Main Sequence contributes up to 20 points
        # - Antipattern count contributes up to 20 points
        mi_debt = max(0.0, (100.0 - avg_mi) * 0.4)
        cc_debt = min(20.0, (avg_complexity / 15.0) * 20.0)
        dist_debt = min(20.0, avg_distance * 20.0)
        smell_debt = min(20.0, antipattern_count * 5.0)

        total_debt = round(min(100.0, mi_debt + cc_debt + dist_debt + smell_debt), 1)

        if total_debt < 25:
            level = "LOW"
        elif total_debt < 50:
            level = "MODERATE"
        elif total_debt < 75:
            level = "HIGH"
        else:
            level = "CRITICAL"

        return ArchitecturalDebtSummary(
            total_modules=total_modules,
            total_loc=total_loc,
            average_complexity=avg_complexity,
            average_maintainability_index=avg_mi,
            debt_score=total_debt,
            debt_level=level,
            critical_hotspots=hotspots[:10],
            package_metrics=pkg_metrics,
        )
