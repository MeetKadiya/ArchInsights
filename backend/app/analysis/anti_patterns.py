from typing import Dict, List, Set, Any
from pydantic import BaseModel, Field
from app.parser.models import CodebaseGraph


class AntiPatternReport(BaseModel):
    id: str
    type: str  # CIRCULAR_DEPENDENCY, GOD_CLASS, TIGHT_COUPLING, SHOTGUN_SURGERY
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    entity_id: str
    entity_name: str
    description: str
    metrics: Dict[str, Any] = Field(default_factory=dict)
    refactoring_suggestion: str


class AntiPatternDetector:
    """
    Detects architectural code smells and anti-patterns across the dependency graph.
    Supports both in-memory graph algorithms and Neo4j Cypher query results.
    """

    @classmethod
    def detect_all(cls, graph: CodebaseGraph) -> List[AntiPatternReport]:
        reports: List[AntiPatternReport] = []
        reports.extend(cls.detect_circular_dependencies(graph))
        reports.extend(cls.detect_god_classes(graph))
        reports.extend(cls.detect_tight_coupling(graph))
        reports.extend(cls.detect_shotgun_surgery(graph))
        reports.extend(cls.detect_orphan_modules(graph))
        return reports

    @classmethod
    def detect_circular_dependencies(cls, graph: CodebaseGraph) -> List[AntiPatternReport]:
        """
        Detects circular module import cycles using Tarjan's Strongly Connected Components
        and DFS simple cycle extraction.
        """
        reports: List[AntiPatternReport] = []

        # Build adjacency list for module import graph
        adj: Dict[str, Set[str]] = {}
        module_names: Dict[str, str] = {}

        for node in graph.nodes:
            if node.label == "Module":
                adj[node.id] = set()
                module_names[node.id] = node.name

        for edge in graph.edges:
            if edge.type == "IMPORTS" and edge.source in adj and edge.target in adj:
                if edge.source != edge.target:
                    adj[edge.source].add(edge.target)

        # Find cycles using DFS with backtracking
        visited = set()
        rec_stack = []
        rec_set = set()
        detected_cycles = set()

        def dfs(curr: str):
            visited.add(curr)
            rec_stack.append(curr)
            rec_set.add(curr)

            for neighbor in adj.get(curr, []):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in rec_set:
                    # Cycle detected
                    idx = rec_stack.index(neighbor)
                    cycle = rec_stack[idx:]
                    # Canonical representation for deduplication
                    canonical = tuple(cycle)
                    # Rotate cycle to minimum element
                    min_idx = canonical.index(min(canonical))
                    rotated = canonical[min_idx:] + canonical[:min_idx]

                    if rotated not in detected_cycles and len(rotated) > 1:
                        detected_cycles.add(rotated)

            rec_stack.pop()
            rec_set.remove(curr)

        for mod_id in list(adj.keys()):
            if mod_id not in visited:
                dfs(mod_id)

        for cycle in detected_cycles:
            cycle_names = [module_names.get(m, m) for m in cycle]
            cycle_path_str = " -> ".join(cycle_names) + f" -> {cycle_names[0]}"
            reports.append(
                AntiPatternReport(
                    id=f"cycle::{':'.join(cycle)}",
                    type="CIRCULAR_DEPENDENCY",
                    severity="CRITICAL" if len(cycle) <= 3 else "HIGH",
                    entity_id=cycle[0],
                    entity_name=cycle_names[0],
                    description=f"Circular dependency cycle detected across {len(cycle)} modules: {cycle_path_str}",
                    metrics={
                        "cycle_length": len(cycle),
                        "cycle_path": list(cycle),
                        "module_names": cycle_names,
                    },
                    refactoring_suggestion="Break the import cycle using Dependency Inversion (DIP) or extract shared interfaces/types into a dedicated common leaf module.",
                )
            )

        return reports

    @classmethod
    def detect_god_classes(cls, graph: CodebaseGraph) -> List[AntiPatternReport]:
        """
        Identifies God Classes with excessive Weighted Method Count (WMC),
        high LOC, or large method count.
        """
        reports: List[AntiPatternReport] = []

        for node in graph.nodes:
            if node.label == "Class":
                wmc = node.properties.get("wmc", 0)
                loc = node.properties.get("loc", 0)
                methods = [
                    edge.target
                    for edge in graph.edges
                    if edge.source == node.id and edge.type == "HAS_METHOD"
                ]
                method_count = len(methods)

                if method_count >= 8 or wmc >= 15 or loc >= 200:
                    severity = "CRITICAL" if (wmc >= 25 or loc >= 350) else "HIGH"
                    reports.append(
                        AntiPatternReport(
                            id=f"god_class::{node.id}",
                            type="GOD_CLASS",
                            severity=severity,
                            entity_id=node.id,
                            entity_name=node.name,
                            description=f"Class '{node.name}' exhibits God Class smell with {method_count} methods, WMC of {wmc}, and {loc} lines of code.",
                            metrics={
                                "method_count": method_count,
                                "wmc": wmc,
                                "loc": loc,
                            },
                            refactoring_suggestion="Apply Single Responsibility Principle (SRP). Decompose this class into smaller, cohesive domain components using Facade or Strategy patterns.",
                        )
                    )

        return reports

    @classmethod
    def detect_tight_coupling(cls, graph: CodebaseGraph) -> List[AntiPatternReport]:
        """
        Identifies hub modules with high combined Fan-In and Fan-Out.
        """
        reports: List[AntiPatternReport] = []

        fan_in: Dict[str, Set[str]] = {}
        fan_out: Dict[str, Set[str]] = {}
        module_names: Dict[str, str] = {}

        for node in graph.nodes:
            if node.label == "Module":
                fan_in[node.id] = set()
                fan_out[node.id] = set()
                module_names[node.id] = node.name

        for edge in graph.edges:
            if edge.type == "IMPORTS" and edge.source in fan_out and edge.target in fan_in:
                fan_out[edge.source].add(edge.target)
                fan_in[edge.target].add(edge.source)

        for mod_id in fan_in.keys():
            fi = len(fan_in[mod_id])
            fo = len(fan_out[mod_id])
            coupling_factor = fi * fo
            total_coupling = fi + fo

            if total_coupling >= 6:
                instability = round(fo / total_coupling, 2) if total_coupling > 0 else 0.0
                severity = "HIGH" if coupling_factor >= 15 else "MEDIUM"
                reports.append(
                    AntiPatternReport(
                        id=f"tight_coupling::{mod_id}",
                        type="TIGHT_COUPLING",
                        severity=severity,
                        entity_id=mod_id,
                        entity_name=module_names.get(mod_id, mod_id),
                        description=f"Module '{module_names.get(mod_id, mod_id)}' acts as a tight coupling hub with Fan-In={fi}, Fan-Out={fo}, Instability={instability}.",
                        metrics={
                            "fan_in": fi,
                            "fan_out": fo,
                            "coupling_factor": coupling_factor,
                            "instability": instability,
                        },
                        refactoring_suggestion="Introduce an interface boundary or event-driven pub/sub messaging to decouple this module from direct dependencies.",
                    )
                )

        return reports

    @classmethod
    def detect_shotgun_surgery(cls, graph: CodebaseGraph) -> List[AntiPatternReport]:
        """
        Identifies modules with high efferent coupling (Fan-Out >= 6) where modifications
        to external contracts can cause cascading ripple effects across multiple downstream consumers.
        """
        reports: List[AntiPatternReport] = []
        fan_out: Dict[str, Set[str]] = {}
        module_names: Dict[str, str] = {}

        for node in graph.nodes:
            if node.label == "Module":
                fan_out[node.id] = set()
                module_names[node.id] = node.name

        for edge in graph.edges:
            if edge.type == "IMPORTS" and edge.source in fan_out and edge.target in fan_out:
                if edge.source != edge.target:
                    fan_out[edge.source].add(edge.target)

        for mod_id, targets in fan_out.items():
            fo = len(targets)
            if fo >= 6:
                severity = "HIGH" if fo >= 10 else "MEDIUM"
                name = module_names.get(mod_id, mod_id)
                reports.append(
                    AntiPatternReport(
                        id=f"shotgun_surgery::{mod_id}",
                        type="SHOTGUN_SURGERY",
                        severity=severity,
                        entity_id=mod_id,
                        entity_name=name,
                        description=(
                            f"Module '{name}' exhibits Shotgun Surgery / High Fan-Out smell by depending "
                            f"on {fo} distinct modules. Modifying external contracts will likely trigger cascading code edits."
                        ),
                        metrics={"fan_out": fo, "target_modules": list(targets)[:8]},
                        refactoring_suggestion=(
                            "Apply Facade Pattern or consolidate fine-grained helper calls into cohesive domain services "
                            "to reduce outbound dependencies."
                        ),
                    )
                )

        return reports

    @classmethod
    def detect_orphan_modules(cls, graph: CodebaseGraph) -> List[AntiPatternReport]:
        """
        Identifies isolated 'island' modules that have 0 incoming and 0 outgoing
        dependency edges, indicating dead code or abandoned experiments.
        """
        reports: List[AntiPatternReport] = []
        incoming: Dict[str, int] = {}
        outgoing: Dict[str, int] = {}
        module_nodes: Dict[str, Any] = {}

        for node in graph.nodes:
            if node.label == "Module":
                incoming[node.id] = 0
                outgoing[node.id] = 0
                module_nodes[node.id] = node

        # Only evaluate if there are at least 5 modules in the codebase
        if len(module_nodes) < 5:
            return reports

        for edge in graph.edges:
            if edge.type == "IMPORTS":
                if edge.source in outgoing:
                    outgoing[edge.source] += 1
                if edge.target in incoming:
                    incoming[edge.target] += 1

        for mod_id, node in module_nodes.items():
            name_lower = node.name.lower()
            if any(k in name_lower for k in ("main", "index", "app", "__init__", "setup", "run")):
                continue

            if incoming[mod_id] == 0 and outgoing[mod_id] == 0:
                loc = node.properties.get("loc", 0)
                if loc > 15:
                    reports.append(
                        AntiPatternReport(
                            id=f"orphan_module::{mod_id}",
                            type="ORPHAN_MODULE",
                            severity="LOW",
                            entity_id=mod_id,
                            entity_name=node.name,
                            description=(
                                f"Module '{node.name}' has 0 incoming callers and 0 outgoing dependencies "
                                f"({loc} lines of code). It appears to be an abandoned or orphaned module."
                            ),
                            metrics={"loc": loc, "incoming_calls": 0, "outgoing_calls": 0},
                            refactoring_suggestion=(
                                "Audit whether this module is dead code. Integrate into the system or remove to reduce "
                                "code bloat and maintenance overhead."
                            ),
                        )
                    )

        return reports
