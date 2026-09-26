import os
from typing import Dict, List, Optional, Tuple, Set
from app.parser.models import (
    ModuleParseResult,
    CodebaseGraph,
    GraphNode,
    DependencyEdge,
)


class SymbolResolver:
    """
    Resolves relative and absolute imports across parsed modules into
    canonical graph nodes and dependency relationships.
    """

    def __init__(self, repo_name: str, root_path: str, modules: Dict[str, ModuleParseResult]):
        self.repo_name = repo_name
        self.root_path = os.path.abspath(root_path)
        self.modules = modules  # key: relative_file_path (forward slashes)

        # Index canonical module names to relative file paths
        # E.g. "services.auth" -> "services/auth.py"
        self.module_name_to_path: Dict[str, str] = {}
        self.file_stem_to_paths: Dict[str, List[str]] = {}

        for rel_path in self.modules.keys():
            normalized = rel_path.replace("\\", "/")
            stem, _ = os.path.splitext(normalized)
            dotted = stem.replace("/", ".")

            self.module_name_to_path[dotted] = rel_path
            self.module_name_to_path[stem] = rel_path

            base_name = os.path.basename(stem)
            self.file_stem_to_paths.setdefault(base_name, []).append(rel_path)

    def resolve_import(self, current_module_path: str, import_source: str, is_relative: bool, relative_level: int) -> Optional[str]:
        """
        Attempts to resolve an import string to a known module file path in the repo.
        Returns relative file path if resolved, else None (external library).
        """
        curr_norm = current_module_path.replace("\\", "/")
        curr_dir = os.path.dirname(curr_norm)

        # 1. Relative import resolution
        if is_relative or import_source.startswith("."):
            clean_source = import_source.lstrip("./\\")
            target_dir = curr_dir

            if relative_level > 1:
                for _ in range(relative_level - 1):
                    target_dir = os.path.dirname(target_dir)

            candidate_base = os.path.normpath(os.path.join(target_dir, clean_source)).replace("\\", "/")

            for ext in (".py", ".js", ".jsx", ".ts", ".tsx", "/__init__.py", "/index.js", "/index.ts"):
                cand = candidate_base + ext
                if cand in self.modules:
                    return cand
            if candidate_base in self.modules:
                return candidate_base

        # 2. Direct match via dotted or slash notation
        if import_source in self.module_name_to_path:
            return self.module_name_to_path[import_source]

        dotted_source = import_source.replace("/", ".")
        if dotted_source in self.module_name_to_path:
            return self.module_name_to_path[dotted_source]

        # 3. Path suffix match
        for dotted_name, path in self.module_name_to_path.items():
            if dotted_name.endswith("." + dotted_source) or dotted_name == dotted_source:
                return path

        # 4. Basename stem match (fallback)
        parts = import_source.split(".")
        last_part = parts[-1]
        if last_part in self.file_stem_to_paths:
            candidates = self.file_stem_to_paths[last_part]
            if len(candidates) == 1:
                return candidates[0]

        return None

    def _create_package_and_module_nodes(
        self, repo_node_id: str, nodes: List[GraphNode], edges: List[DependencyEdge]
    ) -> Dict[str, str]:
        packages: Dict[str, str] = {}

        for rel_path, module in self.modules.items():
            norm_path = rel_path.replace("\\", "/")
            dir_name = os.path.dirname(norm_path)
            pkg_id = f"pkg::{dir_name}" if dir_name else "pkg::root"

            if pkg_id not in packages:
                packages[pkg_id] = dir_name or "root"
                nodes.append(
                    GraphNode(
                        id=pkg_id,
                        label="Package",
                        name=os.path.basename(dir_name) if dir_name else "root",
                        properties={"path": dir_name or "."},
                    )
                )
                edges.append(
                    DependencyEdge(
                        source=repo_node_id,
                        target=pkg_id,
                        type="CONTAINS",
                    )
                )

            mod_node_id = f"mod::{norm_path}"
            nodes.append(
                GraphNode(
                    id=mod_node_id,
                    label="Module",
                    name=module.name,
                    properties={
                        "file_path": norm_path,
                        "language": module.language,
                        "loc": module.loc,
                        "sloc": module.sloc,
                        "cyclomatic_complexity": module.cyclomatic_complexity,
                        "maintainability_index": module.maintainability_index,
                    },
                )
            )

            edges.append(
                DependencyEdge(
                    source=pkg_id,
                    target=mod_node_id,
                    type="CONTAINS",
                )
            )

        return packages

    def _process_classes(self, module: ModuleParseResult, mod_node_id: str, nodes: List[GraphNode], edges: List[DependencyEdge]):
        for cls in module.classes:
            cls_node_id = f"class::{cls.id}"
            nodes.append(
                GraphNode(
                    id=cls_node_id,
                    label="Class",
                    name=cls.name,
                    properties={
                        "loc": cls.loc,
                        "wmc": cls.wmc,
                        "base_classes": cls.base_classes,
                        "interfaces": cls.interfaces,
                        "is_abstract": cls.is_abstract,
                        "is_interface": cls.is_interface,
                    },
                )
            )
            edges.append(
                DependencyEdge(
                    source=mod_node_id,
                    target=cls_node_id,
                    type="DEFINES",
                )
            )

            for base in cls.base_classes:
                edges.append(
                    DependencyEdge(
                        source=cls_node_id,
                        target=f"class::{base}",
                        type="INHERITS_FROM",
                        properties={"base_name": base},
                    )
                )

    def _process_functions(self, module: ModuleParseResult, mod_node_id: str, nodes: List[GraphNode], edges: List[DependencyEdge]):
        for fn in module.functions:
            fn_node_id = f"fn::{fn.id}"
            nodes.append(
                GraphNode(
                    id=fn_node_id,
                    label="Function",
                    name=fn.name,
                    properties={
                        "is_method": fn.is_method,
                        "cyclomatic_complexity": fn.cyclomatic_complexity,
                        "loc": fn.loc,
                        "visibility": fn.visibility,
                        "parameters": fn.parameters,
                    },
                )
            )

            if fn.parent_class:
                edges.append(
                    DependencyEdge(
                        source=f"class::{fn.parent_class}",
                        target=fn_node_id,
                        type="HAS_METHOD",
                    )
                )
            else:
                edges.append(
                    DependencyEdge(
                        source=mod_node_id,
                        target=fn_node_id,
                        type="DEFINES",
                    )
                )

    def _process_imports_and_calls(self, module: ModuleParseResult, mod_node_id: str, norm_path: str, edges: List[DependencyEdge]):
        # Resolve imports
        for imp in module.imports:
            resolved_target = self.resolve_import(
                current_module_path=norm_path,
                import_source=imp.source,
                is_relative=imp.is_relative,
                relative_level=imp.relative_level,
            )
            if resolved_target:
                target_mod_id = "mod::" + resolved_target.replace("\\", "/")
                edges.append(
                    DependencyEdge(
                        source=mod_node_id,
                        target=target_mod_id,
                        type="IMPORTS",
                        properties={
                            "raw_source": imp.source,
                            "symbols": [item.name for item in imp.items],
                        },
                    )
                )

        # Record calls
        for call_item in module.calls:
            cid = call_item.caller_id
            caller_id = f"fn::{cid}" if ("::" in cid or "." in cid) else mod_node_id
            edges.append(
                DependencyEdge(
                    source=caller_id,
                    target=f"fn::{call_item.callee_name}",
                    type="CALLS",
                    properties={"callee_name": call_item.callee_name},
                )
            )

    def build_codebase_graph(self) -> CodebaseGraph:
        """
        Builds the complete GraphNode and DependencyEdge graph representation
        ready for Neo4j persistence and D3 rendering.
        """
        nodes: List[GraphNode] = []
        edges: List[DependencyEdge] = []

        repo_node_id = f"repo::{self.repo_name}"
        nodes.append(
            GraphNode(
                id=repo_node_id,
                label="Repository",
                name=self.repo_name,
                properties={"root_path": self.root_path},
            )
        )

        self._create_package_and_module_nodes(repo_node_id, nodes, edges)

        for rel_path, module in self.modules.items():
            norm_path = rel_path.replace("\\", "/")
            mod_node_id = f"mod::{norm_path}"
            self._process_classes(module, mod_node_id, nodes, edges)
            self._process_functions(module, mod_node_id, nodes, edges)
            self._process_imports_and_calls(module, mod_node_id, norm_path, edges)

        return CodebaseGraph(
            repository_name=self.repo_name,
            root_path=self.root_path,
            nodes=nodes,
            edges=edges,
            modules=self.modules,
        )
