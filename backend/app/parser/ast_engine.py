import os
from pathlib import Path
from typing import Dict, Optional
import tree_sitter
import tree_sitter_python
import tree_sitter_javascript

from app.config import settings
from app.parser.models import ModuleParseResult, CodebaseGraph
from app.parser.visitor_python import PythonAstVisitor
from app.parser.visitor_js import JavaScriptAstVisitor
from app.parser.complexity import (
    compute_code_lines,
    compute_halstead_volume,
    compute_maintainability_index,
)
from app.parser.resolver import SymbolResolver


class AstEngine:
    """
    Multi-language AST Parser engine powered by Tree-sitter.
    Parses codebases, extracts structural dependencies, computes metrics,
    and constructs the complete architectural graph.
    """

    def __init__(self):
        # Initialize Python Language & Parser
        self.py_lang = tree_sitter.Language(tree_sitter_python.language())
        self.py_parser = tree_sitter.Parser(self.py_lang)

        # Initialize JavaScript Language & Parser
        self.js_lang = tree_sitter.Language(tree_sitter_javascript.language())
        self.js_parser = tree_sitter.Parser(self.js_lang)

    def parse_source(self, code_bytes: bytes, file_path: str, repo_root: str) -> Optional[ModuleParseResult]:
        """
        Parses source code from raw bytes and generates a ModuleParseResult.
        """
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in settings.SUPPORTED_EXTENSIONS:
            return None

        # Derive relative path and canonical module id
        norm_file = os.path.abspath(file_path)
        norm_root = os.path.abspath(repo_root)
        try:
            rel_path = os.path.relpath(norm_file, norm_root).replace("\\", "/")
        except ValueError:
            rel_path = os.path.basename(file_path)

        module_stem = os.path.splitext(rel_path)[0].replace("/", ".")
        module_name = os.path.basename(file_path)

        source_text = code_bytes.decode("utf-8", errors="ignore")
        loc, sloc, comment_loc = compute_code_lines(source_text)

        if ext == ".py":
            tree = self.py_parser.parse(code_bytes)
            visitor = PythonAstVisitor(module_id=module_stem, source_bytes=code_bytes)
            visitor.visit(tree.root_node)
            language = "python"
        elif ext in (".js", ".jsx", ".ts", ".tsx"):
            tree = self.js_parser.parse(code_bytes)
            visitor = JavaScriptAstVisitor(module_id=module_stem, source_bytes=code_bytes)
            visitor.visit(tree.root_node)
            language = "javascript" if ext in (".js", ".jsx") else "typescript"
        else:
            return None

        # File-level metrics
        halstead_vol = compute_halstead_volume(tree.root_node, source_bytes=code_bytes)

        # Module cyclomatic complexity: sum of function CC + 1
        module_cc = sum(f.cyclomatic_complexity for f in visitor.functions) + 1

        mi = compute_maintainability_index(
            cyclomatic_complexity=module_cc,
            sloc=sloc,
            halstead_volume=halstead_vol,
        )

        return ModuleParseResult(
            id=module_stem,
            file_path=rel_path,
            name=module_name,
            language=language,
            loc=loc,
            sloc=sloc,
            comment_loc=comment_loc,
            cyclomatic_complexity=module_cc,
            maintainability_index=mi,
            imports=visitor.imports,
            classes=visitor.classes,
            functions=visitor.functions,
            calls=visitor.calls,
        )

    def parse_file(self, file_path: str, repo_root: str) -> Optional[ModuleParseResult]:
        """
        Reads and parses a single file from disk.
        """
        try:
            if os.path.getsize(file_path) > settings.MAX_FILE_SIZE_BYTES:
                return None
            with open(file_path, "rb") as f:
                code_bytes = f.read()
            return self.parse_source(code_bytes, file_path, repo_root)
        except Exception as e:
            print(f"[AstEngine] Error parsing file {file_path}: {e}")
            return None

    def analyze_repository(self, repo_path: str, repo_name: Optional[str] = None) -> CodebaseGraph:
        """
        Scans a repository directory, parses all supported source files,
        resolves inter-module dependencies, and outputs a complete CodebaseGraph.
        """
        root_path = os.path.abspath(repo_path)
        name = repo_name or os.path.basename(root_path)

        parsed_modules: Dict[str, ModuleParseResult] = {}

        for dirpath, dirnames, filenames in os.walk(root_path):
            # Filter excluded directories in-place
            dirnames[:] = [d for d in dirnames if d not in settings.EXCLUDED_DIRS]

            for filename in filenames:
                ext = os.path.splitext(filename)[1].lower()
                if ext in settings.SUPPORTED_EXTENSIONS:
                    full_path = os.path.join(dirpath, filename)
                    result = self.parse_file(full_path, root_path)
                    if result:
                        parsed_modules[result.file_path] = result

        # Cross-file symbol and dependency resolution
        resolver = SymbolResolver(repo_name=name, root_path=root_path, modules=parsed_modules)
        return resolver.build_codebase_graph()

    def analyze_source_files(
        self,
        files: Dict[str, bytes],
        repo_name: str,
        root_path: str = "",
    ) -> CodebaseGraph:
        """
        Parses an in-memory dictionary of {relative_path: code_bytes} directly,
        without writing any files to disk.
        """
        parsed_modules: Dict[str, ModuleParseResult] = {}

        for rel_path, code_bytes in files.items():
            norm_path = rel_path.replace("\\", "/").lstrip("/")

            # Check if any parent folder is in excluded directories
            parts = norm_path.split("/")
            if any(p in settings.EXCLUDED_DIRS for p in parts[:-1]):
                continue

            ext = os.path.splitext(norm_path)[1].lower()
            if ext in settings.SUPPORTED_EXTENSIONS:
                if len(code_bytes) > settings.MAX_FILE_SIZE_BYTES:
                    continue
                result = self.parse_source(code_bytes, norm_path, root_path)
                if result:
                    parsed_modules[result.file_path] = result

        resolver = SymbolResolver(repo_name=repo_name, root_path=root_path or repo_name, modules=parsed_modules)
        return resolver.build_codebase_graph()

    def analyze_github_repository(
        self,
        repo_url: str,
        repo_name: Optional[str] = None,
        timeout: int = 45,
    ) -> CodebaseGraph:
        """
        Directly scans a public GitHub repository in-memory via stream download.
        Does NOT execute git clone or create any files on disk.
        """
        import io
        import re
        import zipfile
        import urllib.request
        import urllib.error

        clean_url = repo_url.strip().rstrip("/")
        # Extract owner and repo name from URL
        match = re.search(r"github\.com[/:]([^/]+)/([^/]+?)(?:\.git)?$", clean_url)
        if not match:
            raise ValueError(f"Invalid GitHub repository URL: {repo_url}")

        owner, repo = match.group(1), match.group(2)
        inferred_name = repo_name or repo

        # URLs to attempt direct in-memory archive streaming
        candidate_urls = [
            f"https://codeload.github.com/{owner}/{repo}/zip/HEAD",
            f"https://codeload.github.com/{owner}/{repo}/zip/main",
            f"https://codeload.github.com/{owner}/{repo}/zip/master",
        ]

        archive_bytes = None
        last_error = None

        for url in candidate_urls:
            try:
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "ArchInsights-AST-Scanner/1.0",
                        "Accept": "application/zip, application/octet-stream",
                    },
                )
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    if response.status == 200:
                        archive_bytes = response.read()
                        break
            except urllib.error.HTTPError as e:
                last_error = f"HTTP {e.code}: {e.reason}"
                if e.code == 404:
                    continue  # Try next candidate branch
                break
            except Exception as e:
                last_error = str(e)
                break

        if not archive_bytes:
            raise ValueError(
                f"Failed to fetch GitHub repository '{owner}/{repo}': {last_error or 'Repository not found or private'}"
            )

        # Unpack archive strictly in memory
        files: Dict[str, bytes] = {}
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue

                # Codeload zip entries start with '{repo}-{branch}/...'
                filename = info.filename.replace("\\", "/")
                parts = filename.split("/", 1)
                if len(parts) > 1 and parts[1]:
                    rel_path = parts[1]
                    ext = os.path.splitext(rel_path)[1].lower()
                    if ext in settings.SUPPORTED_EXTENSIONS:
                        files[rel_path] = z.read(info)

        if not files:
            raise ValueError(
                f"No supported source code files (.py, .js, .ts) found in GitHub repository '{owner}/{repo}'."
            )

        return self.analyze_source_files(
            files=files,
            repo_name=inferred_name,
            root_path=f"github://{owner}/{repo}",
        )
