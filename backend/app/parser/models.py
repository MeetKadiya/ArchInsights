from __future__ import annotations

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class CodeLocation(BaseModel):
    start_line: int
    start_col: int
    end_line: int
    end_col: int


class ImportItem(BaseModel):
    name: str
    alias: Optional[str] = None


class ImportStatement(BaseModel):
    source: str  # E.g. 'os.path', './utils', 'react'
    items: List[ImportItem] = Field(default_factory=list)  # Empty if whole module imported
    is_relative: bool = False
    relative_level: int = 0  # Number of dots (e.g. . or .. in python)
    location: CodeLocation


class CallSite(BaseModel):
    caller_id: str  # Function or module id where call originates
    callee_name: str  # Name of called function/method
    callee_id: Optional[str] = None  # Resolved function id if known
    location: CodeLocation


class FunctionDef(BaseModel):
    id: str
    name: str
    is_method: bool = False
    parent_class: Optional[str] = None
    visibility: str = "public"  # public, private, protected
    parameters: List[str] = Field(default_factory=list)
    return_type: Optional[str] = None
    cyclomatic_complexity: int = 1
    cognitive_complexity: int = 0
    loc: int = 1
    location: CodeLocation


class ClassDef(BaseModel):
    id: str
    name: str
    base_classes: List[str] = Field(default_factory=list)
    interfaces: List[str] = Field(default_factory=list)
    is_abstract: bool = False
    is_interface: bool = False
    methods: List[str] = Field(default_factory=list)  # Method ids
    wmc: int = 0  # Weighted Methods per Class (sum of method cyclomatic complexity)
    loc: int = 1
    location: CodeLocation


class ModuleParseResult(BaseModel):
    id: str  # Canonical module path e.g. "backend.app.main"
    file_path: str  # Path relative to repository root
    name: str  # Base file name e.g. "main.py"
    language: str  # python, javascript, typescript
    loc: int = 0
    sloc: int = 0  # Source lines of code (excluding blanks/comments)
    comment_loc: int = 0
    cyclomatic_complexity: int = 1
    maintainability_index: float = 100.0
    imports: List[ImportStatement] = Field(default_factory=list)
    classes: List[ClassDef] = Field(default_factory=list)
    functions: List[FunctionDef] = Field(default_factory=list)
    calls: List[CallSite] = Field(default_factory=list)


class DependencyEdge(BaseModel):
    source: str
    target: str
    type: str  # IMPORTS, CALLS, INHERITS_FROM, CONTAINS, DEFINES, HAS_METHOD
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphNode(BaseModel):
    id: str
    label: str  # Repository, Package, Module, Class, Function
    name: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class CodebaseGraph(BaseModel):
    repository_name: str
    root_path: str
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[DependencyEdge] = Field(default_factory=list)
    modules: Dict[str, ModuleParseResult] = Field(default_factory=dict)
