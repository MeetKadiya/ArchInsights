import math
from typing import Set, Tuple
import tree_sitter


PYTHON_DECISION_TYPES: Set[str] = {
    "if_statement",
    "elif_clause",
    "for_statement",
    "while_statement",
    "except_clause",
    "conditional_expression",  # a if b else c
    "case_clause",
}

JS_DECISION_TYPES: Set[str] = {
    "if_statement",
    "for_statement",
    "for_in_statement",
    "for_of_statement",
    "while_statement",
    "do_statement",
    "catch_clause",
    "ternary_expression",
    "switch_case",
}

BOOLEAN_OPERATORS: Set[str] = {"and", "or", "&&", "||", "??"}


def compute_node_cyclomatic_complexity(root_node: tree_sitter.Node, language: str = "python", source_bytes: bytes = b"") -> int:
    """
    Computes McCabe's Cyclomatic Complexity for an AST subtree.
    Base complexity is 1. Each branching construct adds 1.
    """
    decision_types = PYTHON_DECISION_TYPES if language == "python" else JS_DECISION_TYPES
    complexity = 1

    # Traverse subtree iteratively
    stack = [root_node]
    while stack:
        current = stack.pop()

        # Check if node is a direct decision statement
        if current.type in decision_types:
            complexity += 1
        elif current.type in ("boolean_operator", "binary_expression"):
            # Check for boolean operators like and/or/&&/||
            for child in current.children:
                child_text = ""
                if source_bytes and child.start_byte is not None and child.end_byte is not None:
                    child_text = source_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="ignore")
                elif child.type in BOOLEAN_OPERATORS:
                    child_text = child.type

                if child.type in BOOLEAN_OPERATORS or child_text in BOOLEAN_OPERATORS:
                    complexity += 1
                    break

        for child in reversed(current.children):
            # Don't recurse into nested function or class definitions when calculating function complexity
            if current != root_node and child.type in (
                "function_definition",
                "class_definition",
                "method_definition",
                "arrow_function",
                "function_declaration",
            ):
                continue
            stack.append(child)

    return complexity


def compute_code_lines(source_code: str) -> Tuple[int, int, int]:
    """
    Calculates (Total LOC, Source LOC, Comment/Blank LOC).
    """
    lines = source_code.splitlines()
    total_loc = len(lines)
    sloc = 0
    comment_blank_loc = 0

    for line in lines:
        stripped = line.strip()
        if not stripped:
            comment_blank_loc += 1
        elif stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            comment_blank_loc += 1
        else:
            sloc += 1

    return max(1, total_loc), max(1, sloc), comment_blank_loc


def compute_halstead_volume(root_node: tree_sitter.Node, source_bytes: bytes = b"") -> float:
    """
    Estimates Halstead Volume V = N * log2(eta) from AST tokens.
    """
    operators = set()
    operands = set()
    total_operators = 0
    total_operands = 0

    stack = [root_node]
    while stack:
        curr = stack.pop()
        if curr.child_count == 0:
            text = ""
            if source_bytes and curr.start_byte is not None and curr.end_byte is not None:
                text = source_bytes[curr.start_byte:curr.end_byte].decode("utf-8", errors="ignore")
            if not text:
                text = curr.type

            # Basic token classification
            if curr.type in ("identifier", "string", "integer", "float", "true", "false", "number"):
                operands.add(text)
                total_operands += 1
            else:
                operators.add(text)
                total_operators += 1
        else:
            for child in reversed(curr.children):
                stack.append(child)

    distinct_operators = max(1, len(operators))
    distinct_operands = max(1, len(operands))
    total_ops = max(1, total_operators + total_operands)
    vocabulary = distinct_operators + distinct_operands

    return total_ops * math.log2(vocabulary)


def compute_maintainability_index(cyclomatic_complexity: int, sloc: int, halstead_volume: float) -> float:
    """
    Calculates the normalized Maintainability Index (MI) on a scale of 0 to 100.
    Formula: MI = max(0, ((171 - 5.2*ln(V) - 0.23*CC - 16.2*ln(SLOC)) * 100 / 171))
    """
    v = max(1.0, halstead_volume)
    loc = max(1, sloc)
    cc = max(1, cyclomatic_complexity)

    raw_mi = 171.0 - (5.2 * math.log(v)) - (0.23 * cc) - (16.2 * math.log(loc))
    normalized_mi = (raw_mi * 100.0) / 171.0
    return round(max(0.0, min(100.0, normalized_mi)), 2)
