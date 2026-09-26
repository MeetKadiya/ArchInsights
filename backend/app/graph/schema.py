"""
Neo4j Graph Schema DDL, Constraints, and Indexes.
"""

CONSTRAINTS = [
    """
    CREATE CONSTRAINT unique_repo_id IF NOT EXISTS
    FOR (r:Repository) REQUIRE r.id IS UNIQUE
    """,
    """
    CREATE CONSTRAINT unique_package_id IF NOT EXISTS
    FOR (p:Package) REQUIRE p.id IS UNIQUE
    """,
    """
    CREATE CONSTRAINT unique_module_id IF NOT EXISTS
    FOR (m:Module) REQUIRE m.id IS UNIQUE
    """,
    """
    CREATE CONSTRAINT unique_class_id IF NOT EXISTS
    FOR (c:Class) REQUIRE c.id IS UNIQUE
    """,
    """
    CREATE CONSTRAINT unique_function_id IF NOT EXISTS
    FOR (f:Function) REQUIRE f.id IS UNIQUE
    """,
]

INDEXES = [
    """
    CREATE INDEX idx_module_lang IF NOT EXISTS
    FOR (m:Module) ON (m.language)
    """,
    """
    CREATE INDEX idx_module_complexity IF NOT EXISTS
    FOR (m:Module) ON (m.cyclomatic_complexity)
    """,
    """
    CREATE INDEX idx_class_wmc IF NOT EXISTS
    FOR (c:Class) ON (c.wmc)
    """,
    """
    CREATE INDEX idx_antipattern_lookup IF NOT EXISTS
    FOR (a:AntiPattern) ON (a.type, a.severity)
    """,
]

CLEAR_DATABASE_QUERY = """
MATCH (n) DETACH DELETE n
"""
