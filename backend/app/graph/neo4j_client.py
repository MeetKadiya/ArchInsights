from typing import Any, Dict, List, Optional
from neo4j import GraphDatabase, Driver
from app.config import settings
from app.graph.schema import CONSTRAINTS, INDEXES, CLEAR_DATABASE_QUERY
from app.graph.queries import (
    DETECT_CIRCULAR_DEPENDENCIES,
    DETECT_GOD_CLASSES,
    DETECT_TIGHT_COUPLING,
    DETECT_SHOTGUN_SURGERY,
    FETCH_GRAPH_FOR_VISUALIZATION,
    FETCH_PACKAGE_METRICS,
)
from app.parser.models import CodebaseGraph


class Neo4jClient:
    """
    High-performance Neo4j graph connector supporting batch ingestion,
    schema constraint creation, and anti-pattern query execution.
    """

    def __init__(self, uri: Optional[str] = None, user: Optional[str] = None, password: Optional[str] = None):
        self.uri = uri or settings.NEO4J_URI
        self.user = user or settings.NEO4J_USER
        self.password = password or settings.NEO4J_PASSWORD
        self.database = settings.NEO4J_DATABASE
        self._driver: Optional[Driver] = None

    def connect(self) -> bool:
        """Establishes driver connection and verifies connectivity."""
        try:
            self._driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
                max_connection_lifetime=30 * 60,
                max_connection_pool_size=50,
            )
            self._driver.verify_connectivity()
            return True
        except Exception as e:
            print(f"[Neo4jClient] Connection failed: {e}")
            self._driver = None
            return False

    def is_connected(self) -> bool:
        if self._driver is None:
            return False
        try:
            self._driver.verify_connectivity()
            return True
        except Exception:
            return False

    def close(self):
        if self._driver:
            self._driver.close()
            self._driver = None

    def init_schema(self):
        """Initializes unique constraints and performance indexes."""
        if not self.is_connected():
            raise RuntimeError("Neo4j database is not connected.")

        with self._driver.session(database=self.database) as session:
            for constraint_ddl in CONSTRAINTS:
                try:
                    session.run(constraint_ddl)
                except Exception as e:
                    print(f"[Neo4jClient] Notice applying constraint: {e}")

            for index_ddl in INDEXES:
                try:
                    session.run(index_ddl)
                except Exception as e:
                    print(f"[Neo4jClient] Notice applying index: {e}")

    def clear_database(self):
        """Wipes the database for clean ingestion."""
        if not self.is_connected():
            raise RuntimeError("Neo4j database is not connected.")
        with self._driver.session(database=self.database) as session:
            session.run(CLEAR_DATABASE_QUERY)

    def ingest_codebase_graph(self, graph: CodebaseGraph, clear_existing: bool = True):
        """
        Batch-ingests a CodebaseGraph into Neo4j using UNWIND queries for optimal throughput.
        """
        if not self.is_connected():
            raise RuntimeError("Neo4j database is not connected.")

        if clear_existing:
            self.clear_database()

        self.init_schema()

        # Group nodes by label for UNWIND batching
        nodes_by_label: Dict[str, List[Dict[str, Any]]] = {}
        for node in graph.nodes:
            nodes_by_label.setdefault(node.label, []).append(
                {
                    "id": node.id,
                    "name": node.name,
                    "properties": node.properties,
                }
            )

        with self._driver.session(database=self.database) as session:
            # 1. Batch insert nodes per label
            for label, batch in nodes_by_label.items():
                query = f"""
                UNWIND $batch AS item
                MERGE (n:{label} {{id: item.id}})
                SET n.name = item.name,
                    n += item.properties
                """
                session.run(query, batch=batch)

            # 2. Batch insert edges grouped by edge type
            edges_by_type: Dict[str, List[Dict[str, Any]]] = {}
            for edge in graph.edges:
                edges_by_type.setdefault(edge.type, []).append(
                    {
                        "source": edge.source,
                        "target": edge.target,
                        "properties": edge.properties,
                    }
                )

            for rel_type, batch in edges_by_type.items():
                query = f"""
                UNWIND $batch AS rel
                MATCH (s {{id: rel.source}}), (t {{id: rel.target}})
                MERGE (s)-[r:{rel_type}]->(t)
                SET r += rel.properties
                """
                session.run(query, batch=batch)

    def detect_circular_dependencies(self) -> List[Dict[str, Any]]:
        if not self.is_connected():
            return []
        with self._driver.session(database=self.database) as session:
            result = session.run(DETECT_CIRCULAR_DEPENDENCIES)
            return [record.data() for record in result]

    def detect_god_classes(self) -> List[Dict[str, Any]]:
        if not self.is_connected():
            return []
        with self._driver.session(database=self.database) as session:
            result = session.run(DETECT_GOD_CLASSES)
            return [record.data() for record in result]

    def detect_tight_coupling(self) -> List[Dict[str, Any]]:
        if not self.is_connected():
            return []
        with self._driver.session(database=self.database) as session:
            result = session.run(DETECT_TIGHT_COUPLING)
            return [record.data() for record in result]

    def detect_shotgun_surgery(self) -> List[Dict[str, Any]]:
        if not self.is_connected():
            return []
        with self._driver.session(database=self.database) as session:
            result = session.run(DETECT_SHOTGUN_SURGERY)
            return [record.data() for record in result]

    def fetch_visualization_graph(self) -> Dict[str, Any]:
        if not self.is_connected():
            return {"nodes": [], "links": []}
        with self._driver.session(database=self.database) as session:
            result = session.run(FETCH_GRAPH_FOR_VISUALIZATION)
            record = result.single()
            if record:
                # filter out null links
                raw_nodes = record.get("nodes", [])
                raw_links = [link for link in record.get("links", []) if link.get("target") is not None]
                return {"nodes": raw_nodes, "links": raw_links}
            return {"nodes": [], "links": []}

    def fetch_package_metrics(self) -> List[Dict[str, Any]]:
        if not self.is_connected():
            return []
        with self._driver.session(database=self.database) as session:
            result = session.run(FETCH_PACKAGE_METRICS)
            return [record.data() for record in result]
