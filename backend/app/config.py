import os
from pydantic import BaseModel, Field


class Settings(BaseModel):
    APP_NAME: str = "ArchInsights: Codebase Refactoring & Architectural Debt Visualizer"
    APP_VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"

    # Neo4j Settings
    NEO4J_URI: str = Field(default_factory=lambda: os.getenv("NEO4J_URI", "bolt://localhost:7687"))
    NEO4J_USER: str = Field(default_factory=lambda: os.getenv("NEO4J_USER", "neo4j"))
    NEO4J_PASSWORD: str = Field(default_factory=lambda: os.getenv("NEO4J_PASSWORD", "architect123!"))
    NEO4J_DATABASE: str = Field(default_factory=lambda: os.getenv("NEO4J_DATABASE", "neo4j"))

    # Parser Settings
    MAX_FILE_SIZE_BYTES: int = 2 * 1024 * 1024  # 2MB max single file
    SUPPORTED_EXTENSIONS: set = {".py", ".js", ".jsx", ".ts", ".tsx"}
    EXCLUDED_DIRS: set = {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        ".next",
        ".idea",
        ".vscode",
    }


settings = Settings()
