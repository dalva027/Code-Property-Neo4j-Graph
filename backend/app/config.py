from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "codegraph"
    neo4j_database: str = "neo4j"

    # Repositories are addressed by a path relative to this directory.
    repos_root: str = "./repos"
    cors_origins: list[str] = ["http://localhost:5173"]

    # Dependency analysis (extractor/, `codegraph-extract deps`). Without the binary, crates and
    # dependency edges still come from parsing Cargo.lock, but there are no advisories.
    codegraph_extractor: str = "codegraph-extract"
    advisory_db_path: str = "./.advisory-db"
    advisory_db_max_age_hours: int = 24      # refresh the database when older; 0 = never refresh
    advisory_db_offline: bool = False        # never fetch; use what is on disk
    extractor_timeout_seconds: int = 300

    # Code facts (`codegraph-extract code`, rust-analyzer). `auto` uses the extractor for every Cargo
    # project when the binary is there and falls back to tree-sitter alone when it is missing or
    # fails; `off` never runs it. The extractor runs `cargo metadata`, which downloads dependency
    # sources unless CODE_FACTS_OFFLINE is set (calls into missing dependencies stay unresolved).
    code_facts: str = "auto"
    code_facts_offline: bool = False
    code_facts_timeout_seconds: int = 1800
    code_facts_cache: str = ""               # directory for cached facts; empty = no cache

    # Taint rules: whether file contents count as untrusted input (sources group `files`).
    taint_files_are_untrusted: bool = False

    # Analyzer thresholds
    max_complexity: int = 10
    max_function_lines: int = 60
    max_class_methods: int = 20
    hub_fan_in: int = 5


settings = Settings()
