# codegraph

A code review / static-analysis platform that stores a **code graph** in Neo4j and expresses
every rule as a graph query.

React + TypeScript (Vite) · FastAPI · Neo4j 5

```
repos/<project>  ──►  GraphBuilder  ──►  Neo4j  ──►  Analyzers  ──►  Findings
   source tree        (ast parsers)     code graph    (Cypher rules)    attached to nodes
                                            │
                                            ▼
                                   React UI: force-directed graph,
                                   filters, findings → node inspector
```

## How it fits together

| Layer | Where | What it does |
|---|---|---|
| Parsers | `backend/app/graph/parsers/` | One `LanguageParser` per language. Python ships (stdlib `ast`); each returns a `ParsedFile` of symbols, imports, calls, inheritance and metrics. |
| Builder | `backend/app/graph/builder.py` | Walks the tree, runs parsers, resolves references lexically, emits an in-memory `CodeGraph`. Pure Python, unit-tested. |
| Repository | `backend/app/graph/repository.py` | The only module that speaks Cypher. Upserts graphs, reads them back, stores findings. |
| Analyzers | `backend/app/analyzers/` | `Analyzer` subclasses; each `run()` is a Cypher query that yields `Finding`s. Registered with `@register`. |
| API | `backend/app/api/` | FastAPI routers. Docs at `/docs`. |
| Web | `frontend/src/` | Project sidebar with a folder picker for `repos/`, force-directed graph canvas (`react-force-graph-2d`), findings panel, node inspector. Data via TanStack Query. |

### Graph model

```
(Project)-[:HAS_FILE]->(File)
(File)-[:CONTAINS]->(Symbol:Class|Function)
(Class)-[:CONTAINS]->(Function)            methods
(File)-[:IMPORTS]->(File)
(Function)-[:CALLS]->(Function)
(Class)-[:INHERITS]->(Class)
(File|Symbol)-[:HAS_FINDING]->(Finding)
```

Every node carries `project_id`, `id` (`<project_id>:<qualified_name>`), `kind`, `name`,
`qualified_name`, `file`, `line_start`/`line_end`, and numeric metrics as flat properties
(`loc`, `complexity`, `parameters`, `decorators`, `methods`). Constraints and indexes live in
`backend/app/db/schema.cypher` and are applied at startup.

## Quick start

```bash
docker compose up --build
```

- UI: http://localhost:5173
- API docs: http://localhost:8000/docs
- Neo4j Browser: http://localhost:7474 (neo4j / codegraph)

Repositories to analyze go under `./repos/` (mounted read-only into the API container). A
deliberately flawed `repos/sample` is included: in the UI the **Add repository** panel lists the
folders found under `repos/`; pick `sample`, click **Scan sample**, then **Run analysis**. You should see a circular import, an
over-complex function, and a few unused functions.

Same thing over HTTP:

```bash
curl -X POST localhost:8000/api/projects -H 'content-type: application/json' \
     -d '{"name":"sample","path":"sample"}'
curl -X POST localhost:8000/api/projects/<id>/analyze
curl localhost:8000/api/projects/<id>/findings
```

### Running without Docker

```bash
# Neo4j
docker run -d --name neo4j -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/codegraph neo4j:5

# API
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env          # REPOS_ROOT defaults to ../repos
uvicorn app.main:app --reload
pytest                        # builder/parser tests, no database needed

# Web
cd frontend
npm install
cp .env.example .env
npm run dev
```

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/repos?path=` | Browse folders under `REPOS_ROOT` with source-file counts; flags ones already scanned |
| `GET` | `/api/projects` | List projects |
| `POST` | `/api/projects` | `{name, path}` — scan a folder under `REPOS_ROOT`, build its graph |
| `GET` | `/api/projects/{id}` | Project summary |
| `POST` | `/api/projects/{id}/ingest` | Re-scan and rebuild (clears findings) |
| `DELETE` | `/api/projects/{id}` | Remove project, graph and findings |
| `GET` | `/api/projects/{id}/graph?limit=` | Nodes + edges for the visualizer |
| `GET` | `/api/projects/{id}/node?id=` | One node with incoming/outgoing edges and findings |
| `POST` | `/api/projects/{id}/analyze` | Run all analyzers; returns counts by severity and rule |
| `GET` | `/api/projects/{id}/findings?severity=&rule=` | Findings, worst first |
| `GET` | `/api/rules` | Registered rules and their descriptions |
| `GET` | `/api/health` | Pings Neo4j |

## Rules that ship

| Rule | Severity | Signal |
|---|---|---|
| `circular-import` | error | `(a)-[:IMPORTS]->(b)` and a path `(b)-[:IMPORTS*]->(a)` |
| `unused-function` | warning | Function with no incoming `CALLS`; skips tests, entry points, decorated and `_private` names |
| `high-complexity` | warning | `complexity > MAX_COMPLEXITY` (10) |
| `god-class` | warning | `methods > MAX_CLASS_METHODS` (20) |
| `long-function` | info | `loc > MAX_FUNCTION_LINES` (60) |
| `hub-file` | info | Imported by ≥ `HUB_FAN_IN` (5) files |

Thresholds are environment variables (see `backend/app/config.py`).

## Extending

**Add a rule.** Subclass `Analyzer` in `backend/app/analyzers/`, decorate with `@register`,
and import the module from `analyzers/__init__.py`:

```python
@register
class DeepInheritance(Analyzer):
    rule = "deep-inheritance"
    severity = Severity.info
    description = "Class more than three levels below its root."

    QUERY = """
    MATCH p = (c:Class {project_id: $pid})-[:INHERITS*4..]->(:Class)
    RETURN DISTINCT c.id AS id, c.qualified_name AS qname, c.file AS file, c.line_start AS line
    """

    async def run(self, repo, project_id):
        rows = await repo.query(self.QUERY, pid=project_id)
        return [self.finding(project_id, f"{r['qname']} sits deep in an inheritance chain",
                             node_id=r["id"], file=r["file"], line=r["line"]) for r in rows]
```

**Add a language.** Implement `LanguageParser` (`graph/parsers/base.py`) and append it to
`PARSERS`. The builder and everything downstream are language-agnostic. tree-sitter is the
natural fit for TypeScript/Go/Java.

## Known limits and next steps

- Ingestion runs inside the request. Fine for small and mid-size repos; large ones want a
  background task (e.g. `BackgroundTasks` or a queue) plus a status endpoint.
- Reference resolution is lexical (no type inference); dynamic dispatch and re-exports are missed.
- The graph endpoint returns everything up to `limit`. For big projects, add neighborhood
  queries (`node?id=&depth=`) and let the UI expand on click.
- Obvious additions: diff-scoped analysis for PRs (only nodes touched by a commit), a
  "blast radius" query (`what depends on X, transitively?`), and GitHub webhook ingestion.
