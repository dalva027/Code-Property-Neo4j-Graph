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
| Parsers | `backend/app/graph/parsers/` | One `LanguageParser` per language: Python (stdlib `ast`) and Rust (tree-sitter). Each returns a `ParsedFile` of symbols, imports, calls, inheritance/impls and metrics. |
| Builder | `backend/app/graph/builder.py` | Walks the tree, runs parsers, resolves references lexically, emits an in-memory `CodeGraph`. Pure Python, unit-tested. |
| Extractor | `extractor/` | `codegraph-extract`, a Rust CLI. `deps` matches a `Cargo.lock` against the RustSec advisory database with the same logic as cargo-audit and prints JSON. |
| Dependencies | `backend/app/graph/deps.py` | Runs the extractor per `Cargo.lock` (or parses the lockfile itself when the binary is missing), finds workspace members and dependency kinds in the manifests, and links crates to files and called paths. |
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
(Function)-[:CALLS {line, count}]->(Function|External)
(Class)-[:INHERITS]->(Class)              Python base classes, Rust supertraits
(Class)-[:IMPLEMENTS]->(Class)            Rust `impl Trait for Type`
(File|Symbol|Crate)-[:HAS_FINDING]->(Finding)

(Function)-[:REFERENCES {via, line}]->(Function|External)   passed as a value: get(handler), spawn(worker)
(Function)-[:CONTAINS]->(Unsafe)            unsafe block/fn/impl/trait spans {has_safety_comment}
(Function)-[:HAS_CALL]->(Call)-[:TARGETS]->(External)   one call site: index/arith ops, catalogue callees
(Function|File)-[:HAS_LITERAL]->(Literal)   secret-looking string literal, redacted

(Project)-[:HAS_CRATE]->(Crate)
(Crate)-[:DEPENDS_ON {kind}]->(Crate)       kind (normal, dev, build) on members' direct deps
(Crate)-[:AFFECTED_BY {kind, functions}]->(Advisory)
(Crate)-[:HAS_FILE]->(File)                 workspace members
(File)-[:USES]->(Crate)                     crate named in `use` / `extern crate`
(External)-[:FROM_CRATE]->(Crate)           called path whose first segment names the crate
```

`Crate` nodes are the packages in each `Cargo.lock` (`name`, `version`, `source`,
`workspace_member`, `manifest_path`; `file`/`line_start` point at the package in the lockfile),
plus unsafe counts summed over their files. `Advisory` nodes are global, one per RustSec id,
shared by every project they affect and removed when nothing references them.

Rust functions also carry `visibility`, `is_unsafe`, `is_async`, `abi`, `no_mangle`, `in_test`,
`params` (JSON) and `entry_kind`: `main`, `handler` (passed to a routing builder such as
`get(handler)` or `.service(index)`, or taking a framework extractor type), `pub_api` (a `pub`
fn of a library crate), `ffi` (`extern "C"` or `#[no_mangle]`), `test`. After a scan, a
breadth-first pass over CALLS and REFERENCES sets `reachable_from_entry` and `entry_distance` on
every function, so the rules can ask "does an entry point reach this?" in one hop.

`Unsafe` spans record whether a `// SAFETY:` comment (or a `# Safety` doc section for fns) sits
directly above them. `Call` nodes exist only where a rule needs a precise site: indexing with a
non-literal index (`ops::index`), arithmetic inside unsafe (`ops::arith`), and calls whose callee
is in the rule catalogue, with `in_unsafe` and the literal arguments (`literal_args`). `Literal`
nodes keep a redacted preview, a sha256, the entropy and the binding name; the value itself is
never stored.

Every node carries `project_id`, `id` (`<project_id>:<qualified_name>`), `kind`, `name`,
`qualified_name`, `file`, `line_start`/`line_end`, `language`, an optional `subkind`, numeric
metrics as flat properties (`loc`, `complexity`, `parameters`, `decorators`, `methods`, and for Rust
`fields`/`variants`), and non-numeric attributes as flat properties too (`attrs` in the API).

`Symbol:External` nodes stand for things a Rust project calls but does not define. Each has a
`path` in `::` form: `std::process::Command::new`, `?::unwrap` when the receiver type is unknown, or
`std::println!` for a macro (`is_macro: true`, `subkind: macro`). `crate` is set when the path is
qualified. Python's unresolved calls are still dropped. `CALLS` edges carry the first call site's
`line` and the number of call sites (`count`).

Findings carry `rule`, `severity` (`info`, `warning`, `error`, `critical`), `category` (`quality`,
or one of the five vulnerability classes `unsafe`, `panic`, `injection`, `dependency`, `crypto`),
`confidence`, `cwe` ids, `line`/`line_end`, `evidence` (ordered node ids that justify the
finding) and `rule_version`. Constraints and indexes, including the schema v2 indexes for
externals, entry points, crates and advisories, live in `backend/app/db/schema.cypher` and are
applied at startup.

## Quick start

```bash
docker compose up --build
```

- UI: http://localhost:5173
- API docs: http://localhost:8000/docs
- Neo4j Browser: http://localhost:7474 (neo4j / codegraph)

Repositories to analyze go under `./repos/` (mounted read-only into the API container). A
deliberately flawed `repos/sample` is included: in the UI the **Add repository** panel lists the
folders found under `repos/`; pick `sample`, click **Scan sample**, wait for the scan to finish,
then **Run analysis**. You should see a circular import, an over-complex function, and a few unused
functions. `repos/sample-rust` does the same for Rust (see its README). For Rust, turn on the
**external** chip to see std, crate and macro callees.

Same thing over HTTP. Scans run in the background, so creating a project returns `202` at once:

```bash
curl -X POST localhost:8000/api/projects -H 'content-type: application/json' \
     -d '{"name":"sample","path":"sample"}'
curl localhost:8000/api/projects/<id>/status          # repeat until "status": "ready"
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
pytest                        # unit tests need no database; the ground-truth harness needs Docker

# Web
cd frontend
npm install
cp .env.example .env
npm run dev
```

The API runs without the extractor; it then reads crates from `Cargo.lock` but finds no
advisories, and says so in the project's scan warnings. To get advisories without a Rust
toolchain, run the extractor through Docker:

```bash
docker build -t codegraph-extract extractor
export CODEGRAPH_EXTRACTOR=$PWD/scripts/codegraph-extract-docker   # mounts the repo at its own path
export ADVISORY_DB_PATH=$PWD/backend/.advisory-db                  # cloned on first use
```

With cargo installed, `cargo install --path extractor` works too. `ADVISORY_DB_MAX_AGE_HOURS`
(default 24) controls when the database is refreshed and `ADVISORY_DB_OFFLINE=true` never fetches.
In Docker the image builds the extractor and keeps the database in the `advisory_db` volume.

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/repos?path=` | Browse folders under `REPOS_ROOT` with source-file counts; flags ones already scanned |
| `GET` | `/api/projects` | List projects |
| `POST` | `/api/projects` | `{name, path}` — register a folder under `REPOS_ROOT` and start scanning it (`202`, `status: scanning`) |
| `GET` | `/api/projects/{id}` | Project summary, including scan `status` (`scanning`, `ready`, `failed`) and `error` |
| `GET` | `/api/projects/{id}/status` | Scan status only, for polling |
| `POST` | `/api/projects/{id}/ingest` | Start a re-scan (`202`; `409` if one is running). Findings are cleared when the new graph lands |
| `DELETE` | `/api/projects/{id}` | Stop any running scan; remove project, graph and findings |
| `GET` | `/api/projects/{id}/graph?limit=` | Nodes + edges for the visualizer (`409` while scanning) |
| `GET` | `/api/projects/{id}/node?id=` | One node with incoming/outgoing edges (with props) and findings |
| `POST` | `/api/projects/{id}/analyze` | Run the analyzers that apply to the project's languages; counts by severity, rule and category (`409` while scanning) |
| `GET` | `/api/projects/{id}/findings?severity=&rule=&category=` | Findings, worst first |
| `GET` | `/api/projects/{id}/advisories` | RustSec advisories affecting the project, with the crate versions they hit |
| `GET` | `/api/projects/{id}/advisories/{advisory_id}/blast-radius` | Affected crates, dependency paths from each workspace member, calling functions (flagging affected ones) and importing files |
| `GET` | `/api/rules` | Rules with category, CWE ids, languages and version, plus the catalogue version and digest |
| `GET` | `/api/health` | Pings Neo4j |

## Rules that ship

| Rule | Severity | Signal |
|---|---|---|
| `circular-import` | error | `(a)-[:IMPORTS]->(b)` and a path `(b)-[:IMPORTS*]->(a)`; Python only, since Rust modules may `use` each other cyclically |
| `unused-function` | warning | Function with no incoming `CALLS`; skips tests, entry points, decorated (attributed, in Rust) and `_private` names, and Rust trait methods |
| `high-complexity` | warning | `complexity > MAX_COMPLEXITY` (10) |
| `god-class` | warning | `methods > MAX_CLASS_METHODS` (20) |
| `long-function` | info | `loc > MAX_FUNCTION_LINES` (60) |
| `hub-file` | info | Imported by ≥ `HUB_FAN_IN` (5) files |
| `vulnerable-dependency` | by CVSS | A `Cargo.lock` crate version has a RustSec vulnerability; the same set cargo-audit reports |
| `vulnerable-api-reachable` | ≥ error | The code calls a function the advisory names as affected |
| `vulnerable-crate-used` | warning | The code calls the vulnerable crate (medium confidence), only imports it, or reaches it through a dependency it uses (low) |
| `vulnerable-dependency-unused` | info | The vulnerable crate is neither called nor imported, directly or through a used dependency |
| `unmaintained-or-unsound-dependency` | warning / info | Informational advisory: unsound (warning), unmaintained or notice (info) |
| `duplicate-crate-versions` | info | One crate locked at several versions |
| `unsafe-reachable-from-entry` | warning | A function with `unsafe` code that an entry point reaches within 8 calls; evidence is the call chain |
| `undocumented-unsafe` | info | An `unsafe` block, fn, impl or trait with no SAFETY comment (clippy's `undocumented_unsafe_blocks`) |
| `dangerous-unsafe-op` | warning | Inside unsafe: transmute, from_raw_parts, set_len, get_unchecked, ptr read/write/copy, Box::from_raw, zeroed, assume_init, raw pointer arithmetic |
| `unsafe-send-sync-impl` | warning | `unsafe impl Send` / `unsafe impl Sync` |
| `ffi-surface` | info | `extern` fns, `#[no_mangle]` exports, foreign fn declarations and raw-pointer parameters |
| `panic-reachable-from-entry` | warning | unwrap, expect, unwrap_unchecked, panic!, unreachable!, todo!, unimplemented! in a function an entry point reaches; one finding per function, test code excluded |
| `unchecked-index` | info | Indexing with a non-literal index, per function |
| `unbounded-recursion` | warning | A call-graph cycle an entry point reaches, with no depth-like parameter or comparison in it |
| `weak-hash-algorithm` | warning | MD5 or SHA-1: the md5/sha1/sha1_smol crates, openssl MessageDigest::{md5,sha1}, ring's legacy SHA-1 |
| `insecure-randomness` | warning | SmallRng, StepRng, fastrand, oorandom, or a constant seed |
| `hardcoded-secret` | error / warning / info | A literal bound to a secret-like name or in a known key format; severity by format match, entropy and length |
| `tls-verification-disabled` | error | danger_accept_invalid_certs(true), SslVerifyMode::NONE, rustls `.dangerous()`, a custom ServerCertVerifier |
| `insecure-cipher-or-mode` | warning | des, rc2, rc4, blowfish, ecb crates; openssl DES/RC4/Blowfish/AES-ECB |
| `weak-kdf-parameters` | warning | PBKDF2 under 100 000 rounds, Argon2 under 19 MiB / t=2, scrypt log_n under 15, bcrypt cost under 10 (literal arguments) |

Thresholds are environment variables (see `backend/app/config.py`).

The first six are `quality` rules. The others are the security classes `dependency` (D),
`unsafe` (U), `panic` (P) and `crypto` (C); they run for Rust projects only and read their
patterns from the rule catalogue. Exactly one of the three `vulnerable-*` triage rules fires per
vulnerable crate and advisory, next to the `vulnerable-dependency` finding. Class T, injection via
taint tracking, needs the typed extractor of phase 3 (see [`docs/build-plan.md`](docs/build-plan.md)).

Every security finding carries `evidence`, an ordered list of node ids: for reachability rules the
chain from the entry point to the function, then the unsafe span or call site. `/projects/{id}/node`
resolves each id.

The scripts under `eval/` compare the rules with other tools (see `eval/README.md`):
`deps_parity.py` against `cargo audit` (ripgrep, fd and zola match exactly), `clippy_compare.py`
against clippy's unwrap/expect/indexing/undocumented-unsafe lints per source line,
`geiger_compare.py` against cargo-geiger's unsafe counts, and `anchors.py` runs real RustSec
advisories on their vulnerable snapshot.

### Rule catalogue

`backend/app/rules/*.yaml` holds the data the security rules use: taint sources, sinks and
sanitizers per rule id, dangerous unsafe operations, weak-crypto APIs and secret patterns.
`catalogue.yaml` lists the files and carries the catalogue `version`. Paths are Rust paths in `::`
form, with brace groups (`std::fs::{read,write}`), `*` for one segment, `?::method` for an unknown
receiver and a trailing `!` for macros. The loader validates everything at startup and computes a
sha256 digest over the files. `/api/rules` and every analysis report state the version, so
evaluation runs are reproducible.

### Ground truth and evaluation

Any directory under `repos/` with an `expected.json` is a ground-truth case: it lists the findings
the analyzers must produce as `{rule, file, line}`, optionally limited by a `scope` of categories
or rules. `repos/sample`, `repos/sample-rust` and the four crates under `repos/vuln-samples/`
(`deps`, `unsafe`, `panics`, `crypto`, one per security class) have one. `backend/tests/test_ground_truth.py` scans every case into a
throwaway Neo4j (testcontainers, so Docker must be running), analyzes it and requires precision and
recall of 1 for every rule in scope. Set `CODEGRAPH_TEST_NEO4J_URI` to use an existing Neo4j
instead; the test only touches the projects it creates.

To score a project by hand:

```bash
cd backend
python -m app.evaluate --path sample-rust --expected ../repos/sample-rust/expected.json
python -m app.evaluate --project <id> --expected <file> --analyze --json
```

`--path` scans a folder under `REPOS_ROOT` into a temporary project and deletes it afterwards. The
exit status is 0 when every rule in scope matches exactly.

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

    # Optional: category (default quality), cwe ids, languages (default all), version.

    async def run(self, repo, project_id):
        rows = await repo.query(self.QUERY, pid=project_id)
        return [self.finding(project_id, f"{r['qname']} sits deep in an inheritance chain",
                             node_id=r["id"], file=r["file"], line=r["line"]) for r in rows]
```

**Add a language.** Implement `LanguageParser` (`graph/parsers/base.py`) and append it to
`PARSERS`. The builder and everything downstream are language-agnostic. `parsers/rust.py` is a
worked tree-sitter example; the same approach fits TypeScript/Go/Java.

### How Rust maps onto the graph

| Rust | Node / edge | `subkind` |
|---|---|---|
| `struct` / `enum` / `union` / `trait` | `Class` | `struct` / `enum` / `union` / `trait` |
| free `fn` | `Function` | `fn` |
| fn in `impl Type` | `Function`, contained by the type | `method` |
| fn in `impl Trait for Type` | `Function` named `Type.<Trait>.fn` | `trait impl fn` |
| fn declared in a `trait` | `Function`, contained by the trait | `trait fn` |
| `impl Trait for Type` | `IMPLEMENTS` edge | |
| `trait A: B` | `INHERITS` edge | |
| `use` | `IMPORTS` edge to the file of the named module | |
| call to std, another crate or an unknown receiver | `CALLS` edge to an `External` node | `external` |
| macro invocation (`println!`, `log::info!`, `tokio::select!`) | `CALLS` edge to an `External` node | `macro` |

Modules come from paths: `<crate>/src/lib.rs` is `<crate>`, `src/main.rs` is `<crate>.main`,
`src/a.rs` and `src/a/mod.rs` are `<crate>.a`. The crate is named after its directory (dashes become
underscores), or `crate` when the package is the scanned folder itself. `crate::`, `self::`,
`super::`, `Self::` and `use` aliases are rewritten to these names before resolution. Cargo's
`target/` is skipped.

Arguments of format-like macros (`println!`, `format!`, `write!`, `assert*!`, `vec!`, `panic!`, and
the `log`/`tracing`/`anyhow` macros) are re-parsed as expressions, so calls inside them count.
Calls that cannot resolve and have no meaningful external path are dropped: enum variant
constructors, prelude constructors such as `Some` and `Ok`, bare names such as closures, and paths
into the project's own crate.

## Known limits and next steps

- The security rules are syntactic. Receiver types are unknown, so `v.insert_many(..)` is
  `?::insert_many` and only path calls match an advisory's affected functions; `unchecked-index`
  cannot tell a slice from a map; `insecure-randomness` cannot tell whether the output becomes a key;
  a handler is only recognised through the routing builders and extractor types the catalogue lists;
  `pub_api` entry points over-approximate (a `pub` fn in a private module counts). The recursion
  rule's depth guard is a name heuristic (`depth`, `recursion`, `budget`, ...). Phase 3's typed
  extractor replaces these approximations.
- Dependency triage is syntactic: affected functions are matched only when called by their path
  (`SmallVec::insert_many(..)`, not `v.insert_many(..)`); calls from tests and examples count as
  use, and dev-dependencies are not told apart in the rules yet; reachability beyond direct callers
  of the crate comes in phase 2. Yanked crates are not checked (that needs the crates.io index), and
  a `Cargo.toml` without a `Cargo.lock` is reported as a scan warning, not resolved.
- Scans run as in-process background tasks, one at a time per project. A scan that is running
  when the API restarts is marked `failed` at startup and needs a rescan. A job queue would be the
  next step for several API workers.
- Reference resolution is lexical (no type inference); dynamic dispatch and re-exports are missed.
  `self.method()` only resolves against the enclosing class/impl/trait, not base classes or
  supertraits.
- Rust specifics: only format-like macros (`println!`, `format!`, `assert!`, `vec!`, logging) have
  their arguments re-parsed, so calls inside other macros are missed; method calls on non-`self`
  receivers resolve only when the method name is unique, and otherwise become a `?::name` external
  rather than a guess; the crate's own name (`use my_crate::...` from `main.rs` or `tests/`) isn't
  known unless the crate sits in a folder of that name; `methods` on a type counts impls in its own
  file only; `pub` API functions of a library crate are still reported as unused.
- The graph endpoint returns everything up to `limit`. For big projects, add neighborhood
  queries (`node?id=&depth=`) and let the UI expand on click.
- Obvious additions: diff-scoped analysis for PRs (only nodes touched by a commit), a
  "blast radius" query (`what depends on X, transitively?`), and GitHub webhook ingestion.

## Roadmap

The project is heading toward vulnerability detection and visualization for Rust: unsafe code,
panics, taint-based injection, vulnerable dependencies, and crypto/secrets, backed by a
rust-analyzer based extractor. The phased plan, schema v2 and evaluation design are in
[`docs/build-plan.md`](docs/build-plan.md).
