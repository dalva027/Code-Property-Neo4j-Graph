# codegraph

A code review / static-analysis platform that stores a **code graph** in Neo4j and expresses
every rule as a graph query.

React + TypeScript (Vite) · FastAPI · Neo4j 5

```
repos/<project>  ──►  GraphBuilder  ──►  Neo4j  ──►  Analyzers  ──►  Findings
   source tree        (ast parsers)     code graph    (Cypher rules)    attached to nodes
        │                  ▲                │
        ▼                  │                ▼
  codegraph-extract ───────┘       React UI: code and dependency graphs,
  (rust-analyzer: resolved calls,  severity overlay, evidence paths step
   types, data flow; RustSec)      by step, source panel, SARIF export
```

## How it fits together

| Layer | Where | What it does |
|---|---|---|
| Parsers | `backend/app/graph/parsers/` | One `LanguageParser` per language: Python (stdlib `ast`) and Rust (tree-sitter). Each returns a `ParsedFile` of symbols, imports, calls, inheritance/impls and metrics. |
| Builder | `backend/app/graph/builder.py` | Walks the tree, runs parsers, resolves references lexically, emits an in-memory `CodeGraph`. Pure Python, unit-tested. |
| Extractor | `extractor/` | `codegraph-extract`, a Rust CLI. `deps` matches a `Cargo.lock` against the RustSec advisory database with the same logic as cargo-audit. `code` loads the Cargo workspace with rust-analyzer (as a library) and reports every call site resolved to its definition, receiver types, the calls macro expansions make, and a def-use data-flow graph. Both print JSON. |
| Code facts | `backend/app/graph/facts.py` | Runs `codegraph-extract code` per Cargo workspace and joins its facts onto the tree-sitter parse by source position. Without the binary, or when a run fails, the tree-sitter facts stand and the scan says so in its warnings. |
| Dependencies | `backend/app/graph/deps.py` | Runs the extractor per `Cargo.lock` (or parses the lockfile itself when the binary is missing), finds workspace members and dependency kinds in the manifests, and links crates to files and called paths. |
| Repository | `backend/app/graph/repository.py` | The only module that speaks Cypher. Upserts graphs, reads them back, stores findings. |
| Analyzers | `backend/app/analyzers/` | `Analyzer` subclasses; each `run()` is a Cypher query that yields `Finding`s. Registered with `@register`. |
| API | `backend/app/api/` | FastAPI routers. Docs at `/docs`. |
| Web | `frontend/src/` | Project sidebar with a folder picker for `repos/`; two force-directed canvases (`react-force-graph-2d`), the code graph and the dependency graph, with findings drawn on them; findings, evidence-path, advisory and node panels; a source panel. Data via TanStack Query. See [The UI](#the-ui). |

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

(Function)-[:DECLARES]->(Var)               a parameter, local or return value        ┐ with the
(Var|Call)-[:FLOWS_TO {via, vias}]->(Var|Call)   data flow inside one function        │ rust-analyzer
(Var|Call)-[:PASSES {via}]->(Var)           an argument to the callee's parameter     │ extractor
(Var)-[:RETURNS_TO]->(Call|Var)             the callee's return value to the call site ┘ only

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
`path` in `::` form: `std::process::Command::new`, or `std::println!` for a macro (`is_macro: true`,
`subkind: macro`). With the extractor a method call carries its receiver's real type
(`std::option::Option::unwrap`); with tree-sitter alone the receiver is unknown and the path is
`?::unwrap`. `crate` is the defining crate, and `aliases` lists the other paths the same item goes
by (where it is defined, where it is re-exported). Python's unresolved calls are still dropped.
`CALLS` edges carry the first call site's `line` and the number of call sites (`count`).

With the extractor every call site is a `Call` node (`callee_path`, `ret_kind`, `recv_type`,
`arg_count`, `in_macro` for a site inside a macro invocation, `writes_out` for a call with a
`&mut` argument), as are index operations (`base_kind`: slice, array, vec, str, map), integer
arithmetic and struct literals. `Var` nodes carry `type`, `ty_kind` (int, bool, str, other, ...),
`type_path`, for parameters the declared `param_type` (`axum::extract::Query`), and `guards`: the
checks applied to the variable anywhere in its function (`starts_with`, `cmp`, `match`, ...). The
flow edges are flow-insensitive and field-insensitive; `via` says how a value arrived (`assign`,
`arg:0`, `recv`, `macro`, `mut`, `out`, `field:name`, `return`, `dispatch`).

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

The API image carries the Rust toolchain, because the code extractor is rust-analyzer and needs
cargo, rustc and the standard library sources at run time. Scanning a Cargo project runs
`cargo metadata`, which downloads the project's dependencies (sources only, into the
`cargo_registry` volume); nothing in the scanned project is built or executed, build scripts and
proc macros included, and nothing is written into it.

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

### The UI

- **Code graph** draws files, types, functions and (with the **external** chip) the std, crate and
  macro paths they call. Each node has a halo in the colour of its worst finding, functions with
  several findings carry a count, and file names show how many findings the file holds; **colour by
  severity** fills the nodes by severity instead of by kind.
- **Findings** (right panel) can be filtered by severity, category and confidence, and the canvases
  follow the same filters. They group by category, file, crate or rule. CWE ids link to MITRE.
  **SARIF** downloads every finding as SARIF 2.1.0 with its evidence path as a code flow; open
  it in VS Code's SARIF viewer with the scanned project as the workspace.
- **Evidence path.** Clicking a finding lists the nodes that justify it, in order: source to sink
  for a taint flow (every variable, call and argument position on the way), entry point to site
  for an unsafe or panic finding, crate to advisory for a dependency finding. The path is drawn
  on the canvas and everything else is dimmed. Arrow keys step through it, and each step opens its
  line in the source panel, where every step in the same file is numbered in the gutter.
- **Dependencies** draws the crates of every `Cargo.lock` (workspace members as rings), their
  dependency edges and the advisories that affect them; on a large lockfile it starts with only
  the crates on a path to an advisory. The **Advisories** tab lists the advisories. Picking one
  shows its blast radius (rule D4): the dependency paths from each member, every function that
  calls into the affected crate with the line of each call (affected functions flagged), and the
  importing files. **code graph** shows those functions and calls in the code graph. From the
  project, an advisory's calling line is three clicks away: **Dependencies**, the advisory, the line.
- **Source panel** shows the file around a line with findings (dots in the gutter, which open the
  finding), unsafe spans (orange bar) and SAFETY comments (green) marked. It serves only files the
  project's graph knows, plus its `Cargo.toml` and `Cargo.lock` files. Escape closes it.

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
pytest                        # unit tests need no database; the harness and endpoint tests need Docker

# Web
cd frontend
npm install
cp .env.example .env
npm run dev
```

The API runs without the extractor. It then reads crates from `Cargo.lock` but finds no
advisories, resolves Rust calls lexically (unknown receivers become `?::name`) and has no data
flow, so the taint rules stay silent; the project's scan warnings say so. To get advisories and
code facts without a Rust toolchain, run the extractor through Docker:

```bash
docker build -t codegraph-extract extractor
export CODEGRAPH_EXTRACTOR=$PWD/scripts/codegraph-extract-docker   # mounts the repo at its own path
export ADVISORY_DB_PATH=$PWD/backend/.advisory-db                  # cloned on first use
```

With cargo installed, `cargo install --path extractor` works too (the `code` subcommand also needs
`rustup component add rust-src`). `ADVISORY_DB_MAX_AGE_HOURS` (default 24) controls when the
database is refreshed and `ADVISORY_DB_OFFLINE=true` never fetches. In Docker the image builds the
extractor and keeps the database in the `advisory_db` volume.

Code facts have their own switches: `CODE_FACTS=off` never runs the extractor's `code` subcommand
(the default `auto` uses it when the binary is there), `CODE_FACTS_OFFLINE=true` passes `--offline`
to `cargo metadata` (dependencies that are not in the registry yet stay unresolved),
`CODE_FACTS_TIMEOUT_SECONDS` (default 1800) bounds one workspace, and `CODE_FACTS_CACHE=<dir>`
keeps the facts keyed by a hash of the sources, manifests and lockfiles, so a rescan of an
unchanged project skips rust-analyzer.

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
| `GET` | `/api/projects/{id}/findings/{finding_id}/evidence` | The finding's evidence as a path: each step's node, the function or file holding it, and the stored edge to the next step |
| `GET` | `/api/projects/{id}/findings.sarif?category=` | Findings as a SARIF 2.1.0 log (download), evidence paths as code flows |
| `GET` | `/api/projects/{id}/source?path=&start=&end=` | Lines of a project file (at most 5 000 per request) with the findings, unsafe spans and SAFETY comments on them |
| `GET` | `/api/projects/{id}/dependencies` | Crates, `DEPENDS_ON` edges, the advisories affecting them, and each workspace member's files |
| `GET` | `/api/projects/{id}/advisories` | RustSec advisories affecting the project, with the crate versions they hit |
| `GET` | `/api/projects/{id}/advisories/{advisory_id}/blast-radius` | Affected crates, dependency paths from each workspace member, calling functions with every call site's line and their distance from an entry point (flagging affected ones), and importing files |
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
| `dangerous-unsafe-op` | warning / error | Inside unsafe: transmute, from_raw_parts, set_len, get_unchecked, ptr read/write/copy, Box::from_raw, zeroed, assume_init, raw pointer arithmetic (with types: `add`/`offset`/`sub` on raw pointers only). An error when an argument is derived from untrusted input |
| `unsafe-send-sync-impl` | warning | `unsafe impl Send` / `unsafe impl Sync` |
| `ffi-surface` | info | `extern` fns, `#[no_mangle]` exports, foreign fn declarations and raw-pointer parameters |
| `panic-reachable-from-entry` | warning | unwrap, expect, unwrap_unchecked, panic!, unreachable!, todo!, unimplemented! in a function an entry point reaches; one finding per function, test code excluded |
| `unchecked-index` | info / warning | Indexing with a non-literal index, per function. With types: slices, arrays, Vec and str only; a warning when the index is derived from untrusted input with no bounds check |
| `overflow-candidate` | warning / info | An integer `+ - * <<` with an operand derived from untrusted input and no bounds check, clamp or checked arithmetic, per function; also arithmetic inside `unsafe` that feeds a pointer or length operation |
| `unbounded-allocation` | warning | A size derived from untrusted input reaches `with_capacity`, `reserve` or `resize` without a cap |
| `unbounded-recursion` | warning | A call-graph cycle an entry point reaches, with no depth-like parameter or comparison in it |
| `weak-hash-algorithm` | warning / error | MD5 or SHA-1: the md5/sha1/sha1_smol crates, openssl MessageDigest::{md5,sha1}, ring's legacy SHA-1. An error when a password-named value flows into the call |
| `weak-password-hashing` | error | A password-named value hashed with a general-purpose digest (SHA-2, SHA-3, BLAKE, MD5, SHA-1) instead of argon2, bcrypt, scrypt or pbkdf2 |
| `insecure-randomness` | warning / error | SmallRng, StepRng, fastrand, oorandom, or a constant seed. An error when the output flows into a variable named like key material (key, token, nonce, salt) |
| `hardcoded-secret` | error / warning / info | A literal bound to a secret-like name or in a known key format; severity by format match, entropy and length |
| `tls-verification-disabled` | error | danger_accept_invalid_certs(true), SslVerifyMode::NONE, rustls `.dangerous()`, a custom ServerCertVerifier |
| `insecure-cipher-or-mode` | warning | des, rc2, rc4, blowfish, ecb crates; openssl DES/RC4/Blowfish/AES-ECB; an AEAD nonce built from a literal or a constant local (CWE-323) |
| `weak-kdf-parameters` | warning | PBKDF2 under 100 000 rounds, Argon2 under 19 MiB / t=2, scrypt log_n under 15, bcrypt cost under 10 (literal arguments) |
| `command-injection` | critical | Untrusted input reaches `Command::new`/`arg`/`args` (std or tokio) |
| `sql-injection` | critical | Untrusted input reaches the text of a statement: `sqlx::query`, `diesel::sql_query`, rusqlite, tokio_postgres. Bind parameters are not findings |
| `path-traversal` | error | Untrusted input reaches the path of a `std::fs` / `tokio::fs` call, with no reduction to a file name and no `starts_with` check |
| `ssrf` | error | Untrusted input reaches the URL or address of an outgoing request: reqwest, ureq, `TcpStream::connect` |
| `unsafe-length-from-input` | critical | A number derived from untrusted input is the length, count or index of `from_raw_parts`, `set_len`, `ptr::copy`, `get_unchecked`, with no bounds check or clamp |
| `open-redirect` | warning | Untrusted input becomes a redirect target: axum/actix/rocket `Redirect`, a `Location` header set by name or written by hand |
| `header-injection` | warning | Untrusted input written into a header unvalidated: `HeaderValue::from_maybe_shared_unchecked`, or a header line assembled by hand. `HeaderValue::from_str` validates and is not a finding |

Thresholds are environment variables (see `backend/app/config.py`).

The first six are `quality` rules. The others are the security classes `dependency` (D),
`unsafe` (U), `panic` (P), `crypto` (C) and `injection` (T, the last seven rows); they run for Rust
projects only and read their patterns from the rule catalogue. Exactly one of the three
`vulnerable-*` triage rules fires per vulnerable crate and advisory, next to the
`vulnerable-dependency` finding.

Every security finding carries `evidence`, an ordered list of node ids: for reachability rules the
chain from the entry point to the function, then the unsafe span or call site; for taint rules
every hop from the source to the sink. `/projects/{id}/node` resolves each id.

### Taint rules

The seven injection rules, `overflow-candidate`, `unbounded-allocation` and the "derived from
untrusted input" forms of the others are one question with different data: is there a path over
`FLOWS_TO`, `PASSES` and `RETURNS_TO` from a source to a node that flows into a sink's sensitive
argument, with nothing on it that blocks? They need the data-flow graph, so they report nothing
for a project scanned without the extractor.

- **Sources** are calls whose result is untrusted (`std::env::args`, stdin, sockets), parameters
  declared with a web-framework extractor type (`axum::extract::Query`, actix `web::Json`, ...),
  and two weak kinds: bytes read through a reader of unknown type (`std::io::Read::read` on a
  generic `R`), and, in a library crate, the parameters of its `pub` functions. Findings from weak
  sources are one severity level lower and low confidence: they are real if the caller passes
  input in. Rules about numbers start from a library parameter only when it is raw data (a slice,
  a string, a buffer, a generic value), not from a number or a struct the caller built.
- **Blocked** is a sanitizer call of the rule (`Path::file_name`, `min`, `HeaderValue::from_str`),
  a variable with one of the rule's guards (a `starts_with` check, a bounds comparison, an
  allow-list `match`), and, for rules that inject text, any value of a numeric or bool type.
  Guards are flow-insensitive: a check anywhere in the function counts.
- The search is a breadth-first expansion from all sources at once, one Cypher statement per level
  and at most 16 levels (`backend/app/analyzers/flow.py`).

Severity is the rule's own for input that is attacker-controlled by construction; a path through
trait dispatch (an impl picked by trait, not by type) loses one confidence level.

The scripts under `eval/` compare the rules with other tools (see `eval/README.md`):
`deps_parity.py` against `cargo audit` (ripgrep, fd and zola match exactly), `clippy_compare.py`
against clippy's unwrap/expect/indexing/undocumented-unsafe lints per source line,
`geiger_compare.py` against cargo-geiger's unsafe counts, `anchors.py` runs real RustSec
advisories on their vulnerable snapshot, and `receivers.py` measures what the extractor adds over
tree-sitter (on fd, ripgrep and zola the share of called externals with an unknown receiver drops
from 52-69 % to 2.5-4.9 %). `eval/rustxec/` holds the benchmark index, the scripts that fetch and
localize its 102 cases, and the frozen `cases.yaml`.

### Rule catalogue

`backend/app/rules/*.yaml` holds the data the security rules use: taint sources, sinks and
sanitizers per rule id, dangerous unsafe operations, weak-crypto APIs and secret patterns.
`catalogue.yaml` lists the files and carries the catalogue `version`. Paths are Rust paths in `::`
form, with brace groups (`std::fs::{read,write}`), `*` for one segment, `?::method` for a method on
any receiver and a trailing `!` for macros. A sink entry can name the argument positions that
matter (`args`), require a format string to match (`template`, for hand-written protocol lines) or
another argument to be a given constant (`when`, e.g. the `LOCATION` header). A sanitizer entry is a
call on the data path, or with `kind: guard` a check on a variable (`?::starts_with`, `ops::cmp`,
`ops::eq`, `ops::match`). With the extractor an external item is matched under any of the names it
goes by, so `http::HeaderValue::from_str` matches whether the code reaches it through `http` or
through `axum::http`. The loader validates everything at startup and computes a
sha256 digest over the files. `/api/rules` and every analysis report state the version, so
evaluation runs are reproducible.

### Ground truth and evaluation

Any directory under `repos/` with an `expected.json` is a ground-truth case: it lists the findings
the analyzers must produce as `{rule, file, line}`, optionally limited by a `scope` of categories
or rules. `repos/sample`, `repos/sample-rust` and the five cases under `repos/vuln-samples/`
(`deps`, `unsafe`, `panics`, `crypto` and `taint`, one per security class) have one.
`backend/tests/test_ground_truth.py` scans every case into a throwaway Neo4j (testcontainers, so
Docker must be running), analyzes it and requires precision and recall of 1 for every rule in
scope. Set `CODEGRAPH_TEST_NEO4J_URI` to use an existing Neo4j instead; the test only touches the
projects it creates.

`vuln-samples/taint` is a workspace of an axum service and a command-line tool. For each rule that
follows data flow it has a function where input reaches the dangerous call and one that does the
same thing safely, which must stay silent; the expected lines are marked `// EXPECT <rule>` in the
sources. It and `deps` declare `"requires": ["extractor"]` and are skipped without the binary. The
other cases pass in both modes: with the extractor (`CODEGRAPH_EXTRACTOR` set) and without it
(`CODE_FACTS=off`, or no binary), which is how the fallback is tested.

`backend/tests/test_code_facts.py` covers the extractor's facts without the binary or a database:
committed facts for `repos/sample-rust` and for a crate of small function bodies
(`tests/fixtures/flows`) are overlaid onto a fresh parse, and the tests check that the extractor
lists the same symbols as tree-sitter, that every receiver type is known, that a call made by a
macro expansion is in the graph, and one data-flow construct per function (let chains, method
chains, `format!`, `?`, struct literals, closures, one and two calls deep, trait dispatch,
`&mut` out-parameters).

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
| call to std or another crate (or, without the extractor, a method on an unknown receiver) | `CALLS` edge to an `External` node | `external` |
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

- **Two modes.** With the extractor, calls are resolved by rust-analyzer and the items below about
  lexical resolution apply only to functions it could not analyze (cfg-disabled code, files outside
  the module tree) and to non-Cargo sources. Without it everything Rust is lexical: receiver types
  are unknown (`v.insert_many(..)` is `?::insert_many`), there is no data flow, and the taint rules
  and the flow forms of the other rules are silent.
- **Data flow is modest on purpose.** Flow-insensitive and field-insensitive def-use: a value
  stored in one field taints the whole struct (the rules about numbers only let a number enter a
  struct literal, which removes the commonest false path); a guard anywhere in a function counts
  even if it comes after the sink or does not reject the value; a call to a function outside the
  workspace passes everything it receives to its result; calls are context-insensitive, so a
  helper's return value flows to all of its call sites; a method on a trait object flows to every
  impl of that trait in the workspace; statics and values sent through channels are not followed;
  a path is at most 16 hops.
- **Macros.** Calls written inside a macro invocation and calls made by `macro_rules!` macros of
  the workspace are in the graph. Proc macros are not expanded (no proc-macro server is started,
  so nothing from the scanned project runs): the item under an attribute macro is analyzed as
  written, derive output is invisible, and function-like proc macros (`sqlx::query!`, `html!`) are
  opaque. Calls a macro from a dependency makes by itself (`write!` calling `write_fmt`) are left out.
- **Naming.** An external callee is named by the path it was written with, else by its defining
  crate; methods of a generic wrapper type cannot be told apart by type argument, so
  `hasher.update(..)` on RustCrypto's `Sha1` and `Sha256` are the same `digest::..::CoreWrapper`
  method and only the constructor (`Sha1::new`) identifies the algorithm.
- **Sources in libraries.** A library has no `main` and no request handlers, so its public
  parameters and reader calls stand in as weak sources. That is where most low-confidence findings
  come from, and it still misses input that arrives through a project-defined trait or through
  another crate of the same workspace when only one member is scanned.
- **Catalogue coverage.** `vec![x; n]` and `read_to_end` are not allocation sinks; `assert!` is not
  a panic site; `format!` followed by `write_all` is not a hand-written header; clap's derived
  structs are sources only through `Parser::parse()`.
- The recursion rule's depth guard is a name heuristic (`depth`, `recursion`, `budget`, ...);
  `pub_api` entry points over-approximate (a `pub` fn in a private module counts) and miss
  `pub(crate)` functions that are reachable from outside.
- Dependency triage: calls from tests and examples count as use, and dev-dependencies are not told
  apart in the rules yet. Yanked crates are not checked (that needs the crates.io index), and a
  `Cargo.toml` without a `Cargo.lock` is reported as a scan warning; the code extractor then
  resolves its dependencies to the newest matching versions, in a temporary lockfile.
- Scans run as in-process background tasks, one at a time per project. A scan that is running
  when the API restarts is marked `failed` at startup and needs a rescan. A job queue would be the
  next step for several API workers.
- Memory: the extractor keeps the standard library, every dependency and the workspace in memory.
  One crate or one member of a large workspace fits in 2 GB (tokio's 2 900 functions take half a
  minute), but analyzing all of gitoxide's crates in one run exceeded a 4 GB Docker VM. The
  Docker wrapper and the compose file cap the memory, so such a run fails on its own and the scan
  falls back to tree-sitter, with a warning; scan a large workspace member by member.
- Lexical resolution (Python, and Rust without the extractor): no type inference; dynamic dispatch
  and re-exports are missed; `self.method()` only resolves against the enclosing class/impl/trait;
  only format-like macros have their arguments re-parsed; method calls on non-`self` receivers
  resolve only when the method name is unique; `methods` on a type counts impls in its own file
  only; `pub` API functions of a library crate are still reported as unused.
- The tree-sitter walk recurses over the syntax tree, and a very deeply nested expression (a
  method chain of a few hundred calls) overflows Python's stack; such a file is skipped and named
  in the scan warnings.
- The canvases draw files and symbols only. A variable or call site on an evidence path is shown
  on the function that holds it (the path panel and the source panel name the exact node and line),
  so a taint path inside one function is a single highlighted node. The graph endpoint returns
  everything up to `limit` (5 000 nodes); a project larger than that is cut off, and the canvas
  gets slow well before it. Neighbourhood queries (`node?id=&depth=`) with expand-on-click would be
  the next step.
- Evidence holds node ids. After a rescan the old findings are cleared, but until the analysis runs
  again a finding opened from an old SARIF file or a bookmark may point at nodes that are gone; the
  path panel says how many.
- SARIF locations are relative to `%SRCROOT%`, the scanned project's root, which the log describes
  but does not resolve (the API sees the project under its container path). Open the file with the
  project as the VS Code workspace. `partialFingerprints` (rule, node and sink, without line
  numbers) stay the same across analysis runs and line shifts.

## Roadmap

The five vulnerability classes (unsafe code, panics, taint-based injection, vulnerable
dependencies, crypto and secrets), the rust-analyzer extractor and the visualization of evidence
paths, dependencies and source (phase 4) are in place. Next is the evaluation on the RustXec
benchmark against cargo-audit, clippy, Semgrep and CodeQL (phase 5), which reads codegraph's
results from the SARIF export. The phased plan, schema v2
and evaluation design are in [`docs/build-plan.md`](docs/build-plan.md).
