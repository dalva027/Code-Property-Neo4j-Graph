# Build plan: graph-based vulnerability detection and visualization for Rust

Topic: **Graph Databases and Software Vulnerabilities Detection and Visualization**.
Target language: **Rust** (analyzed code and the new extractor). Orchestration, rules and UI stay on
the existing FastAPI + Neo4j + React stack.

Status: draft, 2026-10-24; benchmark dataset added 2026-11-02. Phases 0, 1 and 2 done 2026-11-04; Phase 3 next.

---

## 1. Thesis in one paragraph

A code property graph of a Rust workspace, stored in Neo4j, lets vulnerability rules be written as
path queries that cross function, file and crate boundaries: *is this `unwrap` reachable from a
request handler?*, *does user input reach `Command::new`?*, *which of my functions transitively call
the function named in RUSTSEC-2024-0xxx?* Linters answer the first hop; the graph answers the whole
path and shows it. The project builds that graph, five families of rules on top of it, a UI that
renders the evidence paths, and an evaluation against existing tools.

## 2. Where we are and what changes

| Area | Today | After this plan |
|---|---|---|
| Rust facts | tree-sitter: items, calls, imports, impls, metrics | rust-analyzer based extractor: resolved calls, types, macro expansion, unsafe spans, literals, intra-/inter-procedural data flow |
| Graph | File, Class, Function; CONTAINS/IMPORTS/CALLS/INHERITS/IMPLEMENTS | + External, Unsafe, Call, Var, Literal, Crate, Advisory; + DEPENDS_ON, AFFECTED_BY, FLOWS_TO, REFERENCES |
| Rules | 3 quality rules (cycles, complexity, dead code) | 3 quality rules + ~25 security rules in 5 classes, each with CWE, confidence and an evidence path |
| Findings | message + node + line | + category, confidence, CWE, evidence path, SARIF export |
| UI | graph, filters, findings, inspector | + severity overlay, evidence-path highlighting, dependency/advisory view, source panel |
| Evaluation | none | ground-truth corpus, precision/recall per class, comparison with cargo-audit, cargo-geiger, clippy, Semgrep; scalability measurements |

Python support and the three quality rules stay as they are. They demonstrate that the graph model
is language-neutral and cost nothing to keep.

## 3. The five vulnerability classes

Rule ids are prefixed by class. Severity is the default; rules raise it when confidence is high
(e.g. a tainted argument) and lower it when the evidence is weak.

### Class U: unsafe code (CWE-119, CWE-787, CWE-476, unsoundness)

| Rule | What it reports | Needs | Phase |
|---|---|---|---|
| U1 `unsafe-reachable-from-entry` | An entry point (see §5.3) reaches, within 8 calls, a function that contains `unsafe` | CALLS, Unsafe, entry_kind | 2 |
| U2 `undocumented-unsafe` | An `unsafe` block or `unsafe fn` with no `// SAFETY:` comment immediately above it | Unsafe.has_safety_comment | 2 |
| U3 `dangerous-unsafe-op` | Inside `unsafe`: `mem::transmute`, `slice::from_raw_parts(_mut)`, `Vec::set_len`, `get_unchecked(_mut)`, `ptr::{read,write,copy,copy_nonoverlapping}`, `Box::from_raw`, `String::from_utf8_unchecked`, `mem::{zeroed,uninitialized}`, `MaybeUninit::assume_init` | CALLS.unsafe=true, External | 2, raised in 3 when an argument is tainted |
| U4 `unsafe-send-sync-impl` | `unsafe impl Send/Sync for T` | IMPLEMENTS.unsafe | 2 |
| U5 `ffi-surface` | `extern "C"` functions, `extern` blocks, `#[no_mangle]` items and raw-pointer parameters; informational map of the FFI boundary | Function.abi, params | 2 |
| metric | `unsafe_blocks`, `unsafe_fns`, `unsafe_density` per crate and file, comparable with cargo-geiger | Unsafe | 2 |

### Class P: panics and denial of service (CWE-248, CWE-129, CWE-190, CWE-770, CWE-674)

| Rule | What it reports | Needs | Phase |
|---|---|---|---|
| P1 `panic-reachable-from-entry` | Entry point reaches `unwrap`, `expect`, `unwrap_unchecked`, or the macros `panic!`, `unreachable!`, `todo!`, `unimplemented!`; `#[test]` code excluded | CALLS, External (incl. macros), entry_kind | 2 |
| P2 `unchecked-index` | `a[i]` with a non-literal index on a slice/Vec/str; warning when `i` is tainted | index ops as Call nodes; types in phase 3 | 2 (info), 3 (typed) |
| P3 `overflow-candidate` | `+ - * <<` on an integer operand that is tainted, or any arithmetic inside an `unsafe` block feeding a pointer op | FLOWS_TO | 3 |
| P4 `unbounded-allocation` | Tainted value reaches `Vec::with_capacity`, `vec![_; n]`, `String::with_capacity`, `reserve`, or `read_to_end` without `take` | FLOWS_TO | 3 |
| P5 `unbounded-recursion` (CWE-674) | A cycle in the call graph (direct or mutual recursion) reachable from an entry point, with no depth parameter or depth check in the cycle. Typical of parsers and decoders fed untrusted input | CALLS cycles, entry_kind | 2 |

### Class T: injection via taint tracking (CWE-78, CWE-89, CWE-22, CWE-918, CWE-119, CWE-601, CWE-113)

All T rules are the same query with different source/sink/sanitizer sets (§5.5). They need the
data-flow edges from the extractor, so they are Phase 3. T6 and T7 were promoted from optional
because the benchmark (§7) contains real open-redirect and CRLF cases.

| Rule | Sinks (examples) | Sanitizers (examples) |
|---|---|---|
| T1 `command-injection` | `std::process::Command::{new,arg,args}`, `tokio::process::Command::*` | allow-list match, numeric parse, `shell_escape` |
| T2 `sql-injection` | `sqlx::{query,query_as,query_scalar,raw_sql}` (string forms, not the compile-checked macros), `diesel::sql_query`, `rusqlite::Connection::{execute,prepare,query_row,execute_batch}`, `tokio_postgres::Client::{query,execute,simple_query,batch_execute}` | bind parameters (`.bind`), identifier allow-list |
| T3 `path-traversal` | `std::fs::{read,read_to_string,write,remove_file,remove_dir_all,create_dir_all,copy,rename}`, `File::{open,create}`, `tokio::fs::*`, `Path::join`/`PathBuf::push` that reach a fs sink | `canonicalize` + `starts_with`, `Path::file_name`, `path_clean` |
| T4 `ssrf` | `reqwest::get`, `reqwest::Client::{get,post,request}`, `ureq::*`, `TcpStream::connect`, `hyper` client with a tainted URI | host allow-list, `Url::parse` followed by a host check |
| T5 `unsafe-length-from-input` | tainted value in the length/count argument of `from_raw_parts`, `set_len`, `copy_nonoverlapping`, `Layout::from_size_align`, `alloc`, or the index of `get_unchecked` | bounds check on the same value |
| T6 `open-redirect` | `axum::response::Redirect::{to,permanent,temporary}`, `actix_web::HttpResponse::Found` with `Location`, any `Location` header built from input | relative-path check |
| T7 `header-injection` (CWE-113) | `HeaderValue::{from_str,from_bytes,from_maybe_shared_unchecked}`, `HeaderMap::{insert,append}`, `http::response::Builder::header`, hand-written header serialization (`write!` of `\r\n`-joined strings) with a tainted value | CR/LF rejection, `HeaderValue::from_static` |

### Class D: vulnerable and risky dependencies (CWE-1395, CWE-1104)

| Rule | What it reports | Needs | Phase |
|---|---|---|---|
| D1 `vulnerable-dependency` | A crate version in Cargo.lock matches a RustSec advisory; severity from CVSS | Crate, Advisory, AFFECTED_BY | 1 |
| D2 `vulnerable-api-reachable` | The advisory names affected functions and the workspace calls one of them (direct or within N calls of an entry point). Without a function list: `vulnerable-crate-used` when any item of the crate is called (medium confidence), `vulnerable-dependency-unused` when nothing is called (info). This triage is the graph value-add over cargo-audit | External.path, CALLS, Advisory.functions | 1 (crate-level), 2 (function-level) |
| D3 `unmaintained-or-unsound-dependency` | Informational advisories (`unmaintained`, `unsound`, `notice`) and yanked versions | Advisory.informational | 1 |
| D4 `advisory-blast-radius` | Not a finding: for an advisory, the workspace members and dependency paths that lead to the affected crate, plus the functions that reach it | DEPENDS_ON paths | 1 (crates), 2 (functions) |
| D5 `duplicate-crate-versions` (optional) | Same crate at several versions | Crate | 1 |

### Class C: cryptography and secrets (CWE-327, CWE-328, CWE-338, CWE-798, CWE-295, CWE-916)

| Rule | What it reports | Needs | Phase |
|---|---|---|---|
| C1 `weak-hash-algorithm` | Use of the `md5`/`md-5`/`sha1`/`sha-1` crates, `openssl MessageDigest::{md5,sha1}`, `ring SHA1_FOR_LEGACY_USE_ONLY`; error when a password/token-named value flows in | External, IMPORTS; FLOWS_TO in 3 | 2 |
| C2 `weak-password-hashing` | A password-like value hashed with a general-purpose digest instead of `argon2`, `bcrypt`, `scrypt` or `pbkdf2` | FLOWS_TO, identifier heuristics | 3 |
| C3 `insecure-randomness` | `SmallRng`, `StepRng`, `StdRng::{seed_from_u64,from_seed}` with a constant, `fastrand`, `oorandom`, xorshift crates, used for keys, tokens, nonces or salts. `thread_rng`, `OsRng`, `getrandom` are accepted | External, FLOWS_TO | 2 (use), 3 (flow) |
| C4 `hardcoded-secret` | String literal bound to a secret-like identifier or field, or matching a key format (AWS `AKIA…`, PEM private key, `ghp_`, `xox[bp]-`, JWT), or high entropy in a secret-like context. Test code excluded. Values are never stored, only a redacted preview and a hash | Literal | 2 |
| C5 `tls-verification-disabled` | `danger_accept_invalid_certs(true)`, `danger_accept_invalid_hostnames(true)`, `SslVerifyMode::NONE`, rustls `.dangerous()`, a `ServerCertVerifier` impl that unconditionally returns `Ok` | External, literal args, IMPLEMENTS | 2 |
| C6 `insecure-cipher-or-mode` | `des`, `rc2`, `rc4`, `blowfish`, `ecb` crates; `openssl Cipher::{des_*,rc4,aes_*_ecb,bf_*}`; a constant nonce reaching `Nonce::from_slice` (CWE-323) | External; FLOWS_TO for the nonce | 2 (3 for nonce) |
| C7 `weak-kdf-parameters` (optional) | `pbkdf2` with a literal iteration count below 100 000, `argon2` params below OWASP minimums | literal call arguments | 2 |

## 4. Target architecture

```
repos/<crate>  ──► codegraph-extract (Rust, rust-analyzer + cargo_metadata + rustsec)
                        │   facts.json (versioned schema)
                        ▼
                FastAPI loader ──► Neo4j (code property graph + crates + advisories)
                        ▲                      │
   repos/<python>  ──► tree-sitter / ast       ▼
                   (existing parsers)   Analyzers = Cypher rules ──► Findings (+ evidence paths)
                                                                       │
                                                   React UI: graph, paths, deps, source, SARIF
```

### 4.1 Extractor decision

**Write `codegraph-extract` in Rust on top of rust-analyzer's published crates**
(`ra_ap_load_cargo`, `ra_ap_hir`, `ra_ap_ide_db`, `ra_ap_syntax`), plus `cargo_metadata` and
`rustsec`.

Why this and not the alternatives:

- tree-sitter (current) has no name resolution or types. `x.method()` resolves by unique name only,
  and macro bodies are opaque. Taint tracking is not credible on that basis.
- MIR via `rustc_driver` or Charon gives control flow and data flow for free, and is what Rudra,
  MirChecker and SafeDrop use. It needs nightly, `rustc_private`, and a pinned toolchain. It is the
  right tool for soundness analysis but a heavy base for a product that must also parse, resolve and
  visualize. Keep it as the documented alternative, and as a possible Phase 6 for U rules.
- rust-analyzer runs on stable, loads a whole Cargo workspace, resolves paths and method calls,
  infers expression types, and expands macros. We build a modest data-flow layer on its syntax tree
  ourselves (§5.4). The crates are published weekly, so the version is pinned and the usage is kept
  behind one thin module.

The tree-sitter parser stays as the fallback for `.rs` files outside a Cargo project, and as the
path for Phase 2 rules until the extractor lands. Both produce the same facts, so rules do not care
which one ran.

### 4.2 Process and deployment

- The extractor is a CLI: `codegraph-extract code --manifest-path <Cargo.toml> --out facts.json`
  and `codegraph-extract deps --manifest-path <Cargo.toml> --advisory-db <path> --out deps.json`.
- `GraphBuilder` detects a `Cargo.toml`, runs the CLI in a subprocess with a time budget, and loads
  the JSON through `app/graph/facts.py`. If the binary is missing or fails, it logs and falls back to
  tree-sitter, so the UI never breaks.
- Docker: `api` image becomes a multi-stage build. Stage 1 compiles the extractor from `extractor/`.
  The runtime stage is based on the official `rust` image with Python added, because rust-analyzer
  needs `cargo` and the `rust-src` component at runtime. The advisory database is cached in a named
  volume. If image size becomes a problem, split the extractor into its own service behind a small
  HTTP endpoint. That is a deployment change, not an architecture change.
- Scans need `Cargo.lock`. Without network access `cargo metadata` runs with `--offline` and reports
  a warning if resolution fails.

## 5. Graph schema v2

### 5.1 Nodes

| Label | Key properties | Scope |
|---|---|---|
| `Symbol:Function` (existing) | + `visibility` (`pub`, `pub(crate)`, `private`), `is_unsafe`, `is_async`, `abi`, `entry_kind` (`main`, `handler`, `pub_api`, `ffi`, `test`, null), `reachable_from_entry` (post-ingest pass), `params` (JSON string: index, name, type) | project |
| `Symbol:Class` (existing) | + `visibility`, `derives` | project |
| `Symbol:External` | `path` (`std::process::Command::new`, `?::unwrap` when the receiver type is unknown), `name`, `crate`, `receiver_type` (phase 3), `is_macro` | project |
| `Unsafe` | `kind` (`block`, `fn`, `impl`, `trait`), `line_start`, `line_end`, `has_safety_comment`, `ops` | project |
| `Call` | `line`, `col`, `callee_path`, `in_unsafe`, `arg_count`, `literal_args` (JSON) | project, phase 3 (phase 2 only for index ops and sink candidates) |
| `Var` | `name`, `kind` (`param`, `local`, `ret`, `field`), `index`, `type` | project, phase 3 |
| `Literal` | `preview` (redacted), `sha256`, `entropy`, `binding`, `pattern`, `line`, `in_test` | project |
| `Crate` | `name`, `version`, `source` (`path`, `registry`, `git`), `workspace_member`, `manifest_path`, `unsafe_density` | project |
| `Advisory` | `id`, `aliases`, `title`, `severity`, `cvss`, `date`, `informational`, `categories`, `patched`, `unaffected`, `functions`, `url`, `db_commit` | **global**, shared across projects |
| `Finding` (existing) | + `category`, `confidence` (`high`, `medium`, `low`), `cwe`, `line_end`, `evidence` (ordered node ids), `rule_version` | project |

`Severity` gains `critical`, mapped from CVSS ≥ 9 and from taint findings with high confidence.

### 5.2 Edges

| Edge | Meaning |
|---|---|
| `(Function)-[:CALLS {line, unsafe, count}]->(Function\|External)` | existing, now with properties; External targets are no longer dropped |
| `(Function)-[:REFERENCES]->(Function)` | a function passed as a value (handler registration, callbacks) |
| `(Function)-[:CONTAINS]->(Unsafe)` | unsafe spans |
| `(Function)-[:HAS_CALL]->(Call)-[:TARGETS]->(Function\|External)` | per-site calls (phase 3) |
| `(Function)-[:DECLARES]->(Var)` | parameters and locals (phase 3) |
| `(Var\|Call)-[:FLOWS_TO {via}]->(Var\|Call)` | intra-procedural data flow: `assign`, `arg:i`, `return`, `method_chain`, `macro`, `field` |
| `(Call)-[:PASSES {index}]->(Var {kind: param})`, `(Var {kind: ret})-[:RETURNS_TO]->(Call)` | inter-procedural glue |
| `(Function\|File)-[:HAS_LITERAL]->(Literal)` | string literals of interest |
| `(Project)-[:HAS_CRATE]->(Crate)`, `(Crate)-[:HAS_FILE]->(File)` | crate membership |
| `(Crate)-[:DEPENDS_ON {kind, optional}]->(Crate)` | from `cargo metadata` resolve graph |
| `(Crate)-[:AFFECTED_BY]->(Advisory)` | semver match done by `rustsec` |
| `(External)-[:FROM_CRATE]->(Crate)` | links a called path to its crate |
| `(Class)-[:IMPLEMENTS {unsafe}]->(Class)` | existing, with the `unsafe impl` flag |

New indexes: `(External.project_id, External.path)`, `(Crate.project_id, Crate.name)`,
`(Function.project_id, Function.entry_kind)`, unique `Advisory.id`.

### 5.3 Entry points

`entry_kind` is set by the extractor (tree-sitter does a subset):

- `main`: `fn main`, `#[tokio::main]`, `#[actix_web::main]`, `#[async_std::main]`.
- `handler`: a function referenced as an argument of `get/post/put/patch/delete/route/service/to/handler` on axum, actix-web, rocket, warp or tower builders; or whose parameters use framework extractor types.
- `pub_api`: `pub` items of a library crate at any depth, re-exported or not.
- `ffi`: `extern "C"` and `#[no_mangle]`.
- `test`: `#[test]`, `#[cfg(test)]` modules; excluded from reachability rules.

A post-ingest Cypher pass sets `reachable_from_entry` on every function (bounded depth 10), so the
per-rule queries stay a single hop.

### 5.4 Data flow in the extractor (phase 3)

Flow-insensitive, field-insensitive def-use over rust-analyzer's syntax tree with semantic
resolution. This is deliberately modest; it is enough for the T rules and is honest about its
limits.

- A `Var` per parameter, `let` binding, closure parameter and pattern binding.
- `FLOWS_TO` from the right-hand side's vars and calls to the bound var; through `?`, `unwrap`,
  `clone`, `to_string`, `as_str`, `trim`, `to_lowercase`, string concatenation, `format!`/`write!`
  arguments (rust-analyzer expands the macro), struct literals (whole struct becomes tainted),
  tuple and `match` destructuring, method calls on a tainted receiver (unless the method is in the
  sanitizer set or returns `bool`/an integer).
- A `Call` per call expression and macro call, with `arg:i` edges from the argument vars.
- `PASSES`/`RETURNS_TO` edges between call sites and the resolved callee, including trait methods
  when rust-analyzer resolves the impl; otherwise all impls of the trait method, flagged as low
  confidence.
- Depth of inter-procedural paths is capped at 6 in the queries.

### 5.5 Source, sink and sanitizer catalogue

Kept as data, not code, in `backend/app/rules/*.yaml`, versioned with the thesis:

- `sources.yaml`: `std::env::{args,args_os,var,vars}`, `std::io::stdin` readers,
  `TcpStream::read*`, `UdpSocket::recv*`, file contents (configurable trust), axum extractors
  (`Path`, `Query`, `Json`, `Form`, `HeaderMap`, `RawQuery`, `Multipart`, `Request`, body `String`),
  actix-web (`web::Path`, `web::Query`, `web::Json`, `web::Form`, `web::Bytes`,
  `HttpRequest::{match_info,query_string,headers}`), rocket params, warp `path::param`, hyper
  `Request`, tonic `Request::into_inner`, every field of a `#[derive(Parser)]` clap struct.
  **Library mode**: when the scanned crate is a library, every parameter of a `pub` function
  (and of `impl Trait` methods on `pub` types) is also a source. Without this, T finds nothing in
  library crates, which is almost the whole benchmark.
- `sinks.yaml`: one list per T rule plus the U3 and P4 sinks, each entry naming which argument
  index is sensitive.
- `sanitizers.yaml`: per rule, as in §3 Class T.
- `dangerous_ops.yaml`, `weak_crypto.yaml`, `secret_patterns.yaml` for U, C.

The same catalogue is what the evaluation appendix documents.

## 6. Phases

Estimates assume one developer working mostly full time. Phases 2 and 4 can overlap with Phase 3.

### Phase 0: foundations (~1.5 weeks)

Goal: everything later phases depend on, with no new rules yet.

1. **Finding model**: add `category`, `confidence`, `cwe`, `line_end`, `evidence`; add `critical`
   severity; `Analyzer` gets `category`, `cwe`, `languages`; `finding()` accepts the new fields.
   Repository stores lists as list properties. `NodeDetail` unchanged.
2. **Edge properties**: `GraphEdge.props`; repository writes them; `get_graph` returns them.
3. **External nodes**: the builder keeps unresolved Rust callees as `External` nodes instead of
   dropping them. Path kept in `::` form, with `?::name` for unknown receivers. Macro invocations
   become `External {is_macro: true}` targets. For format-like macros the tree-sitter parser
   re-parses the token tree as an argument list to find calls inside it.
4. **Rule catalogue loader** for the YAML files, with a `/rules` response that includes category,
   CWE and the catalogue version.
5. **Ground-truth harness**: `repos/vuln-samples/<class>/` crates, each with an `expected.json` of
   `{rule, file, line}`; `tests/test_ground_truth.py` runs the builder, loads a throwaway Neo4j via
   `testcontainers` (skipped when Docker is absent), runs the analyzers and asserts
   precision/recall = 1 on the samples. `python -m app.evaluate --project <id> --expected <file>`
   prints per-rule precision/recall for later phases.
6. **Schema v2** constraints and indexes in `schema.cypher`; README graph model updated.
7. **Background ingestion**: scans run as a background task with a status endpoint, because
   benchmark projects such as wasmtime, openssl and hyper are too large for an in-request scan.

Acceptance: existing 22 tests pass; a Rust scan shows External nodes in the inspector; the harness
runs against `repos/sample-rust` with an empty expected list and reports zero findings in the new
categories.

**Done (2026-11-04).** All seven items shipped. Scans run as a background task, `POST /projects`
returns `202`, and `GET /projects/{id}/status` reports `scanning`, `ready` or `failed`. Choices made
while building:
- `expected.json` lives at the root of each ground-truth project, with an optional `scope`. The two
  existing samples list their quality findings, so the harness is exercised end to end today. The
  `vuln-samples/` crates themselves arrive with their phases.
- External paths come from the parser (`ParsedCall.external`), so the builder stays
  language-neutral. Unresolved paths into the project's own crate, enum constructors and bare names
  are not externals.
- Node attributes (`GraphNode.attrs`) hold the non-numeric facts later phases need (`visibility`,
  `abi`, `entry_kind`); they are flat Neo4j properties like metrics.
- The catalogue ships populated from §3 and §5.5 and is versioned `0.1.0`, with a sha256 digest.
- Recursive self-calls are still dropped from `CALLS`; P5 in Phase 2 needs them kept.

### Phase 1: dependencies and advisories, Class D (~2 weeks)

Goal: the first security results and the first Rust code, with no parser changes.

1. **`extractor/` crate** with the `deps` subcommand: `cargo_metadata` for the resolve graph,
   `rustsec` for advisory fetch and matching, JSON out (`crates`, `deps`, `advisories`, `matches`).
   Advisory `functions`, `patched`, `unaffected`, CVSS and informational kind are carried through.
2. **Loader** creates `Crate`, `Advisory` (global, merged by id), `DEPENDS_ON`, `AFFECTED_BY`,
   `HAS_CRATE`, `HAS_FILE`, and `FROM_CRATE` from the `use`/call paths already in the graph.
3. **Rules D1, D3, D5** and the crate-level form of **D2** (`vulnerable-crate-used` /
   `vulnerable-dependency-unused` from whether any External of that crate is called).
4. **D4 query** exposed at `GET /projects/{id}/advisories/{advisory_id}/blast-radius` returning the
   dependency paths and reaching functions.
5. **Docker**: multi-stage build, advisory-db volume, `CODEGRAPH_EXTRACTOR` setting.
6. **Samples**: `repos/vuln-samples/deps` pins two crates with known advisories, one of which the
   code actually calls.

Acceptance: D1 results equal `cargo audit --json` on three real crates (counts and advisory ids);
D2 separates used from unused advisories on the sample; blast-radius endpoint returns paths.

**Done (2026-11-04).** All six items shipped and the acceptance checks pass. `eval/deps_parity.py`
on ripgrep 11.0.2, fd 7.4.0 and zola 0.9.0 (advisory-db `965bf9a`) matches cargo-audit 0.22.2
exactly: 3, 3 and 40 vulnerabilities, 6, 8 and 46 unmaintained/unsound warnings. The sample's
ground truth (`repos/vuln-samples/deps/expected.json`) scores 1/1 for every rule. Choices made
while building:
- The extractor reads `Cargo.lock` with `rustsec::Lockfile` and matches with `rustsec::Report`,
  the code cargo-audit runs, instead of calling `cargo metadata`. Scans therefore never run cargo,
  never write into the scanned tree and need no network once the database is present. Dependency
  kinds and workspace members come from the manifests, parsed in Python. `cargo metadata` can
  still be added for features and targets.
- Without the binary the loader parses `Cargo.lock` itself: crates and edges, no advisories, and a
  scan warning. Ground-truth cases that need advisories declare `"requires": ["extractor"]` and
  are skipped without it; `scripts/codegraph-extract-docker` runs the binary through Docker.
- D2 gained a fourth path to "used": a vulnerable transitive crate reached through a direct
  dependency the code uses is `vulnerable-crate-used` with low confidence and the dependency path
  as evidence. Function-level D2 (`vulnerable-api-reachable`) already works for calls by path.
- Extra schema: `(File)-[:USES]->(Crate)` from `use`/`extern crate`, so a crate used only for
  derives or traits counts as used. Edge properties may hold string lists.
- The runtime image is still `python:3.12-slim` plus the binary (217 MB). The Rust toolchain moves
  into the runtime image with the rust-analyzer extractor in phase 3.
- Not done: yanked-crate warnings (they need the crates.io index) and dev-only dependency marking.

### Phase 2: syntactic security facts, Classes U, P, C MVP (~3 weeks)

Goal: everything that can be done without types, done on the tree-sitter parser so results exist
before the extractor is ready. The facts contract is designed so Phase 3 replaces the producer, not
the consumers.

1. **Parser facts**: `unsafe` blocks/fns/impls with SAFETY-comment detection; `visibility`, `abi`,
   `is_async`; attribute-based `entry_kind`; `REFERENCES` edges for functions passed as values;
   handler detection by builder-method name; `CALLS` with `line` and `unsafe`; index expressions
   and arithmetic inside unsafe as `Call` nodes with `callee_path` `ops::index`/`ops::arith`;
   literal call arguments for C5, C6, C7; string `Literal` nodes with secret-pattern and entropy
   classification (test code flagged).
2. **Post-ingest pass** setting `reachable_from_entry`.
3. **Rules**: U1–U5, P1, P2 (info), P5, C1, C3 (use form), C4, C5, C6, C7, and function-level D2
   (`External.path IN advisory.functions`).
4. **Unsafe metrics** per file and crate, compared with `cargo geiger` output on three crates.
5. **Samples**: `repos/vuln-samples/{unsafe,panics,crypto}` with `expected.json`.
6. **Clippy comparison script** (`eval/clippy_compare.py`): run clippy with `unwrap_used`,
   `expect_used`, `indexing_slicing`, `undocumented_unsafe_blocks`, `panic`; map to P1, P2, U2;
   report overlap and how many clippy hits the reachability filter removes.

Acceptance: harness precision/recall = 1 on the three sample crates; every finding carries an
evidence path; unsafe counts match cargo-geiger within the documented differences; the Phase 2
anchor cases of §7.6 are detected on their vulnerable snapshot.

**Done (2026-11-04).** All six items shipped on the tree-sitter parser; the facts contract
(`ParsedUnsafe`, `ParsedRef`, `ParsedOp`, `ParsedLiteral`, `ParsedCall.literal_args`) is what the
phase 3 extractor will fill instead. Acceptance: the harness scores 1/1 for every rule on
`vuln-samples/{unsafe,panics,crypto}` (17, 5 and 10 expected findings) and the three older cases;
every security finding carries evidence (entry chain, then span or call site); cargo-geiger's
unsafe function, impl and trait counts match on the two samples it can build; 6 of the 7 anchor
cases are detected on their vulnerable snapshot (openssl, grcov, protobuf, zlib-rs, gix-features,
metrics-util). Choices and gaps:
- `Call` nodes are created only where a rule needs a site: index/arith operations and calls whose
  callee is in the catalogue. Per-site Call nodes for everything wait for phase 3.
- Entry points: `main`/`test`/`ffi` and handler attributes come from the parser; `handler` by
  routing-builder argument (`get(h)`, `.service(h)`, `routes![h]`) and by extractor parameter type
  (catalogue `sources` of kind `type`), and `pub_api` for library crates, from the builder. The
  reachability pass is a bounded BFS over CALLS and REFERENCES (10 hops), stored as
  `entry_distance`; U1 uses ≤ 8.
- Resolution fixes forced by the new rules: calls whose head is certainly external (std, a prelude
  type, a `use`d or unanchored dependency crate) are never resolved to a project symbol by name;
  `.m()` on an unknown receiver only resolves to methods; self-calls are kept (P5); chained method
  calls anchor on the method name, so each site has its own line.
- P5's depth guard is a name heuristic over bound names and comparisons (`depth`, `recursion`,
  `budget`, `fuel`, `nest*`, `max_depth`); `limit` and `remaining` were dropped after they hid
  protobuf's and zlib-rs's real recursion. protobuf's `incr_recursion` guard, which the bug
  bypasses for groups, is correctly not credited to `skip_group`/`skip_field`.
- nano-id RUSTSEC-2024-0343 is not detectable by C3: its RNG is `getrandom`; the bug is a wrong
  alphabet. Recorded as an "out of reach" case for the evaluation.
- cargo-geiger's `exprs` counts expressions inside unsafe, not blocks; reported but not compared.
  Geiger was run only on the two dependency-free samples: building third-party crates (fd,
  ripgrep) needs an explicit go-ahead.
- clippy comparison on the samples: every shared site agrees; clippy additionally flags literal
  indexing (`v[0]`, skipped on purpose) and codegraph additionally flags an undocumented
  `unsafe fn` (clippy's `missing_safety_doc` is a separate lint).
- Not done: `REFERENCES` for functions stored in struct fields or statics; handler detection for
  warp/tower closures; yanked crates; P2's typed form.

### Phase 3: the extractor, Class T, and typed upgrades (~5 weeks)

Goal: replace tree-sitter for Cargo projects with resolved, typed, macro-aware facts and data flow.

1. **Week 1: workspace loading and symbols.** `code` subcommand loads the workspace with
   `ra_ap_load_cargo`, walks crates/modules/items, emits the same `symbols`, `impls`, `imports` the
   tree-sitter parser emits. Golden test: on `repos/sample-rust` the symbol set equals tree-sitter's.
2. **Week 2: calls and types.** Resolve every call and method call to its definition or to an
   External with a real receiver type (`Option::unwrap`, not `?::unwrap`); expand macros; record
   `Call` nodes with argument literals; resolve handler registrations and extractor-typed
   parameters for `entry_kind`.
3. **Weeks 3–4: data flow.** `Var` nodes and `FLOWS_TO`, `PASSES`, `RETURNS_TO` edges per §5.4.
   Unit tests on small bodies: let chains, method chains, `format!`, `?`, struct literals, closures,
   inter-procedural through one and two calls, trait dispatch.
4. **Week 5: rules and integration.** T1–T7 as one parametrised analyzer over the
   YAML catalogue; P3, P4; typed upgrades of U3, P2, C1, C2, C3, C6; `GraphBuilder` dispatch to the
   extractor with fallback; Docker image with the toolchain; `repos/vuln-samples/taint` (an axum
   service and a CLI, each with one true positive and one sanitized negative per T rule).

Acceptance: T rules reach precision ≥ 0.9 and recall ≥ 0.9 on the synthetic taint samples; the
Phase 3 anchor cases of §7.6 are detected on their vulnerable snapshot; unknown
receivers (`?::`) drop below 10 % of External nodes on three real crates; macro-internal calls
appear in the graph; the whole suite still passes with the extractor disabled.

### Phase 4: visualization (~2 weeks, can start after Phase 1)

1. **Severity overlay**: node halo/colour by the most severe finding; category chips; counts per
   file and crate; confidence filter.
2. **Evidence path explorer**: selecting a finding highlights its `evidence` path, dims the rest,
   and offers step-through from source to sink (or entry to unsafe, or member crate to advisory).
3. **Dependency view**: a second graph mode with `Crate` nodes, `DEPENDS_ON` edges and `Advisory`
   nodes; clicking an advisory runs D4 and highlights the blast radius into the code graph.
4. **Source panel**: `GET /projects/{id}/source?path&start&end` serving a slice of the file from the
   read-only mount; flagged lines and SAFETY comments highlighted.
5. **Findings panel**: grouped by category, CWE links, SARIF export
   (`GET /projects/{id}/findings.sarif`) so results open in VS Code and compare with other tools.

Acceptance: a user can go from an advisory to the exact line that calls the affected function in
three clicks, and from a taint finding to every hop of the flow.

### Phase 5: evaluation and write-up (~3 weeks plus writing)

Research questions and how each is answered:

- **RQ1 Effectiveness.** Precision and recall per class on (a) the synthetic corpus and (b) real
  vulnerabilities. The primary real set is **RustXec** (§7): 102 RustSec cases in 89 projects, run
  as vulnerable/fixed snapshot pairs, reporting detection, fix-awareness, triage rank and noise per
  class. Supplements cover what RustXec lacks: the `unsound` RustSec advisories and Rudra's bugs
  for U; synthetic downstream projects for D; a hand-labelled sample of flows in open-source
  axum/actix services for T.
- **RQ2 Comparison.** Run on the same RustXec snapshots and the synthetic corpus. cargo-audit for D1 (expect parity) and D2 (expect the reachability split to
  cut actionable alerts substantially; report the percentage); cargo-geiger for unsafe metrics;
  clippy restriction lints for P1/P2/U2 with the reachability-filter reduction; Semgrep's Rust rules
  and CodeQL's Rust support, where available, for T and C. Normalize everything to SARIF and
  compute overlap, unique true positives and unique false positives per tool.
- **RQ3 Scalability.** Ingestion time, node/edge counts and per-rule query latency on 8–10 crates
  from 1 kLOC to 100+ kLOC, picked from the RustXec projects (e.g. wasmtime, openssl, hyper, tokio
  at the low and high end); sensitivity of path rules to the depth bound; the same reachability
  queries on an in-memory `networkx` graph as a baseline for the "why a graph database" argument.
- **RQ4 Usefulness of the visualization.** Task-based walkthroughs with 3–5 developers (find the
  root cause of an advisory exposure; decide whether a cargo-audit alert matters; trace an
  injection) with time-to-answer and a short questionnaire. If recruiting is not possible, two
  written case studies.

Prerequisite: the RustXec pipeline of §7 is built at the start of this phase (about one week of
the three), and the Phase 2/3 anchor cases have already been run during those phases.

Deliverables: `eval/` scripts that reproduce every table and figure from a pinned RustXec commit,
a pinned advisory-db commit and pinned crate versions; the catalogue version used; the
limitations list, including the RustXec cases no rule covers.

## 7. Benchmark dataset: RustXec

To be built at the start of Phase 5. The anchor cases in §7.6 are used earlier, as smoke tests in
Phases 2 and 3. Nothing below exists yet.

### 7.1 What it is

RustXec (Ji et al., MSR 2026) is a reproducible Rust vulnerability dataset built from RustSec
advisories dated January 2021 to April 2025. Each case was confirmed by running a proof of
vulnerability (PoV).

| Fact | Value |
|---|---|
| Cases / projects | 102 vulnerabilities in 89 projects |
| Categories (RustSec) | memory-corruption 31, denial-of-service 28, memory-exposure 12, format-injection 11, crypto-failure 10, privilege-escalation 4, code-execution 3, thread-safety 3 |
| Metadata per case | `id`, `package`, `date`, `categories`, `CWE`, `url`, `references`, `severity`, `aliases`, `keywords`, `versions`, `affected`, `affected.functions`, `fix commit links`, `pov candidate links` |
| Function-level labels | `affected.functions` is filled for 16 cases only; all 102 have a fix commit link |
| Distribution | GitHub `ying-selab/RustXec` holds `README.md` and `metadata.csv` (~50 KB). Zenodo record 17508733 holds `rustxec.zip`, 88.5 GB, with one Docker image per case; CC BY 4.0 |
| Construction bias | Advisories marked `unmaintained` (117) or `unsound` (89) were excluded, as were cases without a runnable PoV or needing non-Linux hardware |

Links: <https://github.com/ying-selab/RustXec>, <https://zenodo.org/records/17508733>,
DOI 10.1145/3793302.3793307.

### 7.2 Integration decision

**Use `metadata.csv` as an index and rebuild each case from git; do not use the Zenodo archive.**
The archive exists to execute PoVs in Docker; a static graph analyzer only needs the source at the
vulnerable and fixed revisions. Rebuilding from git costs a few GB of shallow clones instead of
88.5 GB plus 300 GB of disk, gives a fixed snapshot that the archive does not have, and keeps the
corpus reproducible from two pinned commits (RustXec and advisory-db). The archive stays a fallback
for a case whose upstream repository has disappeared, and the PoVs are an optional later step for
dynamically confirming a finding.

### 7.3 Mapping onto the five classes

| RustSec category | Class | Cases | Notes |
|---|---|---|---|
| memory-corruption, memory-exposure, thread-safety | U | 46 | U1–U4; many are logic bugs inside `unsafe` that only rank-based metrics will credit |
| denial-of-service | P | 28 | P1, P3, P4, and P5 for the recursion cases |
| format-injection, code-execution, privilege-escalation | T | 18 | T1, T3, T6, T7; HTML-sanitizer logic bugs are out of reach |
| crypto-failure | C | 10 | C1, C3; signature-comparison and protocol bugs are out of reach |
| none | D | 0 direct | Each case supplies crate, affected range and functions, used to build synthetic downstream projects (§7.5) |

A keyword scan of the 102 advisory texts (advisory-db commit `263a4d9`) gives the expected rule
coverage: panic/unwrap 26, out-of-bounds/indexing 17, use-after-free or double free 15, dangerous
unsafe operation 14, crypto terms 13, unbounded allocation 12, overflow 8, recursion or stack
overflow 5, command/path/redirect 5, `unsafe impl Send/Sync` 1. This motivated adding P5 and T7.

**Gaps that need supplements:**
- U: the excluded `unsound` advisories are the cases unsafe-focused graph rules fit best. Add the
  `unsound` RustSec advisories that carry a fix commit, plus Rudra's reported bugs, as a second U
  set, scored with the same protocol but reported separately.
- U4 has a single RustXec case; evaluate it on Rudra's Send/Sync variance bugs.
- D: no direct cases; see §7.5.

### 7.4 Pipeline

Four scripts under `eval/rustxec/`, run in order:

1. **fetch.** Read the vendored `metadata.csv`. Resolve `fix commit links` to a repository and
   commit: plain commit URLs directly, pull-request URLs through the GitHub API to the merge
   commit, GitLab and others by hand. Shallow-clone into `eval/corpus/<id>/` (gitignored) and
   create two worktrees: `vuln` at the fix commit's parent and `fixed` at the fix commit. Record
   the workspace member that contains `package`.
2. **localize.** Build ground truth per case. Use `affected.functions` where present (16 cases).
   Otherwise diff `vuln` against `fixed`, drop test files, docs, changelogs and version bumps, and
   map the remaining hunks onto function spans using our own parser's line ranges. Fall back to
   file level when a hunk is outside any function. Hand-review about 20 cases, record the verdict,
   and exclude cases where the fix is a large refactor.
3. **run.** Ingest the affected workspace member of each snapshot as its own project, run all
   analyzers, export SARIF. Run clippy, Semgrep and CodeQL on the same snapshots through the same
   runner, normalized to SARIF.
4. **score.** Compute the metrics of §7.5 per case, per class and per RustSec category, and write
   the tables and figures used in the report.

`eval/rustxec/cases.yaml` is the curated record per case: `id`, `class`, `repo`, `vuln_rev`,
`fixed_rev`, `member`, `ground_truth` (function qualified names or files), `granularity`
(`function` or `file`), `source` (`advisory`, `diff`, `manual`), `excluded` with a reason, and the
rules expected to apply.

### 7.5 Metrics and protocol

- **Detection.** A case is detected if a finding of the expected class lands on a ground-truth
  function, or within one call hop of it (reported separately). File-level cases count file hits.
- **Fix-awareness.** Per case: detected and removed in `fixed`, detected but still present in
  `fixed`, or missed. Removed-on-fix is the strongest evidence a finding is the real cause.
- **Triage rank.** Rank of the first true finding among the class's findings in that crate,
  ordered by severity and confidence; report MRR, top-5 and top-10. Large crates produce many
  findings, so rank is a fairer measure than raw precision.
- **Noise.** Findings per kLOC on the `fixed` snapshot as a false-positive proxy.
- **Coverage table.** RustSec category against our five classes, including "no rule applies".
- **D benchmark.** For each case with affected functions, generate two tiny downstream crates
  pinned to the vulnerable version: one that calls an affected function, one that only depends on
  the crate. D2 must mark the first `vulnerable-api-reachable` and the second
  `vulnerable-dependency-unused`; cargo-audit flags both.
- **Protocol.** Analyze the affected workspace member only. Pin the RustXec commit (`83a893b` as of
  2026-11-02), the advisory-db commit, the rule-catalogue version and the Rust toolchain. Report
  excluded cases and why. Use library-mode sources (§5.5) for library crates. Note in the threats
  to validity that ground truth derived from fix diffs can include incidental changes.

### 7.6 Anchor cases

Run these early as smoke tests on the `vuln` snapshot; each should produce the listed rule.

| Phase | Rule | Case |
|---|---|---|
| 2 | U3 dangerous op | openssl RUSTSEC-2024-0357, grcov RUSTSEC-2025-0005 |
| 2 | P5 recursion | protobuf RUSTSEC-2024-0437, zlib-rs RUSTSEC-2024-0401 |
| 2 | C1 weak hash | gix-features RUSTSEC-2025-0021 |
| 2 | C3 insecure randomness | nano-id RUSTSEC-2024-0343 |
| 2 | U4 Send/Sync impl | metrics-util RUSTSEC-2021-0113 |
| 3 | T1 command injection | gix-transport RUSTSEC-2024-0335 |
| 3 | T3 path traversal | gix-fs RUSTSEC-2024-0350, tar RUSTSEC-2021-0080 |
| 3 | T6 open redirect | hyper-staticfile RUSTSEC-2022-0072 |
| 3 | T7 header injection | trillium-http RUSTSEC-2024-0009 |
| 3 | P3 overflow | hyper RUSTSEC-2021-0079, smallvec RUSTSEC-2021-0003 |
| 3 | thread-safety, labelled functions | tokio RUSTSEC-2021-0124 |

### 7.7 Other datasets

- **RustMizan** (Microsoft Research, arXiv 2607.04729): compilable Rust vulnerability benchmark
  with function- and line-level labels. No public download was found as of 2026-11-02; adopt it as
  a second set if it is released.
- **Rudra** bug list and the **Xu et al. (TOSEM 2021)** Rust CVE study: supplements for U.

## 8. Milestones

| Milestone | When | Definition of done |
|---|---|---|
| M0 | end of week 2 | Finding/edge/External model and ground-truth harness merged |
| M1 | week 4 | Dependency graph with advisories in the UI; D1 matches cargo-audit on 3 crates |
| M2 | week 7 | U, P, C MVP rules with evidence paths; harness green; clippy and geiger comparisons scripted |
| M3 | week 12 | Extractor replaces tree-sitter for Cargo projects; T1–T7 pass the taint samples and Phase 3 anchor cases; typed upgrades live |
| M4 | week 14 | Path explorer, dependency view, source panel, SARIF |
| M5 | week 17 | RustXec pipeline built and scored; evaluation reproduced from scripts; report draft |

## 9. Risks and mitigations

| Risk | Mitigation |
|---|---|
| rust-analyzer crate API churn | Pin one `ra_ap_*` version; isolate it behind `extractor/src/ra.rs`; upgrade only at phase boundaries |
| Workspace loading is slow or needs build scripts / proc macros | Load without `cargo check` first; enable it per project with a time budget; cache `facts.json` keyed by lockfile hash |
| Taint false positives | Field-insensitivity and conservative propagation are documented; confidence levels; sanitizer catalogue; depth cap; measure in RQ1 instead of hiding |
| Variable-length path queries blow up | `reachable_from_entry` precomputed; depth bounds; `shortestPath` for evidence; indexes on `External.path` and `entry_kind`; project scoping on every match |
| Advisory data changes between runs | `Advisory.db_commit`; evaluation pins the commit; the extractor accepts `--advisory-db` path |
| Docker image size with the Rust toolchain | Slim base, no docs; split into an `extractor` service if it exceeds what the machine tolerates |
| Secrets leaking into the database | `Literal` stores a redacted preview and a hash only; test code flagged; no raw values in findings |
| RustXec cases cannot be rebuilt from git (repo moved, PR link, history rewritten) | Resolve by hand in `cases.yaml`; fall back to the case's source in the Zenodo archive; report the count |
| Fix-diff ground truth is noisy | Prefer `affected.functions`; drop tests and version bumps; hand-review ~20 cases; report file-level and function-level results separately |
| RustXec under-represents unsafe soundness bugs | Separate U supplement from `unsound` advisories and Rudra, reported alongside |
| Phase 3 slips | Phases 1, 2 and 4 already deliver four of five classes; a lexical same-function taint fallback on tree-sitter is the documented degraded mode for T |

## 10. Repository layout after the plan

```
extractor/                      Rust: codegraph-extract (deps, code subcommands)
  Cargo.toml
  src/main.rs                   CLI
  src/ra.rs                     the only module that touches ra_ap_* APIs
  src/facts.rs                  serde schema for facts.json (schema version field)
  src/symbols.rs calls.rs unsafe_.rs dataflow.rs entries.rs literals.rs deps.rs
backend/app/graph/facts.py      facts.json → CodeGraph
backend/app/graph/parsers/rust.py   tree-sitter fallback (kept)
backend/app/graph/postprocess.py    reachable_from_entry pass
backend/app/rules/*.yaml        sources, sinks, sanitizers, dangerous ops, crypto, secrets
backend/app/analyzers/{unsafe,panics,taint,deps,crypto}.py
backend/app/api/{advisories,source,sarif}.py
backend/app/evaluate.py         precision/recall CLI
backend/tests/test_ground_truth.py
repos/vuln-samples/{unsafe,panics,taint,deps,crypto}/   each with expected.json
eval/                           tool runners, SARIF normalizer, metrics, figures
eval/rustxec/                   vendored metadata.csv, cases.yaml, fetch/localize/run/score scripts
eval/corpus/                    gitignored vuln/fixed checkouts of the RustXec projects
docs/build-plan.md              this file
```

## 11. Out of scope, for the record

- Porting the API from FastAPI to Rust (axum). It adds nothing to the research question; it can be
  a follow-up if a fully-Rust stack is wanted.
- Soundness analysis of `unsafe` (aliasing, lifetimes, drop order). That is MIR territory; the plan
  detects and ranks unsafe surface, it does not prove unsoundness.
- Concurrency bugs (locks across `await`, data races).
- Non-Rust security rules.

## 12. First two weeks, as tickets

1. Finding v2 fields, `critical` severity, edge props, repository changes, tests.
2. External nodes in the builder and tree-sitter parser, including macros; inspector shows them.
3. YAML catalogue loader and `/rules` update.
4. `repos/vuln-samples/deps` and `repos/vuln-samples/unsafe` skeletons with `expected.json`.
5. Ground-truth harness with `testcontainers`; `app.evaluate` CLI.
6. `extractor/` crate skeleton: `deps` subcommand with `cargo_metadata` and `rustsec`, JSON out,
   unit test on a fixture lockfile.
7. Loader for crates and advisories; D1 and D3 rules; compare with `cargo audit` on three crates.
8. Docker multi-stage build and advisory-db volume.
