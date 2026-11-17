# Evaluation scripts

Everything here runs against the configured Neo4j (the docker-compose one by default) from the
backend virtualenv, scans into throwaway projects and deletes them afterwards:

```bash
cd backend
export CODEGRAPH_EXTRACTOR=$PWD/../scripts/codegraph-extract-docker ADVISORY_DB_PATH=$PWD/.advisory-db
.venv/bin/python ../eval/<script>.py ...
```

| Script | Phase | What it checks |
|---|---|---|
| `deps_parity.py` | 1 | `vulnerable-dependency` and `unmaintained-or-unsound-dependency` against `cargo audit --json` on real lockfiles, same advisory database |
| `clippy_compare.py` | 2 | P1, P2 and U2 against clippy's `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and `undocumented_unsafe_blocks`, per source line, plus how many clippy panic sites the reachability filter drops |
| `geiger_compare.py` | 2 | unsafe fn/impl/trait counts per crate against `cargo geiger --output-format Json` |
| `anchors.py` | 2, 3 | the anchor advisories of docs/build-plan.md section 7.6 on their vulnerable snapshots (`--phase 3` for the taint cases, which need the extractor) |
| `receivers.py` | 3 | what the rust-analyzer extractor adds over tree-sitter: the share of called externals whose receiver type is unknown (`?::name`), call sites inside macro invocations, variables and flow edges, per crate and in both modes; no Neo4j needed |
| `rustxec/fetch.py`, `rustxec/localize.py` | 3 | steps 1 and 2 of the RustXec pipeline (section 7.4): vulnerable and fixed snapshots of all 102 cases, ground truth per case, and the frozen `rustxec/cases.yaml`; see `rustxec/README.md` |

Tools that need a Rust toolchain run through `scripts/cargo-docker` (clippy, cargo-geiger) and
`scripts/codegraph-extract-docker`; both mount the repository into the official `rust` image.
The extractor's `code` subcommand downloads the dependencies of whatever it analyzes into the
`codegraph-cargo-registry` volume (sources only; nothing is built) and is capped at 2 GB of memory
(`CODEGRAPH_EXTRACT_MEMORY`), so analyze a large workspace one member at a time.

## Phase 3 results (2026-11-11)

`receivers.py` on the three crates of `corpus/deps/` (extractor 0.2.0, rust-analyzer 0.0.358):

| Crate | External nodes with `?::`, tree-sitter | with the extractor | Call sites inside macro invocations | Functions analyzed |
|---|---|---|---|---|
| fd 7.4.0 | 149 of 216 (69.0 %) | 14 of 288 (4.9 %) | 351 | 133 of 136 |
| ripgrep 11.0.2 | 355 of 654 (54.3 %) | 28 of 731 (3.8 %) | 1 662 | 1 746 of 1 775 |
| zola 0.9.0 | 233 of 447 (52.1 %) | 13 of 517 (2.5 %) | 4 278 | 583 of 585 |

What is left are calls in functions rust-analyzer does not analyze (cfg-disabled code), where the
tree-sitter facts stand.

`anchors.py --phase 3`, each on the affected workspace member of its vulnerable snapshot:

| Case | Rule | Result |
|---|---|---|
| tar RUSTSEC-2021-0080 | path-traversal | detected, `EntryFields::unpack_in` (13 findings in the crate) |
| hyper-staticfile RUSTSEC-2022-0072 | open-redirect | detected, `ResponseBuilder::build` (the only finding) |
| trillium-http RUSTSEC-2024-0009 | header-injection | detected, `Conn::write_headers` (3 findings) |
| hyper RUSTSEC-2021-0079 | overflow-candidate | detected, `ChunkedState::read_size` (10 findings) |
| smallvec RUSTSEC-2021-0003 | overflow-candidate | detected, `SmallVec::insert_many` (24 findings) |
| gix-transport RUSTSEC-2024-0335 | command-injection | missed: the argument is handed to `gix_command::Prepare::arg`, and the `Command` call is in that sibling crate, outside the member |
| gix-fs RUSTSEC-2024-0350 | path-traversal | missed: the path is built in gix-fs, the filesystem calls are in gix-worktree, outside the member |
| tokio RUSTSEC-2021-0124 | (labelled function) | located: `tokio::sync::oneshot::Receiver::close` is `crate.sync.oneshot.Receiver.close` in the graph; no rule is expected to see the race |

Five of the seven cases with a rule are detected. These are smoke tests on cases chosen because a
rule should find them, and the rules were adjusted while running them (reader sources, the
`Location`-by-name sink, the split header line); they are not evidence of recall and must be
reported apart from the other RustXec cases (docs/build-plan.md section 7.8).

## Corpus

`eval/corpus/` is gitignored. It holds:

- `deps/`: ripgrep 11.0.2, fd 7.4.0 and zola 0.9.0 (shallow clones) with their `cargo audit` reports;
- `anchors/`: one checkout per anchor case at the commit before the fix, made with
  `git clone --filter=blob:none --no-checkout` and `git checkout <fix>~1` (openssl at tag
  `openssl-v0.10.65`, the last vulnerable release, because the fix came through a pull request).
  Nothing in them is built or run; the scripts only parse the source.

- `rustxec/`: one directory per RustXec case with a shallow bare repository and the `vuln` and
  `fixed` worktrees (1.6 GB), written by `rustxec/fetch.py`.

The RustXec index (`eval/rustxec/metadata.csv`) is the source of the fix commits.
