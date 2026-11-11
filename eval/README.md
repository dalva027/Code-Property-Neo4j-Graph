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
| `anchors.py` | 2, 3 | the anchor advisories of docs/build-plan.md section 7.6 on their vulnerable snapshots |

Tools that need a Rust toolchain run through `scripts/cargo-docker` (clippy, cargo-geiger) and
`scripts/codegraph-extract-docker`; both mount the repository into the official `rust` image.

## Corpus

`eval/corpus/` is gitignored. It holds:

- `deps/`: ripgrep 11.0.2, fd 7.4.0 and zola 0.9.0 (shallow clones) with their `cargo audit` reports;
- `anchors/`: one checkout per anchor case at the commit before the fix, made with
  `git clone --filter=blob:none --no-checkout` and `git checkout <fix>~1` (openssl at tag
  `openssl-v0.10.65`, the last vulnerable release, because the fix came through a pull request).
  Nothing in them is built or run; the scripts only parse the source.

The RustXec index (`eval/rustxec/metadata.csv`) is the source of the fix commits.
