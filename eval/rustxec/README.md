# RustXec: fetch and localize

Steps 1 and 2 of the benchmark pipeline in `docs/build-plan.md` section 7.4. They clone and diff
only. Nothing from a cloned repository is built or executed, and no analyzer, rule or finding was
consulted while the ground truth and `expected_rules` were decided (section 7.8, condition 1).

| File | What it is |
|---|---|
| `metadata.csv` | The vendored RustXec index, 102 cases |
| `fetch.py` | Resolves each fix link to a repository and commit, checks out a vulnerable and a fixed snapshot |
| `localize.py` | Derives the ground truth per case and maintains `cases.yaml` |
| `cases.yaml` | The curated, frozen record: revisions, ground truth, `expected_rules`, review verdicts |

## Running

```bash
backend/.venv/bin/python eval/rustxec/fetch.py                 # all cases; resumable
backend/.venv/bin/python eval/rustxec/fetch.py RUSTSEC-2024-0357 --force
backend/.venv/bin/python eval/rustxec/localize.py              # adds missing cases, reports drift
backend/.venv/bin/python eval/rustxec/localize.py --show RUSTSEC-2024-0357   # advisory + kept diff
```

`fetch.py` needs network access and git, nothing else. Pull requests go through the unauthenticated
GitHub API (60 requests an hour; a full first run uses about 40). Every API answer is cached in
`eval/corpus/rustxec/api-cache.json` and never requested again. A rerun skips cases whose
worktrees are already at the recorded revisions, and a failure is recorded with its reason instead
of stopping the run. git runs without the user's configuration, without hooks, filters or
submodules, and checks symlinks out as plain files.

`localize.py` imports the backend's tree-sitter parser for function spans and reads the advisory
texts from `backend/.advisory-db` (for `--show` and for a cross-check; it never updates it).
An entry that is already in `cases.yaml` is never rewritten: the script only reports where the
automatic result now differs. `--overwrite-auto` re-derives the automatic fields of entries whose
source is not `manual`; it does not touch `expected_rules`, `expected_reason`, `frozen` or `review`.

## Corpus layout

`eval/corpus/rustxec/` is gitignored, 1.6 GB after a full fetch.

```
api-cache.json      GitHub/GitLab API answers, keyed by URL
fetch.json          per case: repo, fixed_rev, vuln_rev, member, how each was resolved, or the failure
localize.json       per case: what the diff filter dropped, the diff-derived and the advisory-derived truth
manual/             API answers looked up by hand (arrow-rs issue #817 and its pull requests)
<id>/repo.git       bare repository, shallow fetch of the fix commit (depth 2, deeper for rebase merges)
<id>/vuln           worktree at the vulnerable revision
<id>/fixed          worktree at the fix commit
```

## Fetch result (2026-11-11)

All 102 cases were rebuilt. How the fix commit was found:

| Link in the index | Cases | Resolution |
|---|---|---|
| GitHub commit | 62 | used as is; 3 short hashes completed through the API |
| GitHub pull request | 33 | `merge_commit_sha`; 2 were never merged (see below) |
| commit inside a pull request | 1 | used as is |
| GitLab commit | 3 | used as is |
| GitLab merge request | 2 | 1 fast-forward merge (head and base from `diff_refs`), 1 never merged |
| GitHub issue | 1 | by hand (see below) |

The vulnerable revision is the first parent of the fix commit in 97 cases (21 of them merge
commits), the commit before a rebase-merged series in 3 (rusqlite, self_cell, versionize), and
the merge request base in 2.

Cases that need a reader's attention:

| Case | Note |
|---|---|
| RUSTSEC-2021-0118 arrow | The index links umbrella issue #817, worked off by three pull requests. #810 (buffer validation in `ArrayData`) was chosen by hand as the fix; `MANUAL` in `fetch.py` records why. The snapshots were checked: `ArrayData::validate` is an empty stub before and has the buffer-length check after. To be confirmed. |
| RUSTSEC-2021-0041 parse_duration, RUSTSEC-2021-0040 arenavec, RUSTSEC-2023-0066 pleaser | Upstream never merged the fix. The head of the unmerged pull or merge request is the fixed snapshot, its base the vulnerable one. |
| RUSTSEC-2024-0402 hashbrown | The linked pull request is the 0.15.1 release (changelog and version bump). The borsh code is in neither snapshot. Excluded. |
| RUSTSEC-2021-0050 reorder | `swap_index` is already `pub unsafe fn` in the vulnerable snapshot: the advisory's real fix predates the linked commit. Kept, flagged. |
| RUSTSEC-2024-0363 sqlx | The linked commit is one of a series; only `hstore.rs` is still vulnerable in the snapshot. |
| RUSTSEC-2021-0038 fltk, RUSTSEC-2021-0110 wasmtime | The advisory bundles several issues; the linked commit fixes one of them. |
| RUSTSEC-2024-0336 rustls | Three fix commits in the index (one per release branch); the first is used. |
| RUSTSEC-2022-0091 tauri | The link points at a fork (`108518/tauri`); it was fetched from there as given. |
| RUSTSEC-2021-0011 fil-ocl, RUSTSEC-2021-0143 kamadak-exif | No `Cargo.toml` carries the package name; the member is set in `MEMBER_OVERRIDE` with the reason. |

Ground truth outside the workspace member, which matters for the run step (section 7.5 says to
ingest the member only): all entries of RUSTSEC-2024-0441, -2022-0102, -2022-0101, -2022-0098
(wasmtime: the code is in `crates/runtime` or `cranelift`) and -2024-0362 (alloy-json-abi: the
recursion is in `crates/sol-type-parser`), and two of three entries of -2024-0350 (gix-fs).
Entries carry `outside_member: true`.

## Localization

Advisory route, 16 cases: the paths in the index's `affected.functions` are looked up among the
member's function symbols by name, enclosing type and module. 3 of 69 paths could not be mapped
(re-exported items). Advisory functions are the public entry points; in four cases (lettre,
yottadb, wasmtime -0110, fltk) the defective function is a callee or elsewhere.

Diff route, 86 cases: `git diff -w -U0`, minus tests, benches, examples, docs, changelogs,
lockfiles, manifests and CI files, minus hunks that only touch comments, imports or test code.
Old-side lines are mapped to the innermost function span of the vulnerable snapshot. A changed
line outside every function gives a file-level entry with its line range; lines inserted outside
every function are ignored unless nothing else is left.

Large refactor: more than 15 functions or more than 8 Rust files after filtering. Five fixes
crossed it (zlib-rs 31 functions, alloy-json-abi 42, gix-fs 54, trillium-http 16, flatbuffers 66).
Four were narrowed by hand from the advisory text and are kept with `source: manual`; flatbuffers
stays excluded.

The advisory-db checkout (commit `965bf9ad`) names affected functions for 32 further cases that
the RustXec index lists as `[N/A]`. They are not used as ground truth. `localize.json` records them
under `advisory_db` as a cross-check: 24 map to a function, and for 16 of those the function is in
the diff-derived ground truth. Where it is not, the advisory names the public entry and the fix
is in a callee.

## cases.yaml (frozen 2026-11-11, catalogue 0.3.0)

| | Count |
|---|---|
| Cases | 102 (U 46, P 28, T 18, C 10) |
| Rebuilt | 102 |
| Excluded | 2: hashbrown (vulnerable code absent), flatbuffers (large refactor) |
| Granularity | function 92, file 10 |
| Source | diff 74, advisory 16, manual 12 |
| In scope (non-empty `expected_rules`, not excluded) | 40: U 21, P 10, T 8, C 1 |

Expected rule, number of cases (a case can list several):

| Rule | Cases |
|---|---|
| `dangerous-unsafe-op` | 19 |
| `unsafe-length-from-input` | 7 |
| `overflow-candidate` | 6 |
| `unbounded-recursion` | 5 |
| `path-traversal`, `panic-reachable-from-entry`, `unchecked-index`, `unsafe-send-sync-impl` | 2 each |
| `weak-hash-algorithm`, `unbounded-allocation`, `command-injection`, `header-injection`, `open-redirect` | 1 each |

### How `expected_rules` was decided

From the advisory text, the fix diff and the vulnerable source around it, with the rule
definitions of build-plan section 3 read literally:

- A rule is expected only when its pattern is present at the blamed location (the function the
  advisory names or the fix changes, or a function it calls directly where the failure happens)
  and that pattern is the mechanism of the vulnerability.
- U1, U2 and U5 are never expected. They report that unsafe or FFI code exists, not a defect.
- U3 only for the listed operations, with `p.read()` and `p.write(v)` on raw pointers counted as
  `ptr::read` and `ptr::write`. Raw pointer deref, `ptr.add`/`offset`, `CStr::from_ptr`,
  `Vec::from_raw_parts`, `drop_in_place`, a crate's own `set_len` and FFI calls are not listed, so
  a bug that goes through them has an empty list and the reason names the near miss.
- P1 only for the listed calls and macros. `assert!` is not among them. P2 only for a non-literal
  index, so `s.as_bytes()[0]` and `&v[0..2]` are empty with a reason. The compound forms `*=`,
  `+=`, `-=` count as P3's operators.
- P5 when the vulnerable code recurses on input nesting without a depth limit, also when the cycle
  closes through a callback (serde's `Visitor`, parser functions passed to combinators).
- Whether the implementation can in practice see the pattern was not considered.
- Lifetime and variance bugs, sanitizer and protocol logic, infinite loops, leaks and missing
  validation have no rule and an empty list.

The reasons in `cases.yaml` double as a list of near misses for the rule catalogue.

### Review protocol

The mandatory sample of section 7.4 step 2 is every fourth diff-localized case per class in index
order, starting with the second: 22 cases (U 9, P 7, T 4, C 2), chosen before any verdict existed.
For each, the advisory and the diff were read and the automatic ground truth judged `correct`,
`noisy: <what>` or `wrong: <what>`. Result: 13 correct, 9 noisy, 0 wrong. The 9 noisy cases were
narrowed and are `source: manual`.

Four more cases were reviewed outside the sample because the automation flagged them: the three
other large refactors (zlib-rs, trillium-http, flatbuffers) and arrow, whose fix commit was chosen
by hand. Arrow was `wrong` (the diff misses the functions the advisory is about) and corrected.

Every `review` entry is a machine review by Claude and says so in its `by` field. None has been
confirmed by a person. To confirm one, read `localize.py --show <id>` against the entry and
either leave it or record an amendment.

`expected_rules` for the 91 cases outside the curator's own reading were proposed by five
parallel Claude instances working from one written rubric, then adjudicated case by case for
consistency. Borderline decisions carry "borderline" or "low confidence" in `expected_reason`.

### Freeze rule

`expected_rules` is frozen at the date and catalogue version in each entry's `frozen` field. A
later change to `expected_rules`, `ground_truth` or `excluded` is appended to the top-level
`amendments` list with the case id, date, field, old value, new value and reason. It is never a
silent edit, and the entry keeps its original `frozen` stamp.
