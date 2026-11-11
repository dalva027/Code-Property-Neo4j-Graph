# deps-sample

Ground truth for class D, vulnerable and risky dependencies. All four dependencies are pinned to
versions with RustSec advisories, and the code uses each one differently:

| Crate | Advisory | How the code uses it | Expected triage |
|---|---|---|---|
| smallvec 1.6.0 | RUSTSEC-2021-0003 (buffer overflow) | calls the affected `SmallVec::insert_many` | `vulnerable-api-reachable` |
| time 0.1.45 | RUSTSEC-2020-0071 (segfault in localtime) | calls `time::get_time`, which is not affected | `vulnerable-crate-used` |
| base64 0.5.1 | RUSTSEC-2017-0004 (integer overflow) | declared, never used | `vulnerable-dependency-unused` |
| atty 0.2.14 | RUSTSEC-2024-0375 (unmaintained), RUSTSEC-2021-0145 (unsound) | calls `atty::is` | `unmaintained-or-unsound-dependency` |

Every vulnerability also yields one `vulnerable-dependency` finding, matching what `cargo audit`
reports for this lockfile. `Cargo.lock` is committed on purpose: dependency analysis reads it
and never runs cargo.
