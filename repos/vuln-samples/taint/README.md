# taint-sample

Ground truth for the rules that follow data flow: class T (injection via taint tracking), the
tainted panic rules, and the flow forms of the crypto rules. A Cargo workspace of two crates:

- `service/`, an axum service. Input arrives through extractor parameters (`Query`, `Path`).
- `cli/`, a command-line tool with a toy HTTP responder. Input arrives from `std::env::args`,
  stdin and a `TcpStream`.

For every rule there is a function that lets input reach the dangerous call and a twin that does
the same thing safely and must produce nothing. The expected lines carry a `// EXPECT <rule>`
comment in the sources and are listed in `expected.json`.

| Rule | Vulnerable | Safe twin, and what makes it safe |
|---|---|---|
| `command-injection` | `handlers::ping`, `commands::run_tool`, `commands::shell` (reached through `run_script`) | `ping_count` (parsed into a number), `run_known_tool` (allow-list `match`) |
| `sql-injection` | `handlers::find_user`, `commands::delete_user` | `find_user_bound`, `delete_user_bound` (bind parameters) |
| `path-traversal` | `handlers::read_file`, `commands::show_file` | `read_file_checked` (canonicalize, then `starts_with`), `show_data_file` (`Path::file_name`) |
| `ssrf` | `handlers::proxy`, `commands::probe` | `proxy_allowed` (host allow-list), `probe_local` (only a numeric port) |
| `unsafe-length-from-input` | `handlers::peek`, `commands::grow` | `peek_clamped` (`min`), `grow_checked` (bounds comparison) |
| `open-redirect` | `handlers::login_done`, `net::redirect` (a hand-written `Location` header) | `login_done_checked`, `redirect_local` (`starts_with('/')`) |
| `header-injection` | `handlers::set_language` (unchecked `HeaderValue`), `net::echo_id` (a hand-written header line) | `set_language_checked` (`HeaderValue::from_str` validates), `echo_id_checked` (CR/LF rejected) |
| `unbounded-allocation` | `numbers::table` | `table_capped` (`min`) |
| `overflow-candidate` | `numbers::frame_size` | `frame_size_checked` (`checked_mul`) |
| `weak-password-hashing` | `secrets::store_password`, `secrets::legacy_password_hash` | `checksum` (the same digest over data that is not a password) |
| `weak-hash-algorithm` | `secrets::legacy_password_hash` (SHA-1, raised to an error because a password flows in) | |
| `insecure-cipher-or-mode` | `secrets::seal` (a constant nonce) | `seal_fresh` (the caller's nonce) |
| `insecure-randomness` | `secrets::session_token` (raised to an error because the output becomes `token`) | |

The case declares `"requires": ["extractor"]`: these rules need the data-flow graph of the
rust-analyzer extractor, and the harness skips the case without the binary. The crates are
analyzed, not built. Their dependencies are declared and locked (`Cargo.lock`) so rust-analyzer
can resolve the framework types; the first scan downloads their sources into the cargo registry.
The scope is the rules above: the samples also produce unsafe, panic, dependency and quality
findings, which are not part of this ground truth.
