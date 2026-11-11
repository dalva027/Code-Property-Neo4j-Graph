# crypto-sample

Ground truth for class C, cryptography and secrets. The crate is parsed, not built: its
dependencies are declared so the code reads like real code, but there is no `Cargo.lock`.

| Rule | Where |
|---|---|
| `weak-hash-algorithm` | `md5::compute` and `Sha1::new` in `auth::legacy_digest` |
| `insecure-randomness` | `SmallRng::seed_from_u64(42)` in `tokens::session_token`, `fastrand::u32` in `tokens::nonce` |
| `hardcoded-secret` | the AWS-format `API_KEY` const in `main.rs`, `admin_password` in `auth::check_admin` |
| `tls-verification-disabled` | `danger_accept_invalid_certs(true)` in `tls::insecure_client`, `SslVerifyMode::NONE` in `tls::legacy_connector` |
| `insecure-cipher-or-mode` | `Cipher::des_ede3_cbc()` in `tls::legacy_cipher` |
| `weak-kdf-parameters` | `pbkdf2_hmac` with 1000 rounds in `auth::derive_key` |

`"hunter2"` and `"static-salt"` are not bound to secret-like names and are not reported.
