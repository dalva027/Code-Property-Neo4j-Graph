# vuln-samples

Small, deliberately vulnerable crates that form the ground truth for the security rules. One
directory per vulnerability class, added in the phase that ships the class's rules
(see `docs/build-plan.md`):

| Directory | Class | Phase |
|---|---|---|
| `deps/` | D, vulnerable and risky dependencies | 1 |
| `unsafe/` | U, unsafe code | 2 |
| `panics/` | P, panics and denial of service | 2 |
| `crypto/` | C, cryptography and secrets | 2 |
| `taint/` | T, injection via taint tracking | 3 |

Each crate carries an `expected.json` at its root listing every finding the analyzers must
produce, as `{rule, file, line}` with paths relative to the crate. Every planted bug gets a
matching safe variant, such as a sanitized flow or a documented `unsafe` block, which must produce
nothing. The format and the matching rules are documented in `backend/app/evaluate.py`.

The harness in `backend/tests/test_ground_truth.py` picks up every `expected.json` under `repos/`
and requires precision and recall of 1 for each rule in scope. To score one crate by hand:

```bash
cd backend
python -m app.evaluate --path vuln-samples/unsafe --expected ../repos/vuln-samples/unsafe/expected.json
```
