# unsafe-sample

Ground truth for class U, unsafe code. It compiles (no dependencies) so clippy can be run on it.

| Rule | Where |
|---|---|
| `unsafe-reachable-from-entry` | every function with `unsafe` that `main` or the C export reaches: `fill`, `as_slice`, `head_u32`, `sum`, `strlen_of`, `sample_checksum` |
| `undocumented-unsafe` | the block in `as_slice`, the `unsafe fn head_u32` (doc comment but no `# Safety`), the `unsafe impl Send` |
| `dangerous-unsafe-op` | `ptr::write_bytes`, `slice::from_raw_parts` (twice), `ptr::read`, `mem::transmute` |
| `unsafe-send-sync-impl` | `unsafe impl Send for RawBuffer` |
| `ffi-surface` | the foreign `strlen` declaration and the `#[no_mangle] extern "C"` export with raw pointer parameters |

`helper::never_unsafe` and `with_capacity` contain no unsafe code and are not reported.
