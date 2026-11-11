# panics-sample

Ground truth for class P, panics and denial of service. It compiles (no dependencies) so clippy
can be run on it.

| Rule | Where |
|---|---|
| `panic-reachable-from-entry` | `config_port`: `unwrap` and `expect`, reached from `main`. The `unwrap` in the test module is excluded |
| `unchecked-index` | `lookup::nth_byte` (`bytes[index]`) and `lookup::last` (`v[v.len() - 1]`); `first` uses a literal index |
| `unbounded-recursion` | `parse_list` <-> `parse_item` (mutual), `Node::depth` (self); `count_nested` has a depth parameter |
