Small deliberately flawed crate so you can see Rust findings immediately:
a tangled function (`pricing::quote`), unused helpers (`utils`), and trait impls
(`Display`, `Priced`) that show up as IMPLEMENTS edges without being reported as unused.
`models` and `pricing` `use` each other, which Rust allows, so no circular-import is reported.
