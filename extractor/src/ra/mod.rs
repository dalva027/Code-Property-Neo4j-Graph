//! Everything that touches rust-analyzer's `ra_ap_*` crates lives under this module. They are
//! published weekly without API stability, so the version is pinned in Cargo.toml and an upgrade
//! means fixing this directory and nothing else.

mod load;
mod names;
mod walk;

use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use ra_ap_hir::Semantics;

pub use load::LoadOptions;

use crate::facts::{CodeFacts, CODE_SCHEMA_VERSION};

/// The pinned `ra_ap_*` version, reported in the facts so a result can be traced to it.
const RUST_ANALYZER: &str = "0.0.358";

/// Load the workspace of `manifest` and extract code facts for its source files under `root`.
pub fn extract(manifest: &Path, root: &Path, options: &LoadOptions) -> Result<CodeFacts> {
    let started = Instant::now();
    let root = root
        .canonicalize()
        .with_context(|| format!("no directory at {}", root.display()))?;
    let (db, vfs) = load::load(manifest, options)?;
    let loaded = Instant::now();

    let mut facts = ra_ap_hir::attach_db(&db, || {
        let sema = Semantics::new(&db);
        let mut walker = walk::Walker::new(&db, &sema, &vfs, &root);
        walker.run();
        std::mem::take(&mut walker.facts)
    });
    facts.schema_version = CODE_SCHEMA_VERSION;
    facts.tool = format!(
        "codegraph-extract {} (rust-analyzer {RUST_ANALYZER})",
        env!("CARGO_PKG_VERSION")
    );
    facts.root = root.display().to_string();
    facts.manifest = manifest.display().to_string();
    facts.stats.load_seconds = (loaded - started).as_secs_f64();
    facts.stats.analysis_seconds = loaded.elapsed().as_secs_f64();
    if facts.files.is_empty() {
        facts
            .warnings
            .push("no workspace source files were found under the root".to_owned());
    }
    Ok(facts)
}
