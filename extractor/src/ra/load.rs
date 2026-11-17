//! Loading a Cargo workspace into a rust-analyzer database.
//!
//! Nothing in the scanned project is built or executed: build scripts are not run and no
//! proc-macro server is started, so attribute and derive macros stay unexpanded (the item under an
//! attribute macro is analyzed as written). `cargo metadata` does run, to learn the dependency
//! graph, and downloads dependency sources into the cargo registry unless `offline` is set; when it
//! fails rust-analyzer retries with `--no-deps`, which leaves calls into dependencies unresolved.
//!
//! Cargo never writes into the scanned tree. rust-analyzer gives cargo a copy of the lockfile when
//! one sits next to the manifest; when there is none there (no lockfile at all, or the manifest is
//! a workspace member) `load` points cargo at a lockfile in a temporary directory instead.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ra_ap_ide_db::RootDatabase;
use ra_ap_load_cargo::{load_workspace, LoadCargoConfig, ProcMacroServerChoice};
use ra_ap_paths::AbsPathBuf;
use ra_ap_project_model::{
    CargoConfig, CargoFeatures, ProjectManifest, ProjectWorkspace, RustLibSource,
};
use ra_ap_vfs::Vfs;

pub struct LoadOptions {
    pub offline: bool,
    /// Skip the standard library: much faster, but std calls stay unresolved.
    pub no_sysroot: bool,
    pub all_features: bool,
}

pub fn load(manifest: &Path, options: &LoadOptions) -> Result<(RootDatabase, Vfs)> {
    let manifest = manifest
        .canonicalize()
        .with_context(|| format!("no manifest at {}", manifest.display()))?;
    let manifest_dir = manifest.parent().map(Path::to_path_buf).unwrap_or_default();
    let manifest = AbsPathBuf::assert_utf8(manifest);
    let project = ProjectManifest::from_manifest_file(manifest)?;

    let mut cargo = CargoConfig {
        sysroot: (!options.no_sysroot).then_some(RustLibSource::Discover),
        all_targets: true,
        // Workspace crates are analyzed with cfg(test) on, so test modules resolve too.
        set_test: true,
        ..CargoConfig::default()
    };
    if options.all_features {
        cargo.features = CargoFeatures::All;
    }
    if options.offline {
        cargo.metadata_extra_args.push("--offline".to_owned());
    }
    let scratch = redirect_lockfile(&manifest_dir, &mut cargo);
    let load_config = LoadCargoConfig {
        load_out_dirs_from_check: false,
        with_proc_macro_server: ProcMacroServerChoice::None,
        prefill_caches: false,
        num_worker_threads: 1,
        proc_macro_processes: 1,
    };

    let loaded = ProjectWorkspace::load(project, &cargo, &|_| {})
        .and_then(|workspace| load_workspace(workspace, &cargo.extra_env, &load_config));
    if let Some(dir) = scratch {
        let _ = std::fs::remove_dir_all(dir);
    }
    let (db, vfs, _proc_macro) = loaded?;
    Ok((db, vfs))
}

/// When no `Cargo.lock` sits next to the manifest, make cargo read and write one in a temporary
/// directory (seeded from the workspace's lockfile further up, if there is one) by setting
/// `CARGO_RESOLVER_LOCKFILE_PATH`. Returns the directory to remove afterwards.
fn redirect_lockfile(manifest_dir: &Path, cargo: &mut CargoConfig) -> Option<PathBuf> {
    if manifest_dir.join("Cargo.lock").exists() {
        return None;
    }
    let dir = std::env::temp_dir().join(format!("codegraph-extract-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let lockfile = dir.join("Cargo.lock");
    if let Some(existing) = manifest_dir
        .ancestors()
        .map(|it| it.join("Cargo.lock"))
        .find(|it| it.exists())
    {
        let _ = std::fs::copy(existing, &lockfile);
    }
    cargo.extra_env.insert(
        "CARGO_RESOLVER_LOCKFILE_PATH".to_owned(),
        Some(lockfile.to_string_lossy().into_owned()),
    );
    Some(dir)
}
