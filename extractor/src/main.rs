//! codegraph-extract: facts about a Cargo workspace for the codegraph loader.
//!
//! `deps` reads a `Cargo.lock`, matches every package against the RustSec advisory database with the
//! same `rustsec::Report` logic cargo-audit uses, and prints one JSON document (schema in
//! `facts.rs`). It never runs cargo and never writes into the scanned tree, so it works on read-only
//! mounts and without network access once the database is present.
//!
//! `code` loads the Cargo workspace with rust-analyzer (as a library, see `ra/`) and prints
//! resolved call sites, typed receivers, macro-internal calls and a def-use data-flow graph for
//! every function. It runs `cargo metadata` and nothing else: no build scripts, no proc macros.

mod deps;
mod facts;
mod ra;

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "codegraph-extract", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Crates, dependency edges and advisory matches from a Cargo.lock.
    Deps(DepsArgs),
    /// Clone or update the advisory database, then print its commit.
    FetchDb(DbArgs),
    /// Symbols, resolved calls and data flow of a Cargo workspace, through rust-analyzer.
    Code(CodeArgs),
}

#[derive(Args)]
struct CodeArgs {
    /// The Cargo.toml of the package or workspace to analyze.
    #[arg(long)]
    manifest_path: PathBuf,
    /// Directory that file paths are reported relative to; files outside it are skipped.
    /// Defaults to the manifest's directory.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Pass --offline to cargo metadata: use only dependency sources already in the registry.
    #[arg(long)]
    offline: bool,
    /// Do not load the standard library (faster; std calls stay unresolved).
    #[arg(long)]
    no_sysroot: bool,
    /// Analyze with the default features only instead of all features.
    #[arg(long)]
    default_features: bool,
    /// Write the JSON here instead of stdout.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
struct DbArgs {
    /// Directory holding (or to receive) a checkout of the RustSec advisory-db.
    #[arg(long)]
    advisory_db: PathBuf,
    /// Git URL of the advisory database.
    #[arg(long, default_value = rustsec::repository::git::DEFAULT_URL)]
    advisory_db_url: String,
}

#[derive(Args)]
struct DepsArgs {
    /// Path to the Cargo.lock to analyze.
    #[arg(long)]
    lockfile: PathBuf,
    #[command(flatten)]
    db: DbArgs,
    /// Refresh the database when its last fetch is older than this many hours (0 = never fetch;
    /// a missing database is always fetched unless --offline).
    #[arg(long, default_value_t = 24)]
    max_age_hours: u64,
    /// Never touch the network; use whatever database is on disk.
    #[arg(long)]
    offline: bool,
    /// Skip advisory matching entirely and emit only crates and dependency edges.
    #[arg(long)]
    no_advisories: bool,
    /// Write the JSON here instead of stdout.
    #[arg(long)]
    out: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Deps(args) => {
            let mut warnings = Vec::new();
            let db = if args.no_advisories {
                None
            } else {
                deps::open_database(
                    &args.db.advisory_db,
                    &args.db.advisory_db_url,
                    Duration::from_secs(args.max_age_hours * 3600),
                    args.offline,
                    &mut warnings,
                )?
            };
            let mut facts = deps::extract(&args.lockfile, db.as_ref(), warnings)?;
            if let Some(info) = facts.advisory_db.as_mut() {
                info.path = args.db.advisory_db.display().to_string();
            }
            let json = serde_json::to_string_pretty(&facts)?;
            match args.out {
                Some(path) => {
                    fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?
                }
                None => {
                    let mut out = io::stdout().lock();
                    out.write_all(json.as_bytes())?;
                    out.write_all(b"\n")?;
                }
            }
        }
        Command::Code(args) => {
            let root = match &args.root {
                Some(root) => root.clone(),
                None => args
                    .manifest_path
                    .parent()
                    .map(PathBuf::from)
                    .unwrap_or_default(),
            };
            let options = ra::LoadOptions {
                offline: args.offline,
                no_sysroot: args.no_sysroot,
                all_features: !args.default_features,
            };
            // rust-analyzer and the walk recurse over expression trees; deeply nested code
            // (long method chains, generated tables) needs far more than the default stack.
            let manifest = args.manifest_path.clone();
            let worker = std::thread::Builder::new()
                .name("code".to_owned())
                .stack_size(1 << 30)
                .spawn(move || ra::extract(&manifest, &root, &options))
                .context("starting the analysis thread")?;
            let facts = worker
                .join()
                .map_err(|_| anyhow::anyhow!("the analysis thread panicked"))??;
            let json = serde_json::to_string(&facts)?;
            match args.out {
                Some(path) => {
                    fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?
                }
                None => {
                    let mut out = io::stdout().lock();
                    out.write_all(json.as_bytes())?;
                    out.write_all(b"\n")?;
                }
            }
        }
        Command::FetchDb(args) => {
            let db = deps::fetch_database(&args.advisory_db, &args.advisory_db_url)?;
            let mut info = deps::database_info(&db);
            info.path = args.advisory_db.display().to_string();
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
    }
    Ok(())
}
