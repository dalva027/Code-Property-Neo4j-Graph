//! codegraph-extract: facts about a Cargo workspace for the codegraph loader.
//!
//! `deps` reads a `Cargo.lock`, matches every package against the RustSec advisory database with the
//! same `rustsec::Report` logic cargo-audit uses, and prints one JSON document (schema in
//! `facts.rs`). It never runs cargo and never writes into the scanned tree, so it works on read-only
//! mounts and without network access once the database is present.
//!
//! The `code` subcommand (rust-analyzer based symbols, calls and data flow) arrives in phase 3.

mod deps;
mod facts;

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
        Command::FetchDb(args) => {
            let db = deps::fetch_database(&args.advisory_db, &args.advisory_db_url)?;
            let mut info = deps::database_info(&db);
            info.path = args.advisory_db.display().to_string();
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
    }
    Ok(())
}
