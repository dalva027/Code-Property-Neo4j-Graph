//! Cargo.lock + RustSec advisory database -> `DepsFacts`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use rustsec::advisory::{Informational, Metadata};
use rustsec::cargo_lock::{Lockfile, Package};
use rustsec::report::{Report, Settings};
use rustsec::repository::git::Repository;
use rustsec::{Database, Version};

use crate::facts::{
    AdvisoryFact, CrateFact, DatabaseInfo, DepFact, DepsFacts, MatchFact, SCHEMA_VERSION,
};

const LOCK_TIMEOUT: Duration = Duration::from_secs(300);

pub fn key(name: &str, version: &Version) -> String {
    format!("{name}@{version}")
}

/// Clone the advisory database into `path`, or fast-forward an existing checkout.
pub fn fetch_database(path: &Path, url: &str) -> Result<Database> {
    let repo = Repository::fetch(url, path, true, LOCK_TIMEOUT)
        .with_context(|| format!("fetching the advisory database into {}", path.display()))?;
    Database::load_from_repo(&repo).context("loading the advisory database")
}

/// When the checkout was last fetched: git touches FETCH_HEAD on every fetch, HEAD on clone.
fn last_fetch(path: &Path) -> Option<SystemTime> {
    ["FETCH_HEAD", "HEAD"]
        .iter()
        .filter_map(|name| std::fs::metadata(path.join(".git").join(name)).ok())
        .filter_map(|meta| meta.modified().ok())
        .max()
}

/// Open the database, fetching it first when it is missing or older than `max_age`. A failed
/// refresh of an existing checkout is a warning, not an error, so scans keep working offline.
pub fn open_database(
    path: &Path,
    url: &str,
    max_age: Duration,
    offline: bool,
    warnings: &mut Vec<String>,
) -> Result<Option<Database>> {
    let present = path.join(".git").is_dir() || path.join("crates").is_dir();
    if !present {
        if offline {
            warnings.push(format!(
                "no advisory database at {} and --offline was given; advisories skipped",
                path.display()
            ));
            return Ok(None);
        }
        return fetch_database(path, url).map(Some);
    }

    let stale = !max_age.is_zero()
        && last_fetch(path)
            .and_then(|t| t.elapsed().ok())
            .is_none_or(|age| age > max_age);
    if stale && !offline && path.join(".git").is_dir() {
        match fetch_database(path, url) {
            Ok(db) => return Ok(Some(db)),
            Err(err) => warnings.push(format!(
                "could not refresh the advisory database, using the local copy: {err:#}"
            )),
        }
    }

    let db = match Repository::open(path) {
        Ok(repo) => Database::load_from_repo(&repo),
        Err(_) => Database::open(path),
    }
    .with_context(|| format!("opening the advisory database at {}", path.display()))?;
    Ok(Some(db))
}

pub fn database_info(db: &Database) -> DatabaseInfo {
    let commit = db.latest_commit();
    DatabaseInfo {
        path: String::new(),
        commit: commit.map(|c| c.commit_id.to_string()),
        commit_time: commit.map(|c| c.timestamp.to_string()),
        advisory_count: db.iter().count(),
    }
}

fn source_kind(package: &Package) -> (String, Option<String>) {
    match &package.source {
        None => ("path".into(), None),
        Some(source) => {
            let kind = if source.is_registry() {
                "registry"
            } else if source.is_git() {
                "git"
            } else if source.is_path() {
                "path"
            } else {
                "other"
            };
            (kind.into(), Some(source.to_string()))
        }
    }
}

fn advisory_fact(
    meta: &Metadata,
    versions: &rustsec::advisory::Versions,
    affected: Option<&rustsec::advisory::Affected>,
) -> AdvisoryFact {
    let (cvss, cvss_score, severity) = match &meta.cvss {
        Some(c) => (
            Some(c.to_string()),
            Some(c.score()),
            Some(c.severity().to_string()),
        ),
        None => (None, None, None),
    };
    AdvisoryFact {
        id: meta.id.to_string(),
        package: meta.package.to_string(),
        title: meta.title.clone(),
        description: meta.description.clone(),
        date: meta.date.to_string(),
        aliases: meta.aliases.iter().map(ToString::to_string).collect(),
        related: meta.related.iter().map(ToString::to_string).collect(),
        categories: meta.categories.iter().map(ToString::to_string).collect(),
        keywords: meta
            .keywords
            .iter()
            .map(|k| k.as_str().to_string())
            .collect(),
        cvss,
        cvss_score,
        severity,
        informational: meta.informational.as_ref().map(|i| i.as_str().to_string()),
        url: meta.url.as_ref().map(ToString::to_string),
        references: meta.references.iter().map(ToString::to_string).collect(),
        withdrawn: meta.withdrawn.as_ref().map(ToString::to_string),
        patched: versions.patched().iter().map(ToString::to_string).collect(),
        unaffected: versions
            .unaffected()
            .iter()
            .map(ToString::to_string)
            .collect(),
        functions: affected
            .map(|a| {
                a.functions
                    .iter()
                    .map(|(path, reqs)| {
                        (
                            path.to_string(),
                            reqs.iter().map(ToString::to_string).collect(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// Affected function paths whose version ranges include this crate version.
fn functions_for(affected: Option<&rustsec::advisory::Affected>, version: &Version) -> Vec<String> {
    affected
        .map(|a| {
            a.functions
                .iter()
                .filter(|(_, reqs)| reqs.is_empty() || reqs.iter().any(|r| r.matches(version)))
                .map(|(path, _)| path.to_string())
                .collect()
        })
        .unwrap_or_default()
}

pub fn extract(
    lockfile_path: &Path,
    db: Option<&Database>,
    mut warnings: Vec<String>,
) -> Result<DepsFacts> {
    let lockfile = Lockfile::load(lockfile_path)
        .with_context(|| format!("reading {}", lockfile_path.display()))?;

    let crates = lockfile
        .packages
        .iter()
        .map(|p| {
            let (source, source_id) = source_kind(p);
            CrateFact {
                key: key(p.name.as_str(), &p.version),
                name: p.name.to_string(),
                version: p.version.to_string(),
                source,
                source_id,
                checksum: p.checksum.as_ref().map(ToString::to_string),
            }
        })
        .collect::<Vec<_>>();

    // Dependencies in Cargo.lock name a version only when the name is ambiguous.
    let mut versions_by_name: BTreeMap<&str, Vec<&Version>> = BTreeMap::new();
    for p in &lockfile.packages {
        versions_by_name
            .entry(p.name.as_str())
            .or_default()
            .push(&p.version);
    }
    let mut deps = Vec::new();
    for p in &lockfile.packages {
        for d in &p.dependencies {
            let candidates = versions_by_name
                .get(d.name.as_str())
                .cloned()
                .unwrap_or_default();
            let version = if candidates.len() == 1 {
                Some(candidates[0])
            } else {
                candidates.into_iter().find(|v| **v == d.version)
            };
            match version {
                Some(v) => deps.push(DepFact {
                    from: key(p.name.as_str(), &p.version),
                    to: key(d.name.as_str(), v),
                }),
                None => warnings.push(format!(
                    "{} depends on {} {}, which is not in the lockfile",
                    p.name, d.name, d.version
                )),
            }
        }
    }

    let mut advisories: BTreeMap<String, AdvisoryFact> = BTreeMap::new();
    let mut matches = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut db_info = None;

    if let Some(db) = db {
        db_info = Some(database_info(db));

        // The same settings cargo-audit uses by default: every platform, no severity floor, and
        // warnings for unmaintained, unsound and notice advisories.
        let settings = Settings {
            informational_warnings: vec![
                Informational::Unmaintained,
                Informational::Unsound,
                Informational::Notice,
            ],
            ..Settings::default()
        };
        let report = Report::generate(db, &lockfile, &settings);

        for vuln in &report.vulnerabilities.list {
            let crate_key = key(vuln.package.name.as_str(), &vuln.package.version);
            if seen.insert((vuln.advisory.id.to_string(), crate_key.clone())) {
                advisories
                    .entry(vuln.advisory.id.to_string())
                    .or_insert_with(|| {
                        advisory_fact(&vuln.advisory, &vuln.versions, vuln.affected.as_ref())
                    });
                matches.push(MatchFact {
                    advisory: vuln.advisory.id.to_string(),
                    crate_key,
                    kind: "vulnerability".into(),
                    functions: functions_for(vuln.affected.as_ref(), &vuln.package.version),
                });
            }
        }
        for (kind, list) in &report.warnings {
            for warning in list {
                let Some(meta) = &warning.advisory else {
                    continue;
                };
                let crate_key = key(warning.package.name.as_str(), &warning.package.version);
                if !seen.insert((meta.id.to_string(), crate_key.clone())) {
                    continue;
                }
                let versions = warning.versions.clone().unwrap_or_else(|| {
                    rustsec::advisory::Versions::new(vec![], vec![])
                        .expect("empty version ranges are valid")
                });
                advisories
                    .entry(meta.id.to_string())
                    .or_insert_with(|| advisory_fact(meta, &versions, warning.affected.as_ref()));
                matches.push(MatchFact {
                    advisory: meta.id.to_string(),
                    crate_key,
                    kind: kind.as_str().to_string(),
                    functions: functions_for(warning.affected.as_ref(), &warning.package.version),
                });
            }
        }
    }

    Ok(DepsFacts {
        schema_version: SCHEMA_VERSION,
        tool: concat!("codegraph-extract ", env!("CARGO_PKG_VERSION")).into(),
        lockfile: lockfile_path.display().to_string(),
        advisory_db: db_info,
        crates,
        deps,
        advisories: advisories.into_values().collect(),
        matches,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const LOCK: &str = r#"
version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["smallvec", "log 0.4.20"]

[[package]]
name = "log"
version = "0.4.20"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "b5e6163cb8c49088c2c36f57875e58ccd8c87c7427f7fbd50ea6710b2f3f2e8f"

[[package]]
name = "log"
version = "0.3.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e19e8d5c34a3e0e2223db8e060f9e8264aeeb5c5fc64a4ee9965c062211c024b"
dependencies = ["log 0.4.20"]

[[package]]
name = "smallvec"
version = "1.6.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1a55ca5f3b68e41c979bf8c46a6f1da892ca4db8f94023ce0bd32407573b1ac0"
"#;

    #[test]
    fn crates_and_edges_without_a_database() {
        let dir = std::env::temp_dir().join(format!("cg-extract-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Cargo.lock");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(LOCK.as_bytes())
            .unwrap();

        let facts = extract(&path, None, vec![]).unwrap();
        let keys: Vec<_> = facts.crates.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(
            keys,
            ["app@0.1.0", "log@0.4.20", "log@0.3.9", "smallvec@1.6.0"]
        );
        assert_eq!(facts.crates[0].source, "path");
        assert_eq!(facts.crates[1].source, "registry");

        let edges: Vec<_> = facts
            .deps
            .iter()
            .map(|d| (d.from.as_str(), d.to.as_str()))
            .collect();
        assert_eq!(
            edges,
            [
                ("app@0.1.0", "smallvec@1.6.0"),
                ("app@0.1.0", "log@0.4.20"),
                ("log@0.3.9", "log@0.4.20")
            ]
        );
        assert!(facts.advisory_db.is_none() && facts.matches.is_empty());
        std::fs::remove_dir_all(dir).ok();
    }
}
