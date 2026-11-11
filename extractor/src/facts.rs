//! The JSON contract between the extractor and the Python loader (`backend/app/models/deps.py`).
//! Bump `SCHEMA_VERSION` on any incompatible change.

use std::collections::BTreeMap;

use serde::Serialize;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
pub struct DepsFacts {
    pub schema_version: u32,
    pub tool: String,
    /// The lockfile as given on the command line.
    pub lockfile: String,
    pub advisory_db: Option<DatabaseInfo>,
    pub crates: Vec<CrateFact>,
    pub deps: Vec<DepFact>,
    /// Only advisories that match at least one crate, so the document stays small.
    pub advisories: Vec<AdvisoryFact>,
    pub matches: Vec<MatchFact>,
    pub warnings: Vec<String>,
}

#[derive(Serialize)]
pub struct DatabaseInfo {
    pub path: String,
    pub commit: Option<String>,
    pub commit_time: Option<String>,
    pub advisory_count: usize,
}

#[derive(Serialize)]
pub struct CrateFact {
    /// `name@version`, unique within one lockfile.
    pub key: String,
    pub name: String,
    pub version: String,
    /// `registry`, `git`, `path` or `other`; `path` with no source at all means a workspace member
    /// or a path dependency.
    pub source: String,
    pub source_id: Option<String>,
    pub checksum: Option<String>,
}

#[derive(Serialize)]
pub struct DepFact {
    pub from: String,
    pub to: String,
}

#[derive(Serialize)]
pub struct AdvisoryFact {
    pub id: String,
    pub package: String,
    pub title: String,
    pub description: String,
    pub date: String,
    pub aliases: Vec<String>,
    pub related: Vec<String>,
    pub categories: Vec<String>,
    pub keywords: Vec<String>,
    pub cvss: Option<String>,
    pub cvss_score: Option<f64>,
    pub severity: Option<String>,
    /// `unmaintained`, `unsound`, `notice` or another informational kind; None for vulnerabilities.
    pub informational: Option<String>,
    pub url: Option<String>,
    pub references: Vec<String>,
    pub withdrawn: Option<String>,
    pub patched: Vec<String>,
    pub unaffected: Vec<String>,
    /// Affected function paths (`crate::Type::method`) mapped to the affected version ranges.
    pub functions: BTreeMap<String, Vec<String>>,
}

#[derive(Serialize)]
pub struct MatchFact {
    pub advisory: String,
    /// `name@version` of the matching crate.
    pub crate_key: String,
    /// `vulnerability`, `unmaintained`, `unsound`, `notice` or `yanked`.
    pub kind: String,
    /// The affected functions that apply to this crate version.
    pub functions: Vec<String>,
}
