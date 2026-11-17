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

// -- code facts (`codegraph-extract code`) ---------------------------------------------------
//
// The contract with `backend/app/graph/facts.py`. Positions are 1-based lines and 0-based byte
// columns, the same convention the tree-sitter parser uses, so the loader can join both by
// position. Functions, call sites and variables carry integer ids that are unique in one document.

pub const CODE_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize, Default)]
pub struct CodeFacts {
    pub schema_version: u32,
    pub tool: String,
    /// Directory that file paths are relative to.
    pub root: String,
    pub manifest: String,
    /// Workspace member crates (targets) that were analyzed.
    pub crates: Vec<CrateInfo>,
    pub files: Vec<FileFact>,
    pub fns: Vec<FnFact>,
    pub sites: Vec<SiteFact>,
    pub refs: Vec<RefFact>,
    pub vars: Vec<VarFact>,
    pub flows: Vec<FlowFact>,
    /// (trait fn id, impl fn id): a call that resolves to the trait method may run this impl.
    pub dispatch: Vec<(u32, u32)>,
    pub stats: CodeStats,
    pub warnings: Vec<String>,
}

#[derive(Serialize)]
pub struct CrateInfo {
    pub name: String,
    pub root_file: String,
}

#[derive(Serialize)]
pub struct FileFact {
    pub id: u32,
    /// Relative to `root`, with `/` separators.
    pub path: String,
    pub crate_name: String,
    pub symbols: Vec<SymbolFact>,
}

/// One item as written in the source, located by its name token. The golden test compares this
/// list with the tree-sitter parser's symbols.
#[derive(Serialize)]
pub struct SymbolFact {
    /// `fn`, `struct`, `enum`, `union` or `trait`.
    pub kind: &'static str,
    pub name: String,
    pub line: u32,
    pub col: u32,
}

#[derive(Serialize)]
pub struct FnFact {
    pub id: u32,
    pub file: u32,
    pub name: String,
    /// Position of the name token; the join key with the tree-sitter symbol.
    pub line: u32,
    pub col: u32,
    /// False when rust-analyzer has no definition for it (cfg-disabled code, a file outside the
    /// module tree); such functions have no sites, vars or flows.
    pub analyzed: bool,
    pub has_body: bool,
    pub params: Vec<ParamFact>,
    pub ret_kind: &'static str,
    pub ret_type: Option<String>,
    /// `shared`, `exclusive` or `owned` for methods.
    pub self_access: Option<&'static str>,
}

#[derive(Serialize)]
pub struct ParamFact {
    pub index: u32,
    pub name: String,
    pub ty: Option<String>,
    /// Candidate paths of the declared type, most public first (`axum::extract::Query`).
    pub type_paths: Vec<String>,
}

/// One call site, macro invocation, index or arithmetic operation.
#[derive(Serialize, Default)]
pub struct SiteFact {
    pub id: u32,
    #[serde(rename = "fn")]
    pub func: u32,
    /// `call`, `method`, `macro`, `index`, `arith` or `struct` (a struct literal).
    pub kind: &'static str,
    pub name: String,
    pub line: u32,
    pub col: u32,
    /// Orders several sites that share one position (calls made by a macro expansion).
    pub seq: u32,
    pub resolved: bool,
    /// The called function when it is defined in the workspace.
    pub target: Option<u32>,
    /// Candidate `::` paths of an external callee, most public first.
    pub paths: Vec<String>,
    pub def_crate: Option<String>,
    /// Candidate paths of the receiver type of a method call.
    pub recv_type: Vec<String>,
    pub in_unsafe: bool,
    /// The site comes from a macro expansion rather than from tokens written in the function.
    pub in_macro: bool,
    pub literal_args: Vec<(u32, &'static str, String)>,
    pub arg_count: u32,
    /// The call takes a `&mut` argument and so hands data back through it (`read(&mut buf)`):
    /// what flows out of the site is that data, not only its return value.
    pub writes_out: bool,
    pub ret_kind: &'static str,
    /// Index expression text, the operator of an arithmetic site, the format string of a
    /// format-like macro, or the type name of a struct literal.
    pub detail: Option<String>,
    /// For `index`: `slice`, `array`, `vec`, `str`, `map`, `other` or `unknown`.
    pub base_kind: Option<&'static str>,
}

/// A function passed as a value: `get(handler)`, `thread::spawn(worker)`.
#[derive(Serialize)]
pub struct RefFact {
    #[serde(rename = "fn")]
    pub func: u32,
    pub line: u32,
    pub col: u32,
    pub target: Option<u32>,
    pub paths: Vec<String>,
    pub via: String,
}

#[derive(Serialize)]
pub struct VarFact {
    pub id: u32,
    #[serde(rename = "fn")]
    pub func: u32,
    pub name: String,
    /// `param`, `local` or `ret`.
    pub kind: &'static str,
    pub index: Option<u32>,
    pub line: u32,
    pub col: u32,
    pub ty: Option<String>,
    pub ty_kind: &'static str,
    pub type_paths: Vec<String>,
    /// For parameters: candidate paths of the declared parameter type, which differs from the
    /// binding's own type when the parameter is a pattern (`Query(q): Query<Params>`).
    pub param_type_paths: Vec<String>,
    /// Checks applied to this variable anywhere in the function: names of bool-returning calls it
    /// is passed to, methods whose result is compared or matched, and `cmp`, `eq`, `match`.
    pub guards: Vec<String>,
}

/// `from`/`to` are `v<id>` (a variable) or `s<id>` (a site).
#[derive(Serialize)]
pub struct FlowFact {
    pub from: String,
    pub to: String,
    /// `flow` (inside one function), `pass` (argument to the callee's parameter) or `ret`
    /// (the callee's return value to the call site).
    pub kind: &'static str,
    /// `assign`, `arg:<i>`, `recv`, `macro`, `mut`, `out`, `match`, `for`, `closure`, `return`,
    /// `dispatch`.
    pub via: String,
}

#[derive(Serialize, Default)]
pub struct CodeStats {
    pub files: u32,
    pub functions: u32,
    pub analyzed_functions: u32,
    pub path_calls: u32,
    pub resolved_path_calls: u32,
    pub method_calls: u32,
    pub resolved_method_calls: u32,
    pub macro_calls: u32,
    pub expanded_macro_calls: u32,
    pub panicked_functions: u32,
    pub load_seconds: f64,
    pub analysis_seconds: f64,
}
