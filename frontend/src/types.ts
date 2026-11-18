// Mirrors backend/app/models. Keep the two in sync.

export type NodeKind =
  | "file" | "class" | "function" | "external" | "crate" | "advisory"
  // security facts: unsafe spans, call sites of interest, redacted secret literals
  | "unsafe" | "call" | "literal"
  // data flow (rust-analyzer extractor): a parameter, local or return value
  | "var";
export type EdgeKind =
  | "CONTAINS" | "IMPORTS" | "CALLS" | "INHERITS" | "IMPLEMENTS"
  | "REFERENCES" | "HAS_CALL" | "TARGETS" | "HAS_LITERAL"
  // data flow: a function's variables and how values move between variables and call sites
  | "DECLARES" | "FLOWS_TO" | "PASSES" | "RETURNS_TO"
  // dependency graph: crates, advisories and how code reaches them
  | "DEPENDS_ON" | "AFFECTED_BY" | "HAS_FILE" | "USES" | "FROM_CRATE";
export type Severity = "info" | "warning" | "error" | "critical";
export type Category = "quality" | "unsafe" | "panic" | "injection" | "dependency" | "crypto";
export type Confidence = "high" | "medium" | "low";
export type ScanState = "scanning" | "ready" | "failed";

export type Scalar = string | number | boolean;

export interface GraphNode {
  id: string;
  kind: NodeKind;
  name: string;
  qualified_name: string;
  file: string;
  line_start: number;
  line_end: number;
  language: string;
  subkind?: string | null;   // language-specific flavour: "struct", "trait", "method", "macro", ...
  metrics: Record<string, number>;
  attrs?: Record<string, Scalar | string[]>;   // e.g. an external's path, crate, is_macro
}

export interface GraphEdge {
  source: string;
  target: string;
  kind: EdgeKind;
  props?: Record<string, Scalar | string[]>;    // CALLS {line, count}, AFFECTED_BY {kind, functions}
}

export interface CodeGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface Project {
  id: string;
  name: string;
  root: string;
  file_count: number;
  symbol_count: number;
  created_at: string;
  status: ScanState;
  error?: string | null;
  scan_started_at?: string | null;
  scan_finished_at?: string | null;
  warnings?: string[];                          // e.g. a Cargo.toml without Cargo.lock
  advisory_db_commit?: string | null;           // RustSec database used by the last scan
}

/** A folder under REPOS_ROOT offered by the picker. */
export interface RepoDir {
  name: string;
  path: string;              // relative to REPOS_ROOT, posix separators
  source_files: number;      // files a registered parser can read, recursively
  has_subdirs: boolean;
  is_git: boolean;
  project_id: string | null; // set when a project already points at this folder
  project_name: string | null;
}

export interface RepoListing {
  path: string;              // the folder that was listed; "" for REPOS_ROOT itself
  dirs: RepoDir[];
}

export interface Finding {
  id: string;
  project_id: string;
  rule: string;
  severity: Severity;
  message: string;
  node_id: string | null;
  file: string | null;
  line: number | null;
  line_end?: number | null;
  category: Category;
  confidence: Confidence;
  cwe: string[];
  evidence: string[];                           // ordered node ids backing the finding
  rule_version?: string | null;
}

export interface AnalysisReport {
  project_id: string;
  total: number;
  by_severity: Partial<Record<Severity, number>>;
  by_rule: Record<string, number>;
  by_category: Partial<Record<Category, number>>;
  catalogue_version: string | null;
}

export interface NodeDetail {
  node: GraphNode;
  incoming: GraphEdge[];
  outgoing: GraphEdge[];
  findings: Finding[];
}

// -- phase 4 views: evidence paths, source slices, the dependency graph ----------------------------

export interface EvidenceStep {
  node: GraphNode;
  owner: GraphNode | null;     // the function (or file) holding a var, call site, unsafe span or literal
  edge: GraphEdge | null;      // the stored edge to the next step, in either direction; null = no hop
}

export interface Evidence {
  finding: Finding;
  steps: EvidenceStep[];
  missing: string[];           // evidence ids no longer in the graph (rescanned after the analysis)
}

export type SourceFlagKind = "finding" | "unsafe" | "safety";

export interface SourceFlag {
  line: number;
  line_end: number;
  kind: SourceFlagKind;
  severity?: Severity | null;
  rule?: string | null;
  message?: string | null;
  finding_id?: string | null;
  node_id?: string | null;
}

export interface SourceSlice {
  path: string;
  language: string;
  start: number;
  end: number;
  total_lines: number;
  lines: string[];
  flags: SourceFlag[];
}

export interface DependencyView {
  nodes: GraphNode[];                       // crates and the advisories affecting them
  edges: GraphEdge[];                       // DEPENDS_ON, AFFECTED_BY
  crate_files: Record<string, string[]>;    // workspace member crate id -> its files
}

export interface AdvisoryInfo {
  id: string;
  package: string;
  title: string;
  description: string;
  date: string;
  kind: string;                             // vulnerability | unmaintained | unsound | notice
  severity?: string | null;
  cvss_score?: number | null;
  url?: string | null;
  aliases: string[];
  patched: string[];
  functions: string[];
}

export interface CrateRef {
  id: string;
  name: string;
  version: string;
}

export interface ProjectAdvisory {
  advisory: AdvisoryInfo;
  crates: CrateRef[];
}

export interface ReachingFunction {
  function: string;
  qualified_name: string;
  file: string;
  line: number;
  path: string;                 // the called external path
  affected: boolean;            // one of the advisory's affected functions
  external: string;             // node id of the External
  sites: number[];              // every call site's line, when the graph has per-site Call nodes
  entry_distance: number | null;
}

export interface AffectedCrateRadius {
  crate: CrateRef;
  kind: string;
  paths: CrateRef[][];          // member first
  functions: ReachingFunction[];
  importing_files: string[];
}

export interface BlastRadius {
  project_id: string;
  advisory: AdvisoryInfo;
  crates: AffectedCrateRadius[];
}
