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
