// Mirrors backend/app/models. Keep the two in sync.

export type NodeKind = "file" | "class" | "function";
export type EdgeKind = "CONTAINS" | "IMPORTS" | "CALLS" | "INHERITS";
export type Severity = "info" | "warning" | "error";

export interface GraphNode {
  id: string;
  kind: NodeKind;
  name: string;
  qualified_name: string;
  file: string;
  line_start: number;
  line_end: number;
  language: string;
  metrics: Record<string, number>;
}

export interface GraphEdge {
  source: string;
  target: string;
  kind: EdgeKind;
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
}

export interface AnalysisReport {
  project_id: string;
  total: number;
  by_severity: Partial<Record<Severity, number>>;
  by_rule: Record<string, number>;
}

export interface NodeDetail {
  node: GraphNode;
  incoming: GraphEdge[];
  outgoing: GraphEdge[];
  findings: Finding[];
}
