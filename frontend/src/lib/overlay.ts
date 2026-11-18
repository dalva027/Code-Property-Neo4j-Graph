// Findings placed on the canvases: which node each finding belongs to, the worst severity per node
// (the halo), and counts per file and crate.
import { SEVERITY_RANK } from "../theme";
import type {
  Category, CodeGraph, Confidence, DependencyView, EvidenceStep, Finding, GraphNode, Severity,
} from "../types";

export interface FindingFilter {
  categories: Set<Category>;
  confidences: Set<Confidence>;
}

export const passes = (f: Finding, filter: FindingFilter) =>
  filter.categories.has(f.category) && filter.confidences.has(f.confidence);

export interface Mark {
  severity: Severity;
  count: number;
}

function bump(marks: Map<string, Mark>, id: string, severity: Severity) {
  const prev = marks.get(id);
  if (!prev) marks.set(id, { severity, count: 1 });
  else {
    prev.count += 1;
    if (SEVERITY_RANK[severity] < SEVERITY_RANK[prev.severity]) prev.severity = severity;
  }
}

/** Where files and symbols are, so a finding (or an evidence step) on a node the canvas does not
 * draw (a call site, a variable, an unsafe span) lands on the innermost symbol around its line. */
export class CodeIndex {
  readonly ids: Set<string>;
  private files = new Map<string, string>();               // path -> file node id
  private symbols = new Map<string, GraphNode[]>();         // path -> classes and functions, innermost first

  constructor(graph: CodeGraph | undefined) {
    const nodes = graph?.nodes ?? [];
    this.ids = new Set(nodes.map((n) => n.id));
    for (const n of nodes) {
      if (n.kind === "file") this.files.set(n.file, n.id);
      else if ((n.kind === "function" || n.kind === "class") && n.file) {
        const list = this.symbols.get(n.file) ?? [];
        list.push(n);
        this.symbols.set(n.file, list);
      }
    }
    for (const list of this.symbols.values()) list.sort((a, b) => a.line_end - a.line_start - (b.line_end - b.line_start));
  }

  fileNode(path: string | null | undefined): string | null {
    return (path && this.files.get(path)) || null;
  }

  /** The innermost class or function of `path` spanning `line`, else the file. */
  at(path: string | null | undefined, line: number | null | undefined): string | null {
    if (!path) return null;
    if (line) {
      const hit = this.symbols.get(path)?.find((s) => s.line_start <= line && line <= s.line_end);
      if (hit) return hit.id;
    }
    return this.fileNode(path);
  }

  /** The canvas node a finding sits on. */
  anchor(f: Finding): string | null {
    if (f.node_id && this.ids.has(f.node_id)) return f.node_id;
    return this.at(f.file, f.line);
  }

  /** The canvas node standing for one evidence step: the node itself, or what holds it. */
  step(step: EvidenceStep): string | null {
    const { node, owner } = step;
    if (this.ids.has(node.id)) return node.id;
    if (owner && this.ids.has(owner.id)) return owner.id;
    return node.file ? this.at(node.file, node.line_start) : null;
  }
}

/** Worst severity and count per code-canvas node. A file also collects everything inside it. */
export function codeMarks(findings: Finding[], index: CodeIndex): Map<string, Mark> {
  const marks = new Map<string, Mark>();
  for (const f of findings) {
    const anchor = index.anchor(f);
    if (anchor) bump(marks, anchor, f.severity);
    const file = index.fileNode(f.file);
    if (file && file !== anchor) bump(marks, file, f.severity);
  }
  return marks;
}

/** Which crate a finding belongs to: the crate it sits on (dependency rules), else the workspace
 * member whose files contain it. */
export class CrateIndex {
  private byFile = new Map<string, string>();
  readonly names = new Map<string, string>();               // crate id -> "name version"
  readonly members = new Set<string>();

  constructor(view: DependencyView | undefined) {
    for (const [crate, files] of Object.entries(view?.crate_files ?? {})) {
      this.members.add(crate);
      for (const file of files) this.byFile.set(file, crate);
    }
    for (const n of view?.nodes ?? []) {
      if (n.kind === "crate") this.names.set(n.id, `${n.name} ${n.attrs?.version ?? ""}`.trim());
    }
  }

  ofFile(path: string | null | undefined): string | null {
    return (path && this.byFile.get(path)) || null;
  }

  of(f: Finding): string | null {
    if (f.node_id && this.names.has(f.node_id)) return f.node_id;
    return this.ofFile(f.file);
  }
}

/** Worst severity and count per dependency-canvas node: findings on a crate, and findings in the
 * code of a workspace member. */
export function crateMarks(findings: Finding[], crates: CrateIndex): Map<string, Mark> {
  const marks = new Map<string, Mark>();
  for (const f of findings) {
    const crate = crates.of(f);
    if (crate) bump(marks, crate, f.severity);
  }
  return marks;
}
