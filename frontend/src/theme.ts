import type { Category, Confidence, EdgeKind, NodeKind, Severity } from "./types";

// Node colour is the only place hue carries meaning; everything else stays neutral.
export const KIND_COLOR: Record<NodeKind, string> = {
  file: "#8fb4ff",
  class: "#f2c66d",
  function: "#7fd1a8",
  external: "#9aa3b5",
  crate: "#c9a7ff",
  advisory: "#ff7b8b",
  unsafe: "#ff9f43",
  call: "#8fd3ff",
  literal: "#ffd166",
  var: "#b8e986",
};

export const EDGE_COLOR: Record<EdgeKind, string> = {
  CONTAINS: "rgba(230, 233, 240, 0.10)",
  IMPORTS: "rgba(143, 180, 255, 0.45)",
  CALLS: "rgba(127, 209, 168, 0.35)",
  INHERITS: "rgba(242, 198, 109, 0.65)",
  IMPLEMENTS: "rgba(214, 160, 255, 0.6)",
  REFERENCES: "rgba(143, 211, 255, 0.5)",
  HAS_CALL: "rgba(143, 211, 255, 0.25)",
  TARGETS: "rgba(143, 211, 255, 0.25)",
  HAS_LITERAL: "rgba(255, 209, 102, 0.35)",
  DECLARES: "rgba(230, 233, 240, 0.10)",
  FLOWS_TO: "rgba(184, 233, 134, 0.6)",
  PASSES: "rgba(184, 233, 134, 0.6)",
  RETURNS_TO: "rgba(184, 233, 134, 0.6)",
  DEPENDS_ON: "rgba(201, 167, 255, 0.45)",
  AFFECTED_BY: "rgba(255, 123, 139, 0.7)",
  HAS_FILE: "rgba(230, 233, 240, 0.10)",
  USES: "rgba(201, 167, 255, 0.35)",
  FROM_CRATE: "rgba(201, 167, 255, 0.35)",
};

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#ff4d6d",
  error: "#ff7b8b",
  warning: "#ffb86b",
  info: "#8ed0ff",
};

export const SEVERITY_RANK: Record<Severity, number> = { critical: 0, error: 1, warning: 2, info: 3 };
export const SEVERITIES: Severity[] = ["critical", "error", "warning", "info"];
export const NODE_KINDS: NodeKind[] = ["file", "class", "function", "external"];   // canvas filters
/** Externals (std, crates, macros) can outnumber project symbols, so they start hidden. */
export const DEFAULT_NODE_KINDS: NodeKind[] = ["file", "class", "function"];
/** Edge kinds the code graph canvas offers as filters; dependency edges have their own view. */
export const EDGE_KINDS: EdgeKind[] = ["CONTAINS", "IMPORTS", "CALLS", "REFERENCES", "INHERITS", "IMPLEMENTS"];

/** Strip the "<project_id>:" prefix for display. */
export const shortId = (id: string) => id.slice(id.indexOf(":") + 1);

/** Vulnerability classes first, in the order of the build plan's rule tables; quality last. */
export const CATEGORIES: Category[] = ["injection", "unsafe", "panic", "dependency", "crypto", "quality"];
export const CATEGORY_LABEL: Record<Category, string> = {
  injection: "injection",
  unsafe: "unsafe code",
  panic: "panics",
  dependency: "dependencies",
  crypto: "crypto & secrets",
  quality: "code quality",
};
export const CONFIDENCES: Confidence[] = ["high", "medium", "low"];

/** RustSec advisory severity (from CVSS) and informational kinds. */
export const ADVISORY_COLOR: Record<string, string> = {
  critical: SEVERITY_COLOR.critical,
  high: SEVERITY_COLOR.error,
  medium: SEVERITY_COLOR.warning,
  low: "#f2d06b",
  none: "#9aa3b5",
  unmaintained: "#9aa3b5",
  unsound: "#ff9f43",
  notice: "#8ed0ff",
};
export const advisoryColor = (severity?: string | null, kind?: string | null) =>
  ADVISORY_COLOR[(kind && kind !== "vulnerability" ? kind : severity) ?? ""] ?? SEVERITY_COLOR.error;

/** Highlighted evidence paths: a warm colour no node kind uses. */
export const PATH_COLOR = "#ffe08a";
export const CANVAS_BG = "#1c2230";

export const cweUrl = (cwe: string) => {
  const n = cwe.replace(/^CWE-/, "");
  return /^\d+$/.test(n) ? `https://cwe.mitre.org/data/definitions/${n}.html` : null;
};
export const advisoryUrl = (id: string, url?: string | null) =>
  /^RUSTSEC-/.test(id) ? `https://rustsec.org/advisories/${id}.html` : url ?? null;
