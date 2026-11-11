import type { EdgeKind, NodeKind, Severity } from "./types";

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
/** Edge kinds the code graph canvas offers as filters; dependency edges get their own view in phase 4. */
export const EDGE_KINDS: EdgeKind[] = ["CONTAINS", "IMPORTS", "CALLS", "REFERENCES", "INHERITS", "IMPLEMENTS"];

/** Strip the "<project_id>:" prefix for display. */
export const shortId = (id: string) => id.slice(id.indexOf(":") + 1);
