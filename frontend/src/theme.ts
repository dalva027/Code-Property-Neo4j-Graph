import type { EdgeKind, NodeKind, Severity } from "./types";

// Node colour is the only place hue carries meaning; everything else stays neutral.
export const KIND_COLOR: Record<NodeKind, string> = {
  file: "#8fb4ff",
  class: "#f2c66d",
  function: "#7fd1a8",
};

export const EDGE_COLOR: Record<EdgeKind, string> = {
  CONTAINS: "rgba(230, 233, 240, 0.10)",
  IMPORTS: "rgba(143, 180, 255, 0.45)",
  CALLS: "rgba(127, 209, 168, 0.35)",
  INHERITS: "rgba(242, 198, 109, 0.65)",
};

export const SEVERITY_COLOR: Record<Severity, string> = {
  error: "#ff7b8b",
  warning: "#ffb86b",
  info: "#8ed0ff",
};

export const SEVERITY_RANK: Record<Severity, number> = { error: 0, warning: 1, info: 2 };
export const SEVERITIES: Severity[] = ["error", "warning", "info"];
export const NODE_KINDS: NodeKind[] = ["file", "class", "function"];
export const EDGE_KINDS: EdgeKind[] = ["CONTAINS", "IMPORTS", "CALLS", "INHERITS"];

/** Strip the "<project_id>:" prefix for display. */
export const shortId = (id: string) => id.slice(id.indexOf(":") + 1);
