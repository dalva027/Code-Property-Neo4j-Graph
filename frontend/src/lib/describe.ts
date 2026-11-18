// Steps of an evidence path, and the edges between them, in words.
import type { EdgeKind, GraphEdge, GraphNode } from "../types";

export interface StepText {
  title: string;      // what the step is: `parameter path`, `std::process::Command::new`
  detail?: string;    // where: `in cli.commands.run_tool`, a type, an entry kind
  mono?: boolean;     // the title is a path or name, set in the monospace face
}

const inFn = (owner: GraphNode | null) =>
  owner && owner.kind === "function" ? `in ${owner.qualified_name}` : owner ? `in ${owner.name}` : undefined;

export function describeStep(node: GraphNode, owner: GraphNode | null): StepText {
  const a = node.attrs ?? {};
  const type = typeof a.type === "string" ? a.type : undefined;
  switch (node.kind) {
    case "var":
      if (node.subkind === "param")
        return { title: `parameter ${node.name}`, detail: [type && `: ${type}`, inFn(owner)].filter(Boolean).join(" "), mono: true };
      if (node.subkind === "ret") return { title: "return value", detail: owner ? `of ${owner.qualified_name}` : undefined };
      return { title: `let ${node.name}`, detail: [type && `: ${type}`, inFn(owner)].filter(Boolean).join(" "), mono: true };
    case "call":
      if (node.subkind === "index") return { title: "index operation [ ]", detail: inFn(owner) };
      if (node.subkind === "arith") return { title: `arithmetic ${a.detail ?? ""}`.trim(), detail: inFn(owner) };
      if (node.subkind === "struct") return { title: `${node.name} { … }`, detail: inFn(owner), mono: true };
      return { title: String(a.callee_path ?? node.name), detail: inFn(owner), mono: true };
    case "function": {
      const entry = typeof a.entry_kind === "string" ? `${a.entry_kind} entry point` : undefined;
      return { title: node.qualified_name, detail: entry, mono: true };
    }
    case "external":
      return { title: node.qualified_name, detail: "outside the project", mono: true };
    case "unsafe":
      return { title: `unsafe ${node.subkind ?? "block"}`, detail: inFn(owner) };
    case "literal":
      return { title: `string literal (${node.subkind ?? "secret-like"})`, detail: inFn(owner) };
    case "crate":
      return { title: `${node.name} ${a.version ?? ""}`.trim(), detail: node.subkind ?? undefined, mono: true };
    case "advisory":
      return { title: node.name, detail: typeof a.title === "string" ? a.title : undefined, mono: true };
    default:
      return { title: node.qualified_name, mono: true };
  }
}

function via(v: unknown): string | null {
  if (typeof v !== "string" || !v) return null;
  if (v === "assign") return "assigned";
  if (v === "recv") return "as the receiver";
  if (v === "return") return "returned";
  if (v === "macro") return "into the macro";
  if (v === "dispatch") return "through a trait";
  const arg = /^arg:(\d+)$/.exec(v);
  if (arg) return `as argument ${Number(arg[1]) + 1}`;
  if (v.startsWith("field:")) return `into field ${v.slice(6)}`;
  return v;
}

const EDGE_WORDS: Partial<Record<EdgeKind, string>> = {
  FLOWS_TO: "flows",
  PASSES: "passed to the callee",
  RETURNS_TO: "returned to the caller",
  CALLS: "calls",
  REFERENCES: "passes as a value",
  HAS_CALL: "makes the call",
  TARGETS: "targets",
  CONTAINS: "contains",
  DECLARES: "declares",
  HAS_LITERAL: "holds",
  FROM_CRATE: "is defined in",
  DEPENDS_ON: "depends on",
  AFFECTED_BY: "is affected by",
  USES: "uses",
};

/** How step `from` leads to the next one. `null` edge: listed side by side, not a hop. */
export function describeEdge(edge: GraphEdge | null, from: string): string {
  if (!edge) return "and";
  const backwards = edge.target === from;
  const words = EDGE_WORDS[edge.kind] ?? edge.kind.toLowerCase();
  const how = edge.kind === "FLOWS_TO" || edge.kind === "PASSES" ? via(edge.props?.via) : null;
  const line = edge.kind === "CALLS" && typeof edge.props?.line === "number" ? ` (line ${edge.props.line})` : "";
  return `${backwards ? "← " : ""}${words}${how ? ` ${how}` : ""}${line}`;
}
