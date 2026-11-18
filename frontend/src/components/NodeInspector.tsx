import type { CSSProperties } from "react";
import { useNode } from "../hooks/useApi";
import { KIND_COLOR, SEVERITY_COLOR, shortId } from "../theme";
import type { EdgeKind, GraphEdge, GraphNode } from "../types";
import { CweLinks } from "./FindingsPanel";

interface Props {
  projectId: string;
  nodeId: string;
  onClose: () => void;
  onSelectNode: (id: string) => void;
  onOpenFinding: (id: string) => void;
  onOpenSource: (path: string, line: number, lineEnd?: number) => void;
  onOpenAdvisory: (id: string) => void;
  onMode: (mode: "code" | "deps") => void;
}

export function NodeInspector({
  projectId, nodeId, onClose, onSelectNode, onOpenFinding, onOpenSource, onOpenAdvisory, onMode,
}: Props) {
  const { data, isLoading, error } = useNode(projectId, nodeId);

  if (isLoading) return <div className="panel muted">Loading node…</div>;
  if (error || !data) {
    return (
      <div className="panel">
        <p className="error">{error?.message ?? "Node not found. It may have been removed by a rescan."}</p>
        <button className="ghost" onClick={onClose}>Back</button>
      </div>
    );
  }

  const { node, incoming, outgoing, findings } = data;
  const hasSource = node.file !== "" && node.line_start > 0 && node.kind !== "advisory";
  return (
    <div className="panel">
      <header className="panel-header">
        <span className="kind-badge" style={{ "--chip": KIND_COLOR[node.kind] } as CSSProperties}>
          {node.subkind ?? node.kind}
        </span>
        <button className="ghost" onClick={onClose}>Back</button>
      </header>

      <h2 className="mono">{node.name}</h2>
      <p className="muted mono small">{node.qualified_name}</p>
      <NodeLocation node={node} />
      <div className="node-actions">
        {hasSource && (
          <button className="ghost-button" onClick={() => onOpenSource(node.file, node.line_start,
            node.kind === "file" ? undefined : node.line_end)}>
            View source
          </button>
        )}
        {node.kind === "advisory" && (
          <button className="ghost-button" onClick={() => onOpenAdvisory(node.id)}>Blast radius</button>
        )}
        {(node.kind === "crate" || node.kind === "advisory") && (
          <button className="ghost-button" onClick={() => onMode("deps")}>Show in dependency graph</button>
        )}
      </div>

      {node.kind === "advisory" && typeof node.attrs?.title === "string" && (
        <p>
          {node.attrs.title}
          {typeof node.attrs.url === "string" && (
            <>
              {" "}
              <a href={node.attrs.url} target="_blank" rel="noreferrer">details</a>
            </>
          )}
        </p>
      )}

      {node.attrs && Object.keys(node.attrs).length > 0 && (
        <dl className="attrs">
          {Object.entries(node.attrs).filter(([k]) => !LONG_ATTRS.has(k)).map(([k, v]) => (
            <div key={k} style={{ display: "contents" }}>
              <dt>{k}</dt>
              <dd>{Array.isArray(v) ? v.join(", ") : String(v)}</dd>
            </div>
          ))}
        </dl>
      )}

      {Object.keys(node.metrics).length > 0 && (
        <dl className="metrics">
          {Object.entries(node.metrics).map(([k, v]) => (
            <div key={k}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
      )}

      {findings.length > 0 && (
        <section>
          <h3>Findings on this node</h3>
          <ul className="plain">
            {findings.map((f) => (
              <li key={f.id} className="inline-finding">
                <span className="severity-dot" style={{ background: SEVERITY_COLOR[f.severity] }} />
                <span>
                  <span className="finding-rule">{f.rule}</span>
                  <CweLinks cwe={f.cwe} />{" "}
                  <button className="link finding-open-inline" onClick={() => onOpenFinding(f.id)}>{f.message}</button>
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}

      <EdgeList title="Outgoing" edges={outgoing} pick={(e) => e.target} onSelectNode={onSelectNode} />
      <EdgeList title="Incoming" edges={incoming} pick={(e) => e.source} onSelectNode={onSelectNode} />
    </div>
  );
}

function EdgeList({
  title, edges, pick, onSelectNode,
}: {
  title: string;
  edges: GraphEdge[];
  pick: (e: GraphEdge) => string;
  onSelectNode: (id: string) => void;
}) {
  if (edges.length === 0) return null;
  const groups = new Map<EdgeKind, GraphEdge[]>();
  for (const e of edges) groups.set(e.kind, [...(groups.get(e.kind) ?? []), e]);

  return (
    <section>
      <h3>
        {title} <span className="muted">{edges.length}</span>
      </h3>
      {[...groups.entries()].map(([kind, group]) => (
        <div key={kind} className="edge-group">
          <div className="edge-kind">{kind.toLowerCase()}</div>
          <ul className="plain">
            {group.map((e) => (
              <li key={pick(e)}>
                <button className="link mono" onClick={() => onSelectNode(pick(e))}>
                  {shortId(pick(e))}
                </button>
                <EdgeMeta edge={e} />
              </li>
            ))}
          </ul>
        </div>
      ))}
    </section>
  );
}

/** Shown elsewhere (title, link) or too long for the attribute list. */
const LONG_ATTRS = new Set(["title", "url", "description", "params", "sha256"]);

function NodeLocation({ node }: { node: GraphNode }) {
  switch (node.kind) {
    case "external":
      return <p className="muted small">Called from this project but not defined in it · {node.language}</p>;
    case "crate":
      return (
        <p className="muted small">
          {node.subkind} · {node.file}, line {node.line_start}
        </p>
      );
    case "advisory":
      return <p className="muted small">RustSec advisory · {node.subkind}</p>;
    case "unsafe":
      return (
        <p className="muted small">
          unsafe {node.subkind} · {node.file}, lines {node.line_start}–{node.line_end}
          {node.attrs?.has_safety_comment ? " · SAFETY comment present" : " · no SAFETY comment"}
        </p>
      );
    case "call":
      return (
        <p className="muted small">
          {node.subkind === "call" ? `call to ${node.attrs?.callee_path}` : `${node.subkind} operation`} ·{" "}
          {node.file}, line {node.line_start}
          {node.attrs?.in_unsafe ? " · inside unsafe" : ""}
        </p>
      );
    case "literal":
      return (
        <p className="muted small">
          redacted string literal · {node.file}, line {node.line_start} · value never stored
        </p>
      );
    case "var":
      return (
        <p className="muted small">
          {node.subkind === "ret" ? "return value" : node.subkind === "param" ? "parameter" : "local variable"}
          {typeof node.attrs?.type === "string" ? ` of type ${node.attrs.type}` : ""} · {node.file}, line{" "}
          {node.line_start}
        </p>
      );
    default:
      return (
        <p className="muted small">
          {node.file}, lines {node.line_start}–{node.line_end} · {node.language}
        </p>
      );
  }
}

/** CALLS edges carry the first call site's line and how many call sites there are. */
function EdgeMeta({ edge }: { edge: GraphEdge }) {
  const { line, count } = edge.props ?? {};
  if (line === undefined && count === undefined) return null;
  return (
    <span className="edge-meta">
      {line !== undefined && `line ${line}`}
      {typeof count === "number" && count > 1 && ` · ${count}×`}
    </span>
  );
}
