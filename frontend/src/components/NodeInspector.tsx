import type { CSSProperties } from "react";
import { useNode } from "../hooks/useApi";
import { KIND_COLOR, SEVERITY_COLOR, shortId } from "../theme";
import type { EdgeKind, GraphEdge } from "../types";

interface Props {
  projectId: string;
  nodeId: string;
  onClose: () => void;
  onSelectNode: (id: string) => void;
}

export function NodeInspector({ projectId, nodeId, onClose, onSelectNode }: Props) {
  const { data, isLoading, error } = useNode(projectId, nodeId);

  if (isLoading) return <div className="panel muted">Loading node…</div>;
  if (error || !data) {
    return (
      <div className="panel">
        <p className="error">{error?.message ?? "Node not found. It may have been removed by a rescan."}</p>
        <button className="ghost" onClick={onClose}>Back to findings</button>
      </div>
    );
  }

  const { node, incoming, outgoing, findings } = data;
  return (
    <div className="panel">
      <header className="panel-header">
        <span className="kind-badge" style={{ "--chip": KIND_COLOR[node.kind] } as CSSProperties}>
          {node.subkind ?? node.kind}
        </span>
        <button className="ghost" onClick={onClose}>Back to findings</button>
      </header>

      <h2 className="mono">{node.name}</h2>
      <p className="muted mono small">{node.qualified_name}</p>
      <p className="muted small">
        {node.file}, lines {node.line_start}–{node.line_end} · {node.language}
      </p>

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
                  <span className="finding-rule">{f.rule}</span> {f.message}
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
  const groups = new Map<EdgeKind, string[]>();
  for (const e of edges) groups.set(e.kind, [...(groups.get(e.kind) ?? []), pick(e)]);

  return (
    <section>
      <h3>
        {title} <span className="muted">{edges.length}</span>
      </h3>
      {[...groups.entries()].map(([kind, ids]) => (
        <div key={kind} className="edge-group">
          <div className="edge-kind">{kind.toLowerCase()}</div>
          <ul className="plain">
            {ids.map((id) => (
              <li key={id}>
                <button className="link mono" onClick={() => onSelectNode(id)}>
                  {shortId(id)}
                </button>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </section>
  );
}
