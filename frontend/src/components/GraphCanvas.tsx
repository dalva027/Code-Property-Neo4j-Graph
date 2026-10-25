import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import ForceGraph2D from "react-force-graph-2d";
import { useFindings, useGraph } from "../hooks/useApi";
import { EDGE_COLOR, EDGE_KINDS, KIND_COLOR, NODE_KINDS, SEVERITY_COLOR, SEVERITY_RANK } from "../theme";
import type { EdgeKind, GraphNode, NodeKind, Severity } from "../types";

type FGNode = GraphNode & { x?: number; y?: number; degree: number; severity?: Severity };
type FGLink = { source: string; target: string; kind: EdgeKind };

interface Props {
  projectId: string;
  selectedNodeId: string | null;
  onSelectNode: (id: string) => void;
}

export function GraphCanvas({ projectId, selectedNodeId, onSelectNode }: Props) {
  const { data: graph, isLoading, error } = useGraph(projectId);
  const { data: findings = [] } = useFindings(projectId);
  const [kinds, setKinds] = useState<Set<NodeKind>>(() => new Set(NODE_KINDS));
  const [edgeKinds, setEdgeKinds] = useState<Set<EdgeKind>>(() => new Set(EDGE_KINDS));
  const { ref, size } = useSize();

  const data = useMemo(() => {
    if (!graph) return { nodes: [] as FGNode[], links: [] as FGLink[] };

    const worst = new Map<string, Severity>();
    for (const f of findings) {
      if (!f.node_id) continue;
      const prev = worst.get(f.node_id);
      if (!prev || SEVERITY_RANK[f.severity] < SEVERITY_RANK[prev]) worst.set(f.node_id, f.severity);
    }

    const visible = new Set(graph.nodes.filter((n) => kinds.has(n.kind)).map((n) => n.id));
    // Copy links: force-graph mutates source/target into node objects.
    const links: FGLink[] = graph.edges
      .filter((e) => edgeKinds.has(e.kind) && visible.has(e.source) && visible.has(e.target))
      .map((e) => ({ ...e }));

    const degree = new Map<string, number>();
    for (const l of links) {
      degree.set(l.source, (degree.get(l.source) ?? 0) + 1);
      degree.set(l.target, (degree.get(l.target) ?? 0) + 1);
    }
    const nodes: FGNode[] = graph.nodes
      .filter((n) => visible.has(n.id))
      .map((n) => ({ ...n, degree: degree.get(n.id) ?? 0, severity: worst.get(n.id) }));

    return { nodes, links };
  }, [graph, findings, kinds, edgeKinds]);

  return (
    <div className="graph-wrap" ref={ref}>
      <div className="graph-toolbar">
        <div className="chip-group" role="group" aria-label="Node kinds">
          {NODE_KINDS.map((k) => (
            <Chip key={k} on={kinds.has(k)} color={KIND_COLOR[k]} onClick={() => setKinds(toggle(kinds, k))}>
              {k}
            </Chip>
          ))}
        </div>
        <div className="chip-group" role="group" aria-label="Edge kinds">
          {EDGE_KINDS.map((k) => (
            <Chip key={k} on={edgeKinds.has(k)} onClick={() => setEdgeKinds(toggle(edgeKinds, k))}>
              {k.toLowerCase()}
            </Chip>
          ))}
        </div>
        <span className="graph-stats">
          {data.nodes.length} nodes, {data.links.length} edges
        </span>
      </div>

      {isLoading && <div className="overlay">Loading graph…</div>}
      {error && <div className="overlay error">{error.message}</div>}
      {!isLoading && !error && data.nodes.length === 0 && (
        <div className="overlay muted">No nodes to show. Check the filters or rescan the project.</div>
      )}

      {size.width > 0 && (
        <ForceGraph2D
          graphData={data}
          width={size.width}
          height={size.height}
          backgroundColor="#1c2230"
          nodeId="id"
          nodeLabel={(n) => `${(n as FGNode).subkind ?? (n as FGNode).kind}: ${(n as FGNode).qualified_name}`}
          nodeCanvasObject={(node, ctx, scale) =>
            paintNode(node as FGNode, ctx, scale, (node as FGNode).id === selectedNodeId)
          }
          nodePointerAreaPaint={(node, color, ctx) => {
            const n = node as FGNode;
            ctx.beginPath();
            ctx.arc(n.x ?? 0, n.y ?? 0, radius(n) + 2, 0, 2 * Math.PI);
            ctx.fillStyle = color;
            ctx.fill();
          }}
          linkColor={(l) => EDGE_COLOR[(l as FGLink).kind]}
          linkWidth={(l) => (["INHERITS", "IMPLEMENTS"].includes((l as FGLink).kind) ? 1.5 : 1)}
          linkDirectionalArrowLength={(l) => ((l as FGLink).kind === "CONTAINS" ? 0 : 4)}
          linkDirectionalArrowRelPos={1}
          onNodeClick={(node) => onSelectNode((node as FGNode).id)}
          cooldownTicks={150}
        />
      )}
    </div>
  );
}

// -- helpers -------------------------------------------------------------------

function Chip({
  on, color, onClick, children,
}: { on: boolean; color?: string; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      className={`chip${on ? " on" : ""}`}
      style={color ? ({ "--chip": color } as CSSProperties) : undefined}
      aria-pressed={on}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

function toggle<T>(set: Set<T>, value: T): Set<T> {
  const next = new Set(set);
  if (next.has(value)) next.delete(value);
  else next.add(value);
  return next;
}

function radius(n: FGNode) {
  return Math.min(14, 3 + Math.sqrt(n.degree) * 1.8);
}

function paintNode(n: FGNode, ctx: CanvasRenderingContext2D, scale: number, selected: boolean) {
  const x = n.x ?? 0;
  const y = n.y ?? 0;
  const r = radius(n);

  ctx.beginPath();
  ctx.arc(x, y, r, 0, 2 * Math.PI);
  ctx.fillStyle = KIND_COLOR[n.kind];
  ctx.fill();

  if (n.severity) {
    ctx.lineWidth = 2.5 / scale;
    ctx.strokeStyle = SEVERITY_COLOR[n.severity];
    ctx.stroke();
  }
  if (selected) {
    ctx.beginPath();
    ctx.arc(x, y, r + 4 / scale, 0, 2 * Math.PI);
    ctx.lineWidth = 1.5 / scale;
    ctx.strokeStyle = "#ffffff";
    ctx.stroke();
  }

  if (selected || n.kind === "file" || scale > 1.8) {
    ctx.font = `${11 / scale}px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`;
    ctx.textBaseline = "middle";
    ctx.fillStyle = selected ? "#ffffff" : "rgba(230, 233, 240, 0.8)";
    ctx.fillText(n.name, x + r + 3 / scale, y);
  }
}

function useSize() {
  const ref = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const observer = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect;
      setSize({ width, height });
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);
  return { ref, size };
}
