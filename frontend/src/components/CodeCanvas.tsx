import { useMemo, useState } from "react";
import { useGraph } from "../hooks/useApi";
import { CodeIndex, codeMarks } from "../lib/overlay";
import { evidenceHighlight, radiusInCode, type Spotlight } from "../lib/spotlight";
import { DEFAULT_NODE_KINDS, EDGE_COLOR, EDGE_KINDS, KIND_COLOR, NODE_KINDS, SEVERITY_COLOR } from "../theme";
import type { EdgeKind, Finding, NodeKind, ScanState } from "../types";
import { Chip, toggle } from "./Chip";
import { GraphView, type Highlight, type ViewLink, type ViewNode } from "./GraphView";

interface Props {
  projectId: string;
  status: ScanState;
  error: string | null;           // why the last scan failed
  findings: Finding[];            // already narrowed by the category and confidence filters
  selectedNodeId: string | null;
  spotlight: Spotlight | null;
  onSelectNode: (id: string) => void;
}

const NO_FINDING = "#4a5266";

export function CodeCanvas({ projectId, status, error: scanError, findings, selectedNodeId, spotlight, onSelectNode }: Props) {
  const ready = status === "ready";
  const { data: graph, isLoading, error } = useGraph(projectId, ready);
  const [kinds, setKinds] = useState<Set<NodeKind>>(() => new Set(DEFAULT_NODE_KINDS));
  const [edgeKinds, setEdgeKinds] = useState<Set<EdgeKind>>(() => new Set(EDGE_KINDS));
  const [bySeverity, setBySeverity] = useState(false);

  const index = useMemo(() => new CodeIndex(graph), [graph]);
  const marks = useMemo(() => codeMarks(findings, index), [findings, index]);
  const externalCount = useMemo(() => graph?.nodes.filter((n) => n.kind === "external").length ?? 0, [graph]);

  const highlight = useMemo((): Highlight | null => {
    if (!spotlight) return null;
    if (spotlight.kind === "evidence")
      return evidenceHighlight(spotlight.key, spotlight.steps, spotlight.current, (s) => index.step(s));
    return radiusInCode(spotlight.key, spotlight.radius, (id) => index.ids.has(id));
  }, [spotlight, index]);

  // A lit node is drawn even when its kind is filtered out (an external on an advisory's path). The
  // key changes only when that set does, not on every step of a path.
  const forcedKey = useMemo(() => {
    if (!highlight || !graph) return "";
    const kindOf = new Map(graph.nodes.map((n) => [n.id, n.kind] as const));
    return [...highlight.nodes].filter((id) => !kinds.has(kindOf.get(id) ?? "file")).sort().join("\n");
  }, [highlight, graph, kinds]);
  const { nodes, links } = useMemo(() => {
    if (!graph) return { nodes: [] as ViewNode[], links: [] as ViewLink[] };
    const forced = new Set(forcedKey ? forcedKey.split("\n") : []);
    const visible = new Set(graph.nodes.filter((n) => kinds.has(n.kind) || forced.has(n.id)).map((n) => n.id));
    const links: ViewLink[] = graph.edges
      .filter((e) => edgeKinds.has(e.kind) && visible.has(e.source) && visible.has(e.target))
      .map((e) => ({
        source: e.source, target: e.target, color: EDGE_COLOR[e.kind],
        width: e.kind === "INHERITS" || e.kind === "IMPLEMENTS" ? 1.5 : 1, arrow: e.kind !== "CONTAINS",
      }));
    const degree = new Map<string, number>();
    for (const l of links) {
      degree.set(l.source, (degree.get(l.source) ?? 0) + 1);
      degree.set(l.target, (degree.get(l.target) ?? 0) + 1);
    }
    const nodes: ViewNode[] = graph.nodes.filter((n) => visible.has(n.id)).map((n) => {
      const mark = marks.get(n.id);
      return {
        id: n.id,
        name: n.kind === "file" && mark ? `${n.name} · ${mark.count}` : n.name,
        tooltip: `${n.subkind ?? n.kind}: ${n.qualified_name}${mark ? ` — ${mark.count} finding${mark.count === 1 ? "" : "s"}, worst ${mark.severity}` : ""}`,
        color: bySeverity ? (mark ? SEVERITY_COLOR[mark.severity] : NO_FINDING) : KIND_COLOR[n.kind],
        radius: Math.min(14, 3 + Math.sqrt(degree.get(n.id) ?? 0) * 1.8),
        severity: mark?.severity,
        count: n.kind === "file" ? undefined : mark && mark.count > 1 ? mark.count : undefined,
        label: n.kind === "file",
      };
    });
    return { nodes, links };
  }, [graph, kinds, edgeKinds, forcedKey, marks, bySeverity]);

  return (
    <div className="graph-wrap">
      <div className="graph-toolbar">
        <div className="chip-group" role="group" aria-label="Node kinds">
          {NODE_KINDS.map((k) => (
            <Chip key={k} on={kinds.has(k)} color={KIND_COLOR[k]} onClick={() => setKinds(toggle(kinds, k))}>
              {k === "external" ? `external ${externalCount}` : k}
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
        <Chip on={bySeverity} color={SEVERITY_COLOR.error} onClick={() => setBySeverity(!bySeverity)}
              title="Fill nodes with the colour of their worst finding instead of their kind">
          colour by severity
        </Chip>
        <span className="graph-stats">
          {nodes.length} nodes, {links.length} edges
        </span>
      </div>

      {status === "scanning" && <div className="overlay">Scanning the source tree…</div>}
      {status === "failed" && (
        <div className="overlay error">Scan failed: {scanError ?? "unknown error"}. Rescan to try again.</div>
      )}
      {ready && isLoading && <div className="overlay">Loading graph…</div>}
      {ready && error && <div className="overlay error">{error.message}</div>}
      {ready && !isLoading && !error && nodes.length === 0 && (
        <div className="overlay muted">No nodes to show. Check the filters or rescan the project.</div>
      )}

      {ready && (
        <GraphView nodes={nodes} links={links} selectedId={selectedNodeId} highlight={highlight} onNodeClick={onSelectNode} />
      )}
    </div>
  );
}
