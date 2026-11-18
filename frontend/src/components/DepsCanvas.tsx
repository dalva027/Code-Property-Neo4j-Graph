import { useMemo, useState } from "react";
import { useDependencies } from "../hooks/useApi";
import { CrateIndex, crateMarks } from "../lib/overlay";
import { evidenceHighlight, radiusInDeps, type Spotlight } from "../lib/spotlight";
import { advisoryColor, KIND_COLOR } from "../theme";
import type { Finding, ScanState } from "../types";
import { Chip } from "./Chip";
import { GraphView, type Highlight, type ViewLink, type ViewNode } from "./GraphView";

interface Props {
  projectId: string;
  status: ScanState;
  findings: Finding[];
  selectedNodeId: string | null;
  spotlight: Spotlight | null;
  onSelectNode: (id: string) => void;       // a crate: the node inspector
  onSelectAdvisory: (id: string) => void;   // an advisory: its blast radius
}

/** Above this many crates the view starts with only the crates on a path to an advisory. */
const LARGE = 80;

export function DepsCanvas({ projectId, status, findings, selectedNodeId, spotlight, onSelectNode, onSelectAdvisory }: Props) {
  const ready = status === "ready";
  const { data: view, isLoading, error } = useDependencies(projectId, ready);
  const crates = useMemo(() => new CrateIndex(view), [view]);
  const marks = useMemo(() => crateMarks(findings, crates), [findings, crates]);
  const crateCount = view?.nodes.filter((n) => n.kind === "crate").length ?? 0;
  const advisoryCount = view?.nodes.filter((n) => n.kind === "advisory").length ?? 0;
  const [pathsOnly, setPathsOnly] = useState<boolean | null>(null);   // null: decided by size
  const [layered, setLayered] = useState(true);
  const onlyPaths = pathsOnly ?? (crateCount > LARGE && advisoryCount > 0);

  // Crates from which an affected crate can be reached, by walking DEPENDS_ON backwards.
  const onPath = useMemo(() => {
    const keep = new Set<string>();
    if (!view) return keep;
    const dependents = new Map<string, string[]>();
    for (const e of view.edges) {
      if (e.kind === "DEPENDS_ON") dependents.set(e.target, [...(dependents.get(e.target) ?? []), e.source]);
      if (e.kind === "AFFECTED_BY") keep.add(e.source).add(e.target);
    }
    const queue = [...keep];
    while (queue.length) {
      for (const up of dependents.get(queue.pop()!) ?? []) {
        if (!keep.has(up)) {
          keep.add(up);
          queue.push(up);
        }
      }
    }
    return keep;
  }, [view]);

  const highlight = useMemo((): Highlight | null => {
    if (!spotlight) return null;
    if (spotlight.kind === "radius") return radiusInDeps(spotlight.key, spotlight.radius);
    return evidenceHighlight(spotlight.key, spotlight.steps, spotlight.current, ({ node }) =>
      node.kind === "crate" || node.kind === "advisory" ? node.id : crates.ofFile(node.file));
  }, [spotlight, crates]);

  const { nodes, links } = useMemo(() => {
    if (!view) return { nodes: [] as ViewNode[], links: [] as ViewLink[] };
    const shown = (id: string) => !onlyPaths || onPath.has(id) || crates.members.has(id) || highlight?.nodes.has(id);
    const visible = new Set(view.nodes.filter((n) => shown(n.id)).map((n) => n.id));
    const links: ViewLink[] = view.edges
      .filter((e) => visible.has(e.source) && visible.has(e.target))
      .map((e) => ({
        source: e.source, target: e.target, arrow: true,
        color: e.kind === "AFFECTED_BY" ? "rgba(255, 123, 139, 0.75)"
          : e.props?.kind === "dev" || e.props?.kind === "build" ? "rgba(139, 148, 167, 0.3)" : "rgba(201, 167, 255, 0.35)",
      }));
    const dependents = new Map<string, number>();
    const affected = new Set<string>();
    for (const e of view.edges) {
      if (e.kind === "DEPENDS_ON") dependents.set(e.target, (dependents.get(e.target) ?? 0) + 1);
      else if (e.kind === "AFFECTED_BY") affected.add(e.source);
    }
    const nodes: ViewNode[] = view.nodes.filter((n) => visible.has(n.id)).map((n) => {
      const mark = marks.get(n.id);
      if (n.kind === "advisory") {
        const kind = typeof n.attrs?.informational === "string" ? n.attrs.informational : "vulnerability";
        const severity = typeof n.attrs?.severity === "string" ? n.attrs.severity : null;
        return {
          id: n.id, name: n.name, shape: "diamond", radius: 5, label: true,
          color: advisoryColor(severity, kind),
          tooltip: `${n.name} (${kind}${severity ? `, ${severity}` : ""}): ${n.attrs?.title ?? ""}`,
        };
      }
      const member = n.attrs?.workspace_member === true;
      return {
        id: n.id, name: `${n.name} ${n.attrs?.version ?? ""}`.trim(),
        tooltip: `${member ? "workspace member" : "dependency"}: ${n.qualified_name}${mark ? ` — ${mark.count} finding${mark.count === 1 ? "" : "s"}, worst ${mark.severity}` : ""}`,
        color: KIND_COLOR.crate, ring: member,
        radius: member ? 7 : Math.min(9, 3 + Math.sqrt(dependents.get(n.id) ?? 0)),
        severity: mark?.severity, count: mark?.count, label: member || affected.has(n.id),
      };
    });
    return { nodes, links };
  }, [view, onlyPaths, onPath, crates, marks, highlight]);

  const advisoryIds = useMemo(() => new Set(view?.nodes.filter((n) => n.kind === "advisory").map((n) => n.id)), [view]);

  return (
    <div className="graph-wrap">
      <div className="graph-toolbar">
        <div className="chip-group">
          <Chip on={onlyPaths} color="#ff7b8b" onClick={() => setPathsOnly(!onlyPaths)}
                title="Show only the crates that lead from a workspace member to an advisory">
            paths to advisories
          </Chip>
          <Chip on={layered} onClick={() => setLayered(!layered)} title="Lay crates out left to right by dependency depth">
            layered
          </Chip>
        </div>
        <span className="graph-legend">
          <span className="legend-ring" /> member <span className="legend-dot" /> dependency <span className="legend-diamond" /> advisory
        </span>
        <span className="graph-stats">
          {crateCount} crates, {advisoryCount} advisor{advisoryCount === 1 ? "y" : "ies"}
          {onlyPaths && ` · showing ${nodes.length - advisoryCount}`}
        </span>
      </div>

      {status === "scanning" && <div className="overlay">Scanning the source tree…</div>}
      {ready && isLoading && <div className="overlay">Loading dependencies…</div>}
      {ready && error && <div className="overlay error">{error.message}</div>}
      {ready && !isLoading && !error && crateCount === 0 && (
        <div className="overlay muted">No Cargo.lock in this project, so there is no dependency graph.</div>
      )}

      {ready && (
        <GraphView
          nodes={nodes}
          links={links}
          selectedId={selectedNodeId}
          highlight={highlight}
          layered={layered}
          onNodeClick={(id) => (advisoryIds.has(id) ? onSelectAdvisory(id) : onSelectNode(id))}
        />
      )}
    </div>
  );
}
