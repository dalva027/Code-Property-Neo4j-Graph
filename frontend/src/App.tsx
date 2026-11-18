import { useCallback, useEffect, useMemo, useState } from "react";
import { useBlastRadius, useDependencies, useEvidence, useFindings, useProjects } from "./hooks/useApi";
import { ProjectSidebar } from "./components/ProjectSidebar";
import { CodeCanvas } from "./components/CodeCanvas";
import { DepsCanvas } from "./components/DepsCanvas";
import { FindingsPanel, type PanelFilter } from "./components/FindingsPanel";
import { NodeInspector } from "./components/NodeInspector";
import { EvidencePanel } from "./components/EvidencePanel";
import { AdvisoriesPanel, AdvisoryPanel } from "./components/AdvisoryPanels";
import { SourcePanel, type SourceTarget } from "./components/SourcePanel";
import { CrateIndex, passes } from "./lib/overlay";
import type { Spotlight } from "./lib/spotlight";
import { CATEGORIES, CONFIDENCES, SEVERITIES } from "./theme";
import type { EvidenceStep } from "./types";

type Mode = "code" | "deps";
/** What the right-hand panel shows; the panels form a stack so Back returns to the previous one. */
type View =
  | { kind: "node"; nodeId: string }
  | { kind: "finding"; findingId: string; step: number }
  | { kind: "advisory"; advisoryId: string };

const ALL: PanelFilter = {
  categories: new Set(CATEGORIES),
  confidences: new Set(CONFIDENCES),
  severities: new Set(SEVERITIES),
};
const CODE_KINDS = new Set(["file", "class", "function", "var", "call", "unsafe", "literal"]);

const same = (a: View, b: View) =>
  a.kind === b.kind &&
  (a.kind === "node" ? a.nodeId === (b as typeof a).nodeId
    : a.kind === "finding" ? a.findingId === (b as typeof a).findingId
    : a.advisoryId === (b as typeof a).advisoryId);

export default function App() {
  const [projectId, setProjectId] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>("code");
  const [tab, setTab] = useState<"findings" | "advisories">("findings");
  const [stack, setStack] = useState<View[]>([]);
  const [source, setSource] = useState<SourceTarget | null>(null);
  const [filter, setFilter] = useState<PanelFilter>(ALL);

  const { data: projects = [] } = useProjects();
  const project = projects.find((p) => p.id === projectId);
  const status = project?.status ?? "ready";
  const ready = status === "ready";
  const pid = projectId ?? "";

  const { data: findings = [], isLoading: findingsLoading } = useFindings(projectId);
  const { data: depsView } = useDependencies(projectId, ready);
  const crates = useMemo(() => new CrateIndex(depsView), [depsView]);
  const shown = useMemo(
    () => findings.filter((f) => passes(f, filter) && filter.severities.has(f.severity)),
    [findings, filter],
  );

  const view = stack[stack.length - 1] ?? null;
  const findingId = view?.kind === "finding" ? view.findingId : null;
  const step = view?.kind === "finding" ? view.step : 0;
  const advisoryId = view?.kind === "advisory" ? view.advisoryId : null;
  const evidence = useEvidence(pid, findingId);
  const radius = useBlastRadius(pid, advisoryId);

  const open = useCallback((next: View) => {
    setStack((s) => {
      const top = s[s.length - 1];
      return top && same(top, next) ? s : [...s.slice(-30), next];
    });
  }, []);
  const back = () => setStack((s) => s.slice(0, -1));
  const switchMode = (next: Mode) => {
    setMode(next);
    setTab(next === "deps" ? "advisories" : "findings");
  };

  const selectProject = (id: string | null) => {
    setProjectId(id);
    setStack([]);
    setSource(null);
    setFilter(ALL);
    setMode("code");
    setTab("findings");
  };

  const openSource = useCallback((path: string, line: number, lineEnd?: number) => {
    setSource({ path, line: Math.max(1, line), lineEnd });
  }, []);

  // Steps of the evidence path: moving to one updates the canvas focus and the source panel.
  const steps = evidence.data?.steps;
  const showStep = useCallback((all: EvidenceStep[], index: number) => {
    const s = all[index];
    if (!s?.node.file || s.node.line_start <= 0) return;
    const marks = new Map<number, number[]>();
    all.forEach((other, i) => {
      if (other.node.file === s.node.file && other.node.line_start > 0)
        marks.set(other.node.line_start, [...(marks.get(other.node.line_start) ?? []), i + 1]);
    });
    setSource({
      path: s.node.file, line: s.node.line_start, marks,
      lineEnd: s.node.kind === "unsafe" ? s.node.line_end : undefined,
    });
  }, []);
  const goStep = useCallback((index: number) => {
    setStack((s) => s.map((v, i) => (i === s.length - 1 && v.kind === "finding" ? { ...v, step: index } : v)));
    if (steps) showStep(steps, index);
  }, [steps, showStep]);

  // A newly loaded path opens at its current step; a dependency path with no code in it is shown
  // on the dependency graph.
  useEffect(() => {
    if (!evidence.data || !findingId || evidence.data.finding.id !== findingId) return;
    showStep(evidence.data.steps, step);
    const inCode = evidence.data.steps.some((s) => CODE_KINDS.has(s.node.kind));
    if (!inCode && evidence.data.steps.length > 0) setMode("deps");
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only when a path arrives
  }, [evidence.data]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setSource(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const spotlight = useMemo((): Spotlight | null => {
    if (view?.kind === "finding" && evidence.data?.finding.id === view.findingId)
      return { kind: "evidence", key: `finding:${view.findingId}`, steps: evidence.data.steps, current: view.step };
    if (view?.kind === "advisory" && radius.data?.advisory.id === view.advisoryId)
      return { kind: "radius", key: `advisory:${view.advisoryId}`, radius: radius.data };
    return null;
  }, [view, evidence.data, radius.data]);

  const selectedNode = view?.kind === "node" ? view.nodeId : null;
  const openNode = (id: string) => open({ kind: "node", nodeId: id });
  const openFinding = (id: string) => open({ kind: "finding", findingId: id, step: 0 });
  const openAdvisory = (id: string) => open({ kind: "advisory", advisoryId: id });

  return (
    <div className="shell">
      <ProjectSidebar selected={projectId} onSelect={selectProject} />

      <main className="canvas">
        {projectId ? (
          <>
            <div className="mode-bar">
              <div className="segmented" role="tablist" aria-label="Graph">
                <button role="tab" aria-selected={mode === "code"} className={mode === "code" ? "on" : ""}
                        onClick={() => switchMode("code")}>
                  Code graph
                </button>
                <button role="tab" aria-selected={mode === "deps"} className={mode === "deps" ? "on" : ""}
                        onClick={() => switchMode("deps")}>
                  Dependencies
                </button>
              </div>
              {spotlight && (
                <span className="spotlight-note small">
                  {spotlight.kind === "evidence" ? "Evidence path highlighted" : `Blast radius of ${spotlight.radius.advisory.id}`}
                  <button className="ghost" onClick={() => setStack([])}>clear</button>
                </span>
              )}
            </div>
            <div className="canvas-area">
              <div className={`canvas-pane${mode === "code" ? "" : " hidden"}`}>
                <CodeCanvas projectId={projectId} status={status} error={project?.error ?? null} findings={shown}
                            selectedNodeId={selectedNode} spotlight={spotlight} onSelectNode={openNode} />
              </div>
              <div className={`canvas-pane${mode === "deps" ? "" : " hidden"}`}>
                <DepsCanvas projectId={projectId} status={status} findings={shown} selectedNodeId={selectedNode}
                            spotlight={spotlight} onSelectNode={openNode} onSelectAdvisory={openAdvisory} />
              </div>
            </div>
            {source && (
              <SourcePanel projectId={projectId} target={source} onClose={() => setSource(null)} onOpenFinding={openFinding} />
            )}
          </>
        ) : (
          <div className="empty">
            <p>Pick a project on the left, or scan a new one.</p>
            <p className="muted">
              Files, functions, call sites and data flow become nodes and edges; every rule is a graph query, and
              every finding comes with the path that justifies it.
            </p>
          </div>
        )}
      </main>

      <aside className="inspector">
        {projectId && view?.kind === "node" && (
          <NodeInspector projectId={projectId} nodeId={view.nodeId} onClose={back} onSelectNode={openNode}
                         onOpenFinding={openFinding} onOpenSource={openSource} onOpenAdvisory={openAdvisory}
                         onMode={switchMode} />
        )}
        {projectId && view?.kind === "finding" && (
          <EvidencePanel evidence={evidence.data} loading={evidence.isLoading} error={evidence.error} current={view.step}
                         onStep={goStep} onBack={back} onSelectNode={openNode} onOpenSource={openSource} />
        )}
        {projectId && view?.kind === "advisory" && (
          <AdvisoryPanel projectId={projectId} advisoryId={view.advisoryId} mode={mode} onBack={back}
                         onOpenSource={openSource} onSelectNode={openNode} onMode={switchMode} />
        )}
        {projectId && !view && (
          <>
            <div className="tabs" role="tablist">
              <button role="tab" aria-selected={tab === "findings"} className={tab === "findings" ? "on" : ""}
                      onClick={() => setTab("findings")}>
                Findings <span className="muted">{findings.length}</span>
              </button>
              <button role="tab" aria-selected={tab === "advisories"} className={tab === "advisories" ? "on" : ""}
                      onClick={() => setTab("advisories")}>
                Advisories
              </button>
            </div>
            {tab === "findings" ? (
              <FindingsPanel projectId={projectId} ready={ready} warnings={project?.warnings ?? []} findings={findings}
                             loading={findingsLoading} filter={filter} onFilter={setFilter} crates={crates}
                             onOpenFinding={openFinding} onOpenSource={openSource} />
            ) : (
              <AdvisoriesPanel projectId={projectId} ready={ready} onOpenAdvisory={openAdvisory} />
            )}
          </>
        )}
      </aside>
    </div>
  );
}
