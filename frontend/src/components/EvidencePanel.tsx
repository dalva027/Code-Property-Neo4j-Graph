import { useEffect, useMemo, useRef, type CSSProperties } from "react";
import { describeEdge, describeStep } from "../lib/describe";
import { CATEGORY_LABEL, KIND_COLOR, PATH_COLOR, SEVERITY_COLOR } from "../theme";
import type { Evidence, EvidenceStep, Finding } from "../types";
import { CweLinks } from "./FindingsPanel";

interface Props {
  evidence: Evidence | undefined;
  loading: boolean;
  error: Error | null;
  current: number;
  onStep: (index: number) => void;
  onBack: () => void;
  onSelectNode: (id: string) => void;
  onOpenSource: (path: string, line: number) => void;
}

/** A finding's evidence, step by step: source to sink for a taint flow, entry point to site for an
 * unsafe or panic finding, member crate to advisory for a dependency. */
export function EvidencePanel({ evidence, loading, error, current, onStep, onBack, onSelectNode, onOpenSource }: Props) {
  const steps = useMemo(() => evidence?.steps ?? [], [evidence]);
  const roles = useMemo(() => (evidence ? rolesOf(evidence.finding, steps) : []), [evidence, steps]);
  const last = steps.length - 1;

  // Arrow keys step through the path, unless the user is typing somewhere.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (target && (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName))) return;
      if (e.key === "ArrowDown" || e.key === "ArrowRight") {
        if (current < last) onStep(current + 1);
        e.preventDefault();
      } else if (e.key === "ArrowUp" || e.key === "ArrowLeft") {
        if (current > 0) onStep(current - 1);
        e.preventDefault();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [current, last, onStep]);

  return (
    <div className="panel">
      <header className="panel-header">
        <h2>Evidence path</h2>
        <button className="ghost" onClick={onBack}>Back</button>
      </header>

      {loading && <p className="muted">Loading the path…</p>}
      {error && <p className="error">{error.message}</p>}
      {evidence && <FindingHeader finding={evidence.finding} onOpenSource={onOpenSource} />}

      {evidence && evidence.missing.length > 0 && (
        <p className="notice small">
          {evidence.missing.length} step{evidence.missing.length === 1 ? " is" : "s are"} no longer in the graph: the
          project was rescanned after this analysis. Run the analysis again.
        </p>
      )}

      {steps.length > 0 && (
        <>
          <div className="stepper">
            <button className="ghost" disabled={current <= 0} onClick={() => onStep(current - 1)} aria-label="Previous step">
              ← prev
            </button>
            <span className="small muted">
              step {current + 1} of {steps.length}{roles[current] ? ` · ${roles[current]}` : ""}
            </span>
            <button className="ghost" disabled={current >= last} onClick={() => onStep(current + 1)} aria-label="Next step">
              next →
            </button>
          </div>

          <ol className="steps">
            {steps.map((step, i) => (
              <Step
                key={`${step.node.id}-${i}`}
                step={step}
                index={i}
                active={i === current}
                role={roles[i]}
                next={i < last ? describeEdge(step.edge, step.node.id) : null}
                onPick={() => onStep(i)}
                onSelectNode={onSelectNode}
              />
            ))}
          </ol>
          <p className="muted small">Use ← and → (or ↑ ↓) to step. Each step opens its line in the source panel.</p>
        </>
      )}
      {evidence && steps.length === 0 && (
        <p className="muted">This finding has no evidence path; its location is the finding itself.</p>
      )}
    </div>
  );
}

function FindingHeader({ finding: f, onOpenSource }: { finding: Finding; onOpenSource: (path: string, line: number) => void }) {
  return (
    <div className="finding-header">
      <div className="finding-rule">
        <span className="severity-dot" style={{ background: SEVERITY_COLOR[f.severity] }} />
        {f.rule}
        <span className="tag">{f.severity}</span>
        <span className="tag">{CATEGORY_LABEL[f.category]}</span>
        {f.confidence !== "high" && <span className="tag">{f.confidence} confidence</span>}
        <CweLinks cwe={f.cwe} />
      </div>
      <p>{f.message}</p>
      {f.file && (
        <button className="link mono small" onClick={() => onOpenSource(f.file!, f.line ?? 1)}>
          {f.file}{f.line ? `:${f.line}` : ""}
        </button>
      )}
    </div>
  );
}

function Step({
  step, index, active, role, next, onPick, onSelectNode,
}: {
  step: EvidenceStep;
  index: number;
  active: boolean;
  role: string;
  next: string | null;
  onPick: () => void;
  onSelectNode: (id: string) => void;
}) {
  const { node, owner } = step;
  const text = describeStep(node, owner);
  const where = node.file ? `${node.file}${node.line_start ? `:${node.line_start}` : ""}` : null;
  const ref = useRef<HTMLLIElement>(null);
  useEffect(() => {
    if (active) ref.current?.scrollIntoView({ block: "nearest" });
  }, [active]);
  return (
    <li ref={ref} className={`step${active ? " active" : ""}`}>
      <button className="step-main" onClick={onPick} aria-current={active ? "step" : undefined}>
        <span className="step-num" style={active ? ({ background: PATH_COLOR } as CSSProperties) : undefined}>{index + 1}</span>
        <span className="step-body">
          <span className="step-title">
            <span className="kind-badge small" style={{ "--chip": KIND_COLOR[node.kind] } as CSSProperties}>
              {node.kind === "var" ? node.subkind ?? "var" : node.subkind && node.kind === "call" ? node.subkind : node.kind}
            </span>
            {role && role !== node.kind && <span className="tag">{role}</span>}
          </span>
          <span className={text.mono ? "mono step-what" : "step-what"}>{text.title}</span>
          {text.detail && <span className="muted small step-detail">{text.detail}</span>}
          {where && <span className="finding-loc mono">{where}</span>}
        </span>
      </button>
      <span className="step-links">
        {owner && (
          <button className="link small" onClick={() => onSelectNode(owner.id)} title="Inspect the enclosing function">
            inspect {owner.kind}
          </button>
        )}
        {["function", "external", "crate", "advisory", "file", "class"].includes(node.kind) && (
          <button className="link small" onClick={() => onSelectNode(node.id)}>inspect</button>
        )}
      </span>
      {next && <div className="step-edge small">{next}</div>}
    </li>
  );
}

/** What each step is to the finding. Evidence lists a path and then the sites it ends in, side by
 * side (no edge between them): a taint path runs from a source (a call or a parameter) to its
 * sinks; a reachability chain from an entry point to the sites; a dependency chain to an advisory. */
function rolesOf(f: Finding, steps: EvidenceStep[]): string[] {
  const roles = steps.map(() => "");
  if (steps.length === 0) return roles;
  if (f.category === "dependency") {
    steps.forEach((s, i) => {
      if (s.node.kind === "advisory" && i > 0 && steps[i - 1].node.kind === "crate") roles[i - 1] = "affected crate";
      else if (s.node.kind === "crate" && s.node.attrs?.workspace_member === true) roles[i] = "workspace crate";
      else if (s.node.kind === "function" && i === 0) roles[i] = "caller";
    });
    return roles;
  }
  const flow = steps[0].node.kind === "var" || steps[0].node.kind === "call";
  let tail = steps.findIndex((s) => s.edge === null);
  if (tail < 0) tail = steps.length - 1;
  for (let i = Math.max(tail, 1); i < steps.length; i++) roles[i] = flow ? "sink" : "site";
  if (flow) roles[0] = "source";
  else if (typeof steps[0].node.attrs?.entry_kind === "string") roles[0] = "entry point";
  return roles;
}
