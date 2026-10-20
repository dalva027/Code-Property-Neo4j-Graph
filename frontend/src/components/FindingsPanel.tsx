import { useState, type CSSProperties } from "react";
import { useAnalyze, useFindings } from "../hooks/useApi";
import { SEVERITIES, SEVERITY_COLOR } from "../theme";
import type { Severity } from "../types";

interface Props {
  projectId: string;
  onSelectNode: (id: string) => void;
}

export function FindingsPanel({ projectId, onSelectNode }: Props) {
  const { data: findings = [], isLoading } = useFindings(projectId);
  const analyze = useAnalyze(projectId);
  const [filter, setFilter] = useState<Severity | "all">("all");

  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) counts[f.severity] += 1;
  const shown = filter === "all" ? findings : findings.filter((f) => f.severity === filter);

  return (
    <div className="panel">
      <header className="panel-header">
        <h2>Findings</h2>
        <button className="primary" onClick={() => analyze.mutate()} disabled={analyze.isPending}>
          {analyze.isPending ? "Analyzing…" : findings.length ? "Run again" : "Run analysis"}
        </button>
      </header>

      <div className="chip-group">
        <button
          type="button"
          className={`chip${filter === "all" ? " on" : ""}`}
          onClick={() => setFilter("all")}
        >
          all {findings.length}
        </button>
        {SEVERITIES.map((s) => (
          <button
            key={s}
            type="button"
            className={`chip${filter === s ? " on" : ""}`}
            style={{ "--chip": SEVERITY_COLOR[s] } as CSSProperties}
            onClick={() => setFilter(s)}
          >
            {s} {counts[s]}
          </button>
        ))}
      </div>

      {analyze.isError && <p className="error">{analyze.error.message}</p>}

      <ul className="finding-list">
        {isLoading && <li className="muted">Loading…</li>}
        {!isLoading && findings.length === 0 && (
          <li className="muted">No findings yet. Run analysis to query the graph for issues.</li>
        )}
        {shown.map((f) => (
          <li key={f.id}>
            <button
              className="finding"
              disabled={!f.node_id}
              onClick={() => f.node_id && onSelectNode(f.node_id)}
            >
              <span className="severity-dot" style={{ background: SEVERITY_COLOR[f.severity] }} />
              <span className="finding-body">
                <span className="finding-rule">{f.rule}</span>
                <span>{f.message}</span>
                {f.file && (
                  <span className="finding-loc mono">
                    {f.file}
                    {f.line ? `:${f.line}` : ""}
                  </span>
                )}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
