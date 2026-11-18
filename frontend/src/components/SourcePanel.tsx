import { useEffect, useMemo, useRef } from "react";
import { useSource } from "../hooks/useApi";
import { tokenize } from "../lib/syntax";
import { PATH_COLOR, SEVERITY_COLOR, SEVERITY_RANK } from "../theme";
import type { SourceFlag } from "../types";

export interface SourceTarget {
  path: string;
  line: number;                       // the line to show and mark
  lineEnd?: number;                   // the end of the marked range, when it is one
  marks?: Map<number, number[]>;      // evidence step numbers per line of this file
}

interface Props {
  projectId: string;
  target: SourceTarget;
  onClose: () => void;
  onOpenFinding: (findingId: string) => void;
}

const BLOCK = 1000;                     // windows start on block boundaries so nearby lines share a request

export function SourcePanel({ projectId, target, onClose, onOpenFinding }: Props) {
  const block = Math.floor((Math.max(1, target.line) - 1) / BLOCK);
  const start = Math.max(1, (block - 1) * BLOCK + 1);
  const end = start + 3 * BLOCK - 1;
  const { data, isLoading, error } = useSource(projectId, target.path, start, end);
  const scroller = useRef<HTMLDivElement>(null);

  const tokens = useMemo(() => (data ? tokenize(data.lines, data.language) : []), [data]);
  const lines = useMemo(() => byLine(data?.flags ?? []), [data]);
  const focusEnd = Math.max(target.line, target.lineEnd ?? target.line);

  useEffect(() => {
    const row = scroller.current?.querySelector<HTMLElement>(`[data-line="${target.line}"]`);
    row?.scrollIntoView({ block: "center" });
  }, [data, target]);

  return (
    <section className="source-panel" aria-label="Source">
      <header className="source-header">
        <span className="mono source-path" title={target.path}>
          {target.path}
          <span className="muted">:{target.line}{focusEnd > target.line ? `–${focusEnd}` : ""}</span>
        </span>
        {data && (
          <span className="muted small">
            {data.language} · {data.total_lines} lines
            {(data.start > 1 || data.end < data.total_lines) && ` · showing ${data.start}–${data.end}`}
          </span>
        )}
        <span className="source-legend small">
          <span className="legend-swatch finding" /> finding
          <span className="legend-swatch unsafe" /> unsafe
          <span className="legend-swatch safety" /> SAFETY comment
          {target.marks && target.marks.size > 0 && (
            <>
              <span className="legend-swatch step" /> evidence step
            </>
          )}
        </span>
        <button className="ghost" onClick={onClose} aria-label="Close source">close</button>
      </header>

      <div className="source-scroll" ref={scroller}>
        {isLoading && <p className="muted pad">Loading {target.path}…</p>}
        {error && <p className="error pad">{error.message}</p>}
        {data && (
          <div className="source-code mono" role="table">
            {tokens.map((parts, i) => {
              const n = data.start + i;
              const info = lines.get(n);
              const steps = target.marks?.get(n);
              const classes = ["src-line"];
              if (n >= target.line && n <= focusEnd) classes.push("focus");
              if (info?.safety) classes.push("safety");
              if (info?.unsafe) classes.push("unsafe");
              if (info?.inRange) classes.push("in-range");
              if (steps) classes.push("step");
              return (
                <div key={n} className={classes.join(" ")} data-line={n} role="row" title={info?.title}>
                  <span className="src-marks">
                    {steps && <span className="step-badge" style={{ background: PATH_COLOR }}>{steps.join(",")}</span>}
                    {info?.findings.map((f) => (
                      <button
                        key={f.finding_id ?? `${f.rule}${f.line}`}
                        className="flag-dot"
                        style={{ background: f.severity ? SEVERITY_COLOR[f.severity] : undefined }}
                        title={`${f.rule}: ${f.message}`}
                        aria-label={`finding ${f.rule}`}
                        onClick={() => f.finding_id && onOpenFinding(f.finding_id)}
                      />
                    ))}
                  </span>
                  <span className="src-num">{n}</span>
                  <code className="src-text">
                    {parts.map((t, j) => (
                      <span key={j} className={`tok-${t.kind}`}>{t.text}</span>
                    ))}
                    {parts.length === 0 && " "}
                  </code>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </section>
  );
}

interface LineInfo {
  findings: SourceFlag[];   // findings that start on this line, worst first
  inRange: boolean;         // inside a finding's line range
  unsafe: boolean;
  safety: boolean;
  title?: string;
}

function byLine(flags: SourceFlag[]): Map<number, LineInfo> {
  const out = new Map<number, LineInfo>();
  const at = (n: number) => {
    let info = out.get(n);
    if (!info) out.set(n, (info = { findings: [], inRange: false, unsafe: false, safety: false }));
    return info;
  };
  const titles = new Map<number, string[]>();
  const note = (n: number, text: string) => titles.set(n, [...(titles.get(n) ?? []), text]);
  for (const f of flags) {
    if (f.kind === "safety") at(f.line).safety = true;
    else if (f.kind === "unsafe") {
      for (let n = f.line; n <= f.line_end; n++) at(n).unsafe = true;
      if (f.message) note(f.line, f.message);
    } else {
      at(f.line).findings.push(f);
      for (let n = f.line + 1; n <= f.line_end; n++) at(n).inRange = true;
      note(f.line, `${f.rule}: ${f.message}`);
    }
  }
  for (const [n, info] of out) {
    info.findings.sort((a, b) => SEVERITY_RANK[a.severity ?? "info"] - SEVERITY_RANK[b.severity ?? "info"]);
    const text = titles.get(n);
    if (text) info.title = text.join("\n");
  }
  return out;
}
