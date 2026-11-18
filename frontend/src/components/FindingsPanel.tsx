import { useMemo, useState, type CSSProperties } from "react";
import { api } from "../api/client";
import { useAnalyze } from "../hooks/useApi";
import { CrateIndex, passes, type FindingFilter } from "../lib/overlay";
import {
  CATEGORIES, CATEGORY_LABEL, CONFIDENCES, cweUrl, SEVERITIES, SEVERITY_COLOR, SEVERITY_RANK,
} from "../theme";
import type { Category, Finding, Severity } from "../types";
import { Chip, toggle } from "./Chip";

export interface PanelFilter extends FindingFilter {
  severities: Set<Severity>;
}

type GroupBy = "category" | "file" | "crate" | "rule";

interface Props {
  projectId: string;
  ready: boolean;               // false while the project is scanning or its scan failed
  warnings?: string[];          // notes from the last scan, e.g. a crate without Cargo.lock
  findings: Finding[];          // all of the project's findings, unfiltered
  loading: boolean;
  filter: PanelFilter;
  onFilter: (filter: PanelFilter) => void;
  crates: CrateIndex;
  onOpenFinding: (id: string) => void;
  onOpenSource: (path: string, line: number) => void;
}

export function FindingsPanel({
  projectId, ready, warnings = [], findings, loading, filter, onFilter, crates, onOpenFinding, onOpenSource,
}: Props) {
  const analyze = useAnalyze(projectId);
  const [groupBy, setGroupBy] = useState<GroupBy>("category");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const count = <K extends string>(key: (f: Finding) => K) => {
    const out = new Map<K, number>();
    for (const f of findings) out.set(key(f), (out.get(key(f)) ?? 0) + 1);
    return out;
  };
  const bySeverity = count((f) => f.severity);
  const byCategory = count((f) => f.category);
  const byConfidence = count((f) => f.confidence);
  const shown = useMemo(
    () => findings.filter((f) => passes(f, filter) && filter.severities.has(f.severity)),
    [findings, filter],
  );
  const groups = useMemo(() => group(shown, groupBy, crates), [shown, groupBy, crates]);
  const present = CATEGORIES.filter((c) => byCategory.has(c));

  return (
    <div className="panel">
      <header className="panel-header">
        <span className="small muted">{findings.length ? `${findings.length} from the last analysis` : ""}</span>
        <span className="header-actions">
          <a
            className={`button ghost-button${findings.length ? "" : " disabled"}`}
            href={api.sarifUrl(projectId)}
            download
            title="Download every finding as SARIF 2.1.0, with evidence paths as code flows (opens in VS Code's SARIF viewer)"
            aria-disabled={!findings.length}
          >
            SARIF
          </a>
          <button className="primary" onClick={() => analyze.mutate()} disabled={!ready || analyze.isPending}>
            {analyze.isPending ? "Analyzing…" : findings.length ? "Run again" : "Run analysis"}
          </button>
        </span>
      </header>

      {findings.length > 0 && (
        <div className="filters">
          <div className="chip-group" role="group" aria-label="Severity">
            {SEVERITIES.filter((s) => bySeverity.has(s)).map((s) => (
              <Chip key={s} on={filter.severities.has(s)} color={SEVERITY_COLOR[s]}
                    onClick={() => onFilter({ ...filter, severities: toggle(filter.severities, s) })}>
                {s} {bySeverity.get(s)}
              </Chip>
            ))}
          </div>
          {present.length > 1 && (
            <div className="chip-group" role="group" aria-label="Category">
              {present.map((c) => (
                <Chip key={c} on={filter.categories.has(c)}
                      onClick={() => onFilter({ ...filter, categories: toggle(filter.categories, c) })}>
                  {CATEGORY_LABEL[c]} {byCategory.get(c)}
                </Chip>
              ))}
            </div>
          )}
          {byConfidence.size > 1 && (
            <div className="chip-group" role="group" aria-label="Confidence">
              {CONFIDENCES.filter((c) => byConfidence.has(c)).map((c) => (
                <Chip key={c} on={filter.confidences.has(c)}
                      onClick={() => onFilter({ ...filter, confidences: toggle(filter.confidences, c) })}>
                  {c} confidence {byConfidence.get(c)}
                </Chip>
              ))}
            </div>
          )}
          <label className="group-by small">
            Group by{" "}
            <select value={groupBy} onChange={(e) => setGroupBy(e.target.value as GroupBy)}>
              <option value="category">category</option>
              <option value="file">file</option>
              <option value="crate">crate</option>
              <option value="rule">rule</option>
            </select>
            <span className="muted">
              {shown.length === findings.length ? `${findings.length} findings` : `${shown.length} of ${findings.length} shown`}
            </span>
          </label>
        </div>
      )}

      {analyze.isError && <p className="error">{analyze.error.message}</p>}

      {warnings.length > 0 && (
        <details className="scan-warnings">
          <summary>{warnings.length} scan warning{warnings.length === 1 ? "" : "s"}</summary>
          <ul className="plain small">
            {warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        </details>
      )}

      {loading && <p className="muted">Loading…</p>}
      {!loading && findings.length === 0 && (
        <p className="muted">No findings yet. Run analysis to query the graph for issues.</p>
      )}

      {groups.map((g) => {
        const open = !collapsed.has(g.key);
        return (
          <section key={g.key} className="finding-group">
            <button className="group-header" aria-expanded={open} onClick={() => setCollapsed(toggle(collapsed, g.key))}>
              <span className="caret">{open ? "▾" : "▸"}</span>
              <span className={groupBy === "file" || groupBy === "rule" ? "mono group-name" : "group-name"}>{g.label}</span>
              <SeverityCounts findings={g.findings} />
            </button>
            {open && (
              <ul className="finding-list">
                {g.findings.map((f) => (
                  <FindingRow key={f.id} finding={f} showCategory={groupBy !== "category"}
                              onOpen={() => onOpenFinding(f.id)} onOpenSource={onOpenSource} />
                ))}
              </ul>
            )}
          </section>
        );
      })}
    </div>
  );
}

function FindingRow({
  finding: f, showCategory, onOpen, onOpenSource,
}: { finding: Finding; showCategory: boolean; onOpen: () => void; onOpenSource: (path: string, line: number) => void }) {
  return (
    <li className="finding">
      <span className="severity-dot" style={{ background: SEVERITY_COLOR[f.severity] }} title={f.severity} />
      <span className="finding-body">
        <span className="finding-rule">
          {f.rule}
          {showCategory && f.category !== "quality" && <span className="tag">{CATEGORY_LABEL[f.category]}</span>}
          {f.confidence !== "high" && <span className="tag">{f.confidence} confidence</span>}
          <CweLinks cwe={f.cwe} />
        </span>
        <button className="finding-open" onClick={onOpen} title={f.evidence.length ? "Show the evidence path" : "Show the finding"}>
          {f.message}
          {f.evidence.length > 1 && <span className="path-hint"> · show path</span>}
        </button>
        {f.file && (
          <button className="finding-loc mono link" onClick={() => onOpenSource(f.file!, f.line ?? 1)} title="Open in the source panel">
            {f.file}
            {f.line ? `:${f.line}` : ""}
          </button>
        )}
      </span>
    </li>
  );
}

export function CweLinks({ cwe }: { cwe: string[] }) {
  return (
    <>
      {cwe.map((c) => {
        const url = cweUrl(c);
        return url ? (
          <a key={c} className="tag tag-link" href={url} target="_blank" rel="noreferrer" title={`${c} on cwe.mitre.org`}>
            {c}
          </a>
        ) : (
          <span key={c} className="tag">{c}</span>
        );
      })}
    </>
  );
}

function SeverityCounts({ findings }: { findings: Finding[] }) {
  const counts = new Map<Severity, number>();
  for (const f of findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  return (
    <span className="severity-counts">
      {SEVERITIES.filter((s) => counts.has(s)).map((s) => (
        <span key={s} className="severity-count" style={{ "--chip": SEVERITY_COLOR[s] } as CSSProperties} title={s}>
          {counts.get(s)}
        </span>
      ))}
    </span>
  );
}

interface Group {
  key: string;
  label: string;
  findings: Finding[];
  rank: number;       // worst severity, for ordering
}

function group(findings: Finding[], by: GroupBy, crates: CrateIndex): Group[] {
  const groups = new Map<string, Group>();
  for (const f of findings) {
    let key: string;
    let label: string;
    if (by === "category") {
      key = f.category;
      label = CATEGORY_LABEL[f.category as Category];
    } else if (by === "file") {
      key = f.file ?? "";
      label = f.file ?? "(no file)";
    } else if (by === "crate") {
      key = crates.of(f) ?? "";
      label = key ? crates.names.get(key) ?? key : "(no crate)";
    } else {
      key = f.rule;
      label = f.rule;
    }
    let g = groups.get(key);
    if (!g) groups.set(key, (g = { key, label, findings: [], rank: 9 }));
    g.findings.push(f);
    g.rank = Math.min(g.rank, SEVERITY_RANK[f.severity]);
  }
  const list = [...groups.values()];
  if (by === "category") list.sort((a, b) => CATEGORIES.indexOf(a.key as Category) - CATEGORIES.indexOf(b.key as Category));
  else list.sort((a, b) => a.rank - b.rank || b.findings.length - a.findings.length || a.label.localeCompare(b.label));
  return list;
}
