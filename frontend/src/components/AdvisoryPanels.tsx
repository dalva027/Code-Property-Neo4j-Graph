import { useMemo } from "react";
import { useAdvisories, useBlastRadius } from "../hooks/useApi";
import { advisoryColor, advisoryUrl } from "../theme";
import type { AdvisoryInfo, AffectedCrateRadius, ProjectAdvisory, ReachingFunction } from "../types";

/** The advisories that affect the project: the dependency view's starting point. */
export function AdvisoriesPanel({ projectId, ready, onOpenAdvisory }: {
  projectId: string;
  ready: boolean;
  onOpenAdvisory: (id: string) => void;
}) {
  const { data = [], isLoading, error } = useAdvisories(projectId, ready);
  const sorted = useMemo(() => [...data].sort(compareAdvisories), [data]);
  const vulnerabilities = data.filter((a) => a.advisory.kind === "vulnerability").length;

  return (
    <div className="panel">
      <p className="muted small">
        RustSec advisories matching the crate versions in the project's Cargo.lock files. Pick one to see which
        workspace crates depend on it and which functions call into it.
      </p>
      {isLoading && <p className="muted">Loading…</p>}
      {error && <p className="error">{error.message}</p>}
      {!isLoading && !error && data.length === 0 && (
        <p className="muted">
          No advisories affect this project, or it was scanned without the extractor and its advisory database.
        </p>
      )}
      {data.length > 0 && (
        <p className="small">
          {vulnerabilities} vulnerabilit{vulnerabilities === 1 ? "y" : "ies"}, {data.length - vulnerabilities} warning
          {data.length - vulnerabilities === 1 ? "" : "s"} (unmaintained, unsound, notices).
        </p>
      )}
      <ul className="advisory-list">
        {sorted.map(({ advisory: a, crates }) => (
          <li key={a.id}>
            <button className="advisory-row" onClick={() => onOpenAdvisory(a.id)}>
              <span className="diamond" style={{ background: advisoryColor(a.severity, a.kind) }} />
              <span className="finding-body">
                <span className="finding-rule">
                  {a.id}
                  <span className="tag">{a.kind}</span>
                  {a.cvss_score != null && <span className="tag">CVSS {a.cvss_score.toFixed(1)}</span>}
                </span>
                <span>{a.title}</span>
                <span className="finding-loc mono">{crates.map((c) => `${c.name} ${c.version}`).join(", ")}</span>
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

function compareAdvisories(a: ProjectAdvisory, b: ProjectAdvisory) {
  const vuln = (x: ProjectAdvisory) => (x.advisory.kind === "vulnerability" ? 0 : 1);
  return vuln(a) - vuln(b) || (b.advisory.cvss_score ?? 0) - (a.advisory.cvss_score ?? 0) || a.advisory.id.localeCompare(b.advisory.id);
}

interface AdvisoryProps {
  projectId: string;
  advisoryId: string;
  mode: "code" | "deps";
  onBack: () => void;
  onOpenSource: (path: string, line: number) => void;
  onSelectNode: (id: string) => void;
  onMode: (mode: "code" | "deps") => void;
}

/** One advisory's blast radius (rule D4): dependency paths from the workspace members to the
 * affected crate versions, the functions that call into them, and the files that import them. */
export function AdvisoryPanel({ projectId, advisoryId, mode, onBack, onOpenSource, onSelectNode, onMode }: AdvisoryProps) {
  const { data, isLoading, error } = useBlastRadius(projectId, advisoryId);

  return (
    <div className="panel">
      <header className="panel-header">
        <h2 className="mono">{advisoryId}</h2>
        <button className="ghost" onClick={onBack}>Back</button>
      </header>
      {isLoading && <p className="muted">Querying the blast radius…</p>}
      {error && <p className="error">{error.message}</p>}
      {data && (
        <>
          <AdvisoryHeader advisory={data.advisory} />
          <div className="mode-switch-inline">
            <span className="small muted">Highlighted in the</span>
            <button className={`ghost${mode === "deps" ? " active" : ""}`} onClick={() => onMode("deps")}>
              dependency graph
            </button>
            <button className={`ghost${mode === "code" ? " active" : ""}`} onClick={() => onMode("code")}>
              code graph
            </button>
          </div>
          {data.crates.map((c) => (
            <CrateRadius key={c.crate.id} radius={c} onOpenSource={onOpenSource} onSelectNode={onSelectNode} />
          ))}
        </>
      )}
    </div>
  );
}

function AdvisoryHeader({ advisory: a }: { advisory: AdvisoryInfo }) {
  const url = advisoryUrl(a.id, a.url);
  const [summary, ...rest] = a.description.split(/\n\s*\n/);
  return (
    <div className="finding-header">
      <div className="finding-rule">
        <span className="diamond" style={{ background: advisoryColor(a.severity, a.kind) }} />
        {a.package}
        <span className="tag">{a.kind}</span>
        {a.severity && <span className="tag">{a.severity}</span>}
        {a.cvss_score != null && <span className="tag">CVSS {a.cvss_score.toFixed(1)}</span>}
        {a.date && <span className="tag">{a.date}</span>}
      </div>
      <p>
        <strong>{a.title}</strong>
      </p>
      {summary && (
        <details className="advisory-description small">
          <summary>{summary.slice(0, 220)}{summary.length > 220 || rest.length ? "…" : ""}</summary>
          <p className="pre-wrap">{a.description}</p>
        </details>
      )}
      <p className="small">
        {url && <a href={url} target="_blank" rel="noreferrer">RustSec page</a>}
        {a.aliases.map((alias) => {
          const link = aliasUrl(alias);
          return link ? (
            <a key={alias} className="tag tag-link" href={link} target="_blank" rel="noreferrer">{alias}</a>
          ) : (
            <span key={alias} className="tag">{alias}</span>
          );
        })}
      </p>
      <p className="small">
        Fixed in: {a.patched.length ? <span className="mono">{a.patched.join(", ")}</span> : <span className="muted">no fixed version</span>}
      </p>
      {a.functions.length > 0 && (
        <p className="small">
          Affected functions: <span className="mono">{a.functions.join(", ")}</span>
        </p>
      )}
    </div>
  );
}

function aliasUrl(alias: string): string | null {
  if (/^CVE-\d+-\d+$/.test(alias)) return `https://nvd.nist.gov/vuln/detail/${alias}`;
  if (/^GHSA-/.test(alias)) return `https://github.com/advisories/${alias}`;
  return null;
}

function CrateRadius({ radius: r, onOpenSource, onSelectNode }: {
  radius: AffectedCrateRadius;
  onOpenSource: (path: string, line: number) => void;
  onSelectNode: (id: string) => void;
}) {
  // One entry per calling function; calls to affected functions first.
  const callers = useMemo(() => {
    const byFn = new Map<string, ReachingFunction[]>();
    for (const f of r.functions) byFn.set(f.function, [...(byFn.get(f.function) ?? []), f]);
    return [...byFn.values()].sort((a, b) => Number(b.some((f) => f.affected)) - Number(a.some((f) => f.affected)));
  }, [r.functions]);

  return (
    <section className="radius">
      <h3 className="mono">
        {r.crate.name} {r.crate.version}
        <button className="link small inspect-link" onClick={() => onSelectNode(r.crate.id)}>inspect crate</button>
      </h3>

      <h4>How the workspace depends on it</h4>
      {r.paths.length === 0 && <p className="muted small">No dependency path from a workspace member.</p>}
      <ul className="plain dep-paths">
        {r.paths.map((path, i) => (
          <li key={i} className="mono small">
            {path.map((c, j) => (
              <span key={c.id}>
                {j > 0 && <span className="muted"> → </span>}
                <button className="link mono" onClick={() => onSelectNode(c.id)}>{c.name}</button>
              </span>
            ))}
          </li>
        ))}
      </ul>

      <h4>Calls into {r.crate.name} <span className="muted">{callers.length}</span></h4>
      {callers.length === 0 && (
        <p className="muted small">No function of the project calls into this crate{r.importing_files.length ? ", though files import it" : ""}.</p>
      )}
      <ul className="plain callers">
        {callers.map((calls) => {
          const first = calls[0];
          return (
            <li key={first.function} className="caller">
              <button className="link mono" onClick={() => onSelectNode(first.function)}>{first.qualified_name}</button>
              <span className="muted small"> · {reach(first.entry_distance)}</span>
              <ul className="plain">
                {calls.map((f) => (
                  <li key={f.external} className="call-row">
                    <span className={`mono small${f.affected ? " affected" : ""}`}>{f.path}</span>
                    {f.affected && <span className="tag tag-danger">affected function</span>}
                    <span className="call-lines">
                      {(f.sites.length ? f.sites : [f.line]).map((line) => (
                        <button key={line} className="link mono small" onClick={() => onOpenSource(f.file, line)}
                                title="Open this call in the source panel">
                          {f.file}:{line}
                        </button>
                      ))}
                    </span>
                  </li>
                ))}
              </ul>
            </li>
          );
        })}
      </ul>

      {r.importing_files.length > 0 && (
        <>
          <h4>Imported in</h4>
          <ul className="plain">
            {r.importing_files.map((file) => (
              <li key={file}>
                <button className="link mono small" onClick={() => onOpenSource(file, 1)}>{file}</button>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

function reach(distance: number | null): string {
  if (distance === null) return "not reachable from an entry point";
  if (distance === 0) return "an entry point";
  return `${distance} call${distance === 1 ? "" : "s"} from an entry point`;
}
