import { useState } from "react";
import { useDeleteProject, useProjects, useReingestProject } from "../hooks/useApi";
import { RepoPicker } from "./RepoPicker";

interface Props {
  selected: string | null;
  onSelect: (id: string | null) => void;
}

export function ProjectSidebar({ selected, onSelect }: Props) {
  const { data: projects = [], isLoading, error } = useProjects();
  const reingest = useReingestProject();
  const remove = useDeleteProject();
  // null = user hasn't said: show the picker automatically while there is nothing else to pick.
  const [adding, setAdding] = useState<boolean | null>(null);
  const pickerOpen = adding ?? (!isLoading && !error && projects.length === 0);

  const openProject = (id: string) => {
    onSelect(id);
    setAdding(false);
  };

  return (
    <div className="sidebar">
      <div className="brand">codegraph</div>

      {pickerOpen && (
        <RepoPicker
          onCreated={openProject}
          onOpenExisting={openProject}
          onClose={projects.length ? () => setAdding(false) : undefined}
        />
      )}

      <div className="section-header">
        <h3>Projects</h3>
        {!pickerOpen && (
          <button type="button" className="ghost" onClick={() => setAdding(true)}>
            + Add repository
          </button>
        )}
      </div>

      <ul className="project-list">
        {isLoading && <li className="muted">Loading projects…</li>}
        {error && <li className="error">Can't reach the API: {error.message}</li>}
        {projects.map((p) => (
          <li key={p.id} className={p.id === selected ? "active" : undefined}>
            <button className="project-row" onClick={() => onSelect(p.id)}>
              <span className="project-name">{p.name}</span>
              <span className="project-meta">
                {p.status === "scanning"
                  ? "scanning…"
                  : p.status === "failed"
                    ? <span className="error" title={p.error ?? undefined}>scan failed</span>
                    : `${p.file_count} files, ${p.symbol_count} symbols`}
              </span>
            </button>
            <span className="project-actions">
              <button
                className="ghost"
                title="Re-scan source tree"
                disabled={reingest.isPending || p.status === "scanning"}
                onClick={() => reingest.mutate(p.id)}
              >
                rescan
              </button>
              <button
                className="ghost"
                title="Delete project and its graph"
                onClick={() => {
                  remove.mutate(p.id);
                  if (selected === p.id) onSelect(null);
                }}
              >
                delete
              </button>
            </span>
          </li>
        ))}
        {!isLoading && !error && projects.length === 0 && (
          <li className="muted">No projects yet. Pick a folder above to scan it.</li>
        )}
      </ul>
    </div>
  );
}
