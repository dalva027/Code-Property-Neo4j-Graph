import { useState, type FormEvent } from "react";
import { useCreateProject, useDeleteProject, useProjects, useReingestProject } from "../hooks/useApi";

interface Props {
  selected: string | null;
  onSelect: (id: string | null) => void;
}

export function ProjectSidebar({ selected, onSelect }: Props) {
  const { data: projects = [], isLoading, error } = useProjects();
  const create = useCreateProject();
  const reingest = useReingestProject();
  const remove = useDeleteProject();
  const [name, setName] = useState("");
  const [path, setPath] = useState("");

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !path.trim()) return;
    create.mutate(
      { name: name.trim(), path: path.trim() },
      {
        onSuccess: (project) => {
          onSelect(project.id);
          setName("");
          setPath("");
        },
      },
    );
  };

  return (
    <div className="sidebar">
      <div className="brand">codegraph</div>

      <form className="scan-form" onSubmit={submit}>
        <label>
          Project name
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="sample" />
        </label>
        <label>
          Folder under repos/
          <input value={path} onChange={(e) => setPath(e.target.value)} placeholder="sample" />
        </label>
        <button type="submit" className="primary" disabled={create.isPending}>
          {create.isPending ? "Scanning…" : "Scan repository"}
        </button>
        {create.isError && <p className="error">{create.error.message}</p>}
      </form>

      <ul className="project-list">
        {isLoading && <li className="muted">Loading projects…</li>}
        {error && <li className="error">Can't reach the API: {error.message}</li>}
        {projects.map((p) => (
          <li key={p.id} className={p.id === selected ? "active" : undefined}>
            <button className="project-row" onClick={() => onSelect(p.id)}>
              <span className="project-name">{p.name}</span>
              <span className="project-meta">
                {p.file_count} files, {p.symbol_count} symbols
              </span>
            </button>
            <span className="project-actions">
              <button
                className="ghost"
                title="Re-scan source tree"
                disabled={reingest.isPending}
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
          <li className="muted">No projects yet. Scan one above.</li>
        )}
      </ul>
    </div>
  );
}
