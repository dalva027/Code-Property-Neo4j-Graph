import { useState, type FormEvent } from "react";
import { useCreateProject, useRepos } from "../hooks/useApi";
import type { RepoDir } from "../types";

interface Props {
  /** A folder was scanned into a new project; make it the selection. */
  onCreated: (id: string) => void;
  /** The picked folder is already a project; just open it. */
  onOpenExisting: (id: string) => void;
  /** Omitted while there are no projects yet, since there is nothing else to show. */
  onClose?: () => void;
}

const sourceLabel = (n: number) =>
  n === 0 ? "no source files" : `${n} source file${n === 1 ? "" : "s"}`;

/**
 * Browse the folders that actually exist under repos/ instead of typing a path blind.
 * Click a folder to pick it (its name prefills the project name), › to look inside it.
 */
export function RepoPicker({ onCreated, onOpenExisting, onClose }: Props) {
  const [cwd, setCwd] = useState("");                      // folder being browsed, "" = repos/ itself
  const [filter, setFilter] = useState("");
  const [picked, setPicked] = useState<RepoDir | null>(null);
  const [name, setName] = useState("");
  const { data, isLoading, isFetching, error, refetch } = useRepos(cwd);
  const create = useCreateProject();

  const needle = filter.trim().toLowerCase();
  const dirs = (data?.dirs ?? []).filter((d) => !needle || d.name.toLowerCase().includes(needle));
  const crumbs = cwd ? cwd.split("/") : [];

  const browse = (path: string) => {
    setCwd(path);
    setFilter("");
  };

  const pick = (dir: RepoDir) => {
    setPicked(dir);
    setName(dir.project_name ?? dir.name);
    create.reset();
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!picked) return;
    if (picked.project_id) {
      onOpenExisting(picked.project_id);
      return;
    }
    if (!name.trim()) return;
    create.mutate(
      { name: name.trim(), path: picked.path },
      { onSuccess: (project) => onCreated(project.id) },
    );
  };

  const canSubmit = picked !== null && !create.isPending && (picked.project_id !== null || name.trim() !== "");
  const submitLabel = create.isPending
    ? "Starting scan…"
    : !picked
      ? "Pick a folder"
      : picked.project_id
        ? `Open ${picked.project_name}`
        : `Scan ${picked.name}`;

  return (
    <form className="picker" onSubmit={submit}>
      <div className="picker-header">
        <h3>Add repository</h3>
        {onClose && (
          <button type="button" className="ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        )}
      </div>

      <nav className="crumbs" aria-label="Folder path">
        <button
          type="button"
          className="crumb"
          onClick={() => browse("")}
          aria-current={cwd === "" ? "location" : undefined}
        >
          repos
        </button>
        {crumbs.map((segment, i) => {
          const path = crumbs.slice(0, i + 1).join("/");
          const isLast = i === crumbs.length - 1;
          return (
            <span key={path}>
              <span className="crumb-sep">/</span>
              <button
                type="button"
                className="crumb"
                onClick={() => browse(path)}
                aria-current={isLast ? "location" : undefined}
              >
                {segment}
              </button>
            </span>
          );
        })}
      </nav>

      <input
        type="search"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="Filter folders"
        aria-label="Filter folders"
      />

      <ul className="dir-list">
        {isLoading && <li className="muted">Looking in repos/…</li>}
        {error && <li className="error">Can't reach the API: {error.message}</li>}
        {!isLoading && !error && dirs.length === 0 && (
          <li className="muted">
            {needle
              ? `No folders match “${filter.trim()}”.`
              : cwd
                ? "No subfolders here. Use the path above to go back up."
                : "Nothing under repos/ yet. Copy or clone a repository into ./repos and it will show up here."}
          </li>
        )}
        {dirs.map((d) => {
          const isPicked = picked?.path === d.path;
          return (
            <li key={d.path} className={isPicked ? "picked" : undefined}>
              <button
                type="button"
                className="dir-row"
                aria-pressed={isPicked}
                onClick={() => pick(d)}
                onDoubleClick={() => d.has_subdirs && browse(d.path)}
              >
                <span className="dir-name">{d.name}</span>
                <span className="dir-meta">
                  {sourceLabel(d.source_files)}
                  {d.is_git && <span className="badge">git</span>}
                  {d.project_id && <span className="badge on">scanned</span>}
                </span>
              </button>
              {d.has_subdirs && (
                <button
                  type="button"
                  className="ghost dir-open"
                  title={`Look inside ${d.name}`}
                  aria-label={`Look inside ${d.name}`}
                  onClick={() => browse(d.path)}
                >
                  ›
                </button>
              )}
            </li>
          );
        })}
      </ul>

      {picked && !picked.project_id && (
        <label>
          Project name
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder={picked.name} />
        </label>
      )}
      {picked && !picked.project_id && picked.source_files === 0 && (
        <p className="muted small">No parseable files in this folder, so its graph would be empty.</p>
      )}

      <div className="picker-actions">
        <button type="submit" className="primary" disabled={!canSubmit}>
          {submitLabel}
        </button>
        <button
          type="button"
          className="ghost"
          onClick={() => refetch()}
          disabled={isFetching}
          title="Re-read the folders under repos/"
        >
          {isFetching && !isLoading ? "Refreshing…" : "Refresh"}
        </button>
      </div>
      {create.isError && <p className="error">{create.error.message}</p>}
    </form>
  );
}
