import type { AnalysisReport, CodeGraph, Finding, NodeDetail, Project, RepoListing } from "../types";

const BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}/api${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail);
  }
  return res.status === 204 ? (undefined as T) : res.json();
}

export const api = {
  listRepos: (path = "") => request<RepoListing>(`/repos?path=${encodeURIComponent(path)}`),
  listProjects: () => request<Project[]>("/projects"),
  createProject: (body: { name: string; path: string }) =>
    request<Project>("/projects", { method: "POST", body: JSON.stringify(body) }),
  reingestProject: (id: string) => request<Project>(`/projects/${id}/ingest`, { method: "POST" }),
  deleteProject: (id: string) => request<void>(`/projects/${id}`, { method: "DELETE" }),

  getGraph: (id: string) => request<CodeGraph>(`/projects/${id}/graph`),
  getNode: (id: string, nodeId: string) =>
    request<NodeDetail>(`/projects/${id}/node?id=${encodeURIComponent(nodeId)}`),

  analyze: (id: string) => request<AnalysisReport>(`/projects/${id}/analyze`, { method: "POST" }),
  listFindings: (id: string) => request<Finding[]>(`/projects/${id}/findings`),
};
