import type {
  AnalysisReport, BlastRadius, CodeGraph, DependencyView, Evidence, Finding, NodeDetail, Project, ProjectAdvisory,
  RepoListing, SourceSlice,
} from "../types";

const BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
const q = encodeURIComponent;

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
  listRepos: (path = "") => request<RepoListing>(`/repos?path=${q(path)}`),
  listProjects: () => request<Project[]>("/projects"),
  createProject: (body: { name: string; path: string }) =>
    request<Project>("/projects", { method: "POST", body: JSON.stringify(body) }),
  reingestProject: (id: string) => request<Project>(`/projects/${id}/ingest`, { method: "POST" }),
  deleteProject: (id: string) => request<void>(`/projects/${id}`, { method: "DELETE" }),

  getGraph: (id: string) => request<CodeGraph>(`/projects/${id}/graph`),
  getNode: (id: string, nodeId: string) =>
    request<NodeDetail>(`/projects/${id}/node?id=${q(nodeId)}`),

  analyze: (id: string) => request<AnalysisReport>(`/projects/${id}/analyze`, { method: "POST" }),
  listFindings: (id: string) => request<Finding[]>(`/projects/${id}/findings`),
  getEvidence: (id: string, findingId: string) =>
    request<Evidence>(`/projects/${id}/findings/${q(findingId)}/evidence`),
  /** A plain link: the browser downloads it (the response says `attachment`). */
  sarifUrl: (id: string) => `${BASE}/api/projects/${id}/findings.sarif`,

  getSource: (id: string, path: string, start: number, end: number) =>
    request<SourceSlice>(`/projects/${id}/source?path=${q(path)}&start=${start}&end=${end}`),

  getDependencies: (id: string) => request<DependencyView>(`/projects/${id}/dependencies`),
  listAdvisories: (id: string) => request<ProjectAdvisory[]>(`/projects/${id}/advisories`),
  getBlastRadius: (id: string, advisoryId: string) =>
    request<BlastRadius>(`/projects/${id}/advisories/${q(advisoryId)}/blast-radius`),
};
