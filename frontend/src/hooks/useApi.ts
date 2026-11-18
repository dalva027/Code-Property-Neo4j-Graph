import { useEffect, useRef } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import type { Project, ScanState } from "../types";

export const keys = {
  repos: (path: string) => ["repos", path] as const,
  allRepos: ["repos"] as const,
  projects: ["projects"] as const,
  graph: (id: string) => ["graph", id] as const,
  findings: (id: string) => ["findings", id] as const,
  node: (id: string, nodeId: string) => ["node", id, nodeId] as const,
  evidence: (id: string, findingId: string) => ["evidence", id, findingId] as const,
  source: (id: string, path: string, start: number, end: number) => ["source", id, path, start, end] as const,
  dependencies: (id: string) => ["dependencies", id] as const,
  advisories: (id: string) => ["advisories", id] as const,
  blastRadius: (id: string, advisoryId: string) => ["blast-radius", id, advisoryId] as const,
};

/** Everything derived from one project's graph or findings, refreshed together after a scan. */
const PROJECT_VIEWS = ["graph", "findings", "node", "evidence", "source", "dependencies", "advisories", "blast-radius"];

export function useRepos(path: string) {
  return useQuery({
    queryKey: keys.repos(path),
    queryFn: () => api.listRepos(path),
    staleTime: 30_000,
  });
}

/** Projects, polled while any scan is running; a finished scan refreshes that project's views. */
export function useProjects() {
  const qc = useQueryClient();
  const query = useQuery({
    queryKey: keys.projects,
    queryFn: api.listProjects,
    refetchInterval: (q) => (q.state.data?.some((p) => p.status === "scanning") ? 1500 : false),
  });

  const previous = useRef(new Map<string, ScanState>());
  useEffect(() => {
    const now = new Map((query.data ?? []).map((p: Project) => [p.id, p.status] as const));
    for (const [id, status] of now) {
      if (previous.current.get(id) === "scanning" && status !== "scanning") {
        for (const view of PROJECT_VIEWS) qc.invalidateQueries({ queryKey: [view, id] });
      }
    }
    previous.current = now;
  }, [query.data, qc]);

  return query;
}

export function useGraph(projectId: string | null, ready = true) {
  return useQuery({
    queryKey: keys.graph(projectId ?? ""),
    queryFn: () => api.getGraph(projectId!),
    enabled: projectId !== null && ready,
    staleTime: 60_000,
  });
}

export function useFindings(projectId: string | null) {
  return useQuery({
    queryKey: keys.findings(projectId ?? ""),
    queryFn: () => api.listFindings(projectId!),
    enabled: projectId !== null,
  });
}

export function useNode(projectId: string, nodeId: string | null) {
  return useQuery({
    queryKey: keys.node(projectId, nodeId ?? ""),
    queryFn: () => api.getNode(projectId, nodeId!),
    enabled: nodeId !== null,
  });
}

export function useEvidence(projectId: string, findingId: string | null) {
  return useQuery({
    queryKey: keys.evidence(projectId, findingId ?? ""),
    queryFn: () => api.getEvidence(projectId, findingId!),
    enabled: findingId !== null,
    staleTime: 60_000,
  });
}

export function useSource(projectId: string, path: string | null, start: number, end: number) {
  return useQuery({
    queryKey: keys.source(projectId, path ?? "", start, end),
    queryFn: () => api.getSource(projectId, path!, start, end),
    enabled: path !== null,
    staleTime: 60_000,
    placeholderData: (previous) => (previous?.path === path ? previous : undefined),
  });
}

export function useDependencies(projectId: string | null, ready = true) {
  return useQuery({
    queryKey: keys.dependencies(projectId ?? ""),
    queryFn: () => api.getDependencies(projectId!),
    enabled: projectId !== null && ready,
    staleTime: 60_000,
  });
}

export function useAdvisories(projectId: string, ready = true) {
  return useQuery({
    queryKey: keys.advisories(projectId),
    queryFn: () => api.listAdvisories(projectId),
    enabled: ready,
    staleTime: 60_000,
  });
}

export function useBlastRadius(projectId: string, advisoryId: string | null) {
  return useQuery({
    queryKey: keys.blastRadius(projectId, advisoryId ?? ""),
    queryFn: () => api.getBlastRadius(projectId, advisoryId!),
    enabled: advisoryId !== null,
    staleTime: 60_000,
  });
}

export function useCreateProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.createProject,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: keys.projects });
      qc.invalidateQueries({ queryKey: keys.allRepos });   // folder now shows as "scanned"
    },
  });
}

export function useReingestProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.reingestProject,
    // The graph and findings refresh when the scan finishes (see useProjects).
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.projects }),
  });
}

export function useDeleteProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.deleteProject,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: keys.projects });
      qc.invalidateQueries({ queryKey: keys.allRepos });
    },
  });
}

export function useAnalyze(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.analyze(projectId),
    // New findings: new ids, new evidence, new flags in the source panel.
    onSuccess: () => {
      for (const view of ["findings", "node", "evidence", "source"]) qc.invalidateQueries({ queryKey: [view, projectId] });
    },
  });
}
