import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";

export const keys = {
  repos: (path: string) => ["repos", path] as const,
  allRepos: ["repos"] as const,
  projects: ["projects"] as const,
  graph: (id: string) => ["graph", id] as const,
  findings: (id: string) => ["findings", id] as const,
  node: (id: string, nodeId: string) => ["node", id, nodeId] as const,
};

export function useRepos(path: string) {
  return useQuery({
    queryKey: keys.repos(path),
    queryFn: () => api.listRepos(path),
    staleTime: 30_000,
  });
}

export function useProjects() {
  return useQuery({ queryKey: keys.projects, queryFn: api.listProjects });
}

export function useGraph(projectId: string | null) {
  return useQuery({
    queryKey: keys.graph(projectId ?? ""),
    queryFn: () => api.getGraph(projectId!),
    enabled: projectId !== null,
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
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: keys.projects });
      qc.invalidateQueries({ queryKey: keys.graph(id) });
      qc.invalidateQueries({ queryKey: keys.findings(id) });
    },
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
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.findings(projectId) }),
  });
}
