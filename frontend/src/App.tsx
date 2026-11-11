import { useState } from "react";
import { useProjects } from "./hooks/useApi";
import { ProjectSidebar } from "./components/ProjectSidebar";
import { GraphCanvas } from "./components/GraphCanvas";
import { FindingsPanel } from "./components/FindingsPanel";
import { NodeInspector } from "./components/NodeInspector";

export default function App() {
  const [projectId, setProjectId] = useState<string | null>(null);
  const [nodeId, setNodeId] = useState<string | null>(null);
  const { data: projects = [] } = useProjects();
  const project = projects.find((p) => p.id === projectId);
  const status = project?.status ?? "ready";

  const selectProject = (id: string | null) => {
    setProjectId(id);
    setNodeId(null);
  };

  return (
    <div className="shell">
      <ProjectSidebar selected={projectId} onSelect={selectProject} />

      <main className="canvas">
        {projectId ? (
          <GraphCanvas
            projectId={projectId}
            status={status}
            error={project?.error ?? null}
            selectedNodeId={nodeId}
            onSelectNode={setNodeId}
          />
        ) : (
          <div className="empty">
            <p>Pick a project on the left, or scan a new one.</p>
            <p className="muted">Files, classes, functions and external callees become nodes; imports, calls and inheritance become edges.</p>
          </div>
        )}
      </main>

      <aside className="inspector">
        {projectId && nodeId && (
          <NodeInspector
            projectId={projectId}
            nodeId={nodeId}
            onClose={() => setNodeId(null)}
            onSelectNode={setNodeId}
          />
        )}
        {projectId && !nodeId && (
          <FindingsPanel
            projectId={projectId}
            ready={status === "ready"}
            warnings={project?.warnings ?? []}
            onSelectNode={setNodeId}
          />
        )}
      </aside>
    </div>
  );
}
