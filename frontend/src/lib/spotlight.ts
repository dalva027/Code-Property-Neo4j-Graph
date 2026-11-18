// What the canvases light up: a finding's evidence path, or an advisory's blast radius. Each canvas
// turns a spotlight into a Highlight over the nodes it draws.
import type { Highlight } from "../components/GraphView";
import type { BlastRadius, EvidenceStep } from "../types";

export type Spotlight =
  | { kind: "evidence"; key: string; steps: EvidenceStep[]; current: number }
  | { kind: "radius"; key: string; radius: BlastRadius };

/** Evidence steps onto canvas nodes: consecutive steps on the same node collapse into one hop. */
export function evidenceHighlight(
  key: string, steps: EvidenceStep[], current: number, place: (step: EvidenceStep) => string | null,
): Highlight {
  const chain: string[] = [];
  const numbers = new Map<string, number[]>();
  steps.forEach((step, i) => {
    const id = place(step);
    if (!id) return;
    if (chain[chain.length - 1] !== id) chain.push(id);
    numbers.set(id, [...(numbers.get(id) ?? []), i + 1]);
  });
  const focus = steps[current] ? place(steps[current]) : null;
  return { key, nodes: new Set(chain), chains: [chain], focus, numbers };
}

/** In the code graph: every function that calls into an affected crate, and what it calls. */
export function radiusInCode(key: string, radius: BlastRadius, has: (id: string) => boolean): Highlight {
  const nodes = new Set<string>();
  const chains: string[][] = [];
  for (const crate of radius.crates) {
    for (const f of crate.functions) {
      if (has(f.function)) nodes.add(f.function);
      if (has(f.external)) nodes.add(f.external);
      chains.push([f.function, f.external]);
    }
  }
  return { key, nodes, chains, focus: null, numbers: new Map() };
}

/** In the dependency graph: the advisory, the affected crates and the paths from each member. */
export function radiusInDeps(key: string, radius: BlastRadius): Highlight {
  const advisory = radius.advisory.id;
  const nodes = new Set<string>([advisory]);
  const chains: string[][] = [];
  for (const crate of radius.crates) {
    nodes.add(crate.crate.id);
    const paths = crate.paths.length ? crate.paths : [[crate.crate]];
    for (const path of paths) {
      for (const c of path) nodes.add(c.id);
      chains.push([...path.map((c) => c.id), advisory]);
    }
  }
  return { key, nodes, chains, focus: null, numbers: new Map() };
}
