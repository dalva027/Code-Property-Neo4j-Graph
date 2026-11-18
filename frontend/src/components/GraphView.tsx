import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D, { type ForceGraphMethods } from "react-force-graph-2d";
import { CANVAS_BG, PATH_COLOR, SEVERITY_COLOR } from "../theme";
import type { Severity } from "../types";

/** What a canvas wants drawn for one node; GraphView knows nothing about the graph's semantics. */
export interface ViewNode {
  id: string;
  name: string;
  tooltip: string;
  color: string;
  radius: number;
  shape?: "circle" | "diamond";
  ring?: boolean;                 // an outline in the node's colour (workspace members)
  severity?: Severity | null;     // halo: the worst finding on or under this node
  count?: number;                 // findings, drawn as a badge
  label?: boolean;                // always show the name
}

export interface ViewLink {
  source: string;
  target: string;
  color: string;
  width?: number;
  arrow?: boolean;
}

/** Nodes to light up, chains of nodes to draw as a path, and the node to centre on. */
export interface Highlight {
  key: string;                    // a new key fits the view to the lit nodes once
  nodes: Set<string>;
  chains: string[][];
  focus: string | null;
  numbers: Map<string, number[]>; // step numbers shown beside nodes
}

type FGNode = ViewNode & { x?: number; y?: number; vx?: number; vy?: number };
type FGLink = Omit<ViewLink, "source" | "target"> & { source: string | FGNode; target: string | FGNode };

interface Props {
  nodes: ViewNode[];
  links: ViewLink[];
  selectedId: string | null;
  highlight: Highlight | null;
  layered?: boolean;
  onNodeClick: (id: string) => void;
}

const MAX_FIT_ZOOM = 2.5;
const MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";
const endId = (end: string | FGNode) => (typeof end === "string" ? end : end.id);

export function GraphView({ nodes, links, selectedId, highlight, layered = false, onNodeClick }: Props) {
  const { ref, size } = useSize();
  const fg = useRef<ForceGraphMethods<FGNode, FGLink> | undefined>(undefined);
  // Node objects are reused across data changes so a filter toggle keeps the layout in place, and
  // the simulation only restarts when the set of nodes or links changes: a new halo colour or label
  // is written into the existing objects and shows on the next frame.
  const cache = useRef(new Map<string, FGNode>());
  const structure = useMemo(
    () => `${nodes.map((n) => n.id).join("\n")}\u0000${links.map((l) => `${l.source}>${l.target}:${l.color}`).join("\n")}`,
    [nodes, links],
  );
  const data = useMemo(() => {
    const next = new Map<string, FGNode>();
    const fgNodes = nodes.map((n) => {
      const prev = cache.current.get(n.id);
      const obj: FGNode = prev ? Object.assign(prev, n) : { ...n };
      next.set(n.id, obj);
      return obj;
    });
    cache.current = next;
    return { nodes: fgNodes, links: links.map((l): FGLink => ({ ...l })) };
    // Deliberately keyed on `structure` alone (see above).
  }, [structure]);
  for (const n of nodes) {
    const obj = cache.current.get(n.id);
    if (obj) Object.assign(obj, n);
  }

  const pairs = useMemo(() => {
    const out = new Set<string>();
    for (const chain of highlight?.chains ?? []) {
      for (let i = 1; i < chain.length; i++) {
        out.add(`${chain[i - 1]}>${chain[i]}`);
        out.add(`${chain[i]}>${chain[i - 1]}`);
      }
    }
    return out;
  }, [highlight]);

  // Fit the lit nodes when a new path is shown; centre on the focused step when it moves.
  /** Like zoomToFit, but a short path or a small graph is not blown up to fill the canvas. */
  const fit = (filter?: (n: FGNode) => boolean) => {
    const graph = fg.current;
    const box = graph?.getGraphBbox(filter);
    if (!graph || !box) return;
    const [x0, x1] = box.x;
    const [y0, y1] = box.y;
    const k = Math.min(MAX_FIT_ZOOM, size.width / (x1 - x0 + 160), size.height / (y1 - y0 + 160));
    graph.centerAt((x0 + x1) / 2, (y0 + y1) / 2, 600);
    graph.zoom(k, 600);
  };
  // The whole graph is fitted once its layout settles after a load or a filter change.
  const unfitted = useRef(true);
  useEffect(() => {
    unfitted.current = true;
  }, [structure]);

  const fitted = useRef<string | null>(null);
  const visible = size.width > 0;
  useEffect(() => {
    if (!highlight) {
      fitted.current = null;
      return;
    }
    if (!visible || highlight.key === fitted.current) return;   // a hidden canvas fits when shown
    fitted.current = highlight.key;
    const timer = setTimeout(() => fit((n) => highlight.nodes.has(n.id)), 250);
    return () => clearTimeout(timer);
  }, [highlight, visible, size.width, size.height]);
  const focus = highlight?.focus ?? null;
  const focusKey = `${highlight?.key}|${focus}`;
  const lastFocus = useRef<string | null>(null);
  useEffect(() => {
    if (!focus || lastFocus.current === focusKey) return;
    const first = lastFocus.current?.split("|")[0] !== highlight?.key;
    lastFocus.current = focusKey;
    if (first) return;                       // the fit above frames the whole path first
    const n = cache.current.get(focus);
    if (n?.x !== undefined && n.y !== undefined) fg.current?.centerAt(n.x, n.y, 500);
  }, [focus, focusKey, highlight?.key]);

  const lit = (id: string) => !highlight || highlight.nodes.has(id);

  return (
    <div className="graph-view" ref={ref}>
      {size.width > 0 && (
        <ForceGraph2D<FGNode, FGLink>
          ref={fg}
          graphData={data}
          width={size.width}
          height={size.height}
          backgroundColor={CANVAS_BG}
          nodeId="id"
          nodeLabel={(n) => n.tooltip}
          nodeCanvasObject={(n, ctx, scale) => paintNode(n, ctx, scale, {
            selected: n.id === selectedId, lit: lit(n.id), dimming: highlight !== null,
            focus: n.id === focus, numbers: highlight?.numbers.get(n.id),
          })}
          nodePointerAreaPaint={(n, color, ctx) => {
            ctx.beginPath();
            ctx.arc(n.x ?? 0, n.y ?? 0, n.radius + 2, 0, 2 * Math.PI);
            ctx.fillStyle = color;
            ctx.fill();
          }}
          linkColor={(l) => {
            if (!highlight) return l.color;
            return pairs.has(`${endId(l.source)}>${endId(l.target)}`) ? PATH_COLOR : "rgba(230, 233, 240, 0.04)";
          }}
          linkWidth={(l) => (highlight && pairs.has(`${endId(l.source)}>${endId(l.target)}`) ? 2 : l.width ?? 1)}
          linkDirectionalArrowLength={(l) => (l.arrow ? 4 : 0)}
          linkDirectionalArrowRelPos={1}
          onRenderFramePost={(ctx, scale) => highlight && paintChains(ctx, scale, highlight.chains, cache.current)}
          onNodeClick={(n) => onNodeClick(n.id)}
          dagMode={layered ? "lr" : undefined}
          dagLevelDistance={layered ? 70 : undefined}
          onDagError={() => undefined}
          cooldownTicks={150}
          onEngineStop={() => {
            if (unfitted.current && !highlight) fit();
            unfitted.current = false;
          }}
        />
      )}
    </div>
  );
}

interface PaintState {
  selected: boolean;
  lit: boolean;
  dimming: boolean;
  focus: boolean;
  numbers?: number[];
}

function shapePath(ctx: CanvasRenderingContext2D, n: FGNode, r: number) {
  const x = n.x ?? 0;
  const y = n.y ?? 0;
  ctx.beginPath();
  if (n.shape === "diamond") {
    ctx.moveTo(x, y - r * 1.25);
    ctx.lineTo(x + r * 1.25, y);
    ctx.lineTo(x, y + r * 1.25);
    ctx.lineTo(x - r * 1.25, y);
    ctx.closePath();
  } else {
    ctx.arc(x, y, r, 0, 2 * Math.PI);
  }
}

function paintNode(n: FGNode, ctx: CanvasRenderingContext2D, scale: number, s: PaintState) {
  const x = n.x ?? 0;
  const y = n.y ?? 0;
  const r = n.radius;
  ctx.save();
  ctx.globalAlpha = s.lit ? 1 : 0.12;

  if (n.severity) {
    // Halo: a soft disc behind the node in the colour of its worst finding.
    shapePath(ctx, n, r + Math.max(2.5, r * 0.55));
    ctx.fillStyle = SEVERITY_COLOR[n.severity];
    ctx.globalAlpha = s.lit ? 0.35 : 0.06;
    ctx.fill();
    ctx.globalAlpha = s.lit ? 1 : 0.12;
  }

  shapePath(ctx, n, r);
  ctx.fillStyle = n.ring ? CANVAS_BG : n.color;
  ctx.fill();
  if (n.ring) {
    ctx.lineWidth = Math.max(1.5, r * 0.35);
    ctx.strokeStyle = n.color;
    ctx.stroke();
  }
  if (n.severity) {
    ctx.lineWidth = 2 / scale;
    ctx.strokeStyle = SEVERITY_COLOR[n.severity];
    ctx.stroke();
  }
  if (s.selected || s.focus) {
    shapePath(ctx, n, r + 4 / scale + (s.focus ? 2 / scale : 0));
    ctx.lineWidth = (s.focus ? 2.5 : 1.5) / scale;
    ctx.strokeStyle = s.focus ? PATH_COLOR : "#ffffff";
    ctx.stroke();
  }

  const fontSize = 11 / scale;
  if (s.numbers?.length && s.lit) {
    const text = s.numbers.length > 3 ? `${s.numbers[0]}…${s.numbers[s.numbers.length - 1]}` : s.numbers.join(",");
    ctx.font = `600 ${fontSize}px ${MONO}`;
    const w = ctx.measureText(text).width + 6 / scale;
    const h = fontSize + 4 / scale;
    const bx = x - r - w - 2 / scale;
    const by = y - r - h;
    ctx.fillStyle = PATH_COLOR;
    ctx.fillRect(bx, by, w, h);
    ctx.fillStyle = CANVAS_BG;
    ctx.textBaseline = "middle";
    ctx.fillText(text, bx + 3 / scale, by + h / 2);
  }
  if (n.count && n.count > 0 && (s.lit || !s.dimming) && scale > 0.6) {
    const text = String(n.count);
    ctx.font = `600 ${fontSize * 0.9}px ${MONO}`;
    const w = Math.max(ctx.measureText(text).width + 6 / scale, fontSize + 2 / scale);
    const h = fontSize + 2 / scale;
    const bx = x + r * 0.5;
    const by = y - r - h * 0.6;
    ctx.fillStyle = n.severity ? SEVERITY_COLOR[n.severity] : "#8b94a7";
    ctx.beginPath();
    ctx.roundRect(bx, by, w, h, h / 2);
    ctx.fill();
    ctx.fillStyle = CANVAS_BG;
    ctx.textBaseline = "middle";
    ctx.textAlign = "center";
    ctx.fillText(text, bx + w / 2, by + h / 2);
    ctx.textAlign = "start";
  }

  const showLabel = s.dimming ? s.lit : s.selected || n.label || scale > 1.8;
  if (showLabel) {
    ctx.font = `${fontSize}px ${MONO}`;
    ctx.textBaseline = "middle";
    ctx.fillStyle = s.selected || s.focus ? "#ffffff" : "rgba(230, 233, 240, 0.85)";
    ctx.fillText(n.name, x + r + 3 / scale, y);
  }
  ctx.restore();
}

function paintChains(ctx: CanvasRenderingContext2D, scale: number, chains: string[][], nodes: Map<string, FGNode>) {
  ctx.save();
  ctx.strokeStyle = PATH_COLOR;
  ctx.fillStyle = PATH_COLOR;
  ctx.lineWidth = 2.5 / scale;
  ctx.setLineDash([6 / scale, 4 / scale]);
  for (const chain of chains) {
    for (let i = 1; i < chain.length; i++) {
      const a = nodes.get(chain[i - 1]);
      const b = nodes.get(chain[i]);
      if (!a || !b || a === b || a.x === undefined || b.x === undefined) continue;
      const dx = b.x - a.x;
      const dy = (b.y ?? 0) - (a.y ?? 0);
      const len = Math.hypot(dx, dy) || 1;
      const ux = dx / len;
      const uy = dy / len;
      const sx = a.x + ux * (a.radius + 2);
      const sy = (a.y ?? 0) + uy * (a.radius + 2);
      const ex = b.x - ux * (b.radius + 3);
      const ey = (b.y ?? 0) - uy * (b.radius + 3);
      ctx.beginPath();
      ctx.moveTo(sx, sy);
      ctx.lineTo(ex, ey);
      ctx.stroke();
      const head = 7 / scale;
      ctx.beginPath();
      ctx.moveTo(ex, ey);
      ctx.lineTo(ex - ux * head - uy * head * 0.5, ey - uy * head + ux * head * 0.5);
      ctx.lineTo(ex - ux * head + uy * head * 0.5, ey - uy * head - ux * head * 0.5);
      ctx.closePath();
      ctx.fill();
    }
  }
  ctx.restore();
}

function useSize() {
  const ref = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const observer = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect;
      setSize({ width, height });
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);
  return { ref, size };
}
