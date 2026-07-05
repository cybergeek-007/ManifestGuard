import { useEffect, useMemo, useRef, useState } from 'react';
import type { ExtensionFinding } from '../types';

interface CollusionGraphProps {
  extensions: ExtensionFinding[];
  onSelectExtension?: (id: string) => void;
}

interface GraphNode {
  id: string;
  label: string;
  verdict: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  degree: number;
}

interface GraphEdge {
  source: string;
  target: string;
  riskType: string;
  severity: string;
  detail: string;
}

const WIDTH = 640;
const HEIGHT = 420;

function verdictColor(verdict: string): string {
  switch (verdict) {
    case 'known_malicious':
      return '#dc2626';
    case 'suspicious':
      return '#f97316';
    case 'moderate_risk':
      return '#f59e0b';
    case 'low_concern':
      return '#3b82f6';
    case 'trusted':
      return '#10b981';
    default:
      return '#6b7280';
  }
}

function severityColor(severity: string): string {
  switch (severity?.toLowerCase()) {
    case 'high':
    case 'critical':
      return 'rgba(220, 38, 38, 0.7)';
    case 'medium':
      return 'rgba(245, 158, 11, 0.7)';
    default:
      return 'rgba(99, 102, 241, 0.55)';
  }
}

/**
 * Builds the node/edge set from per-extension collusion edges.
 * Extensions are only included if they participate in at least one edge,
 * so the graph stays focused on the actual collusion clusters.
 */
function buildGraph(extensions: ExtensionFinding[]): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const edgeMap = new Map<string, GraphEdge>();
  const nodeIds = new Set<string>();
  const nameById = new Map<string, string>();
  const verdictById = new Map<string, string>();

  for (const ext of extensions) {
    nameById.set(ext.id, ext.name);
    verdictById.set(ext.id, ext.verdict);
    for (const edge of ext.collusionEdges ?? []) {
      nameById.set(edge.source_id, edge.source_name);
      nameById.set(edge.target_id, edge.target_name);
      const [a, b] = [edge.source_id, edge.target_id].sort();
      const key = `${a}::${b}::${edge.risk_type}`;
      if (!edgeMap.has(key)) {
        edgeMap.set(key, {
          source: a,
          target: b,
          riskType: edge.risk_type,
          severity: edge.severity,
          detail: edge.detail,
        });
      }
      nodeIds.add(a);
      nodeIds.add(b);
    }
  }

  const ids = Array.from(nodeIds);
  const nodes: GraphNode[] = ids.map((id, i) => {
    // Seed positions on a circle for a stable, deterministic layout.
    const angle = (i / Math.max(ids.length, 1)) * Math.PI * 2;
    const radius = Math.min(WIDTH, HEIGHT) / 3;
    return {
      id,
      label: nameById.get(id) ?? id.slice(0, 8),
      verdict: verdictById.get(id) ?? 'unknown',
      x: WIDTH / 2 + Math.cos(angle) * radius,
      y: HEIGHT / 2 + Math.sin(angle) * radius,
      vx: 0,
      vy: 0,
      degree: 0,
    };
  });

  const edges = Array.from(edgeMap.values());
  const degreeById = new Map<string, number>();
  for (const e of edges) {
    degreeById.set(e.source, (degreeById.get(e.source) ?? 0) + 1);
    degreeById.set(e.target, (degreeById.get(e.target) ?? 0) + 1);
  }
  for (const n of nodes) n.degree = degreeById.get(n.id) ?? 0;

  return { nodes, edges };
}

/**
 * A dependency-free force-directed layout. Runs a fixed number of
 * simulation ticks with repulsion (Coulomb-like), spring attraction along
 * edges, and gentle centering, then renders to SVG.
 */
export default function CollusionGraph({ extensions, onSelectExtension }: CollusionGraphProps) {
  const base = useMemo(() => buildGraph(extensions), [extensions]);
  const [nodes, setNodes] = useState<GraphNode[]>(base.nodes);
  const [hovered, setHovered] = useState<string | null>(null);
  const frameRef = useRef<number | null>(null);

  useEffect(() => {
    // Deep copy so we can mutate positions during simulation.
    const sim: GraphNode[] = base.nodes.map((n) => ({ ...n }));
    const edges = base.edges;
    if (sim.length === 0) {
      setNodes([]);
      return;
    }

    const byId = new Map(sim.map((n) => [n.id, n]));
    let tick = 0;
    const MAX_TICKS = 320;

    const step = () => {
      const k = 0.02; // spring
      const repulsion = 5200;
      const damping = 0.85;
      const center = { x: WIDTH / 2, y: HEIGHT / 2 };

      // Repulsion between every pair
      for (let i = 0; i < sim.length; i++) {
        for (let j = i + 1; j < sim.length; j++) {
          const a = sim[i];
          const b = sim[j];
          let dx = a.x - b.x;
          let dy = a.y - b.y;
          let dist2 = dx * dx + dy * dy;
          if (dist2 < 0.01) {
            dx = Math.random();
            dy = Math.random();
            dist2 = dx * dx + dy * dy;
          }
          const force = repulsion / dist2;
          const dist = Math.sqrt(dist2);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          a.vx += fx;
          a.vy += fy;
          b.vx -= fx;
          b.vy -= fy;
        }
      }

      // Spring attraction along edges
      for (const e of edges) {
        const a = byId.get(e.source);
        const b = byId.get(e.target);
        if (!a || !b) continue;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        a.vx += dx * k;
        a.vy += dy * k;
        b.vx -= dx * k;
        b.vy -= dy * k;
      }

      // Centering + integrate
      for (const n of sim) {
        n.vx += (center.x - n.x) * 0.008;
        n.vy += (center.y - n.y) * 0.008;
        n.vx *= damping;
        n.vy *= damping;
        n.x += Math.max(-8, Math.min(8, n.vx));
        n.y += Math.max(-8, Math.min(8, n.vy));
        n.x = Math.max(30, Math.min(WIDTH - 30, n.x));
        n.y = Math.max(30, Math.min(HEIGHT - 30, n.y));
      }

      tick += 1;
      setNodes(sim.map((n) => ({ ...n })));
      if (tick < MAX_TICKS) {
        frameRef.current = requestAnimationFrame(step);
      }
    };

    frameRef.current = requestAnimationFrame(step);
    return () => {
      if (frameRef.current) cancelAnimationFrame(frameRef.current);
    };
  }, [base]);

  const posById = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  if (base.nodes.length === 0) {
    return (
      <div className="collusion-graph collusion-graph--empty">
        <h3 className="panel-title">Collusion Graph</h3>
        <p className="muted-text">
          No cross-extension collusion detected in this scan. Extensions that could
          coordinate attacks (shared C2 domains, message passing, overlapping
          capabilities) would appear here as a connected cluster.
        </p>
      </div>
    );
  }

  const hoveredEdges = base.edges.filter(
    (e) => hovered && (e.source === hovered || e.target === hovered),
  );

  return (
    <div className="collusion-graph">
      <div className="collusion-graph__head">
        <h3 className="panel-title">Collusion Graph</h3>
        <span className="muted-text">
          {base.nodes.length} linked extensions · {base.edges.length} risk edges
        </span>
      </div>
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        className="collusion-graph__svg"
        role="img"
        aria-label="Force-directed graph of colluding extensions"
      >
        {/* edges */}
        {base.edges.map((e, i) => {
          const a = posById.get(e.source);
          const b = posById.get(e.target);
          if (!a || !b) return null;
          const active = hovered && (e.source === hovered || e.target === hovered);
          return (
            <line
              key={`e-${i}`}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke={severityColor(e.severity)}
              strokeWidth={active ? 2.6 : 1.4}
              strokeOpacity={hovered && !active ? 0.15 : 0.9}
            >
              <title>{`${e.riskType}: ${e.detail}`}</title>
            </line>
          );
        })}
        {/* nodes */}
        {nodes.map((n) => {
          const r = 9 + Math.min(n.degree * 2.5, 12);
          const dimmed = hovered && hovered !== n.id &&
            !hoveredEdges.some((e) => e.source === n.id || e.target === n.id);
          return (
            <g
              key={n.id}
              transform={`translate(${n.x}, ${n.y})`}
              style={{ cursor: onSelectExtension ? 'pointer' : 'default' }}
              onMouseEnter={() => setHovered(n.id)}
              onMouseLeave={() => setHovered(null)}
              onClick={() => onSelectExtension?.(n.id)}
              opacity={dimmed ? 0.35 : 1}
            >
              <circle
                r={r}
                fill={verdictColor(n.verdict)}
                stroke="var(--bg-surface)"
                strokeWidth={2}
              />
              <text
                y={r + 12}
                textAnchor="middle"
                className="collusion-graph__label"
              >
                {n.label.length > 18 ? `${n.label.slice(0, 17)}…` : n.label}
              </text>
              <title>{n.label}</title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
