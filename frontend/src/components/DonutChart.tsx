import { useEffect, useState } from 'react';

interface DonutData {
  label: string;
  value: number;
  color: string;
}

interface DonutChartProps {
  data: DonutData[];
  size?: number;
}

export default function DonutChart({ data, size = 140 }: DonutChartProps) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => { setMounted(true); }, []);

  const total = data.reduce((sum, d) => sum + d.value, 0);
  if (total === 0) return null;

  const radius = 50;
  const strokeWidth = 14;
  const circumference = 2 * Math.PI * radius;
  const center = 60;

  let offset = 0;
  const segments = data.filter(d => d.value > 0).map(d => {
    const pct = d.value / total;
    const dashLength = pct * circumference;
    const dashOffset = mounted ? -offset : circumference;
    offset += dashLength;
    return { ...d, dashLength, dashOffset, circumference };
  });

  return (
    <div className="donut-chart" aria-label="Verdict distribution chart">
      <svg width={size} height={size} viewBox="0 0 120 120" role="img">
        <circle cx={center} cy={center} r={radius} fill="none" stroke="var(--surface-sunken)" strokeWidth={strokeWidth} />
        {segments.map((seg) => (
          <circle
            key={seg.label}
            className="donut-segment"
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke={seg.color}
            strokeWidth={strokeWidth}
            strokeDasharray={`${seg.dashLength} ${seg.circumference - seg.dashLength}`}
            strokeDashoffset={seg.dashOffset}
            strokeLinecap="round"
            transform={`rotate(-90 ${center} ${center})`}
            style={{ transition: 'stroke-dashoffset 0.8s ease' }}
          />
        ))}
        <text x={center} y={center} textAnchor="middle" dominantBaseline="central"
          fill="var(--text-primary)" fontSize="20" fontWeight="700" fontFamily="var(--font-display)">
          {total}
        </text>
      </svg>
      <div className="donut-chart-legend">
        {data.filter(d => d.value > 0).map(d => (
          <div key={d.label} className="donut-legend-item">
            <span className="donut-legend-dot" style={{ backgroundColor: d.color }} />
            <span>{d.label} ({d.value})</span>
          </div>
        ))}
      </div>
    </div>
  );
}
