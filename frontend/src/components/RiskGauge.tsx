interface RiskGaugeProps {
  score: number; // 0-100 where 0=safe, 100=dangerous
}

function describeArc(cx: number, cy: number, r: number, startAngle: number, endAngle: number): string {
  const startX = cx + r * Math.cos(startAngle);
  const startY = cy - r * Math.sin(startAngle);
  const endX = cx + r * Math.cos(endAngle);
  const endY = cy - r * Math.sin(endAngle);
  const largeArcFlag = Math.abs(endAngle - startAngle) > Math.PI ? 1 : 0;
  return `M ${startX} ${startY} A ${r} ${r} 0 ${largeArcFlag} 0 ${endX} ${endY}`;
}

export default function RiskGauge({ score }: RiskGaugeProps) {
  const clampedScore = Math.max(0, Math.min(100, score));

  const width = 200;
  const height = 120;
  const cx = 100;
  const cy = 100;
  const radius = 80;
  const startAngle = Math.PI; // 180° (left)
  const totalAngle = Math.PI;
  const scoreAngle = startAngle - (clampedScore / 100) * totalAngle;

  const bgArc = describeArc(cx, cy, radius, 0, startAngle);
  const valueArc = describeArc(cx, cy, radius, scoreAngle, startAngle);

  const color = clampedScore <= 30 ? 'var(--color-safe)'
    : clampedScore <= 60 ? 'var(--color-caution)'
    : 'var(--color-risk)';

  return (
    <div className="risk-gauge" aria-label={`Risk score: ${clampedScore} out of 100`}>
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img">
        <path d={bgArc} fill="none" stroke="var(--surface-sunken)" strokeWidth="12" strokeLinecap="round" />
        {clampedScore > 0 && (
          <path d={valueArc} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round" />
        )}
        <text x={cx} y={cy - 10} textAnchor="middle" dominantBaseline="central"
          fill={color} fontSize="32" fontWeight="700" fontFamily="var(--font-display)">
          {clampedScore}
        </text>
      </svg>
      <div className="risk-gauge-label">Risk Score</div>
    </div>
  );
}
