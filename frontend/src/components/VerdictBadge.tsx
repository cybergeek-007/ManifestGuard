interface VerdictBadgeProps {
  verdict: string;
  size?: 'sm' | 'md' | 'lg';
}

const VERDICT_LABELS: Record<string, string> = {
  known_malicious: 'Known Malicious',
  suspicious: 'Suspicious',
  moderate_risk: 'Moderate Risk',
  low_concern: 'Low Concern',
  trusted: 'Trusted',
  unknown: 'Unknown',
};

export default function VerdictBadge({ verdict, size = 'md' }: VerdictBadgeProps) {
  return (
    <span
      className={`verdict-badge ${verdict} ${size}`}
      aria-label={`Verdict: ${VERDICT_LABELS[verdict] || verdict}`}
    >
      {VERDICT_LABELS[verdict] || verdict.replace(/_/g, ' ')}
    </span>
  );
}
