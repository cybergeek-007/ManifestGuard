import type { ScanRecord, ExtensionFinding } from '../types';
import DonutChart from './DonutChart';

interface ScanSummaryProps {
  scan: ScanRecord;
  extensions: ExtensionFinding[];
}

export default function ScanSummary({ scan, extensions }: ScanSummaryProps) {
  const dist = scan.summary.verdictDistribution;
  const total = scan.summary.totalExtensions;
  const highRisk = (dist.known_malicious ?? 0) + (dist.suspicious ?? 0) + (dist.moderate_risk ?? 0);
  const safeCount = (dist.trusted ?? 0) + (dist.low_concern ?? 0);

  const avgReputation = extensions.length > 0
    ? Math.round(extensions.reduce((sum, e) => sum + (e.reputationScore ?? 0), 0) / extensions.length)
    : 0;

  const donutData = [
    { label: 'Trusted', value: dist.trusted ?? 0, color: '#10b981' },
    { label: 'Low Concern', value: dist.low_concern ?? 0, color: '#3b82f6' },
    { label: 'Moderate', value: dist.moderate_risk ?? 0, color: '#f59e0b' },
    { label: 'Suspicious', value: dist.suspicious ?? 0, color: '#f97316' },
    { label: 'Malicious', value: dist.known_malicious ?? 0, color: '#ef4444' },
  ];

  return (
    <div className="scan-summary" aria-label="Scan summary statistics">
      <div className="summary-stat">
        <div className="summary-stat-label">Total Scanned</div>
        <div className="summary-stat-value">{total}</div>
      </div>
      <div className="summary-stat">
        <div className="summary-stat-label">High Risk</div>
        <div className={`summary-stat-value ${highRisk > 0 ? 'risk' : 'safe'}`}>{highRisk}</div>
      </div>
      <div className="summary-stat">
        <div className="summary-stat-label">Safe</div>
        <div className="summary-stat-value safe">{safeCount}</div>
      </div>
      <div className="summary-stat">
        <div className="summary-stat-label">Avg Reputation</div>
        <div className="summary-stat-value">{avgReputation}</div>
      </div>
      <div className="summary-stat" style={{ gridColumn: 'span 2' }}>
        <div className="summary-stat-label">Verdict Distribution</div>
        <DonutChart data={donutData} />
      </div>
    </div>
  );
}
