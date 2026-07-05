import { reportUrl } from '../api';

interface ReportExportProps {
  scanId: string;
}

const FORMATS = [
  { key: 'pdf' as const, label: 'PDF', tooltip: 'Download detailed PDF report' },
  { key: 'csv' as const, label: 'CSV', tooltip: 'Download data as spreadsheet' },
  { key: 'json' as const, label: 'JSON', tooltip: 'Download raw JSON data' },
  { key: 'html' as const, label: 'HTML', tooltip: 'Download standalone HTML report' },
];

export default function ReportExport({ scanId }: ReportExportProps) {
  return (
    <div className="report-actions">
      {FORMATS.map(fmt => (
        <a
          key={fmt.key}
          className="report-btn"
          href={reportUrl(scanId, fmt.key)}
          target="_blank"
          rel="noreferrer"
          title={fmt.tooltip}
          aria-label={fmt.tooltip}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
            <polyline points="7 10 12 15 17 10" />
            <line x1="12" y1="15" x2="12" y2="3" />
          </svg>
          {fmt.label}
        </a>
      ))}
    </div>
  );
}
