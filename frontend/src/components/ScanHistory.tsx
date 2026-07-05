import { useState, useRef, useEffect } from 'react';
import type { ScanRecord } from '../types';

interface ScanHistoryProps {
  scans: ScanRecord[];
  activeScanId: string | null;
  onSelectScan: (scanId: string) => void;
}

export default function ScanHistory({ scans, activeScanId, onSelectScan }: ScanHistoryProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    function handleKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setOpen(false);
    }
    document.addEventListener('mousedown', handleClick);
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('mousedown', handleClick);
      document.removeEventListener('keydown', handleKey);
    };
  }, []);

  return (
    <div className="scan-history" ref={ref}>
      <button
        className="scan-history-trigger"
        onClick={() => setOpen(!open)}
        aria-label="View scan history"
        aria-expanded={open}
        title="Scan History"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <polyline points="12 6 12 12 16 14" />
        </svg>
        History ({scans.length})
      </button>
      {open && (
        <div className="scan-history-dropdown">
          {scans.length === 0 ? (
            <div className="muted" style={{ padding: 16, textAlign: 'center' }}>No scan history yet.</div>
          ) : (
            scans.map(scan => (
              <button
                key={scan.scanId}
                className={`scan-history-item ${scan.scanId === activeScanId ? 'active' : ''}`}
                onClick={() => { onSelectScan(scan.scanId); setOpen(false); }}
              >
                <span className="scan-history-label">{scan.label || scan.scanId.slice(0, 12)}</span>
                <span className="scan-history-date">
                  {new Date(scan.createdAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })} — {scan.summary.totalExtensions} ext
                </span>
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
}
