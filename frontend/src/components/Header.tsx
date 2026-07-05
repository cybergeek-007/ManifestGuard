import DarkModeToggle from './DarkModeToggle';
import ScanHistory from './ScanHistory';
import { getAIConfig } from './AISettings';
import type { ScanRecord } from '../types';

interface HeaderProps {
  scans: ScanRecord[];
  activeScanId: string | null;
  onSelectScan: (scanId: string) => void;
  onRefresh: () => void;
  loading: boolean;
  onOpenAiSettings: () => void;
}

export default function Header({ scans, activeScanId, onSelectScan, onRefresh, loading, onOpenAiSettings }: HeaderProps) {
  const aiConfigured = !!getAIConfig();
  return (
    <header className="header">
      <div className="header-inner">
        <div className="header-brand">
          <div className="header-logo" aria-hidden="true">MG</div>
          <span className="header-title">ManifestGuard</span>
        </div>
        <div className="header-actions">
          <button
            className="scan-history-trigger"
            onClick={onRefresh}
            disabled={loading}
            aria-label="Refresh scans"
            title="Refresh scans"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="23 4 23 10 17 10" />
              <polyline points="1 20 1 14 7 14" />
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
            </svg>
            {loading ? 'Loading...' : 'Refresh'}
          </button>
          <ScanHistory scans={scans} activeScanId={activeScanId} onSelectScan={onSelectScan} />
          <button
            className="scan-history-trigger ai-settings-trigger"
            onClick={onOpenAiSettings}
            aria-label="API Provider Settings"
            title="API Provider Settings"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
            </svg>
            API
            {aiConfigured && <span className="ai-configured-dot" />}
          </button>
          <DarkModeToggle />
        </div>
      </div>
    </header>
  );
}
