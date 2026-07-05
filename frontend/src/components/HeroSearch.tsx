import { useState } from 'react';
import { parseExtensionInput, scanSingleExtension, scanLocalExtensions } from '../api';

interface HeroSearchProps {
  enableAi: boolean;
  onEnableAiChange: (v: boolean) => void;
  onScanComplete: (scanId: string) => void;
}

const QUICK_CHIPS = [
  { label: 'uBlock Origin', id: 'cjpalhdlnbpafiamejdnhcphjbkeiagm' },
  { label: 'Bitwarden', id: 'nngceckbapebfimnlniiiahkandclblb' },
  { label: 'Grammarly', id: 'kbfnbcaeplbcioakkpcpgfkobkghlhen' },
];

export default function HeroSearch({ enableAi, onEnableAiChange, onScanComplete }: HeroSearchProps) {
  const [input, setInput] = useState('');
  const [scanning, setScanning] = useState(false);
  const [localScanning, setLocalScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPermission, setShowPermission] = useState(false);

  async function handleScan(overrideId?: string) {
    const raw = overrideId ?? input;
    const extensionId = parseExtensionInput(raw);
    if (!extensionId) {
      setError('Please enter a valid Chrome Web Store URL or extension ID.');
      return;
    }
    setError(null);
    setScanning(true);
    try {
      const result = await scanSingleExtension(extensionId, enableAi);
      const scanId = result?.scanId ?? (result as unknown as Record<string, string>)?.scan_id;
      if (scanId) onScanComplete(scanId);
      else throw new Error('No scan ID returned from server.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed. Please try again.');
    } finally {
      setScanning(false);
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    void handleScan();
  }

  function handleLocalScanClick() {
    setShowPermission(true);
  }

  async function handleLocalScanConfirm() {
    setShowPermission(false);
    setError(null);
    setLocalScanning(true);
    try {
      const result = await scanLocalExtensions(enableAi);
      const scanId = result?.scanId ?? (result as unknown as Record<string, string>)?.scan_id;
      if (scanId) onScanComplete(scanId);
      else throw new Error('No scan ID returned from server.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Local scan failed. Make sure Chrome is installed and try again.');
    } finally {
      setLocalScanning(false);
    }
  }

  const busy = scanning || localScanning;

  return (
    <section className="hero">
      <div className="hero-badge">
        <span className="hero-badge-dot" />
        Browser Extension Security Scanner
      </div>

      <h1>
        Is your extension{' '}
        <span className="h1-accent">actually safe?</span>
      </h1>

      <p className="hero-subtitle">
        Deep-scan any Chrome extension with threat intelligence, permission auditing,
        and source-code analysis. No account required.
      </p>

      {/* URL / ID search box */}
      <form className="hero-search-wrap" onSubmit={handleSubmit}>
        <div className="hero-search">
          <span className="hero-search-icon" aria-hidden="true">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="11" cy="11" r="8" />
              <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
          </span>
          <input
            className="hero-input"
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="Paste Chrome Web Store URL or extension ID..."
            disabled={busy}
            aria-label="Extension URL or ID"
            id="hero-search-input"
            autoComplete="off"
            autoCorrect="off"
            spellCheck={false}
          />
          <button
            className="hero-btn"
            type="submit"
            disabled={busy || !input.trim()}
            aria-label="Analyze extension"
            id="hero-analyze-btn"
          >
            {scanning ? (
              <><span className="spinner" aria-hidden="true" /> Scanning…</>
            ) : (
              'Analyze'
            )}
          </button>
        </div>
      </form>

      {error && (
        <div className="error-banner" style={{ maxWidth: 600, margin: '0 auto var(--s-4)' }} role="alert" aria-live="polite">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          {error}
        </div>
      )}

      {/* Quick-scan chips */}
      <div className="hero-chips">
        {QUICK_CHIPS.map(chip => (
          <button
            key={chip.id}
            className="chip"
            type="button"
            onClick={() => { setInput(chip.id); void handleScan(chip.id); }}
            disabled={busy}
            aria-label={`Try scanning ${chip.label}`}
          >
            Try: {chip.label}
          </button>
        ))}
      </div>

      {/* AI toggle */}
      <div className="hero-options">
        <label className="hero-toggle">
          <input
            type="checkbox"
            checked={enableAi}
            onChange={e => onEnableAiChange(e.target.checked)}
          />
          Enable AI analysis
        </label>
      </div>

      {/* Divider */}
      <div className="hero-divider">or</div>

      {/* Scan installed extensions */}
      <button
        type="button"
        className="hero-local-btn"
        onClick={handleLocalScanClick}
        disabled={busy}
        id="hero-local-scan-btn"
        aria-label="Scan all Chrome extensions installed on this machine"
      >
        {localScanning ? (
          <><span className="spinner" aria-hidden="true" style={{ borderTopColor: 'var(--accent)', borderColor: 'var(--border-strong)' }} /> Scanning installed extensions…</>
        ) : (
          <>
            <svg className="hero-local-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
            </svg>
            Scan Installed Extensions
          </>
        )}
      </button>

      {/* Permission consent modal */}
      {showPermission && (
        <div className="permission-overlay" onClick={() => setShowPermission(false)}>
          <div className="permission-modal" onClick={e => e.stopPropagation()}>
            <div className="permission-icon">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </div>
            <h3 className="permission-title">Local File Access Required</h3>
            <p className="permission-desc">
              To scan your installed extensions, ManifestGuard needs to read extension files from your local Chrome installation directory.
            </p>
            <div className="permission-details">
              <div className="permission-item">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                <span>Reads extension manifest files &amp; source code</span>
              </div>
              <div className="permission-item">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
                <span>Accesses Chrome&apos;s local extension directory only</span>
              </div>
              <div className="permission-item permission-safe">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                <span>No personal data is collected or uploaded</span>
              </div>
            </div>
            <div className="permission-actions">
              <button className="permission-cancel" onClick={() => setShowPermission(false)}>Cancel</button>
              <button className="permission-allow" onClick={() => void handleLocalScanConfirm()}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                Allow &amp; Scan
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
