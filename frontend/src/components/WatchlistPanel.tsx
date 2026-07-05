import { useEffect, useState } from 'react';
import {
  listWatchlist,
  addToWatchlist,
  removeFromWatchlist,
  checkWatchedExtension,
  parseExtensionInput,
} from '../api';
import type { WatchEntry } from '../types';

/**
 * Continuous-monitoring panel. Lets the user watch specific extensions and
 * re-check them for behavioral drift (new permissions, new domains,
 * obfuscation, verdict escalation) — the real-world attack vector behind
 * incidents like the "Great Suspender" takeover.
 */
export default function WatchlistPanel() {
  const [entries, setEntries] = useState<WatchEntry[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  async function refresh() {
    try {
      setEntries(await listWatchlist());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load watchlist.');
    } finally {
      setLoaded(true);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault();
    const id = parseExtensionInput(input);
    if (!id) {
      setError('Enter a valid extension ID or Chrome Web Store URL.');
      return;
    }
    setBusy('add');
    setError(null);
    try {
      await addToWatchlist(id);
      setInput('');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add extension.');
    } finally {
      setBusy(null);
    }
  }

  async function handleCheck(id: string) {
    setBusy(id);
    setError(null);
    try {
      await checkWatchedExtension(id);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Re-check failed.');
    } finally {
      setBusy(null);
    }
  }

  async function handleRemove(id: string) {
    setBusy(id);
    try {
      await removeFromWatchlist(id);
      await refresh();
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="watchlist-panel" aria-label="Extension watchlist">
      <div className="watchlist-panel__head">
        <div>
          <h3 className="panel-title">Watchlist</h3>
          <p className="muted-text">
            Monitor extensions over time. Re-check to detect risky updates —
            new permissions, new network domains, or newly introduced obfuscation.
          </p>
        </div>
      </div>

      <form className="watchlist-panel__add" onSubmit={handleAdd}>
        <input
          className="watchlist-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Extension ID or Chrome Web Store URL"
          spellCheck={false}
        />
        <button className="btn-primary" type="submit" disabled={busy === 'add'}>
          {busy === 'add' ? 'Adding…' : 'Watch'}
        </button>
      </form>

      {error && <div className="error-banner">{error}</div>}

      {loaded && entries.length === 0 && (
        <p className="muted-text">No extensions are being monitored yet.</p>
      )}

      <ul className="watchlist-list">
        {entries.map((entry) => (
          <li key={entry.extensionId} className="watchlist-item">
            <div className="watchlist-item__main">
              <div className="watchlist-item__name">{entry.name}</div>
              <div className="watchlist-item__meta">
                <span className={`verdict-chip verdict-${entry.lastVerdict ?? 'unknown'}`}>
                  {(entry.lastVerdict ?? 'unknown').replace(/_/g, ' ')}
                </span>
                {entry.lastVersion && <span className="muted-text">v{entry.lastVersion}</span>}
                {entry.lastChecked && (
                  <span className="muted-text">
                    checked {new Date(entry.lastChecked).toLocaleDateString()}
                  </span>
                )}
              </div>
              {entry.alerts.length > 0 && (
                <ul className="watchlist-alerts">
                  {entry.alerts.slice(-4).reverse().map((a, i) => (
                    <li key={i} className={`watchlist-alert sev-${a.severity}`}>
                      <span className="watchlist-alert__type">{a.type.replace(/_/g, ' ')}</span>
                      <span>{a.message}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div className="watchlist-item__actions">
              <button
                className="btn-ghost"
                onClick={() => void handleCheck(entry.extensionId)}
                disabled={busy === entry.extensionId}
              >
                {busy === entry.extensionId ? 'Checking…' : 'Re-check'}
              </button>
              <button
                className="btn-ghost btn-ghost--danger"
                onClick={() => void handleRemove(entry.extensionId)}
                disabled={busy === entry.extensionId}
                aria-label={`Stop watching ${entry.name}`}
              >
                Remove
              </button>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
