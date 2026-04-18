import { useEffect, useMemo, useState } from "react";

import { createScan, fetchExtension, fetchScan, importCsv, listScans, reportUrl } from "./api";
import type { ExtensionFinding, ScanRecord } from "./types";

type Filters = {
  verdict: string;
  storeStatus: string;
  profile: string;
  query: string;
};

type ScanFormState = {
  profiles: string;
  channels: string;
  enableLiveChecks: boolean;
  enableAi: boolean;
};

const verdictTone: Record<string, string> = {
  low_concern: "tone-mint",
  powerful_but_expected: "tone-amber",
  suspicious: "tone-orange",
  known_malicious: "tone-red",
  removed_or_unavailable: "tone-red",
  disabled_by_chrome: "tone-slate",
  unknown: "tone-slate",
};

function humanizeLabel(value: string): string {
  return value.replace(/_/g, " ");
}

function splitCsvishInput(value: string): string[] {
  return value
    .split(/[,\n]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function App() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [activeScan, setActiveScan] = useState<ScanRecord | null>(null);
  const [extensions, setExtensions] = useState<ExtensionFinding[]>([]);
  const [selectedExtension, setSelectedExtension] = useState<ExtensionFinding | null>(null);
  const [filters, setFilters] = useState<Filters>({
    verdict: "all",
    storeStatus: "all",
    profile: "all",
    query: "",
  });
  const [scanForm, setScanForm] = useState<ScanFormState>({
    profiles: "",
    channels: "",
    enableLiveChecks: true,
    enableAi: false,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void refreshScans();
  }, []);

  async function refreshScans(preferredScanId?: string) {
    try {
      setError(null);
      const nextScans = await listScans();
      setScans(nextScans);

      const candidate =
        preferredScanId ??
        activeScan?.scanId ??
        nextScans[0]?.scanId;

      if (candidate) {
        await openScan(candidate);
      } else {
        setActiveScan(null);
        setExtensions([]);
        setSelectedExtension(null);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to load scans.");
    }
  }

  async function openScan(scanId: string) {
    try {
      setLoading(true);
      setError(null);
      const detail = await fetchScan(scanId);
      setActiveScan(detail);
      const nextExtensions = detail.extensions ?? [];
      setExtensions(nextExtensions);

      const preferredExtensionId = selectedExtension?.id;
      const fallbackExtension = nextExtensions.find((item) => item.id === preferredExtensionId) ?? nextExtensions[0];
      if (fallbackExtension) {
        const fullDetail = await fetchExtension(scanId, fallbackExtension.id);
        setSelectedExtension(fullDetail);
      } else {
        setSelectedExtension(null);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to open scan.");
    } finally {
      setLoading(false);
    }
  }

  async function runScan() {
    try {
      setLoading(true);
      setError(null);
      const scan = await createScan({
        profiles: splitCsvishInput(scanForm.profiles),
        channels: splitCsvishInput(scanForm.channels),
        enableLiveChecks: scanForm.enableLiveChecks,
        enableAi: scanForm.enableAi,
      });
      await refreshScans(scan.scanId);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Scan failed.");
    } finally {
      setLoading(false);
    }
  }

  async function handleSelectExtension(extensionId: string) {
    if (!activeScan) return;
    try {
      const detail = await fetchExtension(activeScan.scanId, extensionId);
      setSelectedExtension(detail);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Failed to load extension details.");
    }
  }

  async function handleImport(file: File | null) {
    if (!file) return;
    try {
      setLoading(true);
      setError(null);
      const scan = await importCsv(file);
      await refreshScans(scan.scanId);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "CSV import failed.");
    } finally {
      setLoading(false);
    }
  }

  const availableProfiles = useMemo(() => {
    const profiles = new Set<string>();
    extensions.forEach((item) => item.profiles.forEach((profile) => profiles.add(profile.profile_name)));
    return Array.from(profiles).sort();
  }, [extensions]);

  const filteredExtensions = useMemo(() => {
    return extensions.filter((item) => {
      const matchesVerdict = filters.verdict === "all" || item.verdict === filters.verdict;
      const matchesStore = filters.storeStatus === "all" || item.storeStatus === filters.storeStatus;
      const matchesProfile =
        filters.profile === "all" || item.profiles.some((profile) => profile.profile_name === filters.profile);
      const haystack = [
        item.name,
        item.id,
        item.description,
        item.permissions.join(" "),
        item.hostPermissions.join(" "),
      ]
        .join(" ")
        .toLowerCase();
      const matchesQuery = !filters.query || haystack.includes(filters.query.toLowerCase());
      return matchesVerdict && matchesStore && matchesProfile && matchesQuery;
    });
  }, [extensions, filters]);

  const reviewQueue = useMemo(() => {
    return [...extensions]
      .filter((item) => ["known_malicious", "suspicious", "removed_or_unavailable"].includes(item.verdict))
      .sort((left, right) => {
        const verdictRank = (value: string) =>
          ({ known_malicious: 3, suspicious: 2, removed_or_unavailable: 1 }[value] ?? 0);
        return (
          verdictRank(right.verdict) - verdictRank(left.verdict) ||
          right.suspicionScore - left.suspicionScore ||
          right.powerScore - left.powerScore
        );
      })
      .slice(0, 6);
  }, [extensions]);

  const summaryCards = activeScan?.summary.verdictDistribution ?? {};
  const activeOptions = activeScan?.options;

  return (
    <div className="page-shell">
      <div className="backdrop" />
      <header className="hero">
        <div className="hero-copy">
          <p className="eyebrow">ManifestGuard v2</p>
          <h1>Evidence-first browser extension intelligence.</h1>
          <p className="hero-text">
            Review Chrome and Chromium extensions as a security inventory, not a basic score table. Separate
            powerful access from suspicious behavior, track store availability, and export reports that are
            worth sharing.
          </p>
          <div className="hero-actions">
            <button className="button button-primary" onClick={() => void runScan()} disabled={loading}>
              {loading ? "Scanning..." : "Start Local Scan"}
            </button>
            <label className="button button-secondary">
              Import CSV
              <input
                type="file"
                accept=".csv"
                hidden
                onChange={(event) => void handleImport(event.target.files?.[0] ?? null)}
              />
            </label>
          </div>
        </div>
        <aside className="hero-card">
          <div className="hero-card-label">Current posture</div>
          <div className="hero-card-value">{activeScan?.summary.totalExtensions ?? 0}</div>
          <div className="hero-card-subtitle">
            {activeScan ? `${activeScan.source} • ${new Date(activeScan.createdAt).toLocaleString()}` : "no active scan yet"}
          </div>
          <div className="mini-grid">
            {Object.entries(summaryCards).map(([key, value]) => (
              <div key={key} className="mini-stat">
                <span>{humanizeLabel(key)}</span>
                <strong>{value}</strong>
              </div>
            ))}
          </div>
        </aside>
      </header>

      {error ? <div className="error-banner">{error}</div> : null}

      <main className="layout">
        <section className="panel panel-overview">
          <div className="panel-heading">
            <div>
              <p className="section-kicker">Overview</p>
              <h2>Recent scans</h2>
            </div>
          </div>
          <div className="scan-list">
            {scans.length === 0 ? <div className="empty">No scans yet. Run one to populate the dashboard.</div> : null}
            {scans.map((scan) => (
              <button
                key={scan.scanId}
                className={`scan-item ${activeScan?.scanId === scan.scanId ? "scan-item-active" : ""}`}
                onClick={() => void openScan(scan.scanId)}
              >
                <div>
                  <strong>{scan.scanId}</strong>
                  <div className="muted">{new Date(scan.createdAt).toLocaleString()}</div>
                  <div className="muted muted-inline">{scan.source}</div>
                </div>
                <div className="muted">{scan.summary.totalExtensions} extensions</div>
              </button>
            ))}
          </div>
        </section>

        <section className="panel panel-controls">
          <div className="panel-heading">
            <div>
              <p className="section-kicker">Scan Controls</p>
              <h2>Choose what to inspect</h2>
            </div>
          </div>
          <div className="form-grid">
            <label className="field">
              <span>Chrome channels</span>
              <input
                className="search"
                placeholder="stable, beta, dev, chromium"
                value={scanForm.channels}
                onChange={(event) => setScanForm((current) => ({ ...current, channels: event.target.value }))}
              />
            </label>
            <label className="field">
              <span>Profiles</span>
              <input
                className="search"
                placeholder="Default, Profile 1, Profile 2"
                value={scanForm.profiles}
                onChange={(event) => setScanForm((current) => ({ ...current, profiles: event.target.value }))}
              />
            </label>
          </div>
          <div className="toggle-grid">
            <label className="toggle-card">
              <input
                type="checkbox"
                checked={scanForm.enableLiveChecks}
                onChange={(event) => setScanForm((current) => ({ ...current, enableLiveChecks: event.target.checked }))}
              />
              <div>
                <strong>Enable live store checks</strong>
                <p>Ask Chrome’s update endpoint whether an extension is currently listed or unavailable.</p>
              </div>
            </label>
            <label className="toggle-card">
              <input
                type="checkbox"
                checked={scanForm.enableAi}
                onChange={(event) => setScanForm((current) => ({ ...current, enableAi: event.target.checked }))}
              />
              <div>
                <strong>Enable AI explanations</strong>
                <p>Keep deterministic verdicts, but add plain-English summaries when an AI key is configured.</p>
              </div>
            </label>
          </div>
          <div className="tag-row">
            <span className="tag">Local-first analysis</span>
            <span className="tag">{scanForm.enableLiveChecks ? "live store checks on" : "live store checks off"}</span>
            <span className="tag">{scanForm.enableAi ? "ai summaries on" : "ai summaries off"}</span>
          </div>
        </section>

        <section className="panel panel-kpis">
          <div className="panel-heading">
            <div>
              <p className="section-kicker">Dashboard</p>
              <h2>Verdict distribution</h2>
            </div>
          </div>
          <div className="stat-grid">
            {Object.entries(summaryCards).map(([key, value]) => (
              <article key={key} className={`stat-card ${verdictTone[key] ?? "tone-slate"}`}>
                <span>{humanizeLabel(key)}</span>
                <strong>{value}</strong>
              </article>
            ))}
          </div>
        </section>

        <section className="panel panel-queue">
          <div className="panel-heading">
            <div>
              <p className="section-kicker">Priority Queue</p>
              <h2>Review first</h2>
            </div>
          </div>
          {reviewQueue.length === 0 ? (
            <div className="empty">No high-priority findings in the active scan.</div>
          ) : (
            <div className="queue-list">
              {reviewQueue.map((item) => (
                <button key={item.id} className="queue-item" onClick={() => void handleSelectExtension(item.id)}>
                  <div>
                    <strong>{item.name}</strong>
                    <div className="muted">{item.id}</div>
                  </div>
                  <div className="queue-metrics">
                    <span className={`pill ${verdictTone[item.verdict] ?? "tone-slate"}`}>{humanizeLabel(item.verdict)}</span>
                    <span className="tag">Suspicion {item.suspicionScore}</span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </section>

        <section className="panel panel-inventory">
          <div className="panel-heading">
            <div>
              <p className="section-kicker">Inventory</p>
              <h2>Filter and triage</h2>
            </div>
          </div>

          <div className="filters">
            <input
              className="search"
              placeholder="Search by name, ID, description, permission..."
              value={filters.query}
              onChange={(event) => setFilters((current) => ({ ...current, query: event.target.value }))}
            />
            <select
              value={filters.verdict}
              onChange={(event) => setFilters((current) => ({ ...current, verdict: event.target.value }))}
            >
              <option value="all">All verdicts</option>
              <option value="known_malicious">Known malicious</option>
              <option value="suspicious">Suspicious</option>
              <option value="powerful_but_expected">Powerful but expected</option>
              <option value="removed_or_unavailable">Removed or unavailable</option>
              <option value="disabled_by_chrome">Disabled by Chrome</option>
              <option value="low_concern">Low concern</option>
            </select>
            <select
              value={filters.storeStatus}
              onChange={(event) => setFilters((current) => ({ ...current, storeStatus: event.target.value }))}
            >
              <option value="all">All store states</option>
              <option value="listed">Listed</option>
              <option value="unavailable_or_removed">Removed/unavailable</option>
              <option value="lookup_failed">Lookup failed</option>
              <option value="not_checked">Not checked</option>
            </select>
            <select
              value={filters.profile}
              onChange={(event) => setFilters((current) => ({ ...current, profile: event.target.value }))}
            >
              <option value="all">All profiles</option>
              {availableProfiles.map((profile) => (
                <option key={profile} value={profile}>
                  {profile}
                </option>
              ))}
            </select>
          </div>

          <div className="inventory-table">
            <table>
              <thead>
                <tr>
                  <th>Extension</th>
                  <th>Verdict</th>
                  <th>Power</th>
                  <th>Suspicion</th>
                  <th>Store</th>
                  <th>Profiles</th>
                </tr>
              </thead>
              <tbody>
                {filteredExtensions.map((item) => (
                  <tr key={item.id} onClick={() => void handleSelectExtension(item.id)}>
                    <td>
                      <div className="table-name">{item.name}</div>
                      <div className="muted">{item.id}</div>
                    </td>
                    <td>
                      <span className={`pill ${verdictTone[item.verdict] ?? "tone-slate"}`}>
                        {humanizeLabel(item.verdict)}
                      </span>
                    </td>
                    <td>{item.powerScore}</td>
                    <td>{item.suspicionScore}</td>
                    <td>{item.storeStatus}</td>
                    <td>{item.profiles.map((profile) => profile.profile_name).join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filteredExtensions.length === 0 ? <div className="empty">No extensions match the current filters.</div> : null}
          </div>
        </section>

        <section className="panel panel-detail">
          <div className="panel-heading">
            <div>
              <p className="section-kicker">Extension detail</p>
              <h2>{selectedExtension?.name ?? "Select an extension"}</h2>
            </div>
          </div>
          {!selectedExtension ? (
            <div className="empty">Pick an extension from the inventory to inspect its evidence.</div>
          ) : (
            <div className="detail-grid">
              <div className="detail-card">
                <h3>Classification</h3>
                <div className="detail-stats">
                  <div>
                    <span className="muted">Verdict</span>
                    <strong>{humanizeLabel(selectedExtension.verdict)}</strong>
                  </div>
                  <div>
                    <span className="muted">Power score</span>
                    <strong>{selectedExtension.powerScore}</strong>
                  </div>
                  <div>
                    <span className="muted">Suspicion score</span>
                    <strong>{selectedExtension.suspicionScore}</strong>
                  </div>
                </div>
                <p>{selectedExtension.description || "No description available."}</p>
              </div>

              <div className="detail-card">
                <h3>Suspicious signals</h3>
                {selectedExtension.suspiciousSignals.length === 0 ? (
                  <div className="muted">No high-confidence suspicious signals detected.</div>
                ) : (
                  selectedExtension.suspiciousSignals.map((signal) => (
                    <div key={signal.code} className="signal-card">
                      <strong>{signal.title}</strong>
                      <p>{signal.detail}</p>
                      <div className="tag-row">
                        {signal.evidence.map((evidence) => (
                          <span key={evidence} className="tag">
                            {evidence}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))
                )}
              </div>

              <div className="detail-card">
                <h3>Permissions and hosts</h3>
                <div className="tag-row">
                  {selectedExtension.permissions.map((permission) => (
                    <span key={permission} className="tag">
                      {permission}
                    </span>
                  ))}
                </div>
                <div className="tag-row">
                  {selectedExtension.hostPermissions.map((permission) => (
                    <span key={permission} className="tag tag-host">
                      {permission}
                    </span>
                  ))}
                </div>
              </div>

              <div className="detail-card">
                <h3>Evidence timeline</h3>
                <ul className="timeline">
                  {selectedExtension.evidenceTimeline.map((entry) => (
                    <li key={entry}>{entry}</li>
                  ))}
                </ul>
              </div>

              <div className="detail-card detail-card-wide">
                <h3>AI summary</h3>
                <p>{selectedExtension.aiSummary ?? "AI is optional and is currently disabled or not configured for this scan."}</p>
              </div>

              <div className="detail-card detail-card-wide">
                <h3>Threat-intel matches</h3>
                {selectedExtension.intelMatches.length === 0 ? (
                  <div className="muted">No curated threat-intel matches for this extension ID.</div>
                ) : (
                  selectedExtension.intelMatches.map((match) => (
                    <article key={`${match.source}-${match.label}`} className="intel-item">
                      <strong>{match.label}</strong>
                      <p>{match.detail}</p>
                      <a href={match.source_url} target="_blank" rel="noreferrer">
                        {match.source}
                      </a>
                    </article>
                  ))
                )}
              </div>
            </div>
          )}
        </section>

        <section className="panel panel-reports">
          <div className="panel-heading">
            <div>
              <p className="section-kicker">Reports</p>
              <h2>Export and share</h2>
            </div>
          </div>
          {!activeScan ? (
            <div className="empty">Run or import a scan to unlock report exports.</div>
          ) : (
            <>
              <div className="report-meta">
                <span className="tag">source: {activeScan.source}</span>
                <span className="tag">live checks: {activeOptions?.enableLiveChecks ? "on" : "off"}</span>
                <span className="tag">ai: {activeOptions?.enableAi ? "on" : "off"}</span>
                {(activeOptions?.channels?.length ?? 0) > 0 ? (
                  <span className="tag">channels: {activeOptions?.channels.join(", ")}</span>
                ) : null}
                {(activeOptions?.profiles?.length ?? 0) > 0 ? (
                  <span className="tag">profiles: {activeOptions?.profiles.join(", ")}</span>
                ) : null}
              </div>
              <div className="report-actions">
                {(["csv", "json", "html", "pdf"] as const).map((formatName) => (
                  <a
                    key={formatName}
                    className="button button-secondary"
                    href={reportUrl(activeScan.scanId, formatName)}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Download {formatName.toUpperCase()}
                  </a>
                ))}
              </div>
            </>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
