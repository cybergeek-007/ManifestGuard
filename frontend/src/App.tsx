import { useEffect, useMemo, useState, type CSSProperties } from "react";

import { createScan, createOnlineScan, fetchExtension, fetchScan, listScans, reportUrl } from "./api";
import type { ExtensionFinding, Recommendation, ScanRecord } from "./types";

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
  trusted: "tone-teal",
  low_concern: "tone-mint",
  powerful_but_expected: "tone-amber",
  moderate_risk: "tone-dark-amber",
  suspicious: "tone-orange",
  known_malicious: "tone-red",
  removed_or_unavailable: "tone-red",
  disabled_by_chrome: "tone-slate",
  unknown: "tone-slate",
};

const CATEGORY_ICONS: Record<string, string> = {
  password_manager: "🔑",
  ad_blocker: "🛡️",
  privacy_tool: "🔒",
  developer_tool: "🛠️",
  security_tool: "🔐",
  productivity: "📋",
  communication: "💬",
  shopping: "🛒",
  accessibility: "♿",
  media: "🎬",
  education: "📚",
  ai_tool: "🤖",
  google_official: "🔵",
  microsoft_official: "🟦",
  vpn_security: "🌐",
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

type AiSummarySection = {
  title: string;
  paragraphs: string[];
  bullets: string[];
};

const AI_KNOWN_HEADINGS = ["Risk Summary", "Key Findings", "Recommendation"];

function parseAiSummary(summary?: string | null): AiSummarySection[] | null {
  if (!summary) return null;
  const normalized = summary.replace(/\r\n/g, "\n").trim();
  if (!normalized) return null;

  const lines = normalized
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  const sections: AiSummarySection[] = [];
  let current: AiSummarySection = { title: "Summary", paragraphs: [], bullets: [] };

  const pushCurrent = () => {
    if (current.paragraphs.length || current.bullets.length) {
      sections.push(current);
    }
  };

  const splitInlineHeading = (headingText: string) => {
    let title = headingText;
    let remainder = "";
    for (const marker of AI_KNOWN_HEADINGS) {
      const index = headingText.indexOf(marker);
      if (index >= 0) {
        const end = index + marker.length;
        if (headingText.length > end + 1) {
          title = headingText.slice(0, end).trim();
          remainder = headingText.slice(end).trim();
        }
        break;
      }
    }
    return { title, remainder };
  };

  for (const line of lines) {
    if (line.startsWith("## ")) {
      pushCurrent();
      const headingText = line.replace(/^##\s+/, "").trim();
      const { title, remainder } = splitInlineHeading(headingText);
      current = { title: title || "Summary", paragraphs: [], bullets: [] };
      if (remainder) {
        current.paragraphs.push(remainder);
      }
      continue;
    }

    if (/^[-*•]\s+/.test(line)) {
      current.bullets.push(line.replace(/^[-*•]\s+/, ""));
      continue;
    }

    current.paragraphs.push(line);
  }

  pushCurrent();
  return sections.length ? sections : null;
}

function scoreTone(score: number): string {
  if (score >= 70) return "text-red";
  if (score >= 40) return "text-amber";
  return "text-green";
}

function aiSectionTone(title: string): string {
  const normalized = title.toLowerCase();
  if (normalized.includes("risk")) return "ai-tone-risk";
  if (normalized.includes("finding")) return "ai-tone-findings";
  if (normalized.includes("recommend")) return "ai-tone-recommendation";
  return "ai-tone-neutral";
}

function panelDelay(value: string): CSSProperties {
  return { "--delay": value } as CSSProperties;
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
  const highRiskCount = useMemo(() => {
    const dist = activeScan?.summary.verdictDistribution ?? {};
    return (dist.known_malicious ?? 0) + (dist.suspicious ?? 0) + (dist.removed_or_unavailable ?? 0);
  }, [activeScan]);
  const scanTimestamp = activeScan ? new Date(activeScan.createdAt).toLocaleString() : "No scans yet";
  const aiSummarySections = useMemo(
    () => parseAiSummary(selectedExtension?.aiSummary),
    [selectedExtension?.aiSummary],
  );

  return (
    <div className="app-shell">
      <div className="bg-aurora" />
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">MG</div>
          <div>
            <div className="brand-title">ManifestGuard</div>
            <div className="brand-subtitle">Evidence-driven extension intelligence</div>
          </div>
        </div>
        <div className="topbar-actions">
          <button className="button button-primary" onClick={() => void runScan()} disabled={loading}>
            {loading ? "Scanning..." : "Run Online Audit"}
          </button>
          <button className="button button-ghost" onClick={() => void refreshScans()} disabled={loading}>
            Refresh scans
          </button>
        </div>
      </header>

      {error ? <div className="error-banner">{error}</div> : null}

      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow">ManifestGuard v3</p>
          <h1>Clear decisions for powerful extensions.</h1>
          <p className="hero-text">
            Go beyond permission noise. ManifestGuard correlates deep source analysis with Chrome Web Store reputation to
            explain which extensions are powerful but expected, and which deserve immediate review.
          </p>
          <div className="hero-actions">
            <div className="hero-chip">Online CRX analysis</div>
            <div className="hero-chip">Reputation scoring</div>
            <div className="hero-chip">Safe alternatives</div>
          </div>
        </div>
        <aside className="hero-summary">
          <div className="summary-heading">
            <div>
              <p className="section-kicker">Current snapshot</p>
              <h2>{activeScan ? activeScan.label || "Active scan" : "No scan selected"}</h2>
              <p className="muted">{scanTimestamp}</p>
            </div>
            <div className="summary-score">
              <span>Total extensions</span>
              <strong>{activeScan?.summary.totalExtensions ?? 0}</strong>
            </div>
          </div>
          <div className="summary-grid">
            <div className="summary-card">
              <span>High risk queue</span>
              <strong>{highRiskCount}</strong>
            </div>
            <div className="summary-card">
              <span>Source</span>
              <strong>{activeScan?.source ?? "—"}</strong>
            </div>
            <div className="summary-card">
              <span>Live checks</span>
              <strong>{activeOptions?.enableLiveChecks ? "On" : "Off"}</strong>
            </div>
            <div className="summary-card">
              <span>AI summaries</span>
              <strong>{activeOptions?.enableAi ? "On" : "Off"}</strong>
            </div>
          </div>
        </aside>
      </section>

      <main className="main-grid">
        <section className="panel panel-scans" style={panelDelay("0.05s")}>
          <div className="panel-heading">
            <div>
              <p className="section-kicker">Audit history</p>
              <h2>Recent runs</h2>
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
                  <strong>{scan.label || scan.scanId}</strong>
                  <div className="muted">{new Date(scan.createdAt).toLocaleString()}</div>
                </div>
              </button>
            ))}
          </div>
        </section>

        <section className="panel panel-controls" style={panelDelay("0.1s")}>
          <div className="panel-heading">
            <div>
              <p className="section-kicker">Scan controls</p>
              <h2>Target the right profiles</h2>
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
            <span className="tag">Online CRX analysis</span>
            <span className="tag">{scanForm.enableLiveChecks ? "live store checks on" : "live store checks off"}</span>
            <span className="tag">{scanForm.enableAi ? "ai summaries on" : "ai summaries off"}</span>
          </div>
          <div className="controls-actions">
            <button className="button button-primary" onClick={() => void runScan()} disabled={loading}>
              {loading ? "Scanning..." : "Run Online Audit"}
            </button>
          </div>
        </section>

        <section className="panel panel-kpis" style={panelDelay("0.15s")}>
          <div className="panel-heading">
            <div>
              <p className="section-kicker">Posture</p>
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

        <section className="panel panel-queue" style={panelDelay("0.2s")}>
          <div className="panel-heading">
            <div>
              <p className="section-kicker">Priority queue</p>
              <h2>Review first</h2>
            </div>
          </div>
          {reviewQueue.length === 0 ? (
            <div className="empty">No high-priority findings in the active scan.</div>
          ) : (
            <div className="queue-list queue-scroll">
              {reviewQueue.map((item) => (
                <button key={item.id} className="queue-item" onClick={() => void handleSelectExtension(item.id)}>
                  <div>
                    <strong>{item.name}</strong>
                    <div className="muted">{item.id}</div>
                  </div>
                  <div className="queue-metrics">
                    <span className={`pill ${verdictTone[item.verdict] ?? "tone-slate"}`}>{humanizeLabel(item.verdict)}</span>
                    <div className="queue-scores">
                      <span className={`queue-score ${scoreTone(item.powerScore)}`}>Power {item.powerScore}</span>
                      <span className={`queue-score ${scoreTone(item.suspicionScore)}`}>Susp {item.suspicionScore}</span>
                      {item.reputationScore != null && item.reputationScore >= 0 ? (
                        <span className={`queue-score ${item.reputationScore >= 70 ? "rep-high" : item.reputationScore >= 40 ? "rep-mid" : "rep-low"}`}>
                          Rep {item.reputationScore}
                        </span>
                      ) : (
                        <span className="queue-score">Rep —</span>
                      )}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </section>

        <section className="panel panel-inventory" style={panelDelay("0.25s")}>
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
              <option value="trusted">Trusted</option>
              <option value="known_malicious">Known malicious</option>
              <option value="suspicious">Suspicious</option>
              <option value="moderate_risk">Moderate risk</option>
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

          <div className="inventory-table inventory-scroll">
            <table>
              <thead>
                <tr>
                  <th>Extension</th>
                  <th>Verdict</th>
                  <th>Power</th>
                  <th>Suspicion</th>
                  <th>Reputation</th>
                  <th>Profiles</th>
                </tr>
              </thead>
              <tbody>
                {filteredExtensions.map((item) => (
                  <tr key={item.id} onClick={() => void handleSelectExtension(item.id)}>
                    <td>
                      <div className="table-name">
                        {item.category && CATEGORY_ICONS[item.category] ? (
                          <span className="category-icon" title={humanizeLabel(item.category)}>{CATEGORY_ICONS[item.category]}</span>
                        ) : null}
                        {item.name}
                      </div>
                      <div className="muted">{item.id}</div>
                    </td>
                    <td>
                      <span className={`pill ${verdictTone[item.verdict] ?? "tone-slate"}`}>
                        {humanizeLabel(item.verdict)}
                      </span>
                    </td>
                    <td>
                      <span className={`score-pill ${scoreTone(item.powerScore)}`}>
                        {item.powerScore}
                      </span>
                    </td>
                    <td>
                      <span className={`score-pill ${scoreTone(item.suspicionScore)}`}>
                        {item.suspicionScore}
                      </span>
                    </td>
                    <td>
                      {item.reputationScore != null && item.reputationScore >= 0 ? (
                        <span className={`reputation-badge ${item.reputationScore >= 70 ? "rep-high" : item.reputationScore >= 40 ? "rep-mid" : "rep-low"}`}>
                          {item.reputationScore}
                        </span>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td>{item.profiles.map((profile) => profile.profile_name).join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filteredExtensions.length === 0 ? <div className="empty">No extensions match the current filters.</div> : null}
          </div>
        </section>

        <section className="panel panel-detail" style={panelDelay("0.3s")}>
          <div className="panel-heading">
            <div>
              <p className="section-kicker">Extension detail</p>
              <h2>{selectedExtension?.name ?? "Select an extension"}</h2>
            </div>
          </div>
          {!selectedExtension ? (
            <div className="empty">Pick an extension from the inventory to inspect its evidence.</div>
          ) : (
            <div className="detail-layout">
              <div className="detail-column">
                <div className="detail-card">
                  <div className="detail-header">
                    <div>
                      <h3>Classification</h3>
                      <p className="muted">Verdict and scoring summary</p>
                    </div>
                    <span className={`pill ${verdictTone[selectedExtension.verdict] ?? "tone-slate"}`}>
                      {humanizeLabel(selectedExtension.verdict)}
                    </span>
                  </div>
                  <div className="detail-rows">
                    <div className="detail-row">
                      <span className="detail-row-label">Power score</span>
                      <span className={`detail-row-value score-pill ${scoreTone(selectedExtension.powerScore)}`}>
                        {selectedExtension.powerScore}
                      </span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-row-label">Suspicion</span>
                      <span className={`detail-row-value score-pill ${scoreTone(selectedExtension.suspicionScore)}`}>
                        {selectedExtension.suspicionScore}
                      </span>
                    </div>
                    {selectedExtension.reputationScore != null && selectedExtension.reputationScore >= 0 ? (
                      <div className="detail-row">
                        <span className="detail-row-label">Reputation</span>
                        <span className={`detail-row-value score-pill ${selectedExtension.reputationScore >= 70 ? "text-green" : selectedExtension.reputationScore >= 40 ? "text-amber" : "text-red"}`}>
                          {selectedExtension.reputationScore}/100
                        </span>
                      </div>
                    ) : null}
                    {selectedExtension.category ? (
                      <div className="detail-row">
                        <span className="detail-row-label">Category</span>
                        <span className="detail-row-value">{CATEGORY_ICONS[selectedExtension.category] ?? ""} {humanizeLabel(selectedExtension.category)}</span>
                      </div>
                    ) : null}
                  </div>
                  <p className="detail-description">{selectedExtension.description || "No description available."}</p>
                </div>

                {selectedExtension.reputationDetails ? (
                  <div className="detail-card">
                    <h3>Reputation details</h3>
                    <div className="detail-rows">
                      <div className="detail-row">
                        <span className="detail-row-label">Users</span>
                        <span className="detail-row-value">{selectedExtension.reputationDetails.user_count_display || "Unknown"}</span>
                      </div>
                      <div className="detail-row">
                        <span className="detail-row-label">Rating</span>
                        <span className="detail-row-value">{selectedExtension.reputationDetails.star_rating > 0 ? `${selectedExtension.reputationDetails.star_rating}/5 ⭐` : "N/A"}</span>
                      </div>
                      <div className="detail-row">
                        <span className="detail-row-label">Developer</span>
                        <span className="detail-row-value">{selectedExtension.reputationDetails.developer_name || "Unknown"}</span>
                      </div>
                      <div className="detail-row">
                        <span className="detail-row-label">Last updated</span>
                        <span className="detail-row-value">{selectedExtension.reputationDetails.last_updated || "Unknown"}</span>
                      </div>
                    </div>
                    {(selectedExtension.reputationDetails.is_featured || selectedExtension.reputationDetails.is_established_publisher) ? (
                      <div className="detail-badges">
                        {selectedExtension.reputationDetails.is_featured ? (
                          <span className="tag tag-green">✓ Featured</span>
                        ) : null}
                        {selectedExtension.reputationDetails.is_established_publisher ? (
                          <span className="tag tag-green">✓ Established Publisher</span>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                ) : null}

                <div className="detail-card">
                  <h3>Permissions and hosts</h3>
                  <div className="tag-row tag-row-scroll">
                    {selectedExtension.permissions.map((permission) => (
                      <span key={permission} className="tag">
                        {permission}
                      </span>
                    ))}
                  </div>
                  <div className="tag-row tag-row-scroll">
                    {selectedExtension.hostPermissions.map((permission) => (
                      <span key={permission} className="tag tag-host">
                        {permission}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="detail-card">
                  <h3>AI summary</h3>
                  {aiSummarySections ? (
                    <div className="ai-summary">
                      {aiSummarySections.map((section, index) => (
                        <div key={`${section.title}-${index}`} className={`ai-section ${aiSectionTone(section.title)}`}>
                          <div className="ai-title">{section.title}</div>
                          {section.paragraphs.map((text, textIndex) => (
                            <p key={`${section.title}-p-${textIndex}`}>{text}</p>
                          ))}
                          {section.bullets.length > 0 ? (
                            <ul>
                              {section.bullets.map((bullet, bulletIndex) => (
                                <li key={`${section.title}-b-${bulletIndex}`}>{bullet}</li>
                              ))}
                            </ul>
                          ) : null}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p>AI is optional and is currently disabled or not configured for this scan.</p>
                  )}
                </div>

                {selectedExtension.recommendations && selectedExtension.recommendations.length > 0 ? (
                  <div className="detail-card recommendation-section">
                    <h3>Safe alternatives</h3>
                    <p className="muted">These trusted extensions serve the same purpose:</p>
                    <div className="recommendation-grid">
                      {selectedExtension.recommendations.map((rec) => (
                        <a
                          key={rec.extension_id}
                          className="recommendation-card"
                          href={rec.install_url}
                          target="_blank"
                          rel="noreferrer"
                        >
                          <div className="rec-header">
                            <strong>{rec.name}</strong>
                            <span className="pill tone-teal">trusted</span>
                          </div>
                          <div className="muted">{rec.publisher}</div>
                          {rec.users ? <div className="rec-meta">{rec.users}</div> : null}
                          <div className="rec-reason">{rec.reason}</div>
                          <span className="rec-cta">Install from Chrome Web Store →</span>
                        </a>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>

              <div className="detail-column">
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
                  <h3>Evidence timeline</h3>
                  <ul className="timeline">
                    {selectedExtension.evidenceTimeline.map((entry) => (
                      <li key={entry}>{entry}</li>
                    ))}
                  </ul>
                </div>

                <div className="detail-card">
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
            </div>
          )}
        </section>

        <section className="panel panel-reports" style={panelDelay("0.35s")}>
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
