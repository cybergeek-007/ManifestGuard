import { useState, useMemo } from 'react';
import type { ExtensionFinding } from '../types';
import VerdictBadge from './VerdictBadge';
import RiskGauge from './RiskGauge';
import PermissionBreakdown from './PermissionBreakdown';
import ChatPanel from './ChatPanel';

function safeLinkUrl(url: string | undefined): string {
  if (!url) return '#';
  try {
    const parsed = new URL(url);
    if (parsed.protocol === 'https:' || parsed.protocol === 'http:') return url;
  } catch { /* invalid URL */ }
  return '#';
}

interface ExtensionDetailProps {
  extension: ExtensionFinding;
  scanId: string;
  onClose: () => void;
}

const CATEGORY_ICONS: Record<string, string> = {
  password_manager: '🔑', ad_blocker: '🛡️', privacy_tool: '🔒',
  developer_tool: '🛠️', security_tool: '🔐', productivity: '📋',
  communication: '💬', shopping: '🛒', accessibility: '♿',
  media: '🎬', education: '📚', ai_tool: '🤖',
  google_official: '🔵', microsoft_official: '🟦', vpn_security: '🌐',
};

function humanizeLabel(value: string): string {
  return value.replace(/_/g, ' ');
}

function scoreTone(score: number): string {
  if (score >= 70) return 'text-red';
  if (score >= 40) return 'text-amber';
  return 'text-green';
}

// AI summary parser
type AiSummarySection = {
  title: string;
  paragraphs: string[];
  bullets: string[];
};

const AI_KNOWN_HEADINGS = ['Risk Summary', 'Key Findings', 'Recommendation'];

function parseAiSummary(summary?: string | null): AiSummarySection[] | null {
  if (!summary) return null;
  const normalized = summary.replace(/\r\n/g, '\n').trim();
  if (!normalized) return null;

  const lines = normalized.split('\n').map(l => l.trim()).filter(Boolean);
  const sections: AiSummarySection[] = [];
  let current: AiSummarySection = { title: 'Summary', paragraphs: [], bullets: [] };

  const pushCurrent = () => {
    if (current.paragraphs.length || current.bullets.length) sections.push(current);
  };

  const splitInlineHeading = (headingText: string) => {
    let title = headingText;
    let remainder = '';
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
    if (line.startsWith('## ')) {
      pushCurrent();
      const headingText = line.replace(/^##\s+/, '').trim();
      const { title, remainder } = splitInlineHeading(headingText);
      current = { title: title || 'Summary', paragraphs: [], bullets: [] };
      if (remainder) current.paragraphs.push(remainder);
      continue;
    }
    if (/^[-*•]\s+/.test(line)) {
      current.bullets.push(line.replace(/^[-*•]\s+/, ''));
      continue;
    }
    current.paragraphs.push(line);
  }
  pushCurrent();
  return sections.length ? sections : null;
}

function aiSectionTone(title: string): string {
  const normalized = title.toLowerCase();
  if (normalized.includes('risk')) return 'ai-tone-risk';
  if (normalized.includes('finding')) return 'ai-tone-findings';
  if (normalized.includes('recommend')) return 'ai-tone-recommendation';
  return 'ai-tone-neutral';
}

const VERDICT_EXPLANATIONS: Record<string, string> = {
  trusted: 'This extension has been verified as safe with no suspicious behavior detected. It follows best practices and has a strong reputation.',
  low_concern: 'Minor findings detected but overall risk is low. The extension behaves normally. Monitor for changes in future updates.',
  moderate_risk: 'Several concerning signals found. Review the permissions and behavioral analysis carefully before keeping this extension.',
  suspicious: 'Significant risk indicators detected. This extension shows patterns commonly associated with malicious software. Consider disabling or removing.',
  known_malicious: 'This extension has been flagged as malicious by threat intelligence sources. Remove it immediately to protect your data.',
};

function verdictExplanationLevel(verdict: string): string {
  if (verdict === 'trusted' || verdict === 'low_concern') return 'safe';
  if (verdict === 'moderate_risk') return 'caution';
  if (verdict === 'unknown') return 'caution';
  return 'risk';
}

type Tab = 'overview' | 'signals' | 'intel' | 'ai' | 'actions';

export default function ExtensionDetail({ extension, scanId, onClose }: ExtensionDetailProps) {
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [actionMsg, setActionMsg] = useState<string | null>(null);
  const ext = extension;

  const aiSummarySections = useMemo(() => parseAiSummary(ext.aiSummary), [ext.aiSummary]);

  const tabs: { key: Tab; label: string }[] = [
    { key: 'overview', label: 'Overview' },
    { key: 'signals', label: 'Signals' },
    { key: 'intel', label: 'Intel' },
    { key: 'ai', label: 'AI' },
    { key: 'actions', label: 'Actions' },
  ];

  return (
    <div className="detail-panel">
      {/* Sticky header bar */}
      <div className="detail-header-bar">
        <div className="detail-header-left">
          <div className="detail-ext-icon" aria-hidden="true">
            {ext.category && CATEGORY_ICONS[ext.category] ? CATEGORY_ICONS[ext.category] : '🔌'}
          </div>
          <div>
            <div className="detail-title">{ext.name}</div>
            <div className="detail-version">v{ext.version} · {ext.id.slice(0, 12)}…</div>
          </div>
        </div>
        <VerdictBadge verdict={ext.verdict} size="lg" />
        <button className="detail-close" onClick={onClose} aria-label="Close detail panel">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
          </svg>
        </button>
      </div>

      {/* Scrollable body */}
      <div className="detail-panel-scroll">
        <div className="detail-body">
        <RiskGauge score={ext.anomalyScore} />

          <div className={`verdict-explanation ${verdictExplanationLevel(ext.verdict)}`}>
            <p><strong>What This Means: </strong>{VERDICT_EXPLANATIONS[ext.verdict] || 'Analysis complete.'}</p>
          </div>

          <div className="tabs" role="tablist">
            {tabs.map(tab => (
              <button
                key={tab.key}
                className={`tab-btn ${activeTab === tab.key ? 'active' : ''}`}
                onClick={() => setActiveTab(tab.key)}
                role="tab"
                aria-selected={activeTab === tab.key}
                aria-label={`${tab.label} tab`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="tab-content">
        {/* OVERVIEW TAB */}
        {activeTab === 'overview' && (
          <div>
            <div className="detail-card">
              <h3>Permissions</h3>
              <PermissionBreakdown permissions={ext.permissions} hostPermissions={ext.hostPermissions} />
            </div>

            {ext.reputationDetails && (
              <div className="detail-card" style={{ marginTop: 16 }}>
                <h3>Reputation</h3>
                <div className="detail-rows">
                  <div className="detail-row">
                    <span className="detail-row-label">Users</span>
                    <span className="detail-row-value">{ext.reputationDetails.user_count_display || 'Unknown'}</span>
                  </div>
                  <div className="detail-row">
                    <span className="detail-row-label">Rating</span>
                    <span className="detail-row-value">{ext.reputationDetails.star_rating > 0 ? `${ext.reputationDetails.star_rating}/5 ⭐` : 'N/A'}</span>
                  </div>
                  <div className="detail-row">
                    <span className="detail-row-label">Developer</span>
                    <span className="detail-row-value">{ext.reputationDetails.developer_name || 'Unknown'}</span>
                  </div>
                  <div className="detail-row">
                    <span className="detail-row-label">Last updated</span>
                    <span className="detail-row-value">{ext.reputationDetails.last_updated || 'Unknown'}</span>
                  </div>
                  {ext.reputationScore != null && ext.reputationScore >= 0 && (
                    <div className="detail-row">
                      <span className="detail-row-label">Reputation</span>
                      <span className={`detail-row-value ${ext.reputationScore >= 70 ? 'text-green' : ext.reputationScore >= 40 ? 'text-amber' : 'text-red'}`}>
                        {ext.reputationScore}/100
                      </span>
                    </div>
                  )}
                </div>
                {(ext.reputationDetails.is_featured || ext.reputationDetails.is_established_publisher) && (
                  <div className="detail-badges">
                    {ext.reputationDetails.is_featured && <span className="verdict-badge trusted sm">✓ Featured</span>}
                    {ext.reputationDetails.is_established_publisher && <span className="verdict-badge trusted sm">✓ Established Publisher</span>}
                  </div>
                )}
              </div>
            )}

            <div className="detail-card" style={{ marginTop: 16 }}>
              <h3>Classification</h3>
              <div className="detail-rows">
                <div className="detail-row">
                  <span className="detail-row-label">Reach score</span>
                  <span className={`detail-row-value ${scoreTone(ext.reachScore)}`}>{ext.reachScore}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-row-label">Anomaly score</span>
                  <span className={`detail-row-value ${scoreTone(ext.anomalyScore)}`}>{ext.anomalyScore}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-row-label">Store status</span>
                  <span className="detail-row-value">{humanizeLabel(ext.storeStatus)}</span>
                </div>
                {ext.category && (
                  <div className="detail-row">
                    <span className="detail-row-label">Category</span>
                    <span className="detail-row-value">{CATEGORY_ICONS[ext.category] ?? ''} {humanizeLabel(ext.category)}</span>
                  </div>
                )}
                {ext.intentClassification && (
                  <div className="detail-row">
                    <span className="detail-row-label">AI Intent</span>
                    <span className={`detail-row-value ${ext.intentClassification.is_deceptive ? 'text-red' : ''}`}>
                      {ext.intentClassification.category}
                      {ext.intentClassification.is_deceptive ? ' (Deceptive)' : ''}
                    </span>
                  </div>
                )}
              </div>
              <p className="detail-description">{ext.description || 'No description available.'}</p>
            </div>
          </div>
        )}

        {/* SIGNALS TAB */}
        {activeTab === 'signals' && (
          <div>
            {ext.attackSimulation && (
              <div className="detail-card" style={{ background: 'var(--color-risk-bg)', borderLeft: '3px solid var(--color-risk)', marginBottom: 16 }}>
                <h3 style={{ color: 'var(--color-risk)', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                    <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
                  </svg>
                  Contextual Attack Simulation
                </h3>
                <p style={{ fontWeight: 'bold', fontSize: '1.05rem' }}>{ext.attackSimulation}</p>
              </div>
            )}

            <div className="detail-card">
              <h3>Suspicious Signals</h3>
              {!ext.suspiciousSignals || ext.suspiciousSignals.length === 0 ? (
                <div className="muted">No high-confidence suspicious signals detected.</div>
              ) : (
                ext.suspiciousSignals.map(signal => (
                  <div key={signal.code} className="signal-card">
                    <strong>{signal.title}</strong>
                    <p>{signal.detail}</p>
                    {signal.code === 'obfuscation_or_eval' && ext.deobfuscatedPayload && (
                      <div style={{ marginTop: 8, padding: 12, background: 'var(--surface-sunken)', borderRadius: 'var(--radius-md)', borderLeft: '3px solid var(--color-caution)' }}>
                        <strong style={{ fontSize: '0.85rem', color: 'var(--color-caution)' }}>AI Decoded Payload:</strong>
                        <code style={{ display: 'block', marginTop: 4, wordBreak: 'break-all', fontSize: '0.85rem' }}>{ext.deobfuscatedPayload}</code>
                      </div>
                    )}
                    <div className="tag-row" style={{ marginTop: 8 }}>
                      {signal.evidence && signal.evidence.map(ev => (
                        <span key={ev} className="tag">{ev}</span>
                      ))}
                    </div>
                  </div>
                ))
              )}
            </div>

            <div className="detail-card" style={{ marginTop: 16 }}>
              <h3>Evidence Timeline</h3>
              <ul className="timeline">
                {ext.evidenceTimeline && ext.evidenceTimeline.map(entry => (
                  <li key={entry}>{entry}</li>
                ))}
              </ul>
            </div>

            {ext.versionDelta && (
              <div className="detail-card" style={{ marginTop: 16, background: ext.versionDelta.severity === 'high' ? 'var(--color-risk-bg)' : 'var(--color-caution-bg)' }}>
                <h3>Supply Chain Delta Warning</h3>
                <p className="muted">Version shift detected</p>
                <div className="detail-rows">
                  <div className="detail-row">
                    <span className="detail-row-label">Old version</span>
                    <span className="detail-row-value">{ext.versionDelta.oldVersion}</span>
                  </div>
                  <div className="detail-row">
                    <span className="detail-row-label">New version</span>
                    <span className="detail-row-value">{ext.versionDelta.newVersion}</span>
                  </div>
                  <div className="detail-row">
                    <span className="detail-row-label">Eval delta</span>
                    <span className="detail-row-value">{ext.versionDelta.newEvalCountDelta > 0 ? `+${ext.versionDelta.newEvalCountDelta}` : ext.versionDelta.newEvalCountDelta}</span>
                  </div>
                </div>
                {ext.versionDelta.structuralChanges.length > 0 && (
                  <div className="tag-row" style={{ marginTop: 12 }}>
                    {ext.versionDelta.structuralChanges.map(change => (
                      <span key={change} className="tag" style={{ background: 'var(--color-risk-bg)', color: 'var(--color-risk)' }}>{change}</span>
                    ))}
                  </div>
                )}
                <p style={{ marginTop: 12 }}><strong>Risk:</strong> {ext.versionDelta.riskAssessment}</p>
              </div>
            )}

            {ext.collusionEdges && ext.collusionEdges.length > 0 && (
              <div className="detail-card" style={{ marginTop: 16 }}>
                <h3>Collusion Risks</h3>
                {ext.collusionEdges.map(edge => (
                  <div key={`${edge.source_id}-${edge.target_id}`} className="signal-card" style={{ background: edge.severity === 'high' ? 'var(--color-risk-bg)' : 'var(--color-caution-bg)' }}>
                    <strong>{edge.risk_type.replace(/_/g, ' ').toUpperCase()}</strong>
                    <p>{edge.detail}</p>
                    <div className="tag-row" style={{ marginTop: 8 }}>
                      <span className="tag">Source: {edge.source_name || edge.source_id}</span>
                      <span className="tag">Target: {edge.target_name || edge.target_id}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* INTEL TAB */}
        {activeTab === 'intel' && (
          <div>
            {ext.domainIntel && ext.domainIntel.length > 0 && (
              <div className="detail-card">
                <h3>Domain Intel Burst</h3>
                {ext.domainIntel.map(intel => (
                  <div key={`${intel.domain}-${intel.source}`} className="signal-card" style={{ background: intel.isMalicious ? 'var(--color-risk-bg)' : 'var(--surface-sunken)' }}>
                    <strong>{intel.domain}</strong> ({intel.source})
                    <p>{intel.detail}</p>
                  </div>
                ))}
              </div>
            )}
            <div className="detail-card" style={{ marginTop: ext.domainIntel && ext.domainIntel.length > 0 ? 16 : 0 }}>
              <h3>Threat-Intel Matches</h3>
              {ext.intelMatches.length === 0 ? (
                <div className="muted">No curated threat-intel matches for this extension ID.</div>
              ) : (
                ext.intelMatches.map(match => (
                  <article key={`${match.source}-${match.label}`} className="intel-item">
                    <strong>{match.label}</strong>
                    <p>{match.detail}</p>
                    <a href={safeLinkUrl(match.source_url)} target="_blank" rel="noreferrer">{match.source}</a>
                  </article>
                ))
              )}
            </div>
          </div>
        )}

        {/* AI TAB */}
        {activeTab === 'ai' && (
          <div>
            <div className="detail-card">
              <h3>AI Security Summary</h3>
              {ext.aiSummary ? (
                aiSummarySections ? (
                  // Structured (header-based) AI output
                  <div className="ai-summary">
                    {aiSummarySections.map((section, index) => (
                      <div key={`${section.title}-${index}`} className={`ai-section ${aiSectionTone(section.title)}`}>
                        <div className="ai-title">{section.title}</div>
                        {section.paragraphs.map((text, i) => <p key={i}>{text}</p>)}
                        {section.bullets.length > 0 && (
                          <ul>{section.bullets.map((bullet, i) => <li key={i}>{bullet}</li>)}</ul>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  // Plain paragraph output (no markdown headers)
                  <div className="ai-summary">
                    <div className="ai-section ai-tone-neutral">
                      {ext.aiSummary.split(/\n\n+/).map((para, i) => (
                        <p key={i} style={{ marginBottom: i < ext.aiSummary!.split(/\n\n+/).length - 1 ? 12 : 0 }}>
                          {para.trim()}
                        </p>
                      ))}
                    </div>
                  </div>
                )
              ) : (
                <div className="muted" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8, padding: 24 }}>
                  <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ opacity: 0.35 }}>
                    <path d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
                  </svg>
                  <span>AI summary not generated for this scan.</span>
                  <span style={{ fontSize: '0.8rem' }}>Enable AI analysis before scanning, or ensure a valid API key is set.</span>
                </div>
              )}
            </div>

            {ext.intentClassification && (
              <div className="detail-card" style={{ marginTop: 16 }}>
                <h3>Intent Classification</h3>
                <div className="detail-rows">
                  <div className="detail-row">
                    <span className="detail-row-label">Category</span>
                    <span className="detail-row-value">{ext.intentClassification.category}</span>
                  </div>
                  <div className="detail-row">
                    <span className="detail-row-label">Deceptive</span>
                    <span className={`detail-row-value ${ext.intentClassification.is_deceptive ? 'text-red' : 'text-green'}`}>
                      {ext.intentClassification.is_deceptive ? 'Yes' : 'No'}
                    </span>
                  </div>
                  <div className="detail-row">
                    <span className="detail-row-label">Reason</span>
                    <span className="detail-row-value">{ext.intentClassification.reason}</span>
                  </div>
                </div>
              </div>
            )}

            <div style={{ marginTop: 16 }}>
              <ChatPanel scanId={scanId} extensionId={ext.id} extensionName={ext.name} />
            </div>
          </div>
        )}

        {/* ACTIONS TAB */}
        {activeTab === 'actions' && (
          <div>
            {ext.recommendations && ext.recommendations.length > 0 && (
              <div className="detail-card">
                <h3>Safe Alternatives</h3>
                <p className="muted">These trusted extensions serve the same purpose:</p>
                <div className="recommendation-grid">
                  {ext.recommendations.map(rec => (
                    <a
                      key={rec.extension_id}
                      className="recommendation-card"
                      href={safeLinkUrl(rec.install_url)}
                      target="_blank"
                      rel="noreferrer"
                    >
                      <div className="rec-header">
                        <strong>{rec.name}</strong>
                        <VerdictBadge verdict="trusted" size="sm" />
                      </div>
                      <div className="muted">{rec.publisher}</div>
                      {rec.users && <div className="rec-meta">{rec.users}</div>}
                      <div className="rec-reason">{rec.reason}</div>
                      <span className="rec-cta">Install from Chrome Web Store →</span>
                    </a>
                  ))}
                </div>
              </div>
            )}

            <div className="detail-card" style={{ marginTop: 16 }}>
              <h3>Extension Actions</h3>

              {actionMsg && (
                <div className="error-banner" style={{ borderColor: 'var(--safe-border)', background: 'var(--safe-bg)', color: 'var(--safe)', marginBottom: 12 }}>
                  {actionMsg}
                </div>
              )}

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginTop: 12 }}>
                <button
                  className="report-btn"
                  style={{ background: 'var(--danger-bg)', color: 'var(--danger)', borderColor: 'var(--danger-border)' }}
                  onClick={() => {
                    const w = window as unknown as Record<string, unknown>;
                    const chromeObj = w.chrome as { runtime?: { sendMessage?: (id: string, msg: unknown, cb: (r: { success?: boolean } | undefined) => void) => void } } | undefined;
                    if (chromeObj?.runtime?.sendMessage) {
                      const extId = 'nmlkkglnnkgigimofnhmbdnpmnimldif';
                      chromeObj.runtime.sendMessage(extId, { action: 'uninstall', extensionId: ext.id }, (response: { success?: boolean } | undefined) => {
                        setActionMsg(response?.success ? '✓ Extension successfully uninstalled.' : '✗ Failed to uninstall or user cancelled.');
                      });
                    } else {
                      setActionMsg('ℹ ManifestGuard bridge extension is required for uninstall.');
                    }
                  }}
                  aria-label="Uninstall extension"
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M10 11v6M14 11v6" />
                  </svg>
                  Uninstall
                </button>

                <button
                  className="report-btn"
                  style={{ background: 'rgba(29,161,242,0.1)', color: '#1DA1F2', borderColor: '#1DA1F2' }}
                  onClick={() => {
                    const shareUrl = `${window.location.origin}/?scan=${scanId}`;
                    const isMalicious = ext.verdict === 'known_malicious' || ext.verdict === 'suspicious';
                    const text = isMalicious
                      ? `⚠️ Found dangerous extension "${ext.name}" using ManifestGuard. Check yours: ${shareUrl}`
                      : `✅ Audited "${ext.name}" with ManifestGuard — looks clean! Check yours: ${shareUrl}`;
                    window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}`, '_blank', 'noopener');
                  }}
                  aria-label="Share on Twitter"
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z"/>
                  </svg>
                  Share
                </button>
              </div>
            </div>
          </div>
        )}
        </div> {/* end tab-content */}

        </div> {/* end detail-body */}
      </div> {/* end detail-panel-scroll */}
    </div>
  );
}
