import { useMemo, useState, useEffect } from 'react';
import type { ExtensionFinding } from '../types';
import VerdictBadge from './VerdictBadge';

interface InventoryTableProps {
  extensions: ExtensionFinding[];
  filters: { verdict: string; storeStatus: string; query: string };
  onFilterChange: (filters: { verdict: string; storeStatus: string; query: string }) => void;
  onSelectExtension: (extensionId: string) => void;
  selectedExtensionId: string | null;
}

const CATEGORY_ICONS: Record<string, string> = {
  password_manager: '🔑', ad_blocker: '🛡️', privacy_tool: '🔒',
  developer_tool: '🛠️', security_tool: '🔐', productivity: '📋',
  communication: '💬', shopping: '🛒', accessibility: '♿',
  media: '🎬', education: '📚', ai_tool: '🤖',
  google_official: '🔵', microsoft_official: '🟦', vpn_security: '🌐',
};

type SortKey = 'name' | 'verdict' | 'trustScore' | 'reach' | 'anomaly';
type SortDir = 'asc' | 'desc';

const PAGE_SIZE = 15;

const VERDICT_ORDER: Record<string, number> = {
  known_malicious: 5, suspicious: 4, moderate_risk: 3, low_concern: 2, trusted: 1, unknown: 0,
};

function statusDotClass(verdict: string): string {
  if (verdict === 'trusted' || verdict === 'low_concern') return 'safe';
  if (verdict === 'moderate_risk') return 'caution';
  if (verdict === 'suspicious' || verdict === 'known_malicious') return 'risk';
  return 'unknown';
}

export default function InventoryTable({ extensions, filters, onFilterChange, onSelectExtension, selectedExtensionId }: InventoryTableProps) {
  const [sortKey, setSortKey] = useState<SortKey>('anomaly');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [page, setPage] = useState(0);

  const filtered = useMemo(() => {
    return extensions.filter(item => {
      const matchVerdict = filters.verdict === 'all' || item.verdict === filters.verdict;
      const matchStore = filters.storeStatus === 'all' || item.storeStatus === filters.storeStatus;
      const haystack = [item.name, item.id, item.description, (item.permissions ?? []).join(' '), (item.hostPermissions ?? []).join(' ')].join(' ').toLowerCase();
      const matchQuery = !filters.query || haystack.includes(filters.query.toLowerCase());
      return matchVerdict && matchStore && matchQuery;
    });
  }, [extensions, filters]);

  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case 'name': cmp = a.name.localeCompare(b.name); break;
        case 'verdict': cmp = (VERDICT_ORDER[a.verdict] ?? 0) - (VERDICT_ORDER[b.verdict] ?? 0); break;
        case 'trustScore': cmp = Math.max(0, 100 - a.anomalyScore) - Math.max(0, 100 - b.anomalyScore); break;
        case 'reach': cmp = a.reachScore - b.reachScore; break;
        case 'anomaly': cmp = a.anomalyScore - b.anomalyScore; break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
  }, [filtered, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const pageItems = sorted.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  // Reset page when filters change
  useEffect(() => { setPage(0); }, [filters.verdict, filters.storeStatus, filters.query]);

  function handleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortDir('desc');
    }
  }

  const sortIndicator = (key: SortKey) => {
    if (sortKey !== key) return '';
    return sortDir === 'asc' ? ' ↑' : ' ↓';
  };

  return (
    <div className="inventory-panel">
      <div className="inventory-header">
        <div className="inventory-header-top">
          <span className="inventory-title">Extensions</span>
          <span className="inventory-count">{sorted.length} found</span>
        </div>
        <div className="inventory-controls">
          <input
            className="inventory-search"
            placeholder="Search name, ID, permission..."
            value={filters.query}
            onChange={e => onFilterChange({ ...filters, query: e.target.value })}
            aria-label="Search extensions"
            id="inventory-search"
          />
          <select
            className="inventory-filter"
            value={filters.verdict}
            onChange={e => onFilterChange({ ...filters, verdict: e.target.value })}
            aria-label="Filter by verdict"
            id="inventory-verdict-filter"
          >
            <option value="all">All verdicts</option>
            <option value="trusted">Trusted</option>
            <option value="low_concern">Low concern</option>
            <option value="moderate_risk">Moderate risk</option>
            <option value="suspicious">Suspicious</option>
            <option value="known_malicious">Malicious</option>
          </select>
        </div>
      </div>


      <div className="inventory-table-wrap">
        <table className="inventory-table">
          <thead>
            <tr>
              <th onClick={() => handleSort('name')} aria-label="Sort by name">Extension{sortIndicator('name')}</th>
              <th onClick={() => handleSort('verdict')} aria-label="Sort by verdict">Verdict{sortIndicator('verdict')}</th>
              <th onClick={() => handleSort('trustScore')} aria-label="Sort by trust score">Trust{sortIndicator('trustScore')}</th>
              <th onClick={() => handleSort('reach')} aria-label="Sort by reach score">Reach{sortIndicator('reach')}</th>
              <th onClick={() => handleSort('anomaly')} aria-label="Sort by anomaly score">Anomaly{sortIndicator('anomaly')}</th>
            </tr>
          </thead>
          <tbody>
            {pageItems.map(item => {
              const trustScore = Math.max(0, 100 - item.anomalyScore);
              const trustClass = trustScore >= 70 ? 'high' : trustScore >= 40 ? 'medium' : 'low';
              return (
                <tr
                  key={item.id}
                  onClick={() => onSelectExtension(item.id)}
                  className={item.id === selectedExtensionId ? 'row-active' : ''}
                  aria-label={`Select ${item.name}`}
                >
                  <td>
                    <div className="table-name">
                      <span className={`status-dot ${statusDotClass(item.verdict)}`} aria-hidden="true" />
                      {item.category && CATEGORY_ICONS[item.category] && (
                        <span className="category-icon" title={item.category.replace(/_/g, ' ')}>{CATEGORY_ICONS[item.category]}</span>
                      )}
                      <span className="table-name-text">{item.name}</span>
                    </div>
                  </td>
                  <td><VerdictBadge verdict={item.verdict} size="sm" /></td>
                  <td><span className={`trust-score ${trustClass}`}>{trustScore}</span></td>
                  <td>{item.reachScore}</td>
                  <td>{item.anomalyScore}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {sorted.length === 0 && (
        <div className="muted" style={{ textAlign: 'center', padding: 24 }}>No extensions match the current filters.</div>
      )}

      {totalPages > 1 && (
        <div className="pagination">
          <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0} aria-label="Previous page">← Prev</button>
          {Array.from({ length: totalPages }, (_, i) => {
            // Show first, last, and pages near current
            if (i === 0 || i === totalPages - 1 || Math.abs(i - page) <= 1) {
              return (
                <button key={i} onClick={() => setPage(i)} className={i === page ? 'active' : ''} aria-label={`Page ${i + 1}`}>
                  {i + 1}
                </button>
              );
            }
            if (i === 1 && page > 2) return <span key={i} className="pagination-info">…</span>;
            if (i === totalPages - 2 && page < totalPages - 3) return <span key={i} className="pagination-info">…</span>;
            return null;
          })}
          <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1} aria-label="Next page">Next →</button>
        </div>
      )}
    </div>
  );
}
