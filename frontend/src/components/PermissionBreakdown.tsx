import { useState } from 'react';

interface PermissionBreakdownProps {
  permissions: string[];
  hostPermissions: string[];
}

interface PermGroup {
  label: string;
  level: 'critical' | 'high' | 'medium' | 'low';
  items: string[];
}

const CRITICAL = ['<all_urls>', '*://*/*', 'debugger', 'proxy'];
const HIGH = ['webRequest', 'webRequestBlocking', 'cookies', 'history', 'browsingData', 'bookmarks'];
const MEDIUM = ['tabs', 'activeTab', 'management', 'downloads', 'topSites', 'sessions'];

function categorize(permissions: string[], hostPermissions: string[]): PermGroup[] {
  const all = [...permissions, ...hostPermissions];
  const critical: string[] = [];
  const high: string[] = [];
  const medium: string[] = [];
  const low: string[] = [];

  for (const p of all) {
    if (CRITICAL.some(c => p.includes(c))) critical.push(p);
    else if (HIGH.includes(p)) high.push(p);
    else if (MEDIUM.includes(p)) medium.push(p);
    else low.push(p);
  }

  return ([
    { label: 'Critical', level: 'critical' as const, items: critical },
    { label: 'High', level: 'high' as const, items: high },
    { label: 'Medium', level: 'medium' as const, items: medium },
    { label: 'Low', level: 'low' as const, items: low },
  ] satisfies PermGroup[]).filter(g => g.items.length > 0);
}

export default function PermissionBreakdown({ permissions, hostPermissions }: PermissionBreakdownProps) {
  const groups = categorize(permissions, hostPermissions);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({ critical: true, high: true });

  if (groups.length === 0) {
    return <div className="muted">No permissions requested.</div>;
  }

  return (
    <div>
      {groups.map(g => (
        <div key={g.level} className="permission-group">
          <button
            className={`permission-group-header ${g.level}`}
            onClick={() => setExpanded(prev => ({ ...prev, [g.level]: !prev[g.level] }))}
            aria-expanded={!!expanded[g.level]}
            aria-label={`${g.label} permissions group, ${g.items.length} items`}
          >
            <span className="permission-group-label">
              {expanded[g.level] ? '▼' : '▶'} {g.label}
            </span>
            <span className="permission-group-count">{g.items.length}</span>
          </button>
          {expanded[g.level] && (
            <div className="permission-group-list">
              {g.items.map(item => (
                <div key={item} className="permission-item">{item}</div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
