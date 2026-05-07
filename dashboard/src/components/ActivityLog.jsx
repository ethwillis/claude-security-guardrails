import { useState } from 'react';

const ACTION_CONFIG = {
  blocked: { emoji: '🚫', color: '#ef4444', label: 'Blocked' },
  allowed: { emoji: '✅', color: '#22c55e', label: 'Allowed' },
  warning: { emoji: '⚠️', color: '#eab308', label: 'Warning' },
  findings: { emoji: '🔍', color: '#f97316', label: 'Findings' },
  error: { emoji: '❌', color: '#ef4444', label: 'Error' },
};

function ActivityLog({ events, stats }) {
  const [filter, setFilter] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [tool, setTool] = useState('all');
  const [query, setQuery] = useState('');

  const tools = Array.from(new Set(events.map(e => e.tool).filter(Boolean)));

  const filtered = events.filter(e => {
    if (filter !== 'all' && e.action !== filter) return false;
    if (severity !== 'all' && e.severity !== severity) return false;
    if (tool !== 'all' && e.tool !== tool) return false;
    if (query) {
      const q = query.toLowerCase();
      const hay = [e.target, e.reason, e.tool, e.hook, e.action]
        .filter(Boolean).join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const formatTime = (ts) => {
    const d = new Date(ts);
    const now = new Date();
    const diffMs = now - d;
    const diffMin = Math.floor(diffMs / 60000);
    const diffHr = Math.floor(diffMs / 3600000);

    if (diffMin < 1) return 'just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffHr < 24) return `${diffHr}h ago`;
    return d.toLocaleDateString();
  };

  return (
    <>
      <h3>Hook Activity Log</h3>

      {/* Stats row */}
      {stats && (
        <div className="activity-stats">
          <div className="activity-stat">
            <span className="stat-value" style={{ color: '#ef4444' }}>{stats.blocked}</span>
            <span className="stat-label">Blocked</span>
          </div>
          <div className="activity-stat">
            <span className="stat-value" style={{ color: '#22c55e' }}>{stats.allowed}</span>
            <span className="stat-label">Allowed</span>
          </div>
          <div className="activity-stat">
            <span className="stat-value" style={{ color: '#eab308' }}>{stats.warnings}</span>
            <span className="stat-label">Warnings</span>
          </div>
          <div className="activity-stat">
            <span className="stat-value" style={{ color: 'var(--text-primary)' }}>{stats.total}</span>
            <span className="stat-label">Total Events</span>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="activity-filters">
        {['all', 'blocked', 'allowed', 'warning', 'findings'].map(f => (
          <button
            key={f}
            className={`activity-filter-btn ${filter === f ? 'active' : ''}`}
            onClick={() => setFilter(f)}
          >
            {f === 'all' ? 'All' : ACTION_CONFIG[f]?.label || f}
          </button>
        ))}
      </div>
      <div className="activity-filters-row">
        <select
          className="activity-select"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          aria-label="Filter by severity"
        >
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          className="activity-select"
          value={tool}
          onChange={(e) => setTool(e.target.value)}
          aria-label="Filter by tool"
        >
          <option value="all">All tools</option>
          {tools.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <input
          className="activity-search"
          type="text"
          placeholder="Search target, reason, tool…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        {(severity !== 'all' || tool !== 'all' || query || filter !== 'all') && (
          <button
            className="activity-clear"
            onClick={() => { setFilter('all'); setSeverity('all'); setTool('all'); setQuery(''); }}
          >
            Clear
          </button>
        )}
      </div>
      <div className="activity-result-count">
        Showing {filtered.length} of {events.length} events
      </div>

      {/* Event list */}
      {filtered.length === 0 ? (
        <div className="no-findings">
          No activity logged yet. Hook events will appear here when Claude Code runs.
        </div>
      ) : (
        <div className="activity-list">
          {filtered.map((event) => {
            const config = ACTION_CONFIG[event.action] || ACTION_CONFIG.allowed;
            return (
              <div key={event.id} className="activity-event" style={{ borderLeftColor: config.color }}>
                <div className="activity-event-header">
                  <span className="activity-action" style={{ color: config.color }}>
                    {config.emoji} {config.label}
                  </span>
                  <span className="activity-meta">
                    <code className="activity-tool">{event.tool}</code>
                    <span className="activity-hook">{event.hook}</span>
                    <span className="activity-time">{formatTime(event.timestamp)}</span>
                  </span>
                </div>
                <div className="activity-target">
                  <code>{event.target}</code>
                </div>
                {event.reason && (
                  <div className="activity-reason">{event.reason}</div>
                )}
                {event.severity && (
                  <span className={`severity-badge ${event.severity}`}>{event.severity}</span>
                )}
                {event.findings && event.findings.length > 0 && (
                  <div className="activity-findings">
                    {event.findings.slice(0, 3).map((f, i) => (
                      <div key={i} className="activity-finding-item">
                        <span className={`severity-badge ${f.severity}`}>{f.severity}</span>
                        <span>{f.rule}</span>
                        {f.line && <span className="activity-line">L{f.line}</span>}
                      </div>
                    ))}
                    {event.findings.length > 3 && (
                      <div className="activity-more">+{event.findings.length - 3} more</div>
                    )}
                  </div>
                )}
                {event.score !== undefined && event.action === 'findings' && (
                  <div className="activity-score">
                    Score: <strong style={{ color: event.score >= 80 ? '#22c55e' : event.score >= 50 ? '#eab308' : '#ef4444' }}>
                      {event.score}/100
                    </strong>
                    {event.totalFindings > 0 && ` — ${event.totalFindings} finding(s)`}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}

export default ActivityLog;
