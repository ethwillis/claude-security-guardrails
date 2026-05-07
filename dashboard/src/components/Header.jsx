function Header({ lastScan, totalScans, totalFindings, blockedCount, apiStatus, lastUpdate }) {
  const formatTime = (ts) => {
    if (!ts) return 'Never';
    const d = new Date(ts);
    return d.toLocaleString();
  };

  const formatRelative = (ts) => {
    if (!ts) return '';
    const diffSec = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
    if (diffSec < 5) return 'just now';
    if (diffSec < 60) return `${diffSec}s ago`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    return `${Math.floor(diffSec / 3600)}h ago`;
  };

  const statusColor =
    apiStatus === 'ok' ? '#22c55e' :
    apiStatus === 'degraded' ? '#eab308' : '#ef4444';
  const statusLabel =
    apiStatus === 'ok' ? 'API healthy' :
    apiStatus === 'degraded' ? 'Slow response' :
    apiStatus === 'down' ? 'API unreachable' : 'Connecting…';

  return (
    <header className="header">
      <div className="header-left">
        <h1>Security Guardrails</h1>
        <p>
          {lastScan
            ? `Last scan: ${formatTime(lastScan)}`
            : 'AI-powered security scanning for Claude Code'}
        </p>
        <div className="api-status" title={statusLabel}>
          <span
            className={`api-status-dot ${apiStatus === 'ok' ? 'pulse' : ''}`}
            style={{ backgroundColor: statusColor }}
          />
          <span className="api-status-label">{statusLabel}</span>
          {lastUpdate && apiStatus === 'ok' && (
            <span className="api-status-time">· updated {formatRelative(lastUpdate)}</span>
          )}
        </div>
      </div>
      {lastScan && (
        <div className="header-stats">
          <div className="header-stat">
            <div className="value">{totalScans}</div>
            <div className="label">Total Scans</div>
          </div>
          <div className="header-stat">
            <div className="value">{totalFindings}</div>
            <div className="label">Issues Found</div>
          </div>
          <div className="header-stat">
            <div className="value" style={{ color: blockedCount > 0 ? '#ef4444' : '#22c55e' }}>
              {blockedCount}
            </div>
            <div className="label">Blocked</div>
          </div>
        </div>
      )}
    </header>
  );
}

export default Header;
