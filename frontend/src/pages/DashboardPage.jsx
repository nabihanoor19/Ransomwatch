import React, { useCallback, useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  FolderCheck,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { dashboardApi } from '../api/services';
import { extractErrorMessage } from '../api/client';
import {
  formatTimestamp,
  riskBarColor,
  severityBadgeClass,
} from '../utils/formatters';

export default function DashboardPage() {
  const location = useLocation();
  const [stats, setStats] = useState(null);
  const [recentEvents, setRecentEvents] = useState([]);
  const [severity, setSeverity] = useState({ LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchAll = useCallback(async () => {
    try {
      const [statsRes, eventsRes, sevRes] = await Promise.all([
        dashboardApi.getStats(),
        dashboardApi.getRecentEvents(10),
        dashboardApi.getSeverity(),
      ]);
      setStats(statsRes);
      setRecentEvents(eventsRes);
      setSeverity(sevRes);
      setError('');
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to load dashboard metrics.'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  useEffect(() => {
    if (!autoRefresh) return undefined;
    const id = setInterval(fetchAll, 10000);
    return () => clearInterval(id);
  }, [autoRefresh, fetchAll]);

  const totalSeverityCount =
    (severity.LOW || 0) +
    (severity.MEDIUM || 0) +
    (severity.HIGH || 0) +
    (severity.CRITICAL || 0);

  const avgRecentRisk =
    recentEvents.length > 0
      ? (
          recentEvents.reduce((acc, ev) => acc + (Number(ev.risk_score) || 0), 0) /
          recentEvents.length
        ).toFixed(1)
      : '0.0';

  const severityRows = [
    { key: 'CRITICAL', label: 'Critical', color: '#ef4444' },
    { key: 'HIGH', label: 'High', color: '#f97316' },
    { key: 'MEDIUM', label: 'Medium', color: '#eab308' },
    { key: 'LOW', label: 'Low', color: '#10b981' },
  ];

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Operations Dashboard</h1>
          <p className="page-subtitle">
            Real-time overview of monitored sandbox folders, file activity, and incident status.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <label
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              fontSize: '0.84rem',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
            }}
          >
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            Auto-refresh (10s)
          </label>
          <button type="button" className="btn btn-secondary btn-sm" onClick={fetchAll}>
            <RefreshCw size={15} />
            Refresh
          </button>
        </div>
      </div>

      {location.state?.accessDenied && (
        <div className="alert alert-error">
          <AlertTriangle size={18} style={{ flexShrink: 0 }} />
          <span>Administrator privileges are required to access the Admin Console.</span>
        </div>
      )}

      {error && (
        <div className="alert alert-error">
          <AlertTriangle size={18} style={{ flexShrink: 0 }} />
          <span>{error}</span>
        </div>
      )}

      <div className="kpi-grid">
        <div className="kpi-card">
          <div className="kpi-label">
            <span>Monitoring Status</span>
            <FolderCheck size={16} color="var(--accent-primary)" />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span className="kpi-value" style={{ textTransform: 'capitalize' }}>
              {loading ? '—' : stats?.monitoring_status || 'stopped'}
            </span>
            {!loading && (
              <span
                className={`badge ${
                  stats?.monitoring_status === 'active' ? 'badge-low' : 'badge-neutral'
                }`}
              >
                {stats?.active_folders ?? 0} / {stats?.total_monitored_folders ?? 0} active
              </span>
            )}
          </div>
          <div className="kpi-meta">
            Registered sandbox folders: {stats?.monitored_folders ?? 0}
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label">
            <span>Total File Events</span>
            <Activity size={16} color="#38bdf8" />
          </div>
          <div className="kpi-value">{loading ? '—' : stats?.total_events ?? 0}</div>
          <div className="kpi-meta">
            Suspicious events (Med+): <strong>{stats?.suspicious_events ?? 0}</strong>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label">
            <span>Active Incidents</span>
            <ShieldAlert size={16} color="#f97316" />
          </div>
          <div className="kpi-value">
            {loading
              ? '—'
              : (stats?.open_incidents ?? 0) + (stats?.investigating_incidents ?? 0)}
          </div>
          <div className="kpi-meta">
            Open: {stats?.open_incidents ?? 0} · Investigating:{' '}
            {stats?.investigating_incidents ?? 0} · Resolved: {stats?.resolved_incidents ?? 0}
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label">
            <span>Critical Alerts & Avg Risk</span>
            <ShieldCheck size={16} color="#ef4444" />
          </div>
          <div className="kpi-value">{loading ? '—' : stats?.critical_incidents ?? 0}</div>
          <div className="kpi-meta">
            Recent feed avg risk score: <strong>{avgRecentRisk} / 100</strong>
          </div>
        </div>
      </div>

      <div className="grid-2">
        <section className="card">
          <div className="card-header">
            <h2 className="card-title">Incident Severity Breakdown</h2>
            <Link to="/incidents" style={{ fontSize: '0.84rem' }}>
              View timeline →
            </Link>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {severityRows.map((row) => {
              const count = severity[row.key] || 0;
              const pct =
                totalSeverityCount > 0 ? Math.round((count / totalSeverityCount) * 100) : 0;
              return (
                <div key={row.key} style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      fontSize: '0.86rem',
                    }}
                  >
                    <span>{row.label}</span>
                    <span className="mono">
                      {count} ({pct}%)
                    </span>
                  </div>
                  <div className="bar-track">
                    <div
                      className="bar-fill"
                      style={{ width: `${pct}%`, backgroundColor: row.color }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          <div
            style={{
              marginTop: 20,
              paddingTop: 16,
              borderTop: '1px solid var(--border-subtle)',
              display: 'grid',
              gridTemplateColumns: 'repeat(3, 1fr)',
              gap: 12,
              textAlign: 'center',
            }}
          >
            <div>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#fca5a5' }}>
                {stats?.open_incidents ?? 0}
              </div>
              <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>Open</div>
            </div>
            <div>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#fde047' }}>
                {stats?.investigating_incidents ?? 0}
              </div>
              <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                Investigating
              </div>
            </div>
            <div>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#6ee7b7' }}>
                {stats?.resolved_incidents ?? 0}
              </div>
              <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>Resolved</div>
            </div>
          </div>
        </section>

        <section className="card">
          <div className="card-header">
            <h2 className="card-title">Recent File Activity Feed</h2>
            <Link to="/events" style={{ fontSize: '0.84rem' }}>
              All events →
            </Link>
          </div>

          {recentEvents.length === 0 ? (
            <div className="empty-state">
              {loading
                ? 'Loading recent file events...'
                : 'No file events recorded yet. Start monitoring a sandbox folder to capture activity.'}
            </div>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>File</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Risk</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {recentEvents.map((ev) => (
                    <tr key={ev.event_id}>
                      <td className="mono" style={{ fontSize: '0.82rem' }}>
                        {ev.file_name}
                      </td>
                      <td>
                        <span className="badge badge-neutral">{ev.event_type}</span>
                      </td>
                      <td>
                        <span className={severityBadgeClass(ev.severity)}>{ev.severity}</span>
                      </td>
                      <td style={{ minWidth: 90 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <div className="bar-track" style={{ height: 7 }}>
                            <div
                              className="bar-fill"
                              style={{
                                width: `${Math.min(100, Number(ev.risk_score) || 0)}%`,
                                backgroundColor: riskBarColor(ev.risk_score),
                              }}
                            />
                          </div>
                          <span className="mono" style={{ fontSize: '0.78rem' }}>
                            {Number(ev.risk_score).toFixed(0)}
                          </span>
                        </div>
                      </td>
                      <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                        {formatTimestamp(ev.timestamp)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </>
  );
}
