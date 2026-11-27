import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Clock,
  Eye,
  Filter,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';
import { incidentsApi } from '../api/services';
import { extractErrorMessage } from '../api/client';
import {
  formatTimestamp,
  recommendedActionForSeverity,
  riskBarColor,
  severityBadgeClass,
  statusBadgeClass,
} from '../utils/formatters';
import Modal from '../components/Modal';

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState([]);
  const [severity, setSeverity] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [moduleFilter, setModuleFilter] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [pendingResolve, setPendingResolve] = useState(null);
  const [updatingId, setUpdatingId] = useState(null);

  const loadIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const toUtcNaive = (val) => {
        if (!val) return undefined;
        const d = new Date(val);
        return Number.isNaN(d.getTime()) ? undefined : d.toISOString().slice(0, 19);
      };

      const data = await incidentsApi.listIncidents({
        severity: severity || undefined,
        status: statusFilter || undefined,
        module: moduleFilter || undefined,
        start_date: toUtcNaive(startDate),
        end_date: toUtcNaive(endDate),
        limit: 100,
      });
      setIncidents(data);
      setError('');
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to load incidents.'));
    } finally {
      setLoading(false);
    }
  }, [severity, statusFilter, moduleFilter, startDate, endDate]);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);

  const handleOpenIncident = async (incidentId) => {
    try {
      const detail = await incidentsApi.getIncident(incidentId);
      setSelectedIncident(detail);
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to fetch incident details.'));
    }
  };

  const applyStatusUpdate = async (incidentId, nextStatus) => {
    setError('');
    setNotice('');
    setUpdatingId(incidentId);
    try {
      const updated = await incidentsApi.updateStatus(incidentId, nextStatus);
      setIncidents((prev) =>
        prev.map((inc) => (inc.incident_id === incidentId ? updated : inc))
      );
      if (selectedIncident?.incident_id === incidentId) {
        setSelectedIncident(updated);
      }
      setNotice(`Incident ${incidentId} updated to "${nextStatus}".`);
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to update incident status.'));
    } finally {
      setUpdatingId(null);
    }
  };

  const handleStatusChange = (inc, nextStatus) => {
    if (nextStatus === inc.status) return;
    if (nextStatus === 'resolved') {
      setPendingResolve(inc);
      return;
    }
    applyStatusUpdate(inc.incident_id, nextStatus);
  };

  const resetFilters = () => {
    setSeverity('');
    setStatusFilter('');
    setModuleFilter('');
    setStartDate('');
    setEndDate('');
  };

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">Incident Timeline</h1>
          <p className="page-subtitle">
            Chronological security incidents correlated from high-risk file, entropy, and canary alerts.
          </p>
        </div>

        <button type="button" className="btn btn-secondary btn-sm" onClick={loadIncidents}>
          <RefreshCw size={15} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="alert alert-error">
          <AlertCircle size={18} style={{ flexShrink: 0 }} />
          <span>{error}</span>
        </div>
      )}

      {notice && (
        <div className="alert alert-success">
          <CheckCircle2 size={18} style={{ flexShrink: 0 }} />
          <span>{notice}</span>
        </div>
      )}

      <section className="card">
        <div className="filter-bar">
          <div className="form-group filter-item">
            <label className="form-label" htmlFor="inc-sev">
              Severity
            </label>
            <select
              id="inc-sev"
              className="select"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          <div className="form-group filter-item">
            <label className="form-label" htmlFor="inc-status">
              Status
            </label>
            <select
              id="inc-status"
              className="select"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="">All Statuses</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>

          <div className="form-group filter-item">
            <label className="form-label" htmlFor="inc-module">
              Detection Module
            </label>
            <select
              id="inc-module"
              className="select"
              value={moduleFilter}
              onChange={(e) => setModuleFilter(e.target.value)}
            >
              <option value="">All Modules</option>
              <option value="canary">Canary</option>
              <option value="entropy">Entropy</option>
              <option value="rules">Rules</option>
              <option value="anomaly">Anomaly</option>
              <option value="monitor">Monitor</option>
            </select>
          </div>

          <div className="form-group filter-item">
            <label className="form-label" htmlFor="inc-start">
              Start Date
            </label>
            <input
              id="inc-start"
              type="datetime-local"
              className="input"
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
            />
          </div>

          <div className="form-group filter-item">
            <label className="form-label" htmlFor="inc-end">
              End Date
            </label>
            <input
              id="inc-end"
              type="datetime-local"
              className="input"
              value={endDate}
              onChange={(e) => setEndDate(e.target.value)}
            />
          </div>

          <button type="button" className="btn btn-secondary" onClick={resetFilters}>
            <Filter size={15} />
            Reset
          </button>
        </div>
      </section>

      <section style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        {incidents.length === 0 ? (
          <div className="card empty-state">
            {loading
              ? 'Loading incident timeline...'
              : 'No incidents match the current filters.'}
          </div>
        ) : (
          incidents.map((inc) => (
            <article key={inc.incident_id} className="card">
              <div
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  gap: 12,
                }}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, flex: '1 1 320px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    <ShieldAlert size={17} color="var(--sev-high)" />
                    <span className="mono" style={{ fontWeight: 700, fontSize: '0.96rem' }}>
                      {inc.incident_id}
                    </span>
                    <span className={severityBadgeClass(inc.severity)}>{inc.severity}</span>
                    <span className={statusBadgeClass(inc.status)}>{inc.status}</span>
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 4,
                        fontSize: '0.78rem',
                        color: 'var(--text-muted)',
                      }}
                    >
                      <Clock size={13} />
                      {formatTimestamp(inc.created_at)}
                    </span>
                  </div>

                  <div style={{ fontSize: '0.94rem', fontWeight: 500 }}>
                    {inc.description || 'Suspicious ransomware-like file activity detected'}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, maxWidth: 260 }}>
                    <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                      Risk Score:
                    </span>
                    <div className="bar-track" style={{ height: 8 }}>
                      <div
                        className="bar-fill"
                        style={{
                          width: `${Math.min(100, Number(inc.risk_score) || 0)}%`,
                          backgroundColor: riskBarColor(inc.risk_score),
                        }}
                      />
                    </div>
                    <span className="mono" style={{ fontSize: '0.8rem' }}>
                      {Number(inc.risk_score).toFixed(1)}
                    </span>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <select
                    aria-label={`Change status for ${inc.incident_id}`}
                    className="select"
                    style={{ width: 155 }}
                    value={inc.status}
                    disabled={updatingId === inc.incident_id}
                    onChange={(e) => handleStatusChange(inc, e.target.value)}
                  >
                    <option value="open">Open</option>
                    <option value="investigating">Investigating</option>
                    <option value="resolved">Resolved</option>
                  </select>

                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => handleOpenIncident(inc.incident_id)}
                  >
                    <Eye size={14} />
                    Inspect
                  </button>
                </div>
              </div>

              {inc.evidence?.length > 0 && (
                <div
                  style={{
                    marginTop: 12,
                    paddingTop: 12,
                    borderTop: '1px solid var(--border-subtle)',
                  }}
                >
                  <div className="form-label" style={{ marginBottom: 6 }}>
                    Evidence Highlights
                  </div>
                  <ul className="evidence-list">
                    {inc.evidence.slice(0, 3).map((item, idx) => (
                      <li key={idx}>{item}</li>
                    ))}
                  </ul>
                </div>
              )}
            </article>
          ))
        )}
      </section>

      <Modal
        open={Boolean(selectedIncident)}
        title={`Incident ${selectedIncident?.incident_id || ''}`}
        onClose={() => setSelectedIncident(null)}
        footer={
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => setSelectedIncident(null)}
          >
            Close
          </button>
        }
      >
        {selectedIncident && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
              <span className={severityBadgeClass(selectedIncident.severity)}>
                {selectedIncident.severity}
              </span>
              <span className={statusBadgeClass(selectedIncident.status)}>
                {selectedIncident.status}
              </span>
              <span className="mono" style={{ fontSize: '0.84rem' }}>
                Risk Score: {Number(selectedIncident.risk_score).toFixed(2)} / 100
              </span>
            </div>

            <div>
              <div className="form-label">Description</div>
              <div>{selectedIncident.description || '—'}</div>
            </div>

            <div className="grid-2" style={{ gap: 10 }}>
              <div>
                <div className="form-label">Created At</div>
                <div style={{ fontSize: '0.86rem' }}>
                  {formatTimestamp(selectedIncident.created_at)}
                </div>
              </div>
              <div>
                <div className="form-label">Last Updated</div>
                <div style={{ fontSize: '0.86rem' }}>
                  {formatTimestamp(selectedIncident.updated_at)}
                </div>
              </div>
            </div>

            <div>
              <div className="form-label" style={{ marginBottom: 6 }}>
                Full Supporting Evidence
              </div>
              {selectedIncident.evidence?.length ? (
                <ul className="evidence-list">
                  {selectedIncident.evidence.map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              ) : (
                <div style={{ color: 'var(--text-muted)', fontSize: '0.86rem' }}>
                  No evidence recorded.
                </div>
              )}
            </div>

            <div className="alert alert-info">
              <div>
                <strong>Recommended Action: </strong>
                {recommendedActionForSeverity(selectedIncident.severity)}
              </div>
            </div>
          </div>
        )}
      </Modal>

      <Modal
        open={Boolean(pendingResolve)}
        title="Confirm Incident Resolution"
        onClose={() => setPendingResolve(null)}
        footer={
          <>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setPendingResolve(null)}
            >
              Cancel
            </button>
            <button
              type="button"
              className="btn btn-success"
              onClick={() => {
                const target = pendingResolve;
                setPendingResolve(null);
                if (target) applyStatusUpdate(target.incident_id, 'resolved');
              }}
            >
              Mark Resolved
            </button>
          </>
        }
      >
        <p style={{ margin: 0, color: 'var(--text-secondary)' }}>
          Confirm marking incident{' '}
          <strong className="mono" style={{ color: 'var(--text-primary)' }}>
            {pendingResolve?.incident_id}
          </strong>{' '}
          as <strong>resolved</strong>? This transition will be permanently recorded in the
          audit log.
        </p>
      </Modal>
    </>
  );
}
