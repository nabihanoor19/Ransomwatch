import React, { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertCircle, Eye, Filter, RefreshCw } from 'lucide-react';
import { eventsApi, monitorApi } from '../api/services';
import { extractErrorMessage } from '../api/client';
import {
  formatTimestamp,
  recommendedActionForSeverity,
  riskBarColor,
  severityBadgeClass,
} from '../utils/formatters';
import Modal from '../components/Modal';

export default function EventsPage() {
  const [events, setEvents] = useState([]);
  const [folders, setFolders] = useState([]);
  const [severityFilter, setSeverityFilter] = useState('');
  const [folderFilter, setFolderFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [selectedEvent, setSelectedEvent] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [eventsRes, foldersRes] = await Promise.all([
        eventsApi.listEvents({
          severity: severityFilter || undefined,
          folder_id: folderFilter ? Number(folderFilter) : undefined,
          limit: 100,
        }),
        monitorApi.listFolders(0, 100),
      ]);
      setEvents(eventsRes);
      setFolders(foldersRes);
      setError('');
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to load file events.'));
    } finally {
      setLoading(false);
    }
  }, [severityFilter, folderFilter]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleOpenDetail = async (eventId) => {
    setLoadingDetail(true);
    try {
      const detail = await eventsApi.getEvent(eventId);
      setSelectedEvent(detail);
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to fetch event details.'));
    } finally {
      setLoadingDetail(false);
    }
  };

  const folderNameById = Object.fromEntries(
    folders.map((f) => [f.id, f.folder_name])
  );

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">File Events & Threat Detections</h1>
          <p className="page-subtitle">
            Inspect normalized filesystem events, risk scores, detection modules, and explainable evidence.
          </p>
        </div>

        <button type="button" className="btn btn-secondary btn-sm" onClick={loadData}>
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

      <section className="card">
        <div className="filter-bar">
          <div className="form-group filter-item">
            <label className="form-label" htmlFor="filter-sev">
              Severity
            </label>
            <select
              id="filter-sev"
              className="select"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          <div className="form-group filter-item">
            <label className="form-label" htmlFor="filter-folder">
              Monitored Folder
            </label>
            <select
              id="filter-folder"
              className="select"
              value={folderFilter}
              onChange={(e) => setFolderFilter(e.target.value)}
            >
              <option value="">All Folders</option>
              {folders.map((f) => (
                <option key={f.id} value={f.id}>
                  #{f.id} — {f.folder_name}
                </option>
              ))}
            </select>
          </div>

          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => {
              setSeverityFilter('');
              setFolderFilter('');
            }}
          >
            <Filter size={15} />
            Reset Filters
          </button>
        </div>
      </section>

      <section className="card">
        {events.length === 0 ? (
          <div className="empty-state">
            {loading
              ? 'Loading file events...'
              : 'No file events match the selected filters.'}
          </div>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>File</th>
                  <th>Folder</th>
                  <th>Event Type</th>
                  <th>Module</th>
                  <th>Severity</th>
                  <th>Risk Score</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev) => (
                  <tr key={ev.event_id}>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                      {formatTimestamp(ev.timestamp)}
                    </td>
                    <td className="mono" style={{ fontSize: '0.83rem' }}>
                      {ev.file_name}
                    </td>
                    <td style={{ fontSize: '0.84rem' }}>
                      {folderNameById[ev.folder_id] || `Folder #${ev.folder_id}`}
                    </td>
                    <td>
                      <span className="badge badge-neutral">{ev.event_type}</span>
                    </td>
                    <td>
                      <span className="badge badge-info">{ev.module || 'monitor'}</span>
                    </td>
                    <td>
                      <span className={severityBadgeClass(ev.severity)}>{ev.severity}</span>
                    </td>
                    <td style={{ minWidth: 110 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div className="bar-track" style={{ height: 8 }}>
                          <div
                            className="bar-fill"
                            style={{
                              width: `${Math.min(100, Number(ev.risk_score) || 0)}%`,
                              backgroundColor: riskBarColor(ev.risk_score),
                            }}
                          />
                        </div>
                        <span className="mono" style={{ fontSize: '0.8rem' }}>
                          {Number(ev.risk_score).toFixed(1)}
                        </span>
                      </div>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        disabled={loadingDetail}
                        onClick={() => handleOpenDetail(ev.event_id)}
                      >
                        <Eye size={14} />
                        Evidence
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <Modal
        open={Boolean(selectedEvent)}
        title={`Event Details — ${selectedEvent?.file_name || ''}`}
        onClose={() => setSelectedEvent(null)}
        footer={
          <>
            {selectedEvent?.incident_id && (
              <Link to="/incidents" className="btn btn-primary btn-sm">
                View Correlated Incident
              </Link>
            )}
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => setSelectedEvent(null)}
            >
              Close
            </button>
          </>
        }
      >
        {selectedEvent && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div className="grid-2" style={{ gap: 10 }}>
              <div>
                <div className="form-label">Event UUID</div>
                <div className="mono" style={{ fontSize: '0.82rem', wordBreak: 'break-all' }}>
                  {selectedEvent.event_id}
                </div>
              </div>
              <div>
                <div className="form-label">Timestamp</div>
                <div style={{ fontSize: '0.88rem' }}>
                  {formatTimestamp(selectedEvent.timestamp)}
                </div>
              </div>
              <div>
                <div className="form-label">Detection Module</div>
                <span className="badge badge-info">{selectedEvent.module || 'monitor'}</span>
              </div>
              <div>
                <div className="form-label">Severity & Risk Score</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className={severityBadgeClass(selectedEvent.severity)}>
                    {selectedEvent.severity}
                  </span>
                  <span className="mono">{Number(selectedEvent.risk_score).toFixed(2)} / 100</span>
                </div>
              </div>
            </div>

            <div>
              <div className="form-label" style={{ marginBottom: 6 }}>
                Supporting Evidence
              </div>
              {selectedEvent.evidence?.length ? (
                <ul className="evidence-list">
                  {selectedEvent.evidence.map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              ) : (
                <div style={{ fontSize: '0.86rem', color: 'var(--text-muted)' }}>
                  No additional evidence items recorded.
                </div>
              )}
            </div>

            <div className="alert alert-info">
              <div>
                <strong>Recommended Action: </strong>
                {recommendedActionForSeverity(selectedEvent.severity)}
              </div>
            </div>
          </div>
        )}
      </Modal>
    </>
  );
}
