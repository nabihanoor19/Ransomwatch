import React, { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertCircle,
  CheckCircle2,
  FolderPlus,
  Play,
  RefreshCw,
  ScanSearch,
  Square,
} from 'lucide-react';
import { eventsApi, monitorApi } from '../api/services';
import { extractErrorMessage } from '../api/client';
import {
  formatTimestamp,
  severityBadgeClass,
  statusBadgeClass,
} from '../utils/formatters';
import Modal from '../components/Modal';

export default function MonitorPage() {
  const [folders, setFolders] = useState([]);
  const [selectedFolder, setSelectedFolder] = useState(null);
  const [liveStatus, setLiveStatus] = useState(null);
  const [folderEvents, setFolderEvents] = useState([]);
  const [scanResult, setScanResult] = useState(null);

  const [folderPath, setFolderPath] = useState('');
  const [folderName, setFolderName] = useState('');
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [stopConfirmFolder, setStopConfirmFolder] = useState(null);

  const loadFolders = useCallback(async () => {
    try {
      const list = await monitorApi.listFolders(0, 100);
      setFolders(list);
      setSelectedFolder((prev) => {
        if (!prev && list.length > 0) return list[0];
        if (prev) return list.find((f) => f.id === prev.id) || list[0] || null;
        return null;
      });
      setError('');
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to fetch monitored folders.'));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadFolderDetails = useCallback(async (folder) => {
    if (!folder) {
      setLiveStatus(null);
      setFolderEvents([]);
      return;
    }
    try {
      const [statusData, eventsData] = await Promise.all([
        monitorApi.getStatus(folder.id),
        eventsApi.listEvents({ folder_id: folder.id, limit: 15 }),
      ]);
      setLiveStatus(statusData);
      setFolderEvents(eventsData);
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to inspect folder status.'));
    }
  }, []);

  useEffect(() => {
    loadFolders();
  }, [loadFolders]);

  useEffect(() => {
    if (selectedFolder) {
      loadFolderDetails(selectedFolder);
    }
  }, [selectedFolder, loadFolderDetails]);

  const handleRegister = async (e) => {
    e.preventDefault();
    setError('');
    setNotice('');
    if (!folderPath.trim() || !folderName.trim()) {
      setError('Both folder path and display name are required.');
      return;
    }

    setBusyId('register');
    try {
      const created = await monitorApi.registerFolder({
        folder_path: folderPath.trim(),
        folder_name: folderName.trim(),
      });
      setFolderPath('');
      setFolderName('');
      setNotice(`Registered sandbox folder "${created.folder_name}".`);
      await loadFolders();
      setSelectedFolder(created);
    } catch (err) {
      setError(extractErrorMessage(err, 'Could not register folder.'));
    } finally {
      setBusyId(null);
    }
  };

  const handleStart = async (folder) => {
    setError('');
    setNotice('');
    setScanResult(null);
    setBusyId(`start-${folder.id}`);
    try {
      const updated = await monitorApi.startMonitoring(folder.id);
      setNotice(`Monitoring started & canaries deployed for "${updated.folder_name}".`);
      await loadFolders();
      await loadFolderDetails(updated);
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to start monitoring.'));
    } finally {
      setBusyId(null);
    }
  };

  const handleConfirmStop = async () => {
    if (!stopConfirmFolder) return;
    const folder = stopConfirmFolder;
    setStopConfirmFolder(null);
    setError('');
    setNotice('');
    setBusyId(`stop-${folder.id}`);
    try {
      const updated = await monitorApi.stopMonitoring(folder.id);
      setNotice(`Stopped monitoring "${updated.folder_name}".`);
      await loadFolders();
      await loadFolderDetails(updated);
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to stop monitoring.'));
    } finally {
      setBusyId(null);
    }
  };

  const handleScanCanaries = async (folder) => {
    setError('');
    setNotice('');
    setBusyId(`scan-${folder.id}`);
    try {
      const res = await monitorApi.scanCanaries(folder.id);
      setScanResult(res);
      if (res.alerts_triggered > 0) {
        setNotice(
          `Canary integrity scan found ${res.alerts_triggered} tamper alert(s)!`
        );
      } else {
        setNotice('Canary integrity scan completed: all decoy files intact.');
      }
      await loadFolderDetails(folder);
    } catch (err) {
      setError(extractErrorMessage(err, 'Canary scan failed.'));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">Sandbox Folder Monitoring</h1>
          <p className="page-subtitle">
            Register sandbox paths, control real-time Watchdog observers, and verify canary decoys.
          </p>
        </div>

        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={() => {
            loadFolders();
            if (selectedFolder) loadFolderDetails(selectedFolder);
          }}
        >
          <RefreshCw size={15} />
          Refresh Status
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
        <div className="card-header">
          <h2 className="card-title">
            <FolderPlus size={18} color="var(--accent-primary)" />
            Register Sandbox Folder
          </h2>
        </div>

        <form onSubmit={handleRegister} className="filter-bar">
          <div className="form-group filter-item" style={{ flex: '2 1 280px' }}>
            <label className="form-label" htmlFor="folder-path">
              Sandbox Folder Path
            </label>
            <input
              id="folder-path"
              className="input mono"
              placeholder="C:\RansomWatchSandbox"
              value={folderPath}
              onChange={(e) => setFolderPath(e.target.value)}
              required
            />
          </div>

          <div className="form-group filter-item">
            <label className="form-label" htmlFor="folder-name">
              Display Name
            </label>
            <input
              id="folder-name"
              className="input"
              placeholder="Test Sandbox"
              value={folderName}
              onChange={(e) => setFolderName(e.target.value)}
              required
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            disabled={busyId === 'register'}
          >
            <FolderPlus size={16} />
            {busyId === 'register' ? 'Registering...' : 'Register Folder'}
          </button>
        </form>
      </section>

      <div className="grid-2">
        <section className="card">
          <div className="card-header">
            <h2 className="card-title">Registered Folders ({folders.length})</h2>
          </div>

          {folders.length === 0 ? (
            <div className="empty-state">
              {loading
                ? 'Loading registered folders...'
                : 'No sandbox folders registered yet. Add one above to begin.'}
            </div>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Folder</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {folders.map((folder) => {
                    const isSelected = selectedFolder?.id === folder.id;
                    const isActive = folder.status === 'active';
                    return (
                      <tr
                        key={folder.id}
                        onClick={() => setSelectedFolder(folder)}
                        style={{
                          cursor: 'pointer',
                          background: isSelected ? 'rgba(14, 165, 233, 0.08)' : undefined,
                        }}
                      >
                        <td>
                          <div style={{ fontWeight: 600 }}>{folder.folder_name}</div>
                          <div
                            className="mono"
                            style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}
                          >
                            #{folder.id} · {folder.folder_path}
                          </div>
                        </td>
                        <td>
                          <span className={statusBadgeClass(folder.status)}>
                            {folder.status}
                          </span>
                        </td>
                        <td onClick={(e) => e.stopPropagation()}>
                          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                            {!isActive ? (
                              <button
                                type="button"
                                className="btn btn-success btn-sm"
                                disabled={busyId === `start-${folder.id}`}
                                onClick={() => handleStart(folder)}
                              >
                                <Play size={13} />
                                Start
                              </button>
                            ) : (
                              <button
                                type="button"
                                className="btn btn-danger btn-sm"
                                disabled={busyId === `stop-${folder.id}`}
                                onClick={() => setStopConfirmFolder(folder)}
                              >
                                <Square size={13} />
                                Stop
                              </button>
                            )}
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              disabled={busyId === `scan-${folder.id}`}
                              onClick={() => handleScanCanaries(folder)}
                              title="Run on-demand canary integrity check"
                            >
                              <ScanSearch size={13} />
                              Scan Canaries
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="card">
          <div className="card-header">
            <h2 className="card-title">
              <Activity size={18} color="var(--accent-primary)" />
              {selectedFolder
                ? `Selected Sandbox: ${selectedFolder.folder_name}`
                : 'Sandbox Observer Details'}
            </h2>
          </div>

          {!selectedFolder ? (
            <div className="empty-state">Select a folder on the left to inspect live status.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div className="grid-2" style={{ gap: 12 }}>
                <div
                  style={{
                    padding: 12,
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                    OBSERVER STATE
                  </div>
                  <div style={{ marginTop: 4, display: 'flex', gap: 8, alignItems: 'center' }}>
                    <span
                      className={`badge ${
                        liveStatus?.running ? 'badge-low' : 'badge-neutral'
                      }`}
                    >
                      {liveStatus?.running ? 'Running' : 'Idle'}
                    </span>
                    <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                      Attached: {liveStatus?.attached ? 'Yes' : 'No'}
                    </span>
                  </div>
                </div>

                <div
                  style={{
                    padding: 12,
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                    EVENTS PROCESSED (LIVE)
                  </div>
                  <div className="mono" style={{ marginTop: 4, fontSize: '1.2rem', fontWeight: 700 }}>
                    {liveStatus?.events_processed ?? 0}
                  </div>
                </div>
              </div>

              {scanResult && scanResult.folder_id === selectedFolder.id && (
                <div
                  className={`alert ${
                    scanResult.alerts_triggered > 0 ? 'alert-error' : 'alert-info'
                  }`}
                >
                  <div>
                    <strong>
                      Canary Scan Result: {scanResult.alerts_triggered} alert(s) triggered
                    </strong>
                    {scanResult.alerts?.length > 0 && (
                      <ul className="evidence-list" style={{ marginTop: 6 }}>
                        {scanResult.alerts.map((al, idx) => (
                          <li key={idx}>
                            <span className="mono">{al.file_name}</span> — {al.severity} (
                            {(al.evidence || []).join('; ')})
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              )}

              <div>
                <h3 style={{ margin: '0 0 10px', fontSize: '0.92rem' }}>
                  Recent File Activity in Folder
                </h3>
                {folderEvents.length === 0 ? (
                  <div className="empty-state" style={{ padding: '18px 12px' }}>
                    No events recorded for this folder yet.
                  </div>
                ) : (
                  <div className="table-wrap">
                    <table className="table">
                      <thead>
                        <tr>
                          <th>File</th>
                          <th>Event Type</th>
                          <th>Module</th>
                          <th>Severity</th>
                          <th>Time</th>
                        </tr>
                      </thead>
                      <tbody>
                        {folderEvents.map((ev) => (
                          <tr key={ev.event_id}>
                            <td className="mono" style={{ fontSize: '0.8rem' }}>
                              {ev.file_name}
                            </td>
                            <td>
                              <span className="badge badge-neutral">{ev.event_type}</span>
                            </td>
                            <td style={{ fontSize: '0.82rem' }}>{ev.module || '—'}</td>
                            <td>
                              <span className={severityBadgeClass(ev.severity)}>
                                {ev.severity}
                              </span>
                            </td>
                            <td style={{ fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
                              {formatTimestamp(ev.timestamp)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}
        </section>
      </div>

      <Modal
        open={Boolean(stopConfirmFolder)}
        title="Confirm Stop Monitoring"
        onClose={() => setStopConfirmFolder(null)}
        footer={
          <>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setStopConfirmFolder(null)}
            >
              Cancel
            </button>
            <button type="button" className="btn btn-danger" onClick={handleConfirmStop}>
              Stop Monitoring
            </button>
          </>
        }
      >
        <p style={{ margin: 0, color: 'var(--text-secondary)' }}>
          Are you sure you want to stop the live Watchdog observer on{' '}
          <strong style={{ color: 'var(--text-primary)' }}>
            {stopConfirmFolder?.folder_name}
          </strong>{' '}
          (<span className="mono">{stopConfirmFolder?.folder_path}</span>)? New filesystem
          changes will not generate alerts until monitoring is restarted.
        </p>
      </Modal>
    </>
  );
}
