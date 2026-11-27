import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  FileSearch,
  Plus,
  RefreshCw,
  Save,
  Sliders,
  Users,
} from 'lucide-react';
import { adminApi } from '../api/services';
import { extractErrorMessage } from '../api/client';
import { useAuth } from '../context/AuthContext';
import {
  formatTimestamp,
  KNOWN_RULE_PRESETS,
  statusBadgeClass,
} from '../utils/formatters';
import Modal from '../components/Modal';

export default function AdminPage() {
  const { user: currentUser } = useAuth();
  const [activeTab, setActiveTab] = useState('users');

  const [users, setUsers] = useState([]);
  const [configs, setConfigs] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);

  const [draftValues, setDraftValues] = useState({});
  const [draftEnabled, setDraftEnabled] = useState({});
  const [newRuleName, setNewRuleName] = useState('');
  const [newRuleValue, setNewRuleValue] = useState('');

  const [loading, setLoading] = useState(true);
  const [savingRule, setSavingRule] = useState('');
  const [confirmUserAction, setConfirmUserAction] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const loadAdminData = useCallback(async () => {
    setLoading(true);
    try {
      const [usersRes, configsRes, logsRes] = await Promise.all([
        adminApi.listUsers(0, 100),
        adminApi.listConfigurations(),
        adminApi.listAuditLogs(0, 100),
      ]);
      setUsers(usersRes);
      setConfigs(configsRes);
      setAuditLogs(logsRes);

      const vals = {};
      const enabled = {};
      for (const preset of KNOWN_RULE_PRESETS) {
        vals[preset.rule_name] = String(preset.defaultValue);
        enabled[preset.rule_name] = true;
      }
      for (const cfg of configsRes) {
        vals[cfg.rule_name] = String(cfg.value ?? '');
        enabled[cfg.rule_name] = Boolean(cfg.is_enabled);
      }
      setDraftValues(vals);
      setDraftEnabled(enabled);
      setError('');
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to load administration data.'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAdminData();
  }, [loadAdminData]);

  const executeUserUpdate = async (targetUser, payload) => {
    setError('');
    setNotice('');
    try {
      const updated = await adminApi.updateUser(targetUser.id, payload);
      setUsers((prev) => prev.map((u) => (u.id === updated.id ? updated : u)));
      setNotice(`Updated account "${updated.username}".`);
      const logsRes = await adminApi.listAuditLogs(0, 100);
      setAuditLogs(logsRes);
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to update user.'));
    }
  };

  const handleSaveRule = async (ruleName) => {
    setError('');
    setNotice('');
    const rawVal = draftValues[ruleName];
    const parsedNum = Number(rawVal);
    const valueToSave =
      rawVal !== '' && !Number.isNaN(parsedNum) ? parsedNum : rawVal;

    setSavingRule(ruleName);
    try {
      await adminApi.updateConfiguration(ruleName, {
        value: valueToSave,
        is_enabled: Boolean(draftEnabled[ruleName]),
      });
      setNotice(`Saved configuration rule "${ruleName}".`);
      await loadAdminData();
    } catch (err) {
      setError(extractErrorMessage(err, `Failed to update rule "${ruleName}".`));
    } finally {
      setSavingRule('');
    }
  };

  const handleCreateCustomRule = async (e) => {
    e.preventDefault();
    const trimmedName = newRuleName.trim();
    if (!trimmedName || newRuleValue === '') return;

    setError('');
    setNotice('');
    const parsedNum = Number(newRuleValue);
    const valueToSave = !Number.isNaN(parsedNum) ? parsedNum : newRuleValue;
    setSavingRule('custom');
    try {
      await adminApi.updateConfiguration(trimmedName, {
        value: valueToSave,
        is_enabled: true,
      });
      setNewRuleName('');
      setNewRuleValue('');
      setNotice(`Rule "${trimmedName}" created/updated.`);
      await loadAdminData();
    } catch (err) {
      setError(extractErrorMessage(err, 'Failed to save custom configuration.'));
    } finally {
      setSavingRule('');
    }
  };

  const configByName = Object.fromEntries(configs.map((c) => [c.rule_name, c]));
  const presetNames = new Set(KNOWN_RULE_PRESETS.map((p) => p.rule_name));
  const extraConfigs = configs.filter((c) => !presetNames.has(c.rule_name));

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">Administrator Console</h1>
          <p className="page-subtitle">
            Manage RBAC user accounts, tune detection rule thresholds, and inspect the append-only audit trail.
          </p>
        </div>

        <button type="button" className="btn btn-secondary btn-sm" onClick={loadAdminData}>
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

      <div className="tabs">
        <button
          type="button"
          className={`tab-btn ${activeTab === 'users' ? 'active' : ''}`}
          onClick={() => setActiveTab('users')}
        >
          <Users size={16} />
          User Management ({users.length})
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'configs' ? 'active' : ''}`}
          onClick={() => setActiveTab('configs')}
        >
          <Sliders size={16} />
          Detection Thresholds ({configs.length || KNOWN_RULE_PRESETS.length})
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'audit' ? 'active' : ''}`}
          onClick={() => setActiveTab('audit')}
        >
          <FileSearch size={16} />
          Audit Logs ({auditLogs.length})
        </button>
      </div>

      {activeTab === 'users' && (
        <section className="card">
          {users.length === 0 ? (
            <div className="empty-state">
              {loading ? 'Loading registered users...' : 'No users found.'}
            </div>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => {
                    const isSelf = u.id === currentUser?.id;
                    return (
                      <tr key={u.id}>
                        <td className="mono">#{u.id}</td>
                        <td style={{ fontWeight: 600 }}>
                          {u.username}{' '}
                          {isSelf && (
                            <span className="badge badge-info" style={{ marginLeft: 4 }}>
                              You
                            </span>
                          )}
                        </td>
                        <td style={{ color: 'var(--text-secondary)' }}>{u.email}</td>
                        <td>
                          <select
                            aria-label={`Role for ${u.username}`}
                            className="select"
                            style={{ width: 130 }}
                            value={u.role}
                            onChange={(e) =>
                              setConfirmUserAction({
                                user: u,
                                payload: { role: e.target.value },
                                description: `Change "${u.username}" role from "${u.role}" to "${e.target.value}"?`,
                              })
                            }
                          >
                            <option value="operator">operator</option>
                            <option value="admin">admin</option>
                          </select>
                        </td>
                        <td>
                          <span className={`badge ${u.is_active ? 'badge-low' : 'badge-critical'}`}>
                            {u.is_active ? 'Active' : 'Disabled'}
                          </span>
                        </td>
                        <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                          {formatTimestamp(u.created_at)}
                        </td>
                        <td>
                          <button
                            type="button"
                            className={`btn btn-sm ${
                              u.is_active ? 'btn-danger' : 'btn-success'
                            }`}
                            disabled={isSelf && u.is_active}
                            title={
                              isSelf && u.is_active
                                ? 'Administrators cannot deactivate their own account'
                                : ''
                            }
                            onClick={() =>
                              setConfirmUserAction({
                                user: u,
                                payload: { is_active: !u.is_active },
                                description: u.is_active
                                  ? `Deactivate account "${u.username}"? They will lose API access immediately.`
                                  : `Re-activate account "${u.username}"?`,
                              })
                            }
                          >
                            {u.is_active ? 'Deactivate' : 'Activate'}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {activeTab === 'configs' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <section className="card">
            <div className="card-header">
              <h2 className="card-title">Rule Engine Thresholds</h2>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Changes apply dynamically and are audit-logged
              </span>
            </div>

            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Description</th>
                    <th>Threshold Value</th>
                    <th>Enabled</th>
                    <th>Last Updated</th>
                    <th>Save</th>
                  </tr>
                </thead>
                <tbody>
                  {KNOWN_RULE_PRESETS.map((preset) => {
                    const saved = configByName[preset.rule_name];
                    return (
                      <tr key={preset.rule_name}>
                        <td>
                          <div style={{ fontWeight: 600 }}>{preset.label}</div>
                          <div className="mono" style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                            {preset.rule_name}
                          </div>
                        </td>
                        <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', maxWidth: 300 }}>
                          {preset.description}
                        </td>
                        <td style={{ width: 130 }}>
                          <input
                            type="number"
                            step="any"
                            className="input mono"
                            value={draftValues[preset.rule_name] ?? ''}
                            onChange={(e) =>
                              setDraftValues((prev) => ({
                                ...prev,
                                [preset.rule_name]: e.target.value,
                              }))
                            }
                          />
                        </td>
                        <td>
                          <input
                            type="checkbox"
                            checked={Boolean(draftEnabled[preset.rule_name])}
                            onChange={(e) =>
                              setDraftEnabled((prev) => ({
                                ...prev,
                                [preset.rule_name]: e.target.checked,
                              }))
                            }
                          />
                        </td>
                        <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                          {saved ? formatTimestamp(saved.updated_at) : 'Default (not persisted)'}
                        </td>
                        <td>
                          <button
                            type="button"
                            className="btn btn-primary btn-sm"
                            disabled={savingRule === preset.rule_name}
                            onClick={() => handleSaveRule(preset.rule_name)}
                          >
                            <Save size={14} />
                            {savingRule === preset.rule_name ? 'Saving...' : 'Save'}
                          </button>
                        </td>
                      </tr>
                    );
                  })}

                  {extraConfigs.map((cfg) => (
                    <tr key={cfg.rule_name}>
                      <td>
                        <div className="mono" style={{ fontWeight: 600 }}>
                          {cfg.rule_name}
                        </div>
                      </td>
                      <td style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                        Custom rule configuration
                      </td>
                      <td style={{ width: 130 }}>
                        <input
                          type="text"
                          className="input mono"
                          value={draftValues[cfg.rule_name] ?? ''}
                          onChange={(e) =>
                            setDraftValues((prev) => ({
                              ...prev,
                              [cfg.rule_name]: e.target.value,
                            }))
                          }
                        />
                      </td>
                      <td>
                        <input
                          type="checkbox"
                          checked={Boolean(draftEnabled[cfg.rule_name])}
                          onChange={(e) =>
                            setDraftEnabled((prev) => ({
                              ...prev,
                              [cfg.rule_name]: e.target.checked,
                            }))
                          }
                        />
                      </td>
                      <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                        {formatTimestamp(cfg.updated_at)}
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn btn-primary btn-sm"
                          disabled={savingRule === cfg.rule_name}
                          onClick={() => handleSaveRule(cfg.rule_name)}
                        >
                          <Save size={14} />
                          Save
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="card">
            <div className="card-header">
              <h2 className="card-title">Add / Override Custom Rule</h2>
            </div>
            <form onSubmit={handleCreateCustomRule} className="filter-bar">
              <div className="form-group filter-item">
                <label className="form-label" htmlFor="new-rule-name">
                  Rule Name
                </label>
                <input
                  id="new-rule-name"
                  className="input mono"
                  placeholder="custom_threshold"
                  value={newRuleName}
                  onChange={(e) => setNewRuleName(e.target.value)}
                  required
                />
              </div>
              <div className="form-group filter-item">
                <label className="form-label" htmlFor="new-rule-value">
                  Value
                </label>
                <input
                  id="new-rule-value"
                  className="input mono"
                  placeholder="10"
                  value={newRuleValue}
                  onChange={(e) => setNewRuleValue(e.target.value)}
                  required
                />
              </div>
              <button
                type="submit"
                className="btn btn-secondary"
                disabled={savingRule === 'custom'}
              >
                <Plus size={15} />
                Save Rule
              </button>
            </form>
          </section>
        </div>
      )}

      {activeTab === 'audit' && (
        <section className="card">
          <div className="card-header">
            <h2 className="card-title">Append-Only Security Audit Trail</h2>
            <span className="badge badge-neutral">Read-Only</span>
          </div>

          {auditLogs.length === 0 ? (
            <div className="empty-state">
              {loading ? 'Loading audit logs...' : 'No audit entries recorded yet.'}
            </div>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Action</th>
                    <th>User ID</th>
                    <th>Resource</th>
                    <th>Status</th>
                    <th>Details (Redacted)</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.map((log) => (
                    <tr key={log.id}>
                      <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                        {formatTimestamp(log.timestamp)}
                      </td>
                      <td className="mono" style={{ fontWeight: 600, fontSize: '0.82rem' }}>
                        {log.action}
                      </td>
                      <td className="mono">{log.user_id ?? 'system'}</td>
                      <td style={{ fontSize: '0.82rem' }}>
                        {log.resource_type || '—'}
                        {log.resource_id ? ` #${log.resource_id}` : ''}
                      </td>
                      <td>
                        <span className={statusBadgeClass(log.status)}>{log.status}</span>
                      </td>
                      <td
                        className="mono"
                        style={{
                          fontSize: '0.76rem',
                          color: 'var(--text-secondary)',
                          maxWidth: 340,
                          wordBreak: 'break-word',
                        }}
                      >
                        {JSON.stringify(log.details || {})}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      <Modal
        open={Boolean(confirmUserAction)}
        title="Confirm User Account Change"
        onClose={() => setConfirmUserAction(null)}
        footer={
          <>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setConfirmUserAction(null)}
            >
              Cancel
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => {
                const action = confirmUserAction;
                setConfirmUserAction(null);
                if (action) executeUserUpdate(action.user, action.payload);
              }}
            >
              Confirm Change
            </button>
          </>
        }
      >
        <p style={{ margin: 0, color: 'var(--text-secondary)' }}>
          {confirmUserAction?.description}
        </p>
      </Modal>
    </>
  );
}
