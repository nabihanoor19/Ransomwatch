export function formatTimestamp(value) {
  if (!value) return '—';
  const normalized =
    typeof value === 'string' && !value.endsWith('Z') && !value.includes('+')
      ? `${value}Z`
      : value;
  const d = new Date(normalized);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function severityBadgeClass(severity) {
  switch ((severity || '').toUpperCase()) {
    case 'CRITICAL':
      return 'badge badge-critical';
    case 'HIGH':
      return 'badge badge-high';
    case 'MEDIUM':
      return 'badge badge-medium';
    case 'LOW':
      return 'badge badge-low';
    default:
      return 'badge badge-neutral';
  }
}

export function statusBadgeClass(status) {
  switch ((status || '').toLowerCase()) {
    case 'open':
    case 'failure':
      return 'badge badge-critical';
    case 'investigating':
      return 'badge badge-medium';
    case 'resolved':
    case 'active':
    case 'success':
      return 'badge badge-low';
    case 'stopped':
      return 'badge badge-neutral';
    default:
      return 'badge badge-info';
  }
}

export function riskBarColor(score) {
  const num = Number(score) || 0;
  if (num >= 85) return '#ef4444';
  if (num >= 65) return '#f97316';
  if (num >= 35) return '#eab308';
  return '#10b981';
}

export function recommendedActionForSeverity(severity) {
  switch ((severity || '').toUpperCase()) {
    case 'CRITICAL':
      return 'Halt suspicious process immediately, isolate affected sandbox folder, and verify backup integrity before restoring files.';
    case 'HIGH':
      return 'Pause automated workflows in the monitored folder, inspect the process modifying or renaming files, and escalate to incident investigation.';
    case 'MEDIUM':
      return 'Review recent file activity and entropy changes in the timeline; verify whether bulk operations are authorized.';
    default:
      return 'Routine file activity observed; continue passive monitoring.';
  }
}

export const KNOWN_RULE_PRESETS = [
  {
    rule_name: 'entropy_threshold',
    label: 'Shannon Entropy Threshold',
    defaultValue: 7.5,
    description: 'Entropy level (0-8) above which file content is flagged as encrypted/random.',
  },
  {
    rule_name: 'entropy_delta_threshold',
    label: 'Entropy Spike Delta',
    defaultValue: 1.5,
    description: 'Minimum jump in entropy compared to baseline before triggering an alert.',
  },
  {
    rule_name: 'rapid_mod_count',
    label: 'Rapid Modification Count',
    defaultValue: 5,
    description: 'Number of file modifications within the sliding window that triggers rapid-mod rule.',
  },
  {
    rule_name: 'bulk_rename_count',
    label: 'Bulk Rename Count',
    defaultValue: 4,
    description: 'Number of file renames within the sliding window that triggers bulk-rename rule.',
  },
  {
    rule_name: 'mass_delete_count',
    label: 'Mass Deletion Count',
    defaultValue: 5,
    description: 'Number of deletions within the sliding window that triggers mass-delete rule.',
  },
  {
    rule_name: 'window_seconds',
    label: 'Sliding Window (seconds)',
    defaultValue: 10.0,
    description: 'Time window length in seconds used to aggregate rapid file activity.',
  },
];
