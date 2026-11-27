import apiClient from './client';

export const authApi = {
  async login(identifier, password) {
    const formData = new URLSearchParams();
    formData.append('username', identifier);
    formData.append('password', password);

    const { data } = await apiClient.post('/auth/login', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return data;
  },

  async register({ username, email, password }) {
    const { data } = await apiClient.post('/auth/register', {
      username,
      email,
      password,
    });
    return data;
  },

  async me() {
    const { data } = await apiClient.get('/auth/me');
    return data;
  },

  async logout() {
    const { data } = await apiClient.post('/auth/logout');
    return data;
  },
};

export const dashboardApi = {
  async getHealth() {
    const { data } = await apiClient.get('/health');
    return data;
  },

  async getStats() {
    const { data } = await apiClient.get('/dashboard/stats');
    return data;
  },

  async getRecentEvents(limit = 10) {
    const { data } = await apiClient.get('/dashboard/recent-events', {
      params: { limit },
    });
    return data;
  },

  async getSeverity() {
    const { data } = await apiClient.get('/dashboard/severity');
    return data;
  },
};

export const monitorApi = {
  async listFolders(skip = 0, limit = 50) {
    const { data } = await apiClient.get('/monitor/folders', {
      params: { skip, limit },
    });
    return data;
  },

  async registerFolder({ folder_path, folder_name }) {
    const { data } = await apiClient.post('/monitor/folders', {
      folder_path,
      folder_name,
    });
    return data;
  },

  async startMonitoring(folderId) {
    const { data } = await apiClient.post(`/monitor/start/${folderId}`);
    return data;
  },

  async stopMonitoring(folderId) {
    const { data } = await apiClient.post(`/monitor/stop/${folderId}`);
    return data;
  },

  async getStatus(folderId) {
    const { data } = await apiClient.get(`/monitor/status/${folderId}`);
    return data;
  },

  async scanCanaries(folderId) {
    const { data } = await apiClient.post(`/monitor/scan/${folderId}`);
    return data;
  },
};

export const eventsApi = {
  async listEvents(params = {}) {
    const cleanParams = Object.fromEntries(
      Object.entries(params).filter(([, v]) => v !== '' && v !== null && v !== undefined)
    );
    const { data } = await apiClient.get('/events', { params: cleanParams });
    return data;
  },

  async getEvent(eventId) {
    const { data } = await apiClient.get(`/events/${eventId}`);
    return data;
  },
};

export const incidentsApi = {
  async listIncidents(params = {}) {
    const cleanParams = Object.fromEntries(
      Object.entries(params).filter(([, v]) => v !== '' && v !== null && v !== undefined)
    );
    const { data } = await apiClient.get('/incidents', { params: cleanParams });
    return data;
  },

  async getIncident(incidentId) {
    const { data } = await apiClient.get(`/incidents/${incidentId}`);
    return data;
  },

  async updateStatus(incidentId, status) {
    const { data } = await apiClient.patch(`/incidents/${incidentId}`, { status });
    return data;
  },
};

export const reportsApi = {
  async exportJson() {
    const { data } = await apiClient.get('/reports/export', {
      params: { format: 'json' },
    });
    return data;
  },

  async exportCsvBlob() {
    const response = await apiClient.get('/reports/export', {
      params: { format: 'csv' },
      responseType: 'blob',
    });
    const disposition = response.headers['content-disposition'] || '';
    const match = disposition.match(/filename=([^;]+)/i);
    const filename = match ? match[1].replace(/["']/g, '') : 'ransomwatch_report.csv';
    return { blob: response.data, filename };
  },
};

export const adminApi = {
  async listUsers(skip = 0, limit = 100) {
    const { data } = await apiClient.get('/admin/users', {
      params: { skip, limit },
    });
    return data;
  },

  async updateUser(userId, payload) {
    const { data } = await apiClient.patch(`/admin/users/${userId}`, payload);
    return data;
  },

  async listConfigurations() {
    const { data } = await apiClient.get('/admin/configurations');
    return data;
  },

  async updateConfiguration(ruleName, payload) {
    const { data } = await apiClient.patch(
      `/admin/configurations/${encodeURIComponent(ruleName)}`,
      payload
    );
    return data;
  },

  async listAuditLogs(skip = 0, limit = 100) {
    const { data } = await apiClient.get('/admin/audit-logs', {
      params: { skip, limit },
    });
    return data;
  },
};
