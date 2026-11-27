import axios from 'axios';

export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

const TOKEN_KEY = 'ransomwatch_access_token';

export function getStoredToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setStoredToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearStoredToken() {
  localStorage.removeItem(TOKEN_KEY);
}

export function extractErrorMessage(err, fallback = 'An unexpected error occurred.') {
  const data = err?.response?.data;
  if (!data) {
    if (err?.code === 'ERR_NETWORK') {
      return `Cannot reach backend at ${API_BASE_URL}. Make sure FastAPI is running.`;
    }
    return err?.message || fallback;
  }

  if (typeof data.detail === 'string') {
    return data.detail;
  }

  if (Array.isArray(data.detail) && data.detail.length > 0) {
    return data.detail
      .map((item) => {
        const loc = Array.isArray(item.loc) ? item.loc.slice(1).join('.') : '';
        return loc ? `${loc}: ${item.msg}` : item.msg;
      })
      .join('; ');
  }

  if (typeof data.message === 'string') {
    return data.message;
  }

  return fallback;
}

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
});

apiClient.interceptors.request.use((config) => {
  const token = getStoredToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error?.response?.status;
    const url = error?.config?.url || '';
    const isAuthAttempt =
      url.includes('/auth/login') || url.includes('/auth/register');

    if (status === 401 && !isAuthAttempt) {
      clearStoredToken();
      window.dispatchEvent(new CustomEvent('ransomwatch:unauthorized'));
    }
    return Promise.reject(error);
  }
);

export default apiClient;
