const API = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

async function request(path, options = {}) {
  const headers =
    options.body instanceof FormData
      ? {}
      : { 'Content-Type': 'application/json' };

  const token = localStorage.getItem('pg_token');

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      ...headers,
      ...(options.headers || {}),
    },
  });

  const data = await res
    .json()
    .catch(() => ({ message: 'Unexpected server response' }));

  if (!res.ok) {
    throw new Error(data.message || 'Request failed');
  }

  return data;
}

export const api = {
  // Authentication
  login: (payload) =>
    request('/auth/login', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  register: (payload) =>
    request('/auth/register', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  me: () => request('/auth/me'),

  // Dashboard
  dashboard: () => request('/dashboard'),

  // History
  scans: () => request('/scans'),

  // Full details of one scan
  scan: (id) => request(`/scans/${id}`),

  // Analysis
  analyzeText: (payload) =>
    request('/analyze', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  analyzeFile: (file) => {
    const fd = new FormData();
    fd.append('file', file);

    return request('/analyze', {
      method: 'POST',
      body: fd,
    });
  },

  // Sanitization
  sanitize: (id, mode) =>
    request(`/scans/${id}/sanitize`, {
      method: 'POST',
      body: JSON.stringify({ mode }),
    }),

  // Audit
  audit: () => request('/audit'),

  // Download PDF report
  downloadReport: async (id, filename) => {
    const token = localStorage.getItem('pg_token');

    const res = await fetch(`${API}/scans/${id}/report`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!res.ok) {
      const data = await res
        .json()
        .catch(() => ({ message: 'Failed to download report' }));

      throw new Error(data.message || 'Failed to download report');
    }

    const blob = await res.blob();

    const url = window.URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = url;
    link.download = filename || `privacyguard-scan-${id}.pdf`;

    document.body.appendChild(link);
    link.click();
    link.remove();

    window.URL.revokeObjectURL(url);
  },
};