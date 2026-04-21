const API_BASE = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'

function getToken() {
  return localStorage.getItem('vanguard_token')
}

function authHeaders() {
  const token = getToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(),
      ...(options.headers ?? {}),
    },
    ...options,
  })

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}))
    throw new Error(errorBody.detail ?? `Request failed: ${response.status}`)
  }

  return response.json()
}

export const api = {
  login: (username, password) =>
    request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  me: () => request('/api/auth/me'),
  getSummary: () => request('/api/metrics/summary'),
  getKpis: () => request('/api/metrics/kpis'),
  getDetectionQuality: () => request('/api/metrics/detection-quality'),
  getJobMetrics: () => request('/api/metrics/jobs'),
  getScenarioBenchmarks: () => request('/api/metrics/scenario-benchmarks'),
  getEvents: async () => {
    const response = await request('/api/events')
    return response.items ?? []
  },
  createEvent: (payload) =>
    request('/api/events', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  getAlerts: async () => {
    const response = await request('/api/alerts')
    return response.items ?? []
  },
  getAlert: (id) => request(`/api/alerts/${id}`),
  getAlertNotes: (id) => request(`/api/alerts/${id}/notes`),
  createAlertNote: (id, note) =>
    request(`/api/alerts/${id}/notes`, {
      method: 'POST',
      body: JSON.stringify({ note }),
    }),
  patchAlertStatus: (id, status) =>
    request(`/api/alerts/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),
  getDetections: () => request('/api/detections'),
}

export const authStore = {
  getToken,
  setToken: (token) => localStorage.setItem('vanguard_token', token),
  clear: () => localStorage.removeItem('vanguard_token'),
}
