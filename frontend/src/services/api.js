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
  getEvents: () => request('/api/events'),
  createEvent: (payload) =>
    request('/api/events', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  getAlerts: () => request('/api/alerts'),
  getAlert: (id) => request(`/api/alerts/${id}`),
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
