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
  getAnalysts: () => request('/api/auth/analysts'),
  getSummary: () => request('/api/metrics/summary'),
  getKpis: () => request('/api/metrics/kpis'),
  getDetectionQuality: () => request('/api/metrics/detection-quality'),
  getJobMetrics: () => request('/api/metrics/jobs'),
  getScenarioBenchmarks: () => request('/api/metrics/scenario-benchmarks'),
  getCorrelationHotspots: () => request('/api/metrics/correlation-hotspots'),
  getEvents: async () => {
    const response = await request('/api/events')
    return response.items ?? []
  },
  getEvent: (id) => request(`/api/events/${id}`),
  getEventsFiltered: async ({ username, source_ip, event_type, page_size = 20 } = {}) => {
    const params = new URLSearchParams()
    if (username) params.set('username', username)
    if (source_ip) params.set('source_ip', source_ip)
    if (event_type) params.set('event_type', event_type)
    params.set('page_size', String(page_size))
    const response = await request(`/api/events?${params.toString()}`)
    return response.items ?? []
  },
  createEventsBatch: (payload) =>
    request('/api/events/batch', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  getEventScenarios: () => request('/api/events/scenarios'),
  seedScenario: (scenarioKey) =>
    request(`/api/events/scenarios/${scenarioKey}/seed`, {
      method: 'POST',
    }),
  runSimulation: () =>
    request('/api/events/simulations/run', {
      method: 'POST',
    }),
  createEvent: (payload) =>
    request('/api/events', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  getAlerts: async () => {
    const response = await request('/api/alerts')
    return response.items ?? []
  },
  getRelatedAlerts: async (correlationId) => {
    const response = await request(`/api/alerts?correlation_id=${encodeURIComponent(correlationId)}`)
    return response.items ?? []
  },
  getAlert: (id) => request(`/api/alerts/${id}`),
  getAlertNotes: (id) => request(`/api/alerts/${id}/notes`),
  getAlertTimeline: (id) => request(`/api/alerts/${id}/timeline`),
  getAlertAiSummary: (id) => request(`/api/alerts/${id}/ai-summary`),
  getAlertAiTriage: (id) => request(`/api/alerts/${id}/ai-triage`),
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
  assignAlert: (id, analystId) =>
    request(`/api/alerts/${id}/assign`, {
      method: 'PATCH',
      body: JSON.stringify({ analyst_id: analystId }),
    }),
  submitAlertFeedback: (id, payload) =>
    request(`/api/alerts/${id}/feedback`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  getDetections: () => request('/api/detections'),
  getIncidents: async () => {
    const response = await request('/api/incidents')
    return response.items ?? []
  },
  createIncident: (payload) =>
    request('/api/incidents', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  patchIncidentStatus: (id, status) =>
    request(`/api/incidents/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),
  getIncidentAiWrapup: (id) => request(`/api/incidents/${id}/ai-wrapup`),
  getJobs: () => request('/api/jobs'),
  processPendingJobs: () =>
    request('/api/jobs/process-pending', {
      method: 'POST',
    }),
}

export const authStore = {
  getToken,
  setToken: (token) => localStorage.setItem('vanguard_token', token),
  clear: () => localStorage.removeItem('vanguard_token'),
}
