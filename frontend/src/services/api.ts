import type {
  Alert,
  Detection,
  EventRecord,
  InvestigationNote,
  LoginResponse,
  SummaryMetrics,
  UserContext,
} from '../types/api';
import { apiRequest } from './apiClient';

export const api = {
  login: (username: string, password: string) =>
    apiRequest<LoginResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  me: (token: string) => apiRequest<UserContext>('/auth/me', {}, token),
  getMetrics: (token: string) => apiRequest<SummaryMetrics>('/metrics/summary', {}, token),
  getEvents: (token: string) => apiRequest<EventRecord[]>('/events', {}, token),
  getAlerts: (token: string) => apiRequest<Alert[]>('/alerts', {}, token),
  getAlert: (token: string, id: string) => apiRequest<Alert>(`/alerts/${id}`, {}, token),
  updateAlertStatus: (token: string, id: number, status: string) =>
    apiRequest<Alert>(
      `/alerts/${id}/status`,
      {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      },
      token,
    ),
  getDetections: (token: string) => apiRequest<Detection[]>('/detections', {}, token),
  getNotes: (token: string, alertId: string) =>
    apiRequest<InvestigationNote[]>(`/alerts/${alertId}/notes`, {}, token),
  createNote: (token: string, alertId: string, note: string) =>
    apiRequest<InvestigationNote>(
      `/alerts/${alertId}/notes`,
      {
        method: 'POST',
        body: JSON.stringify({ note }),
      },
      token,
    ),
};
