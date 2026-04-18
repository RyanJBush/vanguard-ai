export type UserRole = 'admin' | 'analyst' | 'viewer';

export interface LoginResponse {
  access_token: string;
  token_type: 'bearer';
  role: UserRole;
}

export interface UserContext {
  id: number;
  username: string;
  role: UserRole;
  organization_id: number;
}

export interface Alert {
  id: number;
  event_id: number;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'resolved';
  created_at: string;
}

export interface EventRecord {
  id: number;
  event_type: string;
  source_ip: string;
  actor: string;
  severity: string;
  occurred_at: string;
}

export interface Detection {
  id: number;
  event_id: number;
  rule_name: string;
  confidence: number;
  created_at: string;
}

export interface InvestigationNote {
  id: number;
  alert_id: number;
  author_id: number;
  note: string;
  created_at: string;
}

export interface SummaryMetrics {
  events_24h: number;
  detections_24h: number;
  alerts_open: number;
  alerts_investigating: number;
  alerts_resolved: number;
}
