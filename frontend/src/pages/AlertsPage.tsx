import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import { StatePanel } from '../components/common/StatePanel';
import { StatusBadge } from '../components/common/StatusBadge';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import type { Alert } from '../types/api';

export function AlertsPage() {
  const { token, user } = useAuth();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    if (!token) return;
    setLoading(true);
    try {
      const data = await api.getAlerts(token);
      setAlerts(data);
    } catch {
      setError('Unable to load alerts.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, [token]);

  async function handleStatusChange(alertId: number, nextStatus: string) {
    if (!token) return;
    await api.updateAlertStatus(token, alertId, nextStatus);
    await refresh();
  }

  const filtered = useMemo(
    () =>
      alerts.filter((alert) => {
        const severityOk = severityFilter === 'all' || alert.severity === severityFilter;
        const statusOk = statusFilter === 'all' || alert.status === statusFilter;
        return severityOk && statusOk;
      }),
    [alerts, severityFilter, statusFilter],
  );

  if (loading) return <StatePanel title="Loading alerts" description="Retrieving active detection outcomes..." />;
  if (error) return <StatePanel title="Alert feed unavailable" description={error} tone="error" />;

  return (
    <section>
      <h2 className="text-3xl font-semibold">Alerts</h2>
      <p className="mt-1 text-sm text-slate-400">Prioritize and triage detections by severity and status.</p>

      <div className="mt-4 flex flex-wrap gap-3">
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm"
        >
          <option value="all">All severities</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm"
        >
          <option value="all">All statuses</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
        </select>
      </div>

      <div className="mt-4 rounded-lg border border-slate-800 bg-slate-900 p-4">
        {filtered.length === 0 ? (
          <StatePanel title="No alerts" description="No alerts match this filter set." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-slate-400">
                <tr>
                  <th className="pb-2">Alert</th>
                  <th className="pb-2">Severity</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2">Created</th>
                  <th className="pb-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((alert) => (
                  <tr key={alert.id} className="border-t border-slate-800">
                    <td className="py-3">
                      <Link className="text-cyan-300 hover:underline" to={`/alerts/${alert.id}`}>
                        {alert.title}
                      </Link>
                    </td>
                    <td className="py-3">
                      <StatusBadge value={alert.severity} variant="severity" />
                    </td>
                    <td className="py-3">
                      <StatusBadge value={alert.status} variant="status" />
                    </td>
                    <td className="py-3 text-slate-400">{new Date(alert.created_at).toLocaleString()}</td>
                    <td className="py-3">
                      {user?.role === 'viewer' ? (
                        <span className="text-xs text-slate-500">Read-only</span>
                      ) : (
                        <select
                          value={alert.status}
                          onChange={(event) => void handleStatusChange(alert.id, event.target.value)}
                          className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs"
                        >
                          <option value="open">Open</option>
                          <option value="investigating">Investigating</option>
                          <option value="resolved">Resolved</option>
                        </select>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
