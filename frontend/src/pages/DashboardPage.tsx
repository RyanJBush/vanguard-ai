import { useEffect, useMemo, useState } from 'react';
import {
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { StatePanel } from '../components/common/StatePanel';
import { StatusBadge } from '../components/common/StatusBadge';
import { KpiCard } from '../components/dashboard/KpiCard';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import type { Alert, EventRecord, SummaryMetrics } from '../types/api';

const SEVERITY_COLORS: Record<string, string> = {
  low: '#94a3b8',
  medium: '#f59e0b',
  high: '#f97316',
  critical: '#ef4444',
};

export function DashboardPage() {
  const { token } = useAuth();
  const [metrics, setMetrics] = useState<SummaryMetrics | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      if (!token) return;
      setLoading(true);
      setError(null);
      try {
        const [summary, alertsData, eventsData] = await Promise.all([
          api.getMetrics(token),
          api.getAlerts(token),
          api.getEvents(token),
        ]);
        setMetrics(summary);
        setAlerts(alertsData);
        setEvents(eventsData);
      } catch {
        setError('Unable to load dashboard data.');
      } finally {
        setLoading(false);
      }
    }

    void load();
  }, [token]);

  const alertTrend = useMemo(() => {
    const byDay = new Map<string, number>();
    alerts.forEach((alert) => {
      const day = new Date(alert.created_at).toISOString().slice(0, 10);
      byDay.set(day, (byDay.get(day) ?? 0) + 1);
    });
    return Array.from(byDay.entries())
      .map(([day, count]) => ({ day, count }))
      .sort((a, b) => a.day.localeCompare(b.day))
      .slice(-7);
  }, [alerts]);

  const severityDistribution = useMemo(() => {
    const buckets: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
    alerts.forEach((alert) => {
      buckets[alert.severity] = (buckets[alert.severity] ?? 0) + 1;
    });
    return Object.entries(buckets)
      .filter(([, value]) => value > 0)
      .map(([name, value]) => ({ name, value }));
  }, [alerts]);

  const recentAlerts = alerts.slice(0, 6);
  const highSeverityCount = alerts.filter((alert) => ['high', 'critical'].includes(alert.severity)).length;
  const mttd = alerts.length > 0 ? `${(events.length / alerts.length).toFixed(1)} min` : 'N/A';

  if (loading) return <StatePanel title="Loading dashboard" description="Pulling SOC telemetry and alerts..." />;
  if (error) return <StatePanel title="Dashboard error" description={error} tone="error" />;
  if (!metrics) return <StatePanel title="No metrics" description="Metrics are unavailable." />;

  return (
    <section>
      <div className="mb-6">
        <h2 className="text-3xl font-semibold">SOC Dashboard</h2>
        <p className="mt-1 text-sm text-slate-400">Operational snapshot for triage and investigation priorities.</p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <KpiCard title="Open Alerts" value={String(metrics.alerts_open)} context="Require active triage" />
        <KpiCard title="Event Volume (24h)" value={String(metrics.events_24h)} context="Ingestion throughput" />
        <KpiCard title="High Severity Alerts" value={String(highSeverityCount)} context="High + critical" />
        <KpiCard title="Mean Time to Detect" value={mttd} context="Illustrative KPI" />
      </div>

      <div className="mt-6 grid gap-4 xl:grid-cols-2">
        <div className="h-72 rounded-lg border border-slate-800 bg-slate-900 p-4">
          <h3 className="mb-3 text-sm font-semibold text-slate-300">Alert Trend (7 days)</h3>
          <ResponsiveContainer width="100%" height="90%">
            <LineChart data={alertTrend}>
              <XAxis dataKey="day" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" allowDecimals={false} />
              <Tooltip />
              <Line type="monotone" dataKey="count" stroke="#22d3ee" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="h-72 rounded-lg border border-slate-800 bg-slate-900 p-4">
          <h3 className="mb-3 text-sm font-semibold text-slate-300">Severity Distribution</h3>
          <ResponsiveContainer width="100%" height="90%">
            <PieChart>
              <Pie data={severityDistribution} dataKey="value" nameKey="name" outerRadius={90}>
                {severityDistribution.map((entry) => (
                  <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="mt-6 rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h3 className="mb-3 text-sm font-semibold text-slate-300">Recent Alerts</h3>
        {recentAlerts.length === 0 ? (
          <StatePanel title="No alerts" description="No alerts generated yet." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-slate-400">
                <tr>
                  <th className="pb-2">Alert</th>
                  <th className="pb-2">Severity</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2">Created</th>
                </tr>
              </thead>
              <tbody>
                {recentAlerts.map((alert) => (
                  <tr key={alert.id} className="border-t border-slate-800">
                    <td className="py-3">{alert.title}</td>
                    <td className="py-3">
                      <StatusBadge value={alert.severity} variant="severity" />
                    </td>
                    <td className="py-3">
                      <StatusBadge value={alert.status} variant="status" />
                    </td>
                    <td className="py-3 text-slate-400">
                      {new Date(alert.created_at).toLocaleString()}
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
