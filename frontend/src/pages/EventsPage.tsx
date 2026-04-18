import { useEffect, useMemo, useState } from 'react';

import { StatePanel } from '../components/common/StatePanel';
import { StatusBadge } from '../components/common/StatusBadge';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import type { EventRecord } from '../types/api';

export function EventsPage() {
  const { token } = useAuth();
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('all');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      if (!token) return;
      setLoading(true);
      try {
        const data = await api.getEvents(token);
        setEvents(data);
      } catch {
        setError('Failed to load events.');
      } finally {
        setLoading(false);
      }
    }
    void load();
  }, [token]);

  const filtered = useMemo(() => {
    return events.filter((event) => {
      const searchText = `${event.event_type} ${event.source_ip} ${event.actor}`.toLowerCase();
      const matchesSearch = searchText.includes(search.toLowerCase());
      const matchesSeverity = severity === 'all' || event.severity.toLowerCase() === severity;
      return matchesSearch && matchesSeverity;
    });
  }, [events, search, severity]);

  if (loading) return <StatePanel title="Loading events" description="Fetching latest telemetry..." />;
  if (error) return <StatePanel title="Event feed unavailable" description={error} tone="error" />;

  return (
    <section>
      <h2 className="text-3xl font-semibold">Events</h2>
      <p className="mt-1 text-sm text-slate-400">Search and filter incoming SOC telemetry.</p>

      <div className="mt-4 flex flex-col gap-3 md:flex-row">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by type, source IP, actor"
          className="flex-1 rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm"
        />
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm"
        >
          <option value="all">All severities</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
      </div>

      <div className="mt-4 rounded-lg border border-slate-800 bg-slate-900 p-4">
        {filtered.length === 0 ? (
          <StatePanel title="No events" description="No events match your current filters." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-slate-400">
                <tr>
                  <th className="pb-2">Type</th>
                  <th className="pb-2">Source IP</th>
                  <th className="pb-2">Actor</th>
                  <th className="pb-2">Severity</th>
                  <th className="pb-2">Time</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((event) => (
                  <tr key={event.id} className="border-t border-slate-800">
                    <td className="py-3">{event.event_type}</td>
                    <td className="py-3">{event.source_ip}</td>
                    <td className="py-3">{event.actor}</td>
                    <td className="py-3">
                      <StatusBadge value={event.severity} variant="severity" />
                    </td>
                    <td className="py-3 text-slate-400">{new Date(event.occurred_at).toLocaleString()}</td>
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
