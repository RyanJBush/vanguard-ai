import { useEffect, useMemo, useState } from 'react'

import { api } from '../services/api'

export default function EventsPage() {
  const [events, setEvents] = useState([])
  const [query, setQuery] = useState('')

  useEffect(() => {
    api.getEvents().then(setEvents).catch(() => null)
  }, [])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return events
    return events.filter((event) => `${event.event_type} ${event.username ?? ''} ${event.source_ip ?? ''}`.toLowerCase().includes(q))
  }, [events, query])

  return (
    <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-semibold">Event Stream</h2>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search by event, user, or IP"
          className="w-full max-w-sm rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
        />
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead className="text-slate-400">
            <tr>
              <th className="pb-2">Time</th>
              <th className="pb-2">Type</th>
              <th className="pb-2">User</th>
              <th className="pb-2">Source IP</th>
              <th className="pb-2">Message</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((event) => (
              <tr key={event.id} className="border-t border-slate-800">
                <td className="py-2 pr-4 text-slate-300">{new Date(event.occurred_at).toLocaleString()}</td>
                <td className="py-2 pr-4">{event.event_type}</td>
                <td className="py-2 pr-4">{event.username ?? '-'}</td>
                <td className="py-2 pr-4">{event.source_ip ?? '-'}</td>
                <td className="py-2 text-slate-400">{event.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
