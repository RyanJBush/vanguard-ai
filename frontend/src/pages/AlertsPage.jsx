import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'

import StatusBadge from '../components/StatusBadge'
import { api } from '../services/api'

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([])
  const [status, setStatus] = useState('all')

  useEffect(() => {
    api.getAlerts().then(setAlerts).catch(() => null)
  }, [])

  const filtered = useMemo(() => {
    if (status === 'all') return alerts
    return alerts.filter((alert) => alert.status === status)
  }, [alerts, status])

  return (
    <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900 p-5">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-lg font-semibold">Alerts</h2>
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
        >
          <option value="all">All statuses</option>
          <option value="open">Open</option>
          <option value="in_progress">In Progress</option>
          <option value="resolved">Resolved</option>
          <option value="dismissed">Dismissed</option>
        </select>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead className="text-slate-400">
            <tr>
              <th className="pb-2">Title</th>
              <th className="pb-2">Severity</th>
              <th className="pb-2">Status</th>
              <th className="pb-2">Confidence</th>
              <th className="pb-2">Action</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((alert) => (
              <tr key={alert.id} className="border-t border-slate-800">
                <td className="py-2 pr-4">{alert.title}</td>
                <td className="py-2 pr-4"><StatusBadge value={alert.severity} /></td>
                <td className="py-2 pr-4"><StatusBadge value={alert.status} /></td>
                <td className="py-2 pr-4">{Math.round(alert.confidence_score * 100)}%</td>
                <td className="py-2">
                  <Link className="text-cyan-300 hover:text-cyan-200" to={`/alerts/${alert.id}`}>
                    Investigate
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
