import { useEffect, useMemo, useState } from 'react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

import { api } from '../services/api'

function Kpi({ label, value }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
      <p className="text-xs uppercase tracking-wide text-slate-400">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-slate-50">{value}</p>
    </div>
  )
}

export default function DashboardPage() {
  const [summary, setSummary] = useState(null)
  const [alerts, setAlerts] = useState([])

  useEffect(() => {
    api.getSummary().then(setSummary).catch(() => null)
    api.getAlerts().then(setAlerts).catch(() => null)
  }, [])

  const chartData = useMemo(() => {
    const counts = alerts.reduce((acc, alert) => {
      acc[alert.severity] = (acc[alert.severity] ?? 0) + 1
      return acc
    }, {})
    return ['critical', 'high', 'medium', 'low'].map((severity) => ({
      severity,
      count: counts[severity] ?? 0,
    }))
  }, [alerts])

  return (
    <div className="space-y-6">
      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <Kpi label="Total Events" value={summary?.total_events ?? '-'} />
        <Kpi label="Total Alerts" value={summary?.total_alerts ?? '-'} />
        <Kpi label="Open Alerts" value={summary?.open_alerts ?? '-'} />
        <Kpi label="High Severity" value={summary?.high_severity_alerts ?? '-'} />
        <Kpi label="Detection Coverage" value={`${summary?.detection_coverage ?? 0}%`} />
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <h2 className="mb-4 text-lg font-semibold">Alert Severity Distribution</h2>
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="severity" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="count" fill="#22d3ee" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>
    </div>
  )
}
