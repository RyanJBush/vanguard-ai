import { useEffect, useMemo, useState } from 'react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

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
  const [kpis, setKpis] = useState(null)
  const [quality, setQuality] = useState(null)
  const [jobMetrics, setJobMetrics] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [incidents, setIncidents] = useState([])

  useEffect(() => {
    api.getSummary().then(setSummary).catch(() => null)
    api.getKpis().then(setKpis).catch(() => null)
    api.getDetectionQuality().then(setQuality).catch(() => null)
    api.getJobMetrics().then(setJobMetrics).catch(() => null)
    api.getAlerts().then(setAlerts).catch(() => null)
    api.getIncidents().then(setIncidents).catch(() => null)
  }, [])

  const alertsBySeverity = useMemo(() => {
    const counts = alerts.reduce((acc, alert) => {
      acc[alert.severity] = (acc[alert.severity] ?? 0) + 1
      return acc
    }, {})
    return ['critical', 'high', 'medium', 'low'].map((severity) => ({
      severity,
      count: counts[severity] ?? 0,
    }))
  }, [alerts])

  const alertsByType = useMemo(() => {
    const counts = alerts.reduce((acc, alert) => {
      const key = (alert.correlation_id || 'unknown').split(':')[0]
      acc[key] = (acc[key] ?? 0) + 1
      return acc
    }, {})

    return Object.entries(counts)
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8)
  }, [alerts])

  const alertsOverTime = useMemo(() => {
    const bucket = alerts.reduce((acc, alert) => {
      const dateKey = new Date(alert.created_at).toISOString().slice(0, 10)
      acc[dateKey] = (acc[dateKey] ?? 0) + 1
      return acc
    }, {})

    return Object.entries(bucket)
      .map(([day, count]) => ({ day, count }))
      .sort((a, b) => a.day.localeCompare(b.day))
      .slice(-10)
  }, [alerts])

  const criticalAlerts = alerts.filter((alert) => alert.severity === 'critical').length
  const activeIncidents = incidents.filter((incident) => incident.status !== 'closed').length
  const alertQueue = alerts.slice(0, 8)
  const incidentQueue = incidents.slice(0, 8)

  return (
    <div className="space-y-6">
      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <Kpi label="Total Events" value={summary?.total_events ?? '-'} />
        <Kpi label="Total Alerts" value={alerts.length || (summary?.total_alerts ?? '-')} />
        <Kpi label="Critical Alerts" value={criticalAlerts} />
        <Kpi label="Active Incidents" value={activeIncidents} />
        <Kpi label="Detection Coverage" value={`${summary?.detection_coverage ?? 0}%`} />
      </section>

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        <Kpi label="MTTD (min)" value={kpis?.mttd_minutes ?? '-'} />
        <Kpi label="MTTR (min)" value={kpis?.mttr_minutes ?? '-'} />
        <Kpi label="False Positive Rate" value={`${quality?.false_positive_rate ?? 0}%`} />
      </section>

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        <Kpi label="Detection Precision" value={`${quality?.precision ?? 0}%`} />
        <Kpi label="Jobs Queued" value={jobMetrics?.queued ?? '-'} />
        <Kpi label="Jobs Completed" value={jobMetrics?.completed ?? '-'} />
      </section>

      <section className="grid gap-4 xl:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5 xl:col-span-2">
          <h2 className="mb-4 text-lg font-semibold">Alerts Over Time</h2>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={alertsOverTime}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="day" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" allowDecimals={false} />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="count" stroke="#22d3ee" strokeWidth={3} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <h2 className="mb-4 text-lg font-semibold">Alerts by Severity</h2>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={alertsBySeverity} dataKey="count" nameKey="severity" outerRadius={90} fill="#22d3ee" />
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <h2 className="mb-4 text-lg font-semibold">Alerts by Type</h2>
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={alertsByType}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="type" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="count" fill="#38bdf8" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="grid gap-4 xl:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <h2 className="mb-4 text-lg font-semibold">Alert Queue</h2>
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="text-slate-400">
                <tr>
                  <th className="pb-2">Title</th>
                  <th className="pb-2">Severity</th>
                  <th className="pb-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {alertQueue.map((item) => (
                  <tr key={item.id} className="border-t border-slate-800">
                    <td className="py-2 pr-4">{item.title}</td>
                    <td className="py-2 pr-4">{item.severity}</td>
                    <td className="py-2 pr-4">{item.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <h2 className="mb-4 text-lg font-semibold">Incident List</h2>
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="text-slate-400">
                <tr>
                  <th className="pb-2">Title</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2">Owner</th>
                </tr>
              </thead>
              <tbody>
                {incidentQueue.map((item) => (
                  <tr key={item.id} className="border-t border-slate-800">
                    <td className="py-2 pr-4">{item.title}</td>
                    <td className="py-2 pr-4">{item.status}</td>
                    <td className="py-2 pr-4">{item.assigned_analyst_id ?? 'Unassigned'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  )
}
