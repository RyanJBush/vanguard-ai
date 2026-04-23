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
  const [kpis, setKpis] = useState(null)
  const [quality, setQuality] = useState(null)
  const [jobMetrics, setJobMetrics] = useState(null)
  const [benchmarks, setBenchmarks] = useState([])
  const [hotspots, setHotspots] = useState([])
  const [alerts, setAlerts] = useState([])

  useEffect(() => {
    api.getSummary().then(setSummary).catch(() => null)
    api.getKpis().then(setKpis).catch(() => null)
    api.getDetectionQuality().then(setQuality).catch(() => null)
    api.getJobMetrics().then(setJobMetrics).catch(() => null)
    api.getScenarioBenchmarks().then(setBenchmarks).catch(() => null)
    api.getCorrelationHotspots().then(setHotspots).catch(() => null)
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
        <Kpi label="Open Alerts" value={kpis?.open_alerts ?? '-'} />
        <Kpi label="High Severity" value={kpis?.high_severity_alerts ?? '-'} />
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

      <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <h2 className="mb-4 text-lg font-semibold">Scenario Benchmark Coverage</h2>
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-slate-400">
              <tr>
                <th className="pb-2">Scenario</th>
                <th className="pb-2">Coverage</th>
                <th className="pb-2">Observed Detections</th>
              </tr>
            </thead>
            <tbody>
              {benchmarks.map((item) => (
                <tr key={item.scenario} className="border-t border-slate-800">
                  <td className="py-2 pr-4">{item.scenario}</td>
                  <td className="py-2 pr-4">{item.coverage_percent}%</td>
                  <td className="py-2 pr-4">{item.observed_detections.join(', ') || 'None'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <h2 className="mb-4 text-lg font-semibold">Correlation Hotspots</h2>
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-slate-400">
              <tr>
                <th className="pb-2">Correlation ID</th>
                <th className="pb-2">Alert Count</th>
                <th className="pb-2">Max Dedup</th>
                <th className="pb-2">Avg Confidence</th>
              </tr>
            </thead>
            <tbody>
              {hotspots.map((item) => (
                <tr key={item.correlation_id} className="border-t border-slate-800">
                  <td className="py-2 pr-4">{item.correlation_id}</td>
                  <td className="py-2 pr-4">{item.alert_count}</td>
                  <td className="py-2 pr-4">{item.max_dedup_count}</td>
                  <td className="py-2 pr-4">{Math.round(item.avg_confidence * 100)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
