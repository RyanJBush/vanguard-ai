import { useEffect, useMemo, useState } from 'react'

import StatusBadge from '../components/StatusBadge'
import { api } from '../services/api'

const INCIDENT_STATUSES = ['open', 'investigating', 'contained', 'closed']

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [selectedAlertIds, setSelectedAlertIds] = useState([])
  const [title, setTitle] = useState('Credential Access Investigation')
  const [summary, setSummary] = useState('')
  const [feedback, setFeedback] = useState('')
  const [error, setError] = useState('')
  const [wrapups, setWrapups] = useState({})

  async function refresh() {
    try {
      const [incidentRows, alertRows] = await Promise.all([api.getIncidents(), api.getAlerts()])
      setIncidents(incidentRows)
      setAlerts(alertRows)
      setError('')
    } catch (err) {
      setError(err.message)
    }
  }

  useEffect(() => {
    Promise.all([api.getIncidents(), api.getAlerts()])
      .then(([incidentRows, alertRows]) => {
        setIncidents(incidentRows)
        setAlerts(alertRows)
      })
      .catch((err) => setError(err.message))
  }, [])

  const candidateAlerts = useMemo(
    () => alerts.filter((alert) => ['open', 'triaged', 'investigating', 'escalated'].includes(alert.status)),
    [alerts],
  )

  async function createIncident(event) {
    event.preventDefault()
    setFeedback('')
    setError('')
    try {
      const incident = await api.createIncident({
        title,
        summary,
        alert_ids: selectedAlertIds,
      })
      setFeedback(`Incident ${incident.id} created successfully.`)
      setSelectedAlertIds([])
      await refresh()
    } catch (err) {
      setError(err.message)
    }
  }

  async function updateStatus(incidentId, status) {
    setFeedback('')
    setError('')
    try {
      await api.patchIncidentStatus(incidentId, status)
      await refresh()
    } catch (err) {
      setError(err.message)
    }
  }

  async function fetchWrapup(incidentId) {
    setFeedback('')
    setError('')
    try {
      const response = await api.getIncidentAiWrapup(incidentId)
      setWrapups((current) => ({ ...current, [incidentId]: response.summary }))
    } catch (err) {
      setError(err.message)
    }
  }

  function toggleAlert(alertId) {
    setSelectedAlertIds((current) =>
      current.includes(alertId) ? current.filter((id) => id !== alertId) : [...current, alertId],
    )
  }

  return (
    <div className="space-y-4">
      <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <h2 className="text-lg font-semibold">Create Incident</h2>
        <p className="mt-1 text-sm text-slate-400">Group related alerts into a response case and track status end-to-end.</p>
        <form onSubmit={createIncident} className="mt-4 space-y-3">
          <label className="block text-sm">
            Incident Title
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2"
            />
          </label>
          <label className="block text-sm">
            Summary
            <textarea
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              className="mt-1 min-h-20 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2"
              placeholder="Capture initial triage findings and scope..."
            />
          </label>
          <div>
            <p className="text-sm text-slate-400">Attach alerts</p>
            <div className="mt-2 grid gap-2 md:grid-cols-2">
              {candidateAlerts.slice(0, 12).map((alert) => (
                <label key={alert.id} className="flex items-center gap-2 rounded-md border border-slate-800 bg-slate-950 p-2 text-sm">
                  <input
                    type="checkbox"
                    checked={selectedAlertIds.includes(alert.id)}
                    onChange={() => toggleAlert(alert.id)}
                  />
                  <span className="truncate">#{alert.id} {alert.title}</span>
                </label>
              ))}
            </div>
          </div>
          <button className="rounded-md bg-cyan-500 px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400">
            Create Incident
          </button>
        </form>
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <h2 className="mb-4 text-lg font-semibold">Incident Queue</h2>
        <div className="space-y-3">
          {incidents.map((incident) => (
            <article key={incident.id} className="rounded-lg border border-slate-800 bg-slate-950 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h3 className="font-semibold">#{incident.id} {incident.title}</h3>
                  <p className="text-sm text-slate-400">{incident.summary || 'No summary yet.'}</p>
                </div>
                <StatusBadge value={incident.status} />
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                {INCIDENT_STATUSES.map((status) => (
                  <button
                    key={status}
                    onClick={() => updateStatus(incident.id, status)}
                    className="rounded-md bg-slate-800 px-3 py-1.5 text-xs hover:bg-slate-700"
                  >
                    Mark {status}
                  </button>
                ))}
                <button
                  onClick={() => fetchWrapup(incident.id)}
                  className="rounded-md bg-fuchsia-500 px-3 py-1.5 text-xs font-semibold text-white hover:bg-fuchsia-400"
                >
                  Generate AI Wrap-up
                </button>
              </div>
              {wrapups[incident.id] ? (
                <p className="mt-3 rounded-md border border-fuchsia-700/40 bg-fuchsia-900/20 p-3 text-sm text-fuchsia-100">
                  {wrapups[incident.id]}
                </p>
              ) : null}
            </article>
          ))}
          {incidents.length === 0 ? <p className="text-sm text-slate-400">No incidents created yet.</p> : null}
        </div>
      </section>

      {feedback ? <p className="rounded-md border border-emerald-700/40 bg-emerald-900/20 p-3 text-sm text-emerald-200">{feedback}</p> : null}
      {error ? <p className="rounded-md border border-red-700/40 bg-red-900/20 p-3 text-sm text-red-200">{error}</p> : null}
    </div>
  )
}
