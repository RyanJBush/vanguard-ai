import { useEffect, useMemo, useState } from 'react'

import { api } from '../services/api'

const emptyEvent = {
  source: 'identity_provider',
  event_type: 'login_failed',
  username: 'jdoe',
  source_ip: '198.51.100.10',
  message: 'Failed login attempt',
  severity: 'medium',
}

export default function EventsPage() {
  const [events, setEvents] = useState([])
  const [query, setQuery] = useState('')
  const [form, setForm] = useState(emptyEvent)
  const [scenarios, setScenarios] = useState([])
  const [selectedScenario, setSelectedScenario] = useState('')
  const [batchCount, setBatchCount] = useState(6)
  const [feedback, setFeedback] = useState('')
  const [error, setError] = useState('')

  async function loadEvents() {
    const rows = await api.getEvents()
    setEvents(rows)
  }

  useEffect(() => {
    api.getEvents().then(setEvents).catch(() => null)
    api.getEventScenarios().then((items) => {
      setScenarios(items)
      if (items.length > 0) {
        setSelectedScenario(items[0].key)
      }
    }).catch(() => null)
  }, [])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return events
    return events.filter((event) => `${event.event_type} ${event.username ?? ''} ${event.source_ip ?? ''}`.toLowerCase().includes(q))
  }, [events, query])

  async function ingestSingleEvent(event) {
    event.preventDefault()
    setFeedback('')
    setError('')
    try {
      const response = await api.createEvent(form)
      await loadEvents()
      setFeedback(`Event ingested. Detections: ${response.detections.length}, Alerts: ${response.alerts.length}.`)
    } catch (err) {
      setError(err.message)
    }
  }

  async function ingestBatch() {
    setFeedback('')
    setError('')
    const eventsPayload = Array.from({ length: Math.max(1, batchCount) }, () => ({ ...form }))
    try {
      const result = await api.createEventsBatch({ events: eventsPayload })
      await loadEvents()
      setFeedback(
        `Batch ingested (${result.events_ingested} events). Detections: ${result.detections_generated}, Alerts: ${result.alerts_generated}.`,
      )
    } catch (err) {
      setError(err.message)
    }
  }

  async function seedScenario() {
    if (!selectedScenario) return
    setFeedback('')
    setError('')
    try {
      const result = await api.seedScenario(selectedScenario)
      await loadEvents()
      setFeedback(
        `Scenario seeded: ${result.scenario} (${result.events_ingested} events, ${result.alerts_generated} alerts).`,
      )
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div className="space-y-4">
      <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <h2 className="text-lg font-semibold">Ingest Security Telemetry</h2>
        <p className="mt-1 text-sm text-slate-400">Generate demo telemetry and drive the event → detection → alert flow.</p>
        <form onSubmit={ingestSingleEvent} className="mt-4 grid gap-3 md:grid-cols-2">
          <label className="text-sm">
            Source
            <input
              value={form.source}
              onChange={(e) => setForm((current) => ({ ...current, source: e.target.value }))}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2"
            />
          </label>
          <label className="text-sm">
            Event Type
            <input
              value={form.event_type}
              onChange={(e) => setForm((current) => ({ ...current, event_type: e.target.value }))}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2"
            />
          </label>
          <label className="text-sm">
            Username
            <input
              value={form.username}
              onChange={(e) => setForm((current) => ({ ...current, username: e.target.value }))}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2"
            />
          </label>
          <label className="text-sm">
            Source IP
            <input
              value={form.source_ip}
              onChange={(e) => setForm((current) => ({ ...current, source_ip: e.target.value }))}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2"
            />
          </label>
          <label className="text-sm md:col-span-2">
            Message
            <input
              value={form.message}
              onChange={(e) => setForm((current) => ({ ...current, message: e.target.value }))}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2"
            />
          </label>
          <div className="md:col-span-2 flex flex-wrap gap-2">
            <button type="submit" className="rounded-md bg-cyan-500 px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400">
              Ingest Single Event
            </button>
            <input
              type="number"
              min={1}
              max={100}
              value={batchCount}
              onChange={(e) => setBatchCount(Number(e.target.value) || 1)}
              className="w-24 rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
            />
            <button type="button" onClick={ingestBatch} className="rounded-md bg-blue-500 px-3 py-2 text-sm font-semibold text-white hover:bg-blue-400">
              Ingest Batch
            </button>
          </div>
        </form>
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <h3 className="font-semibold">Seed Attack Scenarios</h3>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <select
            value={selectedScenario}
            onChange={(e) => setSelectedScenario(e.target.value)}
            className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
          >
            {scenarios.map((scenario) => (
              <option key={scenario.key} value={scenario.key}>
                {scenario.title}
              </option>
            ))}
          </select>
          <button onClick={seedScenario} className="rounded-md bg-fuchsia-500 px-3 py-2 text-sm font-semibold text-white hover:bg-fuchsia-400">
            Seed Scenario
          </button>
        </div>
      </section>

      {feedback ? <p className="rounded-md border border-emerald-700/40 bg-emerald-900/20 p-3 text-sm text-emerald-200">{feedback}</p> : null}
      {error ? <p className="rounded-md border border-red-700/40 bg-red-900/20 p-3 text-sm text-red-200">{error}</p> : null}

      <section className="space-y-4 rounded-xl border border-slate-800 bg-slate-900 p-5">
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
      </section>
    </div>
  )
}
