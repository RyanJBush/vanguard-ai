import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'

import StatusBadge from '../components/StatusBadge'
import { api } from '../services/api'

const STATUSES = ['open', 'in_progress', 'resolved', 'dismissed']

export default function AlertDetailPage() {
  const { alertId } = useParams()
  const [alert, setAlert] = useState(null)
  const [note, setNote] = useState('')

  useEffect(() => {
    api.getAlert(alertId).then(setAlert).catch(() => null)
  }, [alertId])

  async function setStatus(status) {
    const updated = await api.patchAlertStatus(alertId, status)
    setAlert(updated)
  }

  return (
    <div className="space-y-5">
      <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <h2 className="text-lg font-semibold">Alert Investigation</h2>
        {alert ? (
          <div className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
            <div>
              <p className="text-slate-400">Title</p>
              <p>{alert.title}</p>
            </div>
            <div>
              <p className="text-slate-400">Severity</p>
              <StatusBadge value={alert.severity} />
            </div>
            <div>
              <p className="text-slate-400">Status</p>
              <StatusBadge value={alert.status} />
            </div>
            <div>
              <p className="text-slate-400">Confidence</p>
              <p>{Math.round(alert.confidence_score * 100)}%</p>
            </div>
            <div className="sm:col-span-2">
              <p className="text-slate-400">Explanation</p>
              <p>{alert.explanation}</p>
            </div>
          </div>
        ) : (
          <p className="mt-4 text-slate-400">Loading alert...</p>
        )}
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <h3 className="font-semibold">Workflow Actions</h3>
        <div className="mt-3 flex flex-wrap gap-2">
          {STATUSES.map((status) => (
            <button
              key={status}
              onClick={() => setStatus(status)}
              className="rounded-md bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
            >
              Mark {status.replace('_', ' ')}
            </button>
          ))}
        </div>
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <h3 className="font-semibold">Investigation Notes (MVP placeholder)</h3>
        <textarea
          className="mt-3 min-h-28 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Capture analyst findings and next steps..."
        />
      </section>
    </div>
  )
}
