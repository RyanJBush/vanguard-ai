import { useEffect, useState } from 'react'

import { api } from '../services/api'

export default function DetectionsPage() {
  const [detections, setDetections] = useState([])
  const [jobs, setJobs] = useState([])
  const [error, setError] = useState('')

  async function refresh() {
    try {
      const [detectionRows, jobRows] = await Promise.all([api.getDetections(), api.getJobs()])
      setDetections(detectionRows)
      setJobs(jobRows)
      setError('')
    } catch (err) {
      setError(err.message)
    }
  }

  useEffect(() => {
    Promise.all([api.getDetections(), api.getJobs()])
      .then(([detectionRows, jobRows]) => {
        setDetections(detectionRows)
        setJobs(jobRows)
      })
      .catch((err) => setError(err.message))
  }, [])

  async function processPendingJobs() {
    setError('')
    try {
      await api.processPendingJobs()
      await refresh()
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div className="space-y-4">
      <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-lg font-semibold">Detection Pipeline Jobs</h2>
          <button onClick={processPendingJobs} className="rounded-md bg-cyan-500 px-3 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400">
            Process Pending Jobs
          </button>
        </div>
        <p className="mt-1 text-sm text-slate-400">Use this to process queued detections when events were ingested with deferred processing.</p>
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-slate-400">
              <tr>
                <th className="pb-2">Job ID</th>
                <th className="pb-2">Event ID</th>
                <th className="pb-2">Status</th>
                <th className="pb-2">Detections</th>
                <th className="pb-2">Alerts</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.id} className="border-t border-slate-800">
                  <td className="py-2 pr-4">{job.id}</td>
                  <td className="py-2 pr-4">{job.event_id}</td>
                  <td className="py-2 pr-4 capitalize">{job.status}</td>
                  <td className="py-2 pr-4">{job.detections_generated}</td>
                  <td className="py-2">{job.alerts_generated}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <h2 className="mb-4 text-lg font-semibold">Detection Results</h2>
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-slate-400">
              <tr>
                <th className="pb-2">Type</th>
                <th className="pb-2">Method</th>
                <th className="pb-2">Event ID</th>
                <th className="pb-2">Confidence</th>
                <th className="pb-2">Explanation</th>
              </tr>
            </thead>
            <tbody>
              {detections.map((detection) => (
                <tr key={detection.id} className="border-t border-slate-800">
                  <td className="py-2 pr-4">{detection.detection_type}</td>
                  <td className="py-2 pr-4 capitalize">{detection.detection_method}</td>
                  <td className="py-2 pr-4">{detection.event_id}</td>
                  <td className="py-2 pr-4">{Math.round(detection.confidence_score * 100)}%</td>
                  <td className="py-2 text-slate-400">{detection.explanation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {error ? <p className="rounded-md border border-red-700/40 bg-red-900/20 p-3 text-sm text-red-200">{error}</p> : null}
    </div>
  )
}
