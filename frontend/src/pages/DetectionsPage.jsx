import { useEffect, useState } from 'react'

import { api } from '../services/api'

export default function DetectionsPage() {
  const [detections, setDetections] = useState([])

  useEffect(() => {
    api.getDetections().then(setDetections).catch(() => null)
  }, [])

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      <h2 className="mb-4 text-lg font-semibold">Detection Results</h2>
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead className="text-slate-400">
            <tr>
              <th className="pb-2">Type</th>
              <th className="pb-2">Event ID</th>
              <th className="pb-2">Confidence</th>
              <th className="pb-2">Explanation</th>
            </tr>
          </thead>
          <tbody>
            {detections.map((detection) => (
              <tr key={detection.id} className="border-t border-slate-800">
                <td className="py-2 pr-4">{detection.detection_type}</td>
                <td className="py-2 pr-4">{detection.event_id}</td>
                <td className="py-2 pr-4">{Math.round(detection.confidence_score * 100)}%</td>
                <td className="py-2 text-slate-400">{detection.explanation}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
