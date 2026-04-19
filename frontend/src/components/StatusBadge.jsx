const STATUS_STYLES = {
  open: 'bg-red-500/15 text-red-200 border-red-500/40',
  in_progress: 'bg-amber-500/15 text-amber-200 border-amber-500/40',
  resolved: 'bg-emerald-500/15 text-emerald-200 border-emerald-500/40',
  dismissed: 'bg-slate-500/15 text-slate-200 border-slate-500/40',
  high: 'bg-orange-500/15 text-orange-200 border-orange-500/40',
  critical: 'bg-fuchsia-500/15 text-fuchsia-200 border-fuchsia-500/40',
  medium: 'bg-blue-500/15 text-blue-200 border-blue-500/40',
  low: 'bg-slate-500/15 text-slate-200 border-slate-500/40',
}

export default function StatusBadge({ value }) {
  const normalized = String(value ?? '').toLowerCase()
  const style = STATUS_STYLES[normalized] ?? 'bg-slate-700 text-slate-200 border-slate-600'

  return (
    <span className={`inline-flex rounded-md border px-2 py-1 text-xs font-semibold capitalize ${style}`}>
      {normalized.replace('_', ' ')}
    </span>
  )
}
