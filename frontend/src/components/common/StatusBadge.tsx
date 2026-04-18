interface StatusBadgeProps {
  value: string;
  variant: 'severity' | 'status';
}

const severityClasses: Record<string, string> = {
  low: 'bg-slate-500/20 text-slate-300 border-slate-500/30',
  medium: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
  high: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  critical: 'bg-red-500/20 text-red-300 border-red-500/30',
};

const statusClasses: Record<string, string> = {
  open: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
  investigating: 'bg-violet-500/20 text-violet-300 border-violet-500/30',
  resolved: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
};

export function StatusBadge({ value, variant }: StatusBadgeProps) {
  const normalized = value.toLowerCase();
  const classes = variant === 'severity' ? severityClasses : statusClasses;
  return (
    <span className={`rounded-full border px-2 py-1 text-xs font-medium ${classes[normalized] ?? ''}`}>
      {value}
    </span>
  );
}
