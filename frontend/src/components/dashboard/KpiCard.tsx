interface KpiCardProps {
  title: string;
  value: string;
  context: string;
}

export function KpiCard({ title, value, context }: KpiCardProps) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <p className="text-xs uppercase tracking-wide text-slate-400">{title}</p>
      <p className="mt-2 text-2xl font-semibold text-slate-100">{value}</p>
      <p className="mt-1 text-xs text-slate-400">{context}</p>
    </div>
  );
}
