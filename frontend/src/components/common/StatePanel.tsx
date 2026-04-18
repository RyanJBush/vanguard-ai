interface StatePanelProps {
  title: string;
  description: string;
  tone?: 'default' | 'error';
}

export function StatePanel({ title, description, tone = 'default' }: StatePanelProps) {
  const toneClasses =
    tone === 'error'
      ? 'border-red-500/30 bg-red-950/30 text-red-200'
      : 'border-slate-700 bg-slate-900 text-slate-300';

  return (
    <div className={`rounded-lg border p-6 ${toneClasses}`}>
      <p className="text-base font-semibold">{title}</p>
      <p className="mt-1 text-sm">{description}</p>
    </div>
  );
}
