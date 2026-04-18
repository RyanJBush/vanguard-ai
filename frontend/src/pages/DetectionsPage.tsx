const rules = [
  { id: 'rule_001', name: 'Multiple Failed Logins', type: 'threshold', enabled: true },
  { id: 'rule_002', name: 'Suspicious Parent Process', type: 'behavioral', enabled: true },
  { id: 'rule_003', name: 'Rare Geolocation Login', type: 'anomaly', enabled: false },
];

export function DetectionsPage() {
  return (
    <section>
      <h2 className="text-2xl font-semibold">Detections</h2>
      <p className="mt-1 text-slate-400">Rule catalog and anomaly model controls.</p>
      <div className="mt-4 rounded-lg border border-slate-800 bg-slate-900 p-4">
        <ul className="space-y-3 text-sm">
          {rules.map((rule) => (
            <li key={rule.id} className="flex items-center justify-between border-b border-slate-800 pb-2">
              <span>
                {rule.name} <span className="text-slate-500">({rule.type})</span>
              </span>
              <span className={rule.enabled ? 'text-emerald-400' : 'text-slate-500'}>
                {rule.enabled ? 'Enabled' : 'Disabled'}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
