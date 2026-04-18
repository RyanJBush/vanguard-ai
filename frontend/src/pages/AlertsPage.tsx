import { Link } from 'react-router-dom';

const alerts = [
  { id: 'alrt_001', title: 'Brute Force Activity', status: 'open', severity: 'high' },
  { id: 'alrt_002', title: 'Suspicious PowerShell', status: 'in_review', severity: 'critical' },
];

export function AlertsPage() {
  return (
    <section>
      <h2 className="text-2xl font-semibold">Alerts</h2>
      <div className="mt-4 grid gap-4">
        {alerts.map((alert) => (
          <Link
            key={alert.id}
            to={`/alerts/${alert.id}`}
            className="rounded-lg border border-slate-800 bg-slate-900 p-4 hover:border-brand"
          >
            <p className="font-medium">{alert.title}</p>
            <p className="text-sm text-slate-400">
              {alert.id} • {alert.status} • {alert.severity}
            </p>
          </Link>
        ))}
      </div>
    </section>
  );
}
