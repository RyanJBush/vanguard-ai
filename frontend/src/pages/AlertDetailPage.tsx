import { useParams } from 'react-router-dom';

export function AlertDetailPage() {
  const { alertId } = useParams();

  return (
    <section>
      <h2 className="text-2xl font-semibold">Alert Detail</h2>
      <p className="mt-2 text-slate-300">Alert ID: {alertId}</p>
      <div className="mt-4 rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h3 className="font-medium">Triage Notes</h3>
        <p className="mt-2 text-sm text-slate-400">
          Placeholder triage timeline, entities, and analyst actions for Phase 2.
        </p>
      </div>
    </section>
  );
}
