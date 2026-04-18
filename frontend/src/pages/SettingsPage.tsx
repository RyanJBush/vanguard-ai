import { useAuth } from '../context/AuthContext';

export function SettingsPage() {
  const { user } = useAuth();

  return (
    <section>
      <h2 className="text-3xl font-semibold">Settings</h2>
      <p className="mt-1 text-sm text-slate-400">Environment and session configuration for demo operators.</p>

      <div className="mt-4 rounded-lg border border-slate-800 bg-slate-900 p-4 text-sm">
        <p>
          <span className="text-slate-400">Current User:</span> {user?.username}
        </p>
        <p className="mt-2">
          <span className="text-slate-400">Role:</span> {user?.role}
        </p>
        <p className="mt-2 text-slate-400">
          TODO (Phase 3): tenant settings, notification routing, and investigation workflow preferences.
        </p>
      </div>
    </section>
  );
}
