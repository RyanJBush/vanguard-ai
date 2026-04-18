import { useEffect, useMemo, useState } from 'react';

import { StatePanel } from '../components/common/StatePanel';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import type { Detection } from '../types/api';

const DESCRIPTIONS: Record<string, string> = {
  brute_force_login: 'Triggers when failed login count exceeds threshold.',
  unusual_login_hour: 'Highlights authentications outside normal operating windows.',
  privilege_escalation_indicator: 'Flags role/admin privilege changes that may indicate abuse.',
  failed_access_spike_anomaly: 'Placeholder anomaly rule for sudden denied-access spikes.',
};

export function DetectionsPage() {
  const { token } = useAuth();
  const [detections, setDetections] = useState<Detection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      if (!token) return;
      setLoading(true);
      try {
        const data = await api.getDetections(token);
        setDetections(data);
      } catch {
        setError('Failed to load detections.');
      } finally {
        setLoading(false);
      }
    }

    void load();
  }, [token]);

  const activeDetectionNames = useMemo(
    () => Array.from(new Set(detections.map((detection) => detection.rule_name))),
    [detections],
  );

  if (loading) return <StatePanel title="Loading detections" description="Fetching active detection outputs..." />;
  if (error) return <StatePanel title="Detection data unavailable" description={error} tone="error" />;

  return (
    <section>
      <h2 className="text-3xl font-semibold">Detections</h2>
      <p className="mt-1 text-sm text-slate-400">Active detection rules and recent trigger activity.</p>

      {activeDetectionNames.length === 0 ? (
        <div className="mt-4">
          <StatePanel title="No detections" description="Ingest events to produce detections." />
        </div>
      ) : (
        <div className="mt-4 grid gap-3">
          {activeDetectionNames.map((name) => (
            <article key={name} className="rounded-lg border border-slate-800 bg-slate-900 p-4">
              <h3 className="font-semibold text-cyan-300">{name}</h3>
              <p className="mt-1 text-sm text-slate-400">{DESCRIPTIONS[name] ?? 'Detection description pending.'}</p>
              <p className="mt-2 text-xs text-slate-500">
                Recent triggers: {detections.filter((detection) => detection.rule_name === name).length}
              </p>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
