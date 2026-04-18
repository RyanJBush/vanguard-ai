import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

const data = [
  { hour: '00:00', events: 820, alerts: 8 },
  { hour: '06:00', events: 1240, alerts: 17 },
  { hour: '12:00', events: 1820, alerts: 22 },
  { hour: '18:00', events: 1390, alerts: 12 },
];

export function DashboardPage() {
  return (
    <section>
      <h2 className="text-2xl font-semibold">SOC Overview</h2>
      <p className="mb-6 mt-1 text-slate-400">High-level telemetry and alerting trends.</p>
      <div className="h-80 rounded-lg border border-slate-800 bg-slate-900 p-4">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="hour" stroke="#94a3b8" />
            <YAxis stroke="#94a3b8" />
            <Tooltip />
            <Area dataKey="events" stroke="#22d3ee" fill="#0891b2" fillOpacity={0.45} />
            <Area dataKey="alerts" stroke="#f97316" fill="#ea580c" fillOpacity={0.35} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
