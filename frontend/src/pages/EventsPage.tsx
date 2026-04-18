const events = [
  { id: 'evt_001', type: 'failed_login', sourceIp: '10.3.2.9', severity: 'medium' },
  { id: 'evt_002', type: 'process_spawn', sourceIp: '172.16.4.1', severity: 'low' },
];

export function EventsPage() {
  return (
    <section>
      <h2 className="text-2xl font-semibold">Events</h2>
      <div className="mt-4 overflow-hidden rounded-lg border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-300">
            <tr>
              <th className="px-4 py-3">ID</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Source IP</th>
              <th className="px-4 py-3">Severity</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.id} className="border-t border-slate-800">
                <td className="px-4 py-3">{event.id}</td>
                <td className="px-4 py-3">{event.type}</td>
                <td className="px-4 py-3">{event.sourceIp}</td>
                <td className="px-4 py-3 capitalize">{event.severity}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
