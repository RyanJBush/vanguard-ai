export default function SettingsPage() {
  return (
    <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900 p-5">
      <h2 className="text-lg font-semibold">Settings</h2>
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="text-sm">
          Alert SLA (minutes)
          <input defaultValue="30" className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2" />
        </label>
        <label className="text-sm">
          Data Retention (days)
          <input defaultValue="90" className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2" />
        </label>
      </div>
      <p className="text-sm text-slate-400">MVP settings are placeholders for platform configuration management.</p>
    </div>
  )
}
