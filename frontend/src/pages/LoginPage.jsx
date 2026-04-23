import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { api, authStore } from '../services/api'

export default function LoginPage({ onAuthenticated }) {
  const navigate = useNavigate()
  const [form, setForm] = useState({ username: 'admin', password: 'admin123' })
  const [error, setError] = useState('')

  async function handleSubmit(event) {
    event.preventDefault()
    setError('')
    try {
      const data = await api.login(form.username, form.password)
      authStore.setToken(data.access_token)
      await onAuthenticated()
      navigate('/dashboard')
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4 text-slate-100">
      <form onSubmit={handleSubmit} className="w-full max-w-md space-y-5 rounded-2xl border border-slate-800 bg-slate-900 p-8">
        <div>
          <h1 className="text-2xl font-bold text-cyan-300">Vanguard AI</h1>
          <p className="mt-1 text-sm text-slate-400">SOC Threat Detection Platform</p>
        </div>

        <label className="block text-sm">
          Username
          <input
            value={form.username}
            onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))}
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2"
          />
        </label>

        <label className="block text-sm">
          Password
          <input
            type="password"
            value={form.password}
            onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2"
          />
        </label>

        {error ? <p className="text-sm text-red-300">{error}</p> : null}

        <button className="w-full rounded-md bg-cyan-500 px-4 py-2 font-semibold text-slate-950 hover:bg-cyan-400">
          Sign in
        </button>
      </form>
    </div>
  )
}
