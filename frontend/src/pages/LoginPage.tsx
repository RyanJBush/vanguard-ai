import { FormEvent, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { useAuth } from '../context/AuthContext';

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState('analyst');
  const [password, setPassword] = useState('analyst123');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await login(username, password);
      navigate('/dashboard');
    } catch {
      setError('Unable to sign in. Check credentials or backend availability.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto mt-24 max-w-md rounded-lg border border-slate-800 bg-slate-900 p-6">
      <h2 className="text-2xl font-semibold">Vanguard AI Login</h2>
      <p className="mt-2 text-sm text-slate-400">Use demo SOC credentials to enter the analyst console.</p>
      <form className="mt-6 space-y-4" onSubmit={handleSubmit}>
        <label className="block text-sm">
          <span className="text-slate-300">Username</span>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
          />
        </label>

        <label className="block text-sm">
          <span className="text-slate-300">Password</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
          />
        </label>

        {error ? <p className="text-sm text-red-300">{error}</p> : null}

        <button
          disabled={loading}
          className="w-full rounded bg-cyan-400 px-4 py-2 font-medium text-slate-900 hover:bg-cyan-300 disabled:opacity-60"
        >
          {loading ? 'Signing in...' : 'Sign in'}
        </button>
      </form>
export function LoginPage() {
  return (
    <div className="mx-auto mt-24 max-w-md rounded-lg border border-slate-800 bg-slate-900 p-6">
      <h2 className="text-2xl font-semibold">SOC Analyst Login</h2>
      <p className="mt-2 text-sm text-slate-400">Placeholder JWT login form for Phase 2.</p>
      <button className="mt-6 rounded bg-brand px-4 py-2 font-medium text-slate-950 hover:bg-brand-dark">
        Sign In
      </button>
    </div>
  );
}
