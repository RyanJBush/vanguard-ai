import { Link, NavLink, useNavigate } from 'react-router-dom'

import { authStore } from '../services/api'

const navItems = [
  ['Dashboard', '/dashboard'],
  ['Events', '/events'],
  ['Alerts', '/alerts'],
  ['Incidents', '/incidents'],
  ['Detections', '/detections'],
  ['Settings', '/settings'],
]

export default function Layout({ user, children }) {
  const navigate = useNavigate()

  function logout() {
    authStore.clear()
    navigate('/login')
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <Link to="/dashboard" className="text-xl font-semibold tracking-tight text-cyan-300">
            Vanguard AI SOC
          </Link>
          <div className="flex items-center gap-4 text-sm">
            <span className="text-slate-300">
              {user?.full_name} · <strong>{user?.role}</strong>
            </span>
            <button onClick={logout} className="rounded-md bg-slate-800 px-3 py-1.5 hover:bg-slate-700">
              Logout
            </button>
          </div>
        </div>
      </header>

      <div className="mx-auto grid max-w-7xl grid-cols-1 gap-6 px-6 py-6 md:grid-cols-[220px_1fr]">
        <aside className="rounded-xl border border-slate-800 bg-slate-900 p-3">
          <nav className="space-y-1">
            {navItems.map(([label, href]) => (
              <NavLink
                key={href}
                to={href}
                className={({ isActive }) =>
                  `block rounded-md px-3 py-2 text-sm font-medium ${
                    isActive ? 'bg-cyan-500/15 text-cyan-200' : 'text-slate-300 hover:bg-slate-800'
                  }`
                }
              >
                {label}
              </NavLink>
            ))}
          </nav>
        </aside>
        <main>{children}</main>
      </div>
    </div>
  )
}
