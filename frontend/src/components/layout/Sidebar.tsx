import { NavLink } from 'react-router-dom';

import { useAuth } from '../../context/AuthContext';

const navItems = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/events', label: 'Events' },
  { to: '/alerts', label: 'Alerts' },
  { to: '/detections', label: 'Detections' },
  { to: '/settings', label: 'Settings' },
];

export function Sidebar() {
  const { logout, user } = useAuth();

  return (
    <aside className="sticky top-0 flex h-screen w-72 flex-col border-r border-slate-800 bg-slate-950 p-5">
      <div>
        <p className="text-xs uppercase tracking-wide text-slate-500">Vanguard AI</p>
        <h1 className="mt-1 text-2xl font-semibold text-cyan-300">SOC Console</h1>
      </div>

      <nav className="mt-8 flex-1 space-y-2">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `block rounded-md px-3 py-2 text-sm transition ${
                isActive ? 'bg-cyan-500/20 text-cyan-200' : 'text-slate-300 hover:bg-slate-900'
              }`
            }
          >
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="rounded-md border border-slate-800 bg-slate-900 p-3">
        <p className="text-sm font-medium text-slate-100">{user?.username}</p>
        <p className="text-xs uppercase text-slate-400">{user?.role}</p>
        <button
          type="button"
          onClick={logout}
          className="mt-3 w-full rounded bg-slate-800 px-3 py-2 text-sm text-slate-200 hover:bg-slate-700"
        >
          Sign out
        </button>
      </div>
    </aside>
  );
}
