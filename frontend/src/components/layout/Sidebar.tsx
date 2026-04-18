import { NavLink } from 'react-router-dom';

const navItems = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/events', label: 'Events' },
  { to: '/alerts', label: 'Alerts' },
  { to: '/detections', label: 'Detections' },
];

export function Sidebar() {
  return (
    <aside className="sticky top-0 h-screen w-64 border-r border-slate-800 p-4">
      <h1 className="mb-6 text-xl font-semibold text-brand">Vanguard AI</h1>
      <nav className="space-y-2">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `block rounded-md px-3 py-2 transition ${
                isActive ? 'bg-brand/20 text-brand' : 'text-slate-300 hover:bg-slate-900'
              }`
            }
          >
            {item.label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
