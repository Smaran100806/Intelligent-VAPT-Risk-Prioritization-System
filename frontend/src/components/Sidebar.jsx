import { NavLink } from "react-router-dom";

const links = [
  { to: "/dashboard", label: "Dashboard", icon: "📊" },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: "🐛" },
  { to: "/comparison", label: "Comparison", icon: "⚖️" },
  { to: "/assets", label: "Assets", icon: "🖥️" },
];

export default function Sidebar() {
  return (
    <aside className="w-16 lg:w-56 bg-gray-900 border-r border-gray-800 flex flex-col shrink-0">
      <div className="h-14 flex items-center justify-center lg:justify-start lg:px-4 border-b border-gray-800 shrink-0">
        <span className="text-2xl">🛡️</span>
        <span className="ml-2 font-bold text-white text-sm hidden lg:block">VAPT</span>
      </div>
      <nav className="flex-1 py-4 flex flex-col gap-1 px-2">
        {links.map(({ to, label, icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-2 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? "bg-blue-600 text-white"
                  : "text-gray-400 hover:text-white hover:bg-gray-800"
              }`
            }
          >
            <span className="text-lg shrink-0">{icon}</span>
            <span className="hidden lg:block truncate">{label}</span>
          </NavLink>
        ))}
      </nav>
      <div className="p-2 pb-4 hidden lg:block">
        <p className="text-xs text-gray-600 text-center">v0.1.0 · ML-Powered</p>
      </div>
    </aside>
  );
}
