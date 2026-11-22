import { NavLink } from "react-router-dom";

const links = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/vulnerabilities", label: "Vulnerabilities" },
  { to: "/comparison", label: "Comparison" },
  { to: "/assets", label: "Assets" },
];

export default function Navbar() {
  return (
    <header className="h-14 bg-gray-900 border-b border-gray-800 flex items-center justify-between px-6 shrink-0 z-10">
      <div className="flex items-center gap-3">
        <span className="text-xl">🛡️</span>
        <span className="font-bold text-white text-sm tracking-wide hidden lg:block">
          VAPT Risk Prioritization
        </span>
      </div>
      <nav className="flex gap-1">
        {links.map(({ to, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                isActive
                  ? "bg-blue-600 text-white"
                  : "text-gray-400 hover:text-white hover:bg-gray-800"
              }`
            }
          >
            {label}
          </NavLink>
        ))}
      </nav>
    </header>
  );
}
