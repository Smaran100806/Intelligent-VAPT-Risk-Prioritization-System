/**
 * KpiCard — stat card component.
 * @param {{ title: string, value: string|number, subtitle?: string, color?: string }} props
 */
export default function KpiCard({ title, value, subtitle, color = "blue" }) {
  const colorMap = {
    blue:   "from-blue-900/50 to-blue-800/30 border-blue-800",
    red:    "from-red-900/50 to-red-800/30 border-red-800",
    orange: "from-orange-900/50 to-orange-800/30 border-orange-800",
    green:  "from-green-900/50 to-green-800/30 border-green-800",
    purple: "from-purple-900/50 to-purple-800/30 border-purple-800",
    yellow: "from-yellow-900/50 to-yellow-800/30 border-yellow-800",
  };
  const textColorMap = {
    blue:   "text-blue-400",
    red:    "text-red-400",
    orange: "text-orange-400",
    green:  "text-green-400",
    purple: "text-purple-400",
    yellow: "text-yellow-400",
  };

  const gradClass = colorMap[color] ?? colorMap.blue;
  const textClass = textColorMap[color] ?? textColorMap.blue;

  return (
    <div className={`bg-gradient-to-br ${gradClass} border rounded-xl p-5 flex flex-col gap-2`}>
      <p className="text-xs text-gray-400 uppercase tracking-widest font-medium">{title}</p>
      <p className={`text-3xl font-bold ${textClass}`}>{value ?? "—"}</p>
      {subtitle && <p className="text-xs text-gray-500">{subtitle}</p>}
    </div>
  );
}
