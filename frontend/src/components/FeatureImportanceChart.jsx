import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm shadow-xl">
      <p className="font-semibold text-white">{label}</p>
      <p className="text-blue-300">Importance: {payload[0]?.value?.toFixed(4)}</p>
    </div>
  );
};

/**
 * FeatureImportanceChart — Recharts BarChart of ML feature importances.
 * @param {{ data: Array<{feature: string, importance: number}> }} props
 */
export default function FeatureImportanceChart({ data = [] }) {
  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-gray-500 text-sm">
        No feature importance data available.
      </div>
    );
  }

  const sorted = [...data].sort((a, b) => b.importance - a.importance).slice(0, 12);

  return (
    <ResponsiveContainer width="100%" height={320}>
      <BarChart
        data={sorted}
        layout="vertical"
        margin={{ top: 5, right: 20, left: 10, bottom: 5 }}
      >
        <CartesianGrid strokeDasharray="3 3" stroke="#374151" horizontal={false} />
        <XAxis
          type="number"
          tick={{ fill: "#9ca3af", fontSize: 11 }}
          axisLine={{ stroke: "#4b5563" }}
          tickLine={false}
        />
        <YAxis
          type="category"
          dataKey="feature"
          width={160}
          tick={{ fill: "#d1d5db", fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          tickFormatter={(v) => v.replace(/_/g, " ")}
        />
        <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,0.05)" }} />
        <Bar dataKey="importance" radius={[0, 4, 4, 0]}>
          {sorted.map((_, i) => (
            <Cell
              key={`cell-${i}`}
              fill={`hsl(${220 - i * 15}, 70%, ${60 - i * 2}%)`}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
