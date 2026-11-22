import RiskBadge from "./RiskBadge.jsx";

/**
 * ComparisonTable — side-by-side CVSS Rank vs ML Rank table.
 * @param {{ data: Array }} props
 */
export default function ComparisonTable({ data = [] }) {
  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-32 text-gray-500 text-sm">
        No comparison data available.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-gray-800">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-gray-800/80 text-gray-400 text-left">
            <th className="px-4 py-3 font-semibold uppercase tracking-wider text-xs">CVSS Rank</th>
            <th className="px-4 py-3 font-semibold uppercase tracking-wider text-xs">ML Rank</th>
            <th className="px-4 py-3 font-semibold uppercase tracking-wider text-xs text-center">Δ</th>
            <th className="px-4 py-3 font-semibold uppercase tracking-wider text-xs">Title</th>
            <th className="px-4 py-3 font-semibold uppercase tracking-wider text-xs">Asset</th>
            <th className="px-4 py-3 font-semibold uppercase tracking-wider text-xs">CVSS</th>
            <th className="px-4 py-3 font-semibold uppercase tracking-wider text-xs">ML Score</th>
            <th className="px-4 py-3 font-semibold uppercase tracking-wider text-xs">Risk Tier</th>
            <th className="px-4 py-3 font-semibold uppercase tracking-wider text-xs">Reason</th>
          </tr>
        </thead>
        <tbody>
          {data.map((row, idx) => {
            const delta = (row.cvss_rank ?? idx + 1) - (row.ml_rank ?? idx + 1);
            const absDelta = Math.abs(delta);
            const isHighlighted = absDelta > 2;
            return (
              <tr
                key={idx}
                className={`border-t border-gray-800 transition-colors ${
                  isHighlighted
                    ? "bg-yellow-900/20 hover:bg-yellow-900/30"
                    : "hover:bg-gray-800/40"
                }`}
              >
                <td className="px-4 py-3 font-mono text-gray-400">
                  #{row.cvss_rank ?? idx + 1}
                </td>
                <td className="px-4 py-3 font-mono text-blue-400 font-bold">
                  #{row.ml_rank ?? idx + 1}
                </td>
                <td className="px-4 py-3 text-center">
                  {delta === 0 ? (
                    <span className="text-gray-500 text-xs">—</span>
                  ) : delta > 0 ? (
                    <span
                      className={`font-bold ${
                        absDelta > 2 ? "text-red-400" : "text-orange-400"
                      }`}
                      title="ML ranked higher (more urgent)"
                    >
                      ↑{absDelta}
                    </span>
                  ) : (
                    <span
                      className={`font-bold ${
                        absDelta > 2 ? "text-green-400" : "text-gray-400"
                      }`}
                      title="ML ranked lower (less urgent)"
                    >
                      ↓{absDelta}
                    </span>
                  )}
                </td>
                <td className="px-4 py-3 font-medium text-white max-w-xs">
                  <div className="flex items-center gap-2">
                    {isHighlighted && (
                      <span title="Significant re-ranking" className="text-yellow-400 text-xs">⚠️</span>
                    )}
                    <span className="truncate">{row.title ?? row.name ?? "—"}</span>
                  </div>
                </td>
                <td className="px-4 py-3 text-gray-300 whitespace-nowrap text-xs">
                  {row.asset_name ?? row.asset ?? "—"}
                </td>
                <td className="px-4 py-3 font-mono text-orange-400">
                  {row.cvss_score != null ? row.cvss_score.toFixed(1) : "—"}
                </td>
                <td className="px-4 py-3 font-mono font-bold text-blue-400">
                  {row.ml_score != null ? row.ml_score.toFixed(1) : "—"}
                </td>
                <td className="px-4 py-3">
                  <RiskBadge tier={row.risk_tier ?? row.severity} />
                </td>
                <td className="px-4 py-3 text-gray-400 text-xs max-w-xs">
                  <span className="truncate block">{row.reason ?? "—"}</span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
