const TIER_STYLES = {
  Critical: "bg-red-900 text-red-300 border border-red-700",
  High:     "bg-orange-900 text-orange-300 border border-orange-700",
  Medium:   "bg-yellow-900 text-yellow-300 border border-yellow-700",
  Low:      "bg-green-900 text-green-300 border border-green-700",
};

/**
 * RiskBadge — colored chip for risk tier.
 * @param {{ tier: string }} props
 */
export default function RiskBadge({ tier }) {
  const cls = TIER_STYLES[tier] ?? "bg-gray-700 text-gray-300 border border-gray-600";
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wide ${cls}`}>
      {tier ?? "Unknown"}
    </span>
  );
}
