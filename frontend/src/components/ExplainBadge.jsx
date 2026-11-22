import { useState } from "react";

/**
 * ExplainBadge — tooltip chip showing why ML boosted/lowered a score.
 * @param {{ factors: object }} props  e.g. { exploit_available: 12, exposure: 10, patch_available: -8 }
 */
export default function ExplainBadge({ factors }) {
  const [open, setOpen] = useState(false);

  if (!factors || Object.keys(factors).length === 0) return null;

  const entries = Object.entries(factors).filter(
  ([k, v]) => typeof v === "number" && v !== 0 && k !== "total_score");
  if (entries.length === 0) return null;

  return (
    <div className="relative inline-block">
      <button
        onClick={() => setOpen((o) => !o)}
        className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-indigo-900 border border-indigo-700 text-indigo-300 text-xs font-medium hover:bg-indigo-800 transition-colors"
        title="ML score explanation"
      >
        🧠 Why?
      </button>
      {open && (
        <div className="absolute z-50 top-7 left-0 bg-gray-800 border border-gray-700 rounded-lg shadow-xl p-3 min-w-max flex flex-col gap-1.5">
          <p className="text-xs text-gray-400 font-semibold mb-1 uppercase tracking-wide">Score Factors</p>
          {entries.map(([key, value]) => {
            const isPositive = value > 0;
            return (
              <span
                key={key}
                className={`inline-flex items-center justify-between gap-3 px-2 py-0.5 rounded text-xs font-medium ${
                  isPositive
                    ? "bg-red-900/60 text-red-300"
                    : "bg-green-900/60 text-green-300"
                }`}
              >
                <span>{key.replace(/_/g, " ")}</span>
                <span className="font-bold">{isPositive ? `+${value}` : value}</span>
              </span>
            );
          })}
        </div>
      )}
    </div>
  );
}
