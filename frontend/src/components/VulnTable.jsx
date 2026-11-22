import React, { useState, useCallback } from "react";
import RiskBadge from "./RiskBadge.jsx";
import ExplainBadge from "./ExplainBadge.jsx";
import { vulnsAPI } from "../services/api.js";

const COLUMNS = [
  { key: "rank",           label: "#",          sortable: false },
  { key: "title",          label: "Title",      sortable: true },
  { key: "asset_name",     label: "Asset",      sortable: true },
  { key: "cvss_score",     label: "CVSS",       sortable: true },
  { key: "priority_score", label: "ML Score",   sortable: true },
  { key: "risk_tier",      label: "Risk Tier",  sortable: true },
  { key: "exploit",        label: "Exploit",    sortable: false },
  { key: "actions",        label: "Actions",    sortable: false },
];

function SortIcon({ direction }) {
  if (!direction) return <span className="ml-1 text-gray-600">⇅</span>;
  return <span className="ml-1 text-blue-400">{direction === "asc" ? "↑" : "↓"}</span>;
}

/**
 * VulnTable — sortable vulnerability table.
 * @param {{ vulnerabilities: Array, onRemediate: Function, isLoading: boolean }} props
 */
export default function VulnTable({
  vulnerabilities = [],
  onRemediate,
  isLoading = false,
}) {
  const [sortKey, setSortKey] = useState("priority_score");
  const [sortDir, setSortDir] = useState("desc");
  const [expandedId, setExpandedId] = useState(null);
  const [remediating, setRemediating] = useState(null);

  const handleSort = useCallback(
    (key) => {
      if (sortKey === key) {
        setSortDir((d) => (d === "asc" ? "desc" : "asc"));
      } else {
        setSortKey(key);
        setSortDir("desc");
      }
    },
    [sortKey]
  );

  const sorted = [...vulnerabilities].sort((a, b) => {
    const av = a[sortKey] ?? "";
    const bv = b[sortKey] ?? "";
    if (typeof av === "number" && typeof bv === "number") {
      return sortDir === "asc" ? av - bv : bv - av;
    }
    return sortDir === "asc"
      ? String(av).localeCompare(String(bv))
      : String(bv).localeCompare(String(av));
  });

  const handleRemediate = async (id) => {
    setRemediating(id);
    try {
      await vulnsAPI.remediate(id);
      onRemediate?.(id);
    } catch (err) {
      console.error("Remediate failed", err);
    } finally {
      setRemediating(null);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-40 text-gray-500">
        <span className="animate-spin text-2xl mr-3">⟳</span> Loading vulnerabilities…
      </div>
    );
  }

  if (vulnerabilities.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-40 text-gray-500 gap-2">
        <span className="text-4xl">🎉</span>
        <p>No vulnerabilities found.</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-gray-800">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-gray-800/80 text-gray-400 text-left">
            {COLUMNS.map((col) => (
              <th
                key={col.key}
                className={`px-4 py-3 font-semibold uppercase tracking-wider text-xs whitespace-nowrap ${
                  col.sortable ? "cursor-pointer select-none hover:text-white" : ""
                }`}
                onClick={col.sortable ? () => handleSort(col.key) : undefined}
              >
                {col.label}
                {col.sortable && (
                  <SortIcon direction={sortKey === col.key ? sortDir : null} />
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((vuln, idx) => {
            const vulnId = vuln.id ?? vuln._id ?? idx;
            const isExpanded = expandedId === vulnId;
            const isRemediated = vuln.is_remediated === true;

            return (
              <React.Fragment key={vulnId}>
                <tr
                  className={`border-t border-gray-800 transition-colors ${
                    isRemediated
                      ? "opacity-50 bg-gray-900/40"
                      : "hover:bg-gray-800/40"
                  }`}
                >
                  <td className="px-4 py-3 text-gray-500 font-mono">{idx + 1}</td>
                  <td className="px-4 py-3 font-medium text-white max-w-xs">
                    <div className="flex items-center gap-2">
                      <span className="truncate">{vuln.title ?? "—"}</span>
                      {vuln.explainability && (
                        <ExplainBadge factors={vuln.explainability} />
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-300 whitespace-nowrap">
                    {vuln.asset_name ?? "—"}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`font-mono font-bold ${
                        (vuln.cvss_score ?? 0) >= 9
                          ? "text-red-400"
                          : (vuln.cvss_score ?? 0) >= 7
                          ? "text-orange-400"
                          : (vuln.cvss_score ?? 0) >= 4
                          ? "text-yellow-400"
                          : "text-green-400"
                      }`}
                    >
                      {vuln.cvss_score != null ? Number(vuln.cvss_score).toFixed(1) : "—"}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="font-mono font-bold text-blue-400">
                      {vuln.priority_score != null ? Number(vuln.priority_score).toFixed(1) : "—"}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <RiskBadge tier={vuln.risk_tier ?? vuln.severity} />
                  </td>
                  <td className="px-4 py-3 text-center">
                    {vuln.exploit_available ? (
                      <span className="text-red-400" title="Public exploit available">💀</span>
                    ) : (
                      <span className="text-gray-600">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setExpandedId(isExpanded ? null : vulnId)}
                        className="px-2 py-1 text-xs rounded bg-gray-700 text-gray-300 hover:bg-gray-600 transition-colors"
                      >
                        {isExpanded ? "▲ Hide" : "▼ Details"}
                      </button>
                      {!isRemediated && (
                        <button
                          disabled={remediating === vulnId}
                          onClick={() => handleRemediate(vulnId)}
                          className="px-2 py-1 text-xs rounded bg-green-800 text-green-300 hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          {remediating === vulnId ? "…" : "✓ Fix"}
                        </button>
                      )}
                      {isRemediated && (
                        <span className="px-2 py-1 text-xs rounded bg-gray-800 text-gray-500">
                          Remediated
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
                {isExpanded && (
                  <tr className="border-t border-gray-800 bg-gray-900/60">
                    <td colSpan={8} className="px-6 py-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                        <div>
                          <p className="text-gray-400 text-xs uppercase tracking-wide mb-1">Description</p>
                          <p className="text-gray-300">{vuln.description ?? "No description available."}</p>
                          {vuln.asset_exposure && (
                            <p className="text-xs text-indigo-300 mt-2">
                              Target Exposure: <strong className="capitalize">{vuln.asset_exposure}</strong> (Criticality: {vuln.asset_criticality ?? 3}/5)
                            </p>
                          )}
                        </div>
                        <div>
                          <p className="text-gray-400 text-xs uppercase tracking-wide mb-1">Explainability Vector</p>
                          {vuln.explainability ? (
                            <div className="space-y-1">
                              {vuln.explainability.note && (
                                <p className="text-[11px] text-gray-400 italic mb-1">{vuln.explainability.note}</p>
                              )}
                              <div className="flex flex-wrap gap-1.5">
                                {Object.entries(vuln.explainability)
                                  .filter(([k, v]) => k !== "note" && typeof v === "number" && v !== 0)
                                  .map(([k, v]) => (
                                    <span
                                      key={k}
                                      className={`px-2 py-0.5 rounded text-xs font-medium ${
                                        v > 0
                                          ? "bg-red-900/60 text-red-300"
                                          : "bg-green-900/60 text-green-300"
                                      }`}
                                    >
                                      {k.replace(/_/g, " ")}: {v > 0 ? `+${v}` : v}
                                    </span>
                                  ))}
                              </div>
                            </div>
                          ) : (
                            <p className="text-gray-500 text-xs">Full factor attribution available on detail inspection.</p>
                          )}
                        </div>
                        {vuln.cve_id && (
                          <div>
                            <p className="text-gray-400 text-xs uppercase tracking-wide mb-1">CVE ID</p>
                            <a
                              href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-blue-400 hover:underline"
                            >
                              {vuln.cve_id}
                            </a>
                          </div>
                        )}
                        {vuln.solution && (
                          <div>
                            <p className="text-gray-400 text-xs uppercase tracking-wide mb-1">Solution</p>
                            <p className="text-gray-300">{vuln.solution}</p>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
