import React, { useState, useEffect } from "react";
import ComparisonTable from "../components/ComparisonTable.jsx";
import FeatureImportanceChart from "../components/FeatureImportanceChart.jsx";
import { comparisonAPI } from "../services/api.js";

export default function ComparisonPage() {
  const [data, setData] = useState(null);
  const [importance, setImportance] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchComparison() {
      try {
        setLoading(true);
        const [compRes, impRes] = await Promise.all([
          comparisonAPI.getCvssVsMl(),
          comparisonAPI.getFeatureImportance().catch(() => ({ data: [] })),
        ]);
        setData(compRes.data);
        setImportance(impRes.data || []);
      } catch (err) {
        console.error("Comparison fetch error:", err);
      } finally {
        setLoading(false);
      }
    }
    fetchComparison();
  }, []);

  // Compute live callout data dynamically from returned rows
  const rows = data?.rows || [];
  
  // Find largest promotion (maximum positive delta)
  const largestPromotion = [...rows].sort((a, b) => (b.delta ?? 0) - (a.delta ?? 0))[0] || null;
  // Find largest demotion (maximum negative delta)
  const largestDemotion = [...rows].sort((a, b) => (a.delta ?? 0) - (b.delta ?? 0))[0] || null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gray-900 border border-gray-800 p-6 rounded-2xl shadow-xl">
        <h1 className="text-2xl font-bold text-white tracking-tight">Traditional CVSS vs. ML Prioritization</h1>
        <p className="text-gray-400 text-sm mt-1">
          Demonstrating why legacy CVSS sorting fails security teams, and how ML ranking aligns remediation with business impact.
        </p>
      </div>

      {/* Flagship Live Demonstration Callouts */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {largestPromotion && (
          <div className="bg-gradient-to-br from-red-950/40 via-gray-900 to-gray-900 border border-red-800/50 p-5 rounded-2xl shadow-lg relative overflow-hidden">
            <div className="absolute top-3 right-3 text-2xl opacity-40">🔥</div>
            <span className="text-xs font-bold uppercase tracking-wider text-red-400">Largest ML Escalation</span>
            <h3 className="text-base font-bold text-white mt-1 truncate" title={largestPromotion.title}>
              {largestPromotion.title}
            </h3>
            <div className="text-xs text-gray-400 font-mono mt-0.5">Asset: {largestPromotion.asset_name}</div>
            <div className="flex items-center gap-4 mt-3">
              <div>
                <div className="text-xs text-gray-400">CVSS v3.1</div>
                <div className="text-xl font-black text-amber-400">{Number(largestPromotion.cvss_score).toFixed(1)}</div>
              </div>
              <div className="text-gray-600 font-bold text-lg">➜</div>
              <div>
                <div className="text-xs text-gray-400">ML Priority Score</div>
                <div className="text-xl font-black text-red-500">{Number(largestPromotion.ml_score).toFixed(1)}</div>
              </div>
              <div className="ml-auto text-right">
                <span className="text-xs bg-red-900/60 border border-red-700 text-red-200 px-2 py-0.5 rounded-full font-semibold">
                  {largestPromotion.risk_tier} (↑{largestPromotion.delta} ranks)
                </span>
              </div>
            </div>
            <p className="text-xs text-gray-400 mt-3 leading-relaxed">
              Reason: {largestPromotion.reason}
            </p>
          </div>
        )}

        {largestDemotion && (
          <div className="bg-gradient-to-br from-emerald-950/40 via-gray-900 to-gray-900 border border-emerald-800/50 p-5 rounded-2xl shadow-lg relative overflow-hidden">
            <div className="absolute top-3 right-3 text-2xl opacity-40">🛡️</div>
            <span className="text-xs font-bold uppercase tracking-wider text-emerald-400">Largest Noise Deprioritization</span>
            <h3 className="text-base font-bold text-white mt-1 truncate" title={largestDemotion.title}>
              {largestDemotion.title}
            </h3>
            <div className="text-xs text-gray-400 font-mono mt-0.5">Asset: {largestDemotion.asset_name}</div>
            <div className="flex items-center gap-4 mt-3">
              <div>
                <div className="text-xs text-gray-400">CVSS v3.1</div>
                <div className="text-xl font-black text-amber-400">{Number(largestDemotion.cvss_score).toFixed(1)}</div>
              </div>
              <div className="text-gray-600 font-bold text-lg">➜</div>
              <div>
                <div className="text-xs text-gray-400">ML Priority Score</div>
                <div className="text-xl font-black text-emerald-400">{Number(largestDemotion.ml_score).toFixed(1)}</div>
              </div>
              <div className="ml-auto text-right">
                <span className="text-xs bg-emerald-900/60 border border-emerald-700 text-emerald-200 px-2 py-0.5 rounded-full font-semibold">
                  {largestDemotion.risk_tier} (↓{Math.abs(largestDemotion.delta)} ranks)
                </span>
              </div>
            </div>
            <p className="text-xs text-gray-400 mt-3 leading-relaxed">
              Reason: {largestDemotion.reason}
            </p>
          </div>
        )}
      </div>

      {/* Feature Importance Chart */}
      <div className="bg-gray-900 border border-gray-800 p-6 rounded-2xl shadow-xl">
        <h2 className="text-lg font-bold text-white mb-1">Global ML Model Feature Importance</h2>
        <p className="text-xs text-gray-400 mb-4">
          Trained feature weights learned by Gradient Boosting Regressor pipeline across synthetic enterprise observations.
        </p>
        <div className="h-80">
          {importance.length > 0 ? (
            <FeatureImportanceChart data={importance} />
          ) : (
            <div className="h-full flex items-center justify-center text-gray-500 text-sm">
              Loading model feature weights...
            </div>
          )}
        </div>
      </div>

      {/* Side-by-Side Comparison Table */}
      <div className="bg-gray-900 border border-gray-800 p-6 rounded-2xl shadow-xl space-y-4">
        <div>
          <h2 className="text-lg font-bold text-white">Live Findings Re-Ordering (CVSS Rank vs. ML Rank)</h2>
          <p className="text-xs text-gray-400">
            Yellow highlighted rows indicate significant triage re-alignments (|Δ Rank| ≥ 2).
          </p>
        </div>
        <ComparisonTable data={rows} />
      </div>
    </div>
  );
}
