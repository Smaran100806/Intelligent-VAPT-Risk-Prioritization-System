import React, { useState, useEffect } from "react";
import VulnTable from "../components/VulnTable.jsx";
import ScanUploadModal from "../components/ScanUploadModal.jsx";
import { vulnsAPI, assetsAPI } from "../services/api.js";

export default function VulnerabilitiesPage() {
  const [vulns, setVulns] = useState([]);
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);

  // Filters
  const [tierFilter, setTierFilter] = useState("");
  const [assetFilter, setAssetFilter] = useState("");
  const [remediatedFilter, setRemediatedFilter] = useState(false);

  const fetchData = async () => {
    try {
      setLoading(true);
      const params = {};
      if (tierFilter) params.risk_tier = tierFilter;
      if (assetFilter) params.asset_id = assetFilter;
      params.remediated = remediatedFilter;

      const [vulnsRes, assetsRes] = await Promise.all([
        vulnsAPI.list(params),
        assetsAPI.list()
      ]);

      setVulns(Array.isArray(vulnsRes.data) ? vulnsRes.data : vulnsRes.data.items || []);
      setAssets(assetsRes.data || []);
    } catch (err) {
      console.error("Error fetching vulnerabilities:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [tierFilter, assetFilter, remediatedFilter]);

  const handleRemediate = async () => {
    fetchData();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-gray-900 border border-gray-800 p-6 rounded-2xl shadow-xl">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Vulnerability Triage & Registry</h1>
          <p className="text-gray-400 text-sm mt-1">
            Browse, filter, and inspect detailed explainability vectors for all detected flaws.
          </p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="px-4 py-2.5 bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white font-medium text-sm rounded-xl transition shadow-lg shadow-indigo-600/30 flex items-center gap-2"
        >
          <span>📤</span> Upload & Simulate Scan
        </button>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center gap-3 bg-gray-900 border border-gray-800 p-4 rounded-xl">
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-400 font-medium">Risk Tier:</label>
          <select
            value={tierFilter}
            onChange={(e) => setTierFilter(e.target.value)}
            className="bg-gray-950 border border-gray-800 text-xs text-white rounded-lg px-3 py-1.5 focus:border-indigo-500 outline-none"
          >
            <option value="">All Tiers</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-400 font-medium">Target Asset:</label>
          <select
            value={assetFilter}
            onChange={(e) => setAssetFilter(e.target.value)}
            className="bg-gray-950 border border-gray-800 text-xs text-white rounded-lg px-3 py-1.5 focus:border-indigo-500 outline-none max-w-xs"
          >
            <option value="">All Assets</option>
            {assets.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} ({a.exposure})
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-2 ml-auto">
          <label className="text-xs text-gray-400 font-medium cursor-pointer flex items-center gap-2">
            <input
              type="checkbox"
              checked={remediatedFilter}
              onChange={(e) => setRemediatedFilter(e.target.checked)}
              className="rounded bg-gray-950 border-gray-800 text-indigo-600 focus:ring-0"
            />
            Show Remediated Only
          </label>
        </div>
      </div>

      {/* Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 shadow-xl">
        <VulnTable
          vulnerabilities={vulns}
          onRemediate={handleRemediate}
          isLoading={loading}
        />
      </div>

      {/* Upload Modal (Fixed prop names: open and onSuccess) */}
      <ScanUploadModal
        open={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSuccess={() => {
          setIsModalOpen(false);
          fetchData();
        }}
      />
    </div>
  );
}
