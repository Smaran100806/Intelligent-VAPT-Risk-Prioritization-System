import React, { useState, useEffect } from "react";
import { assetsAPI } from "../services/api.js";

export default function AssetsPage() {
  const [assets, setAssets] = useState([]);
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadAssets() {
      try {
        setLoading(true);
        const res = await assetsAPI.list();
        setAssets(res.data || []);
      } catch (err) {
        console.error("Error loading assets:", err);
      } finally {
        setLoading(false);
      }
    }
    loadAssets();
  }, []);

  const getExposureBadge = (exp) => {
    switch (exp) {
      case "internet-facing":
        return <span className="bg-red-950/80 border border-red-800 text-red-300 text-xs px-2.5 py-0.5 rounded-full font-semibold">Internet-Facing</span>;
      case "dmz":
        return <span className="bg-amber-950/80 border border-amber-800 text-amber-300 text-xs px-2.5 py-0.5 rounded-full font-semibold">DMZ</span>;
      case "internal":
        return <span className="bg-blue-950/80 border border-blue-800 text-blue-300 text-xs px-2.5 py-0.5 rounded-full font-semibold">Internal Corporate</span>;
      default:
        return <span className="bg-emerald-950/80 border border-emerald-800 text-emerald-300 text-xs px-2.5 py-0.5 rounded-full font-semibold">Isolated Sandbox</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gray-900 border border-gray-800 p-6 rounded-2xl shadow-xl">
        <h1 className="text-2xl font-bold text-white tracking-tight">Asset Inventory & Threat Topology</h1>
        <p className="text-gray-400 text-sm mt-1">
          Catalog of target hosts, networks, and services providing contextual weights to the ML inference engine.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Assets List */}
        <div className="lg:col-span-2 bg-gray-900 border border-gray-800 rounded-2xl p-5 shadow-xl">
          <h2 className="text-base font-bold text-white mb-4">Enterprise Assets ({assets.length})</h2>
          {loading ? (
            <div className="py-12 text-center text-gray-500 text-sm">Loading assets...</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-gray-300">
                <thead className="text-[11px] uppercase bg-gray-950/80 text-gray-400 border-b border-gray-800">
                  <tr>
                    <th className="py-3 px-3">Asset</th>
                    <th className="py-3 px-3">Type</th>
                    <th className="py-3 px-3">Network Exposure</th>
                    <th className="py-3 px-3 text-center">Criticality</th>
                    <th className="py-3 px-3">Business Unit</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/60">
                  {assets.map((asset) => (
                    <tr
                      key={asset.id}
                      onClick={() => setSelectedAsset(asset)}
                      className={`cursor-pointer transition hover:bg-gray-800/40 ${
                        selectedAsset?.id === asset.id ? "bg-indigo-950/40 border-l-2 border-indigo-500" : ""
                      }`}
                    >
                      <td className="py-3 px-3 font-semibold text-white">
                        <div>{asset.name}</div>
                        <div className="text-[11px] text-gray-500 font-mono">{asset.ip_address}</div>
                      </td>
                      <td className="py-3 px-3 font-mono capitalize">{asset.asset_type}</td>
                      <td className="py-3 px-3">{getExposureBadge(asset.exposure)}</td>
                      <td className="py-3 px-3 text-center">
                        <span className="font-bold text-amber-400">{asset.criticality}</span>
                        <span className="text-gray-600">/5</span>
                      </td>
                      <td className="py-3 px-3 text-gray-400">{asset.business_unit}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Selected Asset Details Panel */}
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 shadow-xl h-fit">
          <h2 className="text-base font-bold text-white mb-4">Contextual Impact Profile</h2>
          {selectedAsset ? (
            <div className="space-y-4 text-xs">
              <div className="p-4 bg-gray-950 rounded-xl border border-gray-800">
                <div className="text-gray-400">Target Identifier</div>
                <div className="text-base font-bold text-white mt-0.5">{selectedAsset.name}</div>
                <div className="text-gray-500 font-mono mt-1">{selectedAsset.hostname || "No hostname"}</div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 bg-gray-950 rounded-xl border border-gray-800">
                  <div className="text-gray-400">Criticality Weight</div>
                  <div className="text-lg font-black text-amber-400 mt-1">{selectedAsset.criticality} / 5</div>
                </div>
                <div className="p-3 bg-gray-950 rounded-xl border border-gray-800">
                  <div className="text-gray-400">Risk Multiplier</div>
                  <div className="text-lg font-black text-indigo-400 mt-1">
                    {selectedAsset.criticality * 4.5} pts
                  </div>
                </div>
              </div>

              <div className="space-y-2 pt-2">
                <div className="flex justify-between py-1 border-b border-gray-800/80">
                  <span className="text-gray-400">System Owner:</span>
                  <span className="text-gray-200">{selectedAsset.owner || "Unassigned"}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-gray-800/80">
                  <span className="text-gray-400">Exposure Vector:</span>
                  <span className="capitalize text-gray-200">{selectedAsset.exposure}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-gray-800/80">
                  <span className="text-gray-400">Asset Category:</span>
                  <span className="capitalize text-gray-200">{selectedAsset.asset_type}</span>
                </div>
              </div>

              <div className="p-3 bg-indigo-950/30 border border-indigo-900/40 rounded-xl text-[11px] text-indigo-300 leading-relaxed">
                ℹ️ When a scanner detects a vulnerability on this asset, the ML engine factors in this criticality ({selectedAsset.criticality}) and exposure ({selectedAsset.exposure}) to calculate priority.
              </div>
            </div>
          ) : (
            <div className="py-16 text-center text-gray-500 text-xs">
              Select an asset from the table to inspect its ML threat profile.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
