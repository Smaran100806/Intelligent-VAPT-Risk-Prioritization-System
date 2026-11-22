import { useState, useRef, useCallback } from "react";
import { scansAPI } from "../services/api.js";

/**
 * ScanUploadModal — modal with JSON textarea + file drag-drop.
 * @param {{ open: boolean, onClose: Function, onSuccess: Function }} props
 */
export default function ScanUploadModal({ open, onClose, onSuccess }) {
  const [jsonText, setJsonText] = useState("");
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState(null);
  const fileRef = useRef(null);

  const showToast = (msg, type = "success") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 4000);
  };

  const handleFile = useCallback((file) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => setJsonText(e.target.result);
    reader.readAsText(file);
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    handleFile(file);
  }, [handleFile]);

  const handleSubmit = async () => {
    if (!jsonText.trim()) {
      showToast("Please provide scan JSON data.", "error");
      return;
    }
    let payload;
    try {
      payload = JSON.parse(jsonText);
    } catch {
      showToast("Invalid JSON — please check your scan data.", "error");
      return;
    }
    setLoading(true);
    try {
      await scansAPI.upload(payload);
      showToast("Scan uploaded and processed successfully! 🎉");
      setJsonText("");
      onSuccess?.();
      setTimeout(() => onClose?.(), 1500);
    } catch (err) {
      const msg = err.response?.data?.detail ?? err.message ?? "Upload failed.";
      showToast(msg, "error");
    } finally {
      setLoading(false);
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="bg-gray-900 border border-gray-700 rounded-2xl shadow-2xl w-full max-w-2xl mx-4 flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          <h2 className="text-lg font-bold text-white">📤 Upload Scan Results</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white text-xl transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-4 flex flex-col gap-4">
          {/* Toast */}
          {toast && (
            <div
              className={`px-4 py-3 rounded-lg text-sm font-medium ${
                toast.type === "error"
                  ? "bg-red-900/80 text-red-300 border border-red-700"
                  : "bg-green-900/80 text-green-300 border border-green-700"
              }`}
            >
              {toast.type === "error" ? "❌ " : "✅ "} {toast.msg}
            </div>
          )}

          {/* Drag-drop area */}
          <div
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            onClick={() => fileRef.current?.click()}
            className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-colors ${
              dragging
                ? "border-blue-500 bg-blue-900/20"
                : "border-gray-700 hover:border-gray-500 bg-gray-800/30"
            }`}
          >
            <p className="text-gray-400 text-sm">
              <span className="text-2xl block mb-2">📁</span>
              Drag & drop a JSON scan file here, or{" "}
              <span className="text-blue-400 underline">click to browse</span>
            </p>
            <input
              ref={fileRef}
              type="file"
              accept=".json,application/json"
              className="hidden"
              onChange={(e) => handleFile(e.target.files?.[0])}
            />
          </div>

          {/* JSON textarea */}
          <div>
            <label className="block text-xs text-gray-400 uppercase tracking-wide mb-2">
              Or paste scan JSON directly
            </label>
            <textarea
              value={jsonText}
              onChange={(e) => setJsonText(e.target.value)}
              rows={10}
              placeholder={'{\n  "scan_id": "...",\n  "vulnerabilities": [...]\n}'}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm font-mono text-gray-200 placeholder-gray-600 focus:outline-none focus:border-blue-500 resize-y"
            />
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-gray-800">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-sm bg-gray-800 text-gray-300 hover:bg-gray-700 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={loading}
            className="px-5 py-2 rounded-lg text-sm bg-blue-600 text-white font-semibold hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
          >
            {loading && (
              <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
              </svg>
            )}
            {loading ? "Uploading…" : "Upload Scan"}
          </button>
        </div>
      </div>
    </div>
  );
}
