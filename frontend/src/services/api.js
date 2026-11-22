/**
 * api.js — Centralised Axios API client for the VAPT backend.
 */

import axios from "axios";

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";
const API_KEY = import.meta.env.VITE_API_KEY ?? "vapt-secure-api-key-2026";

const apiClient = axios.create({
  baseURL: BASE_URL,
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY,
  },
  timeout: 30_000,
});

// Interceptor to ensure auth key is attached dynamically if stored
apiClient.interceptors.request.use((config) => {
  const customKey = localStorage.getItem("vapt_api_key") || API_KEY;
  config.headers["X-API-Key"] = customKey;
  return config;
});

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

export const dashboardAPI = {
  getStats: () => apiClient.get("/api/dashboard"),
};

export const vulnsAPI = {
  list: (params) => apiClient.get("/api/vulnerabilities", { params }),
  get: (id) => apiClient.get(`/api/vulnerabilities/${id}`),
  remediate: (id) => apiClient.patch(`/api/vulnerabilities/${id}/remediate`),
};

export const scansAPI = {
  upload: (payload) => apiClient.post("/api/scans/upload", payload),
  list: () => apiClient.get("/api/scans"),
  get: (id) => apiClient.get(`/api/scans/${id}`),
};

export const assetsAPI = {
  list: (params) => apiClient.get("/api/assets", { params }),
  get: (id) => apiClient.get(`/api/assets/${id}`),
};

export const comparisonAPI = {
  getCvssVsMl: () => apiClient.get("/api/comparison/cvss-vs-ml"),
  getFeatureImportance: () => apiClient.get("/api/comparison/feature-importance"),
  getModelMetadata: () => apiClient.get("/api/model/metadata"),
};

export const seedAPI = {
  seed: (reset = true) => apiClient.post("/api/seed", null, { params: { reset } }),
};

export default apiClient;
