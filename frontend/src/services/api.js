/**
 * api.js — Centralised Axios API client for the VAPT backend.
 *
 * All component-level data fetching imports from here so the base URL
 * and auth headers are configured in one place.
 *
 * Full endpoint implementations to be added in the Frontend milestone.
 */

import axios from "axios";

// ---------------------------------------------------------------------------
// Base configuration
// ---------------------------------------------------------------------------

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

const apiClient = axios.create({
  baseURL: BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
  timeout: 15_000, // 15 s
});

// ---------------------------------------------------------------------------
// Request interceptor — attach JWT access token
// ---------------------------------------------------------------------------

apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("access_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// ---------------------------------------------------------------------------
// Response interceptor — handle 401 / token refresh
// ---------------------------------------------------------------------------

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      // TODO: attempt token refresh, then retry once
      localStorage.removeItem("access_token");
      window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

// ---------------------------------------------------------------------------
// Endpoint helpers (stubs — implement in Frontend milestone)
// ---------------------------------------------------------------------------

/** Auth */
export const authAPI = {
  login:  (credentials) => apiClient.post("/api/auth/login",  credentials),
  logout: ()            => apiClient.post("/api/auth/logout"),
  me:     ()            => apiClient.get("/api/auth/me"),
};

/** Asset management */
export const assetsAPI = {
  list:   (params)  => apiClient.get("/api/assets", { params }),
  get:    (id)      => apiClient.get(`/api/assets/${id}`),
  create: (payload) => apiClient.post("/api/assets", payload),
  update: (id, payload) => apiClient.put(`/api/assets/${id}`, payload),
  delete: (id)      => apiClient.delete(`/api/assets/${id}`),
};

/** Vulnerabilities */
export const vulnsAPI = {
  list:   (params)  => apiClient.get("/api/vulns", { params }),
  get:    (id)      => apiClient.get(`/api/vulns/${id}`),
  create: (payload) => apiClient.post("/api/vulns", payload),
  patch:  (id, payload) => apiClient.patch(`/api/vulns/${id}`, payload),
  importScan: (payload) => apiClient.post("/api/vulns/import", payload),
};

/** Risk scores */
export const riskAPI = {
  score:     (vulnId)  => apiClient.get(`/api/vulns/${vulnId}/risk-score`),
  dashboard: ()        => apiClient.get("/api/reports/dashboard"),
  topRisks:  (limit = 10) => apiClient.get("/api/reports/top-risks", { params: { limit } }),
};

export default apiClient;
