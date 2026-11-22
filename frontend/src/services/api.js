/**
 * api.js — Centralised Axios API client for the VAPT backend.
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
  timeout: 30_000,
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
      localStorage.removeItem("access_token");
      window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export const dashboardAPI = {
  /** GET /api/dashboard */
  getStats: () => apiClient.get("/api/dashboard"),
};

// ---------------------------------------------------------------------------
// Vulnerabilities
// ---------------------------------------------------------------------------

export const vulnsAPI = {
  /** GET /api/vulnerabilities?risk_tier=...&asset=...&remediated=...&page=...&limit=... */
  list: (params) => apiClient.get("/api/vulnerabilities", { params }),
  /** GET /api/vulnerabilities/:id */
  get: (id) => apiClient.get(`/api/vulnerabilities/${id}`),
  /** PATCH /api/vulnerabilities/:id/remediate */
  remediate: (id) => apiClient.patch(`/api/vulnerabilities/${id}/remediate`),
};

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export const scansAPI = {
  /** POST /api/scans/upload */
  upload: (payload) => apiClient.post("/api/scans/upload", payload),
  /** GET /api/scans */
  list: () => apiClient.get("/api/scans"),
};

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------

export const assetsAPI = {
  /** GET /api/assets */
  list: (params) => apiClient.get("/api/assets", { params }),
  /** GET /api/assets/:id */
  get: (id) => apiClient.get(`/api/assets/${id}`),
};

// ---------------------------------------------------------------------------
// Comparison (CVSS vs ML)
// ---------------------------------------------------------------------------

export const comparisonAPI = {
  /** GET /api/comparison/cvss-vs-ml */
  getCvssVsMl: () => apiClient.get("/api/comparison/cvss-vs-ml"),
};

// ---------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------

export const seedAPI = {
  /** POST /api/seed */
  seed: () => apiClient.post("/api/seed"),
};

// ---------------------------------------------------------------------------
// Auth (kept for compatibility)
// ---------------------------------------------------------------------------

export const authAPI = {
  login: (credentials) => apiClient.post("/api/auth/login", credentials),
  logout: () => apiClient.post("/api/auth/logout"),
  me: () => apiClient.get("/api/auth/me"),
};

export default apiClient;
