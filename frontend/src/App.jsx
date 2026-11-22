import { Routes, Route, Navigate } from "react-router-dom";
import Sidebar from "./components/Sidebar.jsx";
import Navbar from "./components/Navbar.jsx";
import DashboardPage from "./pages/DashboardPage.jsx";
import VulnerabilitiesPage from "./pages/VulnerabilitiesPage.jsx";
import ComparisonPage from "./pages/ComparisonPage.jsx";
import AssetsPage from "./pages/AssetsPage.jsx";

export default function App() {
  return (
    <div className="flex h-screen bg-gray-950 overflow-hidden">
      <Sidebar />
      <div className="flex flex-col flex-1 overflow-hidden">
        <Navbar />
        <main className="flex-1 overflow-y-auto p-6 scrollbar-thin">
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
            <Route path="/comparison" element={<ComparisonPage />} />
            <Route path="/assets" element={<AssetsPage />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
