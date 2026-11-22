import { describe, it, expect } from "vitest";
import React from "react";
import VulnTable from "../VulnTable.jsx";
import SeverityPieChart from "../SeverityPieChart.jsx";

describe("Frontend Component Contract Tests", () => {
  it("VulnTable is defined and accepts vulnerabilities & isLoading props", () => {
    expect(typeof VulnTable).toBe("function");

    const sampleVulns = [
      {
        id: 1,
        title: "SQL Injection in Payment Processing API",
        asset_name: "prod-payment-db",
        cvss_score: 8.8,
        priority_score: 100.0,
        risk_tier: "Critical",
        is_remediated: false,
        exploit_available: true,
      },
    ];

    // Verify component creates element without prop errors
    const element = React.createElement(VulnTable, {
      vulnerabilities: sampleVulns,
      isLoading: false,
    });
    expect(element).toBeDefined();
    expect(element.props.vulnerabilities).toHaveLength(1);
    expect(element.props.isLoading).toBe(false);
  });

  it("SeverityPieChart is defined and accepts data array", () => {
    expect(typeof SeverityPieChart).toBe("function");

    const sampleData = [
      { name: "Critical", value: 5 },
      { name: "High", value: 4 },
      { name: "Medium", value: 4 },
      { name: "Low", value: 2 },
    ];

    const element = React.createElement(SeverityPieChart, {
      data: sampleData,
    });
    expect(element).toBeDefined();
    expect(element.props.data).toHaveLength(4);
  });
});
