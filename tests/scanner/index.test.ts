import { describe, it, expect } from "vitest";
import {
  calculateRiskScore,
  riskLevel,
  generateSummary,
} from "@/convex/scanner/scanners/index";
import type { Finding, Platform } from "@/convex/scanner/scanners/types";

function makeFinding(
  severity: Finding["severity"],
  confidence: Finding["confidence"] = "high"
): Finding {
  return {
    category: "code_injection",
    ruleId: "TEST001",
    severity,
    confidence,
    title: "Test finding",
    description: "Test description",
  };
}

describe("calculateRiskScore", () => {
  it("returns 0 for empty findings", () => {
    expect(calculateRiskScore([])).toBe(0);
  });

  it("returns 0 for info-only findings", () => {
    expect(calculateRiskScore([makeFinding("info")])).toBe(0);
  });

  it("scores 25 for single critical/high-confidence finding", () => {
    expect(calculateRiskScore([makeFinding("critical", "high")])).toBe(25);
  });

  it("scores 13 for single critical/medium-confidence finding", () => {
    // 25 * 0.5 = 12.5, rounded to 13
    expect(calculateRiskScore([makeFinding("critical", "medium")])).toBe(13);
  });

  it("scores 6 for single critical/low-confidence finding", () => {
    // 25 * 0.25 = 6.25, rounded to 6
    expect(calculateRiskScore([makeFinding("critical", "low")])).toBe(6);
  });

  it("scores 10 for single high-severity finding", () => {
    expect(calculateRiskScore([makeFinding("high")])).toBe(10);
  });

  it("scores 3 for single medium-severity finding", () => {
    expect(calculateRiskScore([makeFinding("medium")])).toBe(3);
  });

  it("scores 1 for single low-severity finding", () => {
    expect(calculateRiskScore([makeFinding("low")])).toBe(1);
  });

  it("accumulates scores from multiple findings", () => {
    const findings = [
      makeFinding("critical"), // 25
      makeFinding("high"),     // 10
      makeFinding("medium"),   // 3
    ];
    expect(calculateRiskScore(findings)).toBe(38);
  });

  it("caps at 100", () => {
    const findings = Array(10).fill(makeFinding("critical")); // 10 * 25 = 250
    expect(calculateRiskScore(findings)).toBe(100);
  });

  it("never returns negative", () => {
    expect(calculateRiskScore([])).toBeGreaterThanOrEqual(0);
  });
});

describe("riskLevel", () => {
  it("maps 0 to safe", () => {
    expect(riskLevel(0)).toBe("safe");
  });

  it("maps 1-10 to low", () => {
    expect(riskLevel(1)).toBe("low");
    expect(riskLevel(10)).toBe("low");
  });

  it("maps 11-30 to medium", () => {
    expect(riskLevel(11)).toBe("medium");
    expect(riskLevel(30)).toBe("medium");
  });

  it("maps 31-60 to high", () => {
    expect(riskLevel(31)).toBe("high");
    expect(riskLevel(60)).toBe("high");
  });

  it("maps 61+ to critical", () => {
    expect(riskLevel(61)).toBe("critical");
    expect(riskLevel(100)).toBe("critical");
  });
});

describe("generateSummary", () => {
  it("reports no issues for empty findings", () => {
    const summary = generateSummary([], "claude_code", 0);
    expect(summary).toContain("No security issues");
    expect(summary).toContain("claude code");
    expect(summary).toContain("0/100");
  });

  it("formats finding counts by severity", () => {
    const findings = [
      makeFinding("critical"),
      makeFinding("critical"),
      makeFinding("high"),
      makeFinding("medium"),
    ];
    const summary = generateSummary(findings, "cursor", 38);
    expect(summary).toContain("4 issues");
    expect(summary).toContain("2 critical");
    expect(summary).toContain("1 high");
    expect(summary).toContain("1 medium");
    expect(summary).toContain("cursor");
  });

  it("shows unknown platform label", () => {
    const summary = generateSummary([], "unknown", 0);
    expect(summary).toContain("unknown platform");
  });

  it("includes risk level", () => {
    const summary = generateSummary([makeFinding("critical")], "agentskills", 25);
    expect(summary).toContain("medium");
    expect(summary).toContain("25/100");
  });
});
