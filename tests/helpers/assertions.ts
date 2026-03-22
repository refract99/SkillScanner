import { expect } from "vitest";
import type { Finding } from "@/convex/scanner/scanners/types";

export function findingsByRule(findings: Finding[], ruleId: string): Finding[] {
  return findings.filter((f) => f.ruleId === ruleId);
}

export function expectFinding(
  findings: Finding[],
  ruleId: string,
  opts?: { severity?: string; count?: number; category?: string }
): void {
  const matched = findingsByRule(findings, ruleId);
  expect(
    matched.length,
    `Expected finding ${ruleId} but found none. All rules: [${findings.map((f) => f.ruleId).join(", ")}]`
  ).toBeGreaterThan(0);

  if (opts?.count !== undefined) {
    expect(matched.length).toBe(opts.count);
  }
  if (opts?.severity) {
    expect(matched[0].severity).toBe(opts.severity);
  }
  if (opts?.category) {
    expect(matched[0].category).toBe(opts.category);
  }
}

export function expectNoFinding(findings: Finding[], ruleId: string): void {
  const matched = findingsByRule(findings, ruleId);
  expect(
    matched.length,
    `Expected no finding ${ruleId} but found ${matched.length}: ${matched.map((f) => f.title).join(", ")}`
  ).toBe(0);
}

export function expectNoFindings(findings: Finding[]): void {
  expect(
    findings.length,
    `Expected no findings but found ${findings.length}: ${findings.map((f) => `${f.ruleId}: ${f.title}`).join(", ")}`
  ).toBe(0);
}
