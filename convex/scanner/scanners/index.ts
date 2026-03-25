import { ScanContext, ScannerResult, Finding, ExternalLink, Platform } from "./types";
import { PreFilterResult, runPreFilter } from "./preFilter";
import { HardStopResult, runHardStopChecks } from "./hardStops";

export { runPreFilter } from "./preFilter";
export type { PreFilterResult } from "./preFilter";
export { runHardStopChecks } from "./hardStops";
export type { HardStopResult } from "./hardStops";
export { runCodePatternChecks } from "./codePatterns";
export type { CodePatternResult } from "./codePatterns";
export { runSecretsDetection } from "./secretsDetection";
export type { SecretsDetectionResult } from "./secretsDetection";
export { runDependencyAudit } from "./dependencyAudit";
export type { DependencyAuditResult } from "./dependencyAudit";
export { aggregateResults } from "./aggregateResults";
export type { AggregatedScore, SourceContribution } from "./aggregateResults";

/** Calculate risk score from findings. Weights by severity and confidence.
 *  High confidence: full weight. Medium: 50%. Low: 25%. */
export function calculateRiskScore(findings: Finding[]): number {
  const severityWeights: Record<string, number> = {
    critical: 25,
    high: 10,
    medium: 3,
    low: 1,
    info: 0,
  };

  const confidenceMultipliers: Record<string, number> = {
    high: 1.0,
    medium: 0.5,
    low: 0.25,
  };

  let score = 0;
  for (const f of findings) {
    const sevWeight = severityWeights[f.severity] || 0;
    const confMultiplier = confidenceMultipliers[f.confidence] || 0.5;
    score += sevWeight * confMultiplier;
  }

  return Math.min(100, Math.max(0, Math.round(score)));
}

export function riskLevel(
  score: number
): "safe" | "low" | "medium" | "high" | "critical" {
  if (score === 0) return "safe";
  if (score <= 10) return "low";
  if (score <= 30) return "medium";
  if (score <= 60) return "high";
  return "critical";
}

export function generateSummary(
  findings: Finding[],
  platform: Platform,
  riskScore: number
): string {
  const counts: Record<string, number> = {};
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }

  const parts: string[] = [];
  if (counts.critical) parts.push(`${counts.critical} critical`);
  if (counts.high) parts.push(`${counts.high} high`);
  if (counts.medium) parts.push(`${counts.medium} medium`);
  if (counts.low) parts.push(`${counts.low} low`);
  if (counts.info) parts.push(`${counts.info} informational`);

  const level = riskLevel(riskScore);
  const platformName = platform === "unknown" ? "unknown platform" : platform.replace(/_/g, " ");

  if (findings.length === 0) {
    return `No security issues detected in this ${platformName} skill. Risk score: ${riskScore}/100.`;
  }

  return `Found ${findings.length} issues (${parts.join(", ")}) in this ${platformName} skill. Overall risk: ${level} (${riskScore}/100).`;
}
