import { Finding } from "./types";

/**
 * Weighted Aggregation Scoring
 *
 * Combines findings from all scanner sources using per-source weights,
 * with boosts for secrets and CVE severity. Backward-compatible: scans
 * lacking new finding types simply contribute zero from those sources.
 */

// Source weights by finding category
const SOURCE_WEIGHTS: Record<string, number> = {
  // Hard-stop categories (weight 1.0)
  prompt_injection: 1.0,
  credential_access: 1.0,
  network_exfiltration: 1.0,
  dangerous_operations: 1.0,
  code_injection: 1.0,
  obfuscation: 1.0,
  bundled_payloads: 1.0,
  // Secrets detection (weight 0.9)
  secrets_detection: 0.9,
  // Dependency audit (weight 0.8)
  dependency_audit: 0.8,
  // Code pattern findings (weight 0.7)
  dependency_risks: 0.7,
  standard_compliance: 0.7,
  cross_platform: 0.7,
  // AI semantic findings (weight 0.5)
  ai_semantic: 0.5,
  // External links (weight 0.3)
  external_links: 0.3,
};

const SEVERITY_BASE: Record<string, number> = {
  critical: 25,
  high: 10,
  medium: 3,
  low: 1,
  info: 0,
};

const CONFIDENCE_MULTIPLIER: Record<string, number> = {
  high: 1.0,
  medium: 0.5,
  low: 0.25,
};

export interface AggregatedScore {
  /** Final weighted risk score 0-100 */
  score: number;
  /** Per-source contribution breakdown */
  sourceBreakdown: SourceContribution[];
  /** Whether the secrets minimum-score boost was applied */
  secretsBoostApplied: boolean;
  /** Total CVE boost points added */
  cveBoostTotal: number;
}

export interface SourceContribution {
  source: string;
  label: string;
  weight: number;
  rawPoints: number;
  weightedPoints: number;
  findingCount: number;
}

/** Human-readable labels for scanner sources */
const SOURCE_LABELS: Record<string, string> = {
  prompt_injection: "Hard-stop",
  credential_access: "Hard-stop",
  network_exfiltration: "Hard-stop",
  dangerous_operations: "Hard-stop",
  code_injection: "Hard-stop",
  obfuscation: "Hard-stop",
  bundled_payloads: "Hard-stop",
  secrets_detection: "Secrets Detection",
  dependency_audit: "Dependency Audit",
  dependency_risks: "Code Patterns",
  standard_compliance: "Code Patterns",
  cross_platform: "Code Patterns",
  ai_semantic: "AI Semantic",
  external_links: "External Links",
};

/**
 * Aggregate findings into a weighted risk score.
 *
 * Applies per-source weights, secrets minimum-score boost, and CVE severity boosts.
 * Backward compatible: if no secrets or dependency findings exist, those simply
 * contribute zero and the score relies on the other sources.
 */
export function aggregateResults(findings: Finding[]): AggregatedScore {
  // Group findings by category
  const byCategory: Record<string, Finding[]> = {};
  for (const f of findings) {
    const cat = f.category;
    if (!byCategory[cat]) byCategory[cat] = [];
    byCategory[cat].push(f);
  }

  // Calculate per-source contributions
  const contributionMap: Record<string, SourceContribution> = {};
  let totalWeightedPoints = 0;

  for (const [category, catFindings] of Object.entries(byCategory)) {
    const weight = SOURCE_WEIGHTS[category] ?? 0.5;
    const label = SOURCE_LABELS[category] ?? category;

    // Merge hard-stop categories into a single "Hard-stop" bucket for display
    const bucketKey = label === "Hard-stop" ? "hard_stop" : category;

    if (!contributionMap[bucketKey]) {
      contributionMap[bucketKey] = {
        source: bucketKey,
        label,
        weight,
        rawPoints: 0,
        weightedPoints: 0,
        findingCount: 0,
      };
    }

    const bucket = contributionMap[bucketKey];

    for (const f of catFindings) {
      const base = SEVERITY_BASE[f.severity] ?? 0;
      const confMult = CONFIDENCE_MULTIPLIER[f.confidence] ?? 0.5;
      const raw = base * confMult;
      bucket.rawPoints += raw;
      bucket.weightedPoints += raw * weight;
      bucket.findingCount++;
    }

    totalWeightedPoints += bucket.weightedPoints - (contributionMap[bucketKey] === bucket ? 0 : bucket.weightedPoints);
  }

  // Recalculate total from all buckets
  totalWeightedPoints = Object.values(contributionMap).reduce(
    (sum, c) => sum + c.weightedPoints,
    0
  );

  let score = Math.round(totalWeightedPoints);

  // CVE boost: critical CVE = +20, high = +10, medium = +5
  let cveBoostTotal = 0;
  const depFindings = byCategory["dependency_audit"] || [];
  for (const f of depFindings) {
    if (f.ruleId === "DA001") {
      if (f.severity === "critical") cveBoostTotal += 20;
      else if (f.severity === "high") cveBoostTotal += 10;
      else if (f.severity === "medium") cveBoostTotal += 5;
    }
  }
  score += cveBoostTotal;

  // Secrets boost: if any high/critical secrets found, minimum risk score = 60
  let secretsBoostApplied = false;
  const secretsFindings = byCategory["secrets_detection"] || [];
  const hasHighSecrets = secretsFindings.some(
    (f) => f.severity === "critical" || f.severity === "high"
  );
  if (hasHighSecrets && score < 60) {
    score = 60;
    secretsBoostApplied = true;
  }

  score = Math.min(100, Math.max(0, score));

  const sourceBreakdown = Object.values(contributionMap)
    .filter((c) => c.findingCount > 0)
    .sort((a, b) => b.weightedPoints - a.weightedPoints);

  return {
    score,
    sourceBreakdown,
    secretsBoostApplied,
    cveBoostTotal,
  };
}
