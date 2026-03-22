/**
 * AI First Review Integration Tests
 *
 * These tests call the real LLM API and measure detection accuracy.
 * They require OPENAI_API_KEY (or equivalent) in the environment.
 *
 * Run with: npm run test:ai
 *
 * NOTE: These tests are slow (30-60s per case) and cost money.
 * They are excluded from the default test run.
 */

import { config as dotenvConfig } from "dotenv";
dotenvConfig({ path: ".env.local" });

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { aiFirstReview, AiConfig } from "@/convex/scanner/scanners/aiFirstReview";
import { runPreFilter } from "@/convex/scanner/scanners/preFilter";
import { makeFile, makeContext } from "../../helpers/fixtures";
import { AI_TEST_CORPUS, MetricsCollector, AiTestMetrics } from "../../helpers/metrics";
import type { ScanContext } from "@/convex/scanner/scanners/types";

// Read LLM config from .env.local (same keys the app uses)
const apiKey = process.env.LLM_API_KEY || process.env.OPENAI_API_KEY || "";
const shouldSkip = !apiKey;

const config: AiConfig = {
  apiKey,
  baseUrl: process.env.LLM_BASE_URL || "https://api.z.ai/api/paas/v4/",
  model: process.env.LLM_MODEL || "glm-5",
  timeoutMs: Number(process.env.LLM_TIMEOUT_MS) || 120000,
};

const metrics = new MetricsCollector();

describe.skipIf(shouldSkip)("AI First Review — Labeled Corpus", () => {
  afterAll(() => {
    console.log("\n" + metrics.printSummary());
  });

  for (const testCase of AI_TEST_CORPUS) {
    it(
      testCase.name,
      async () => {
        // Build context
        const files = testCase.files.map((f) =>
          makeFile(f.relativePath, f.content)
        );
        const context: ScanContext = makeContext(files);

        // Run pre-filter (needed by AI review)
        const preFilter = await runPreFilter(context);

        // Time the AI review
        const startTime = Date.now();
        const result = await aiFirstReview(context, config, preFilter);
        const latencyMs = Date.now() - startTime;

        // Collect metrics
        const minScore = testCase.expectedMinRiskScore ?? 0;
        const maxScore = testCase.expectedMaxRiskScore ?? 100;

        const falsePositiveCount = testCase.mustNotFlag
          ? result.findings.filter((f) =>
              testCase.mustNotFlag!.some((cat) =>
                f.description.toLowerCase().includes(cat.replace("_", " "))
              )
            ).length
          : 0;

        const missedCategories = testCase.expectedCategories
          ? testCase.expectedCategories.filter(
              (cat) =>
                !result.findings.some(
                  (f) =>
                    f.description.toLowerCase().includes(cat.replace("_", " ")) ||
                    f.title.toLowerCase().includes(cat.replace("_", " "))
                )
            )
          : [];

        const testMetrics: AiTestMetrics = {
          testName: testCase.name,
          expectedVerdict: testCase.expectedVerdict,
          actualVerdict: result.verdict,
          verdictCorrect: result.verdict === testCase.expectedVerdict,
          expectedRiskRange: [minScore, maxScore],
          actualRiskScore: result.riskScore,
          riskInRange:
            result.riskScore >= minScore && result.riskScore <= maxScore,
          falsePositiveCount,
          falseNegativeCount: missedCategories.length,
          missedCategories,
          findingTitles: result.findings.map((f) => f.title),
          latencyMs,
        };

        metrics.record(testMetrics);

        // Assertions
        expect(
          result.verdict,
          `Expected verdict "${testCase.expectedVerdict}" for "${testCase.name}" but got "${result.verdict}". Reason: ${result.verdictReason}`
        ).toBe(testCase.expectedVerdict);

        if (testCase.expectedMinRiskScore !== undefined) {
          expect(
            result.riskScore,
            `Risk score ${result.riskScore} below expected minimum ${testCase.expectedMinRiskScore}`
          ).toBeGreaterThanOrEqual(testCase.expectedMinRiskScore);
        }

        if (testCase.expectedMaxRiskScore !== undefined) {
          expect(
            result.riskScore,
            `Risk score ${result.riskScore} above expected maximum ${testCase.expectedMaxRiskScore}`
          ).toBeLessThanOrEqual(testCase.expectedMaxRiskScore);
        }

        // False positive check
        if (testCase.mustNotFlag) {
          expect(
            falsePositiveCount,
            `Found ${falsePositiveCount} false positives in categories: ${testCase.mustNotFlag.join(", ")}`
          ).toBe(0);
        }
      },
      120000
    );
  }
});
