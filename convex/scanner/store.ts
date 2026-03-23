import { v } from "convex/values";
import { internalMutation } from "../_generated/server";

function generateSlug(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let slug = "";
  for (let i = 0; i < 8; i++) {
    slug += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return slug;
}

export const updateScanStatus = internalMutation({
  args: {
    scanId: v.id("scans"),
    status: v.union(
      v.literal("pending"),
      v.literal("cloning"),
      v.literal("scanning"),
      v.literal("triage"),
      v.literal("analyzing"),
      v.literal("complete"),
      v.literal("failed")
    ),
    errorMessage: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const update: Record<string, unknown> = { status: args.status };
    if (args.errorMessage !== undefined) {
      update.errorMessage = args.errorMessage;
    }
    await ctx.db.patch(args.scanId, update);
  },
});

export const batchInsertFindings = internalMutation({
  args: {
    findings: v.array(
      v.object({
        scanId: v.id("scans"),
        category: v.union(
          v.literal("standard_compliance"),
          v.literal("prompt_injection"),
          v.literal("credential_access"),
          v.literal("network_exfiltration"),
          v.literal("dangerous_operations"),
          v.literal("code_injection"),
          v.literal("obfuscation"),
          v.literal("dependency_risks"),
          v.literal("bundled_payloads"),
          v.literal("external_links"),
          v.literal("ai_semantic"),
          v.literal("cross_platform"),
          v.literal("secrets_detection"),
          v.literal("dependency_audit")
        ),
        ruleId: v.string(),
        severity: v.union(
          v.literal("info"),
          v.literal("low"),
          v.literal("medium"),
          v.literal("high"),
          v.literal("critical")
        ),
        confidence: v.union(
          v.literal("high"),
          v.literal("medium"),
          v.literal("low")
        ),
        title: v.string(),
        description: v.string(),
        filePath: v.optional(v.string()),
        lineNumber: v.optional(v.number()),
        matchedPattern: v.optional(v.string()),
        snippet: v.optional(v.string()),
        dismissed: v.optional(v.boolean()),
        dismissReason: v.optional(v.string()),
      })
    ),
  },
  handler: async (ctx, args) => {
    for (const finding of args.findings) {
      await ctx.db.insert("scanFindings", finding);
    }
  },
});

export const batchInsertLinks = internalMutation({
  args: {
    links: v.array(
      v.object({
        scanId: v.id("scans"),
        url: v.string(),
        domain: v.string(),
        filePath: v.string(),
        lineNumber: v.optional(v.number()),
        classification: v.union(
          v.literal("safe"),
          v.literal("unknown"),
          v.literal("suspicious")
        ),
        context: v.optional(v.string()),
      })
    ),
  },
  handler: async (ctx, args) => {
    for (const link of args.links) {
      await ctx.db.insert("scanLinks", link);
    }
  },
});

export const completeScan = internalMutation({
  args: {
    scanId: v.id("scans"),
    platform: v.optional(
      v.union(
        v.literal("claude_code"),
        v.literal("openclaw"),
        v.literal("cursor"),
        v.literal("windsurf"),
        v.literal("cline"),
        v.literal("agentskills"),
        v.literal("unknown")
      )
    ),
    overallRisk: v.union(
      v.literal("safe"),
      v.literal("low"),
      v.literal("medium"),
      v.literal("high"),
      v.literal("critical")
    ),
    riskScore: v.number(),
    adjustedRiskScore: v.optional(v.number()),
    verdict: v.optional(
      v.union(
        v.literal("SAFE TO USE"),
        v.literal("USE WITH CAUTION"),
        v.literal("DO NOT USE")
      )
    ),
    verdictReason: v.optional(v.string()),
    summary: v.string(),
    aiReviewSummary: v.optional(v.string()),
    fileCount: v.number(),
    totalFindings: v.number(),
    scanDurationMs: v.number(),
    commitHash: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const update: Record<string, unknown> = {
      status: "complete",
      platform: args.platform,
      overallRisk: args.overallRisk,
      riskScore: args.riskScore,
      summary: args.summary,
      aiReviewSummary: args.aiReviewSummary,
      fileCount: args.fileCount,
      totalFindings: args.totalFindings,
      scanDurationMs: args.scanDurationMs,
      commitHash: args.commitHash,
    };
    if (args.adjustedRiskScore !== undefined) {
      update.adjustedRiskScore = args.adjustedRiskScore;
    }
    if (args.verdict !== undefined) {
      update.verdict = args.verdict;
    }
    if (args.verdictReason !== undefined) {
      update.verdictReason = args.verdictReason;
    }
    await ctx.db.patch(args.scanId, update);
  },
});

export const createChildScan = internalMutation({
  args: {
    collectionId: v.id("scans"),
    url: v.string(),
    repoOwner: v.string(),
    repoName: v.string(),
    repoPath: v.string(),
    branch: v.optional(v.string()),
    userId: v.optional(v.id("users")),
    skillName: v.string(),
    skillPath: v.string(),
  },
  handler: async (ctx, args) => {
    const shareSlug = generateSlug();
    const scanId = await ctx.db.insert("scans", {
      url: args.url,
      repoOwner: args.repoOwner,
      repoName: args.repoName,
      repoPath: args.repoPath,
      branch: args.branch,
      userId: args.userId,
      status: "pending",
      shareSlug,
      collectionId: args.collectionId,
      skillName: args.skillName,
      skillPath: args.skillPath,
    });
    return { scanId, shareSlug };
  },
});

export const completeCollection = internalMutation({
  args: {
    scanId: v.id("scans"),
    overallRisk: v.union(
      v.literal("safe"),
      v.literal("low"),
      v.literal("medium"),
      v.literal("high"),
      v.literal("critical")
    ),
    riskScore: v.number(),
    summary: v.string(),
    fileCount: v.number(),
    totalFindings: v.number(),
    scanDurationMs: v.number(),
    commitHash: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    await ctx.db.patch(args.scanId, {
      status: "complete",
      overallRisk: args.overallRisk,
      riskScore: args.riskScore,
      summary: args.summary,
      fileCount: args.fileCount,
      totalFindings: args.totalFindings,
      scanDurationMs: args.scanDurationMs,
      commitHash: args.commitHash,
    });
  },
});
