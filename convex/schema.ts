import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";
import { paymentAttemptSchemaValidator } from "./paymentAttemptTypes";

export default defineSchema({
    users: defineTable({
      name: v.string(),
      // this the Clerk ID, stored in the subject JWT field
      externalId: v.string(),
      // Primary email from Clerk
      email: v.optional(v.string()),
    })
      .index("byExternalId", ["externalId"])
      .index("byEmail", ["email"]),

    paymentAttempts: defineTable(paymentAttemptSchemaValidator)
      .index("byPaymentId", ["payment_id"])
      .index("byUserId", ["userId"])
      .index("byPayerUserId", ["payer.user_id"]),

    // Security monitoring table
    // userId is optional to allow logging violations from unauthenticated requests
    securityEvents: defineTable({
      userId: v.optional(v.id("users")),
      eventType: v.union(
        v.literal("origin_mismatch"),
        v.literal("rate_limit_exceeded"),
        v.literal("invalid_api_key"),
        v.literal("fingerprint_change"),
        v.literal("suspicious_activity"),
        v.literal("jwt_validation_failed"),
        v.literal("unauthorized_access"),
        v.literal("input_validation_failed"),
        v.literal("replay_detected"),
        v.literal("not_found_enumeration"),
        v.literal("jwt_algorithm_attack"),
        v.literal("tenant_isolation_attack"),
        v.literal("jwt_replay_attack"),
        v.literal("xss_attempt"),
        v.literal("fingerprint_manipulation"),
        v.literal("http_origin_blocked"),
        v.literal("prompt_injection_attempt"),
        v.literal("ai_response_validation_failed"),
        v.literal("csrf_validation_failed")
      ),
      severity: v.union(
        v.literal("low"),
        v.literal("medium"),
        v.literal("high"),
        v.literal("critical")
      ),
      metadata: v.object({
        origin: v.optional(v.string()),
        ipAddress: v.optional(v.string()),
        fingerprint: v.optional(v.string()),
        endpoint: v.optional(v.string()),
        errorMessage: v.optional(v.string()),
        endUserEmail: v.optional(v.string()),
        endUserName: v.optional(v.string()),
        endUserId: v.optional(v.string()),
        actionType: v.optional(v.string()),
        requestPayload: v.optional(v.string()),
      }),
      timestamp: v.number(),
      isRead: v.boolean(),
    })
      .index("byUser", ["userId", "timestamp"])
      .index("bySeverity", ["userId", "severity", "timestamp"])
      .index("byUnread", ["userId", "isRead", "timestamp"]),

    // SkillScanner tables
    scans: defineTable({
      url: v.string(),
      repoOwner: v.string(),
      repoName: v.string(),
      repoPath: v.optional(v.string()),
      commitHash: v.optional(v.string()),
      branch: v.optional(v.string()),
      userId: v.optional(v.id("users")),
      status: v.union(
        v.literal("pending"),
        v.literal("cloning"),
        v.literal("scanning"),
        v.literal("triage"),
        v.literal("analyzing"),
        v.literal("complete"),
        v.literal("failed")
      ),
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
      overallRisk: v.optional(
        v.union(
          v.literal("safe"),
          v.literal("low"),
          v.literal("medium"),
          v.literal("high"),
          v.literal("critical")
        )
      ),
      riskScore: v.optional(v.number()),
      adjustedRiskScore: v.optional(v.number()),
      verdict: v.optional(
        v.union(
          v.literal("SAFE TO USE"),
          v.literal("USE WITH CAUTION"),
          v.literal("DO NOT USE")
        )
      ),
      verdictReason: v.optional(v.string()),
      summary: v.optional(v.string()),
      aiReviewSummary: v.optional(v.string()),
      fileCount: v.optional(v.number()),
      totalFindings: v.optional(v.number()),
      scanDurationMs: v.optional(v.number()),
      errorMessage: v.optional(v.string()),
      shareSlug: v.string(),
      // Collection support: parent-child relationship for multi-skill repos
      collectionId: v.optional(v.id("scans")),
      skillName: v.optional(v.string()),
      skillPath: v.optional(v.string()),
    })
      .index("by_shareSlug", ["shareSlug"])
      .index("by_userId", ["userId"])
      .index("by_status", ["status"])
      .index("by_url", ["url"])
      .index("by_collectionId", ["collectionId"]),

    scanFindings: defineTable({
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
      .index("by_scanId", ["scanId"])
      .index("by_scanId_category", ["scanId", "category"])
      .index("by_scanId_severity", ["scanId", "severity"]),

    scanLinks: defineTable({
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
      .index("by_scanId", ["scanId"]),
  });