import { v } from "convex/values";
import { internalQuery, query } from "../_generated/server";
import { getCurrentUser } from "../users";

export const internal_getScan = internalQuery({
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    return await ctx.db.get(args.scanId);
  },
});

export const getScanBySlug = query({
  args: { slug: v.string() },
  handler: async (ctx, args) => {
    const scan = await ctx.db
      .query("scans")
      .withIndex("by_shareSlug", (q) => q.eq("shareSlug", args.slug))
      .first();
    return scan;
  },
});

export const getScanFindings = query({
  args: {
    scanId: v.id("scans"),
    category: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    if (args.category) {
      return await ctx.db
        .query("scanFindings")
        .withIndex("by_scanId_category", (q) =>
          q.eq("scanId", args.scanId).eq("category", args.category as never)
        )
        .collect();
    }
    return await ctx.db
      .query("scanFindings")
      .withIndex("by_scanId", (q) => q.eq("scanId", args.scanId))
      .collect();
  },
});

export const getScanLinks = query({
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("scanLinks")
      .withIndex("by_scanId", (q) => q.eq("scanId", args.scanId))
      .collect();
  },
});

export const getScanStatus = query({
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    const scan = await ctx.db.get(args.scanId);
    if (!scan) return null;
    return {
      status: scan.status,
      errorMessage: scan.errorMessage,
      overallRisk: scan.overallRisk,
      riskScore: scan.riskScore,
    };
  },
});

export const getUserScans = query({
  args: {},
  handler: async (ctx) => {
    const user = await getCurrentUser(ctx);
    if (!user) return [];
    return await ctx.db
      .query("scans")
      .withIndex("by_userId", (q) => q.eq("userId", user._id))
      .order("desc")
      .take(100);
  },
});

export const getScanSummaryStats = query({
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    const findings = await ctx.db
      .query("scanFindings")
      .withIndex("by_scanId", (q) => q.eq("scanId", args.scanId))
      .collect();

    const bySeverity: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    const byCategory: Record<string, number> = {};
    let dismissedCount = 0;

    for (const f of findings) {
      if (f.dismissed) {
        dismissedCount++;
        continue;
      }
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
      byCategory[f.category] = (byCategory[f.category] || 0) + 1;
    }

    const activeTotal = findings.length - dismissedCount;
    return { bySeverity, byCategory, total: activeTotal, dismissedCount };
  },
});

export const getCollectionChildren = query({
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("scans")
      .withIndex("by_collectionId", (q) => q.eq("collectionId", args.scanId))
      .collect();
  },
});

export const deleteScan = query({
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    // This is actually a mutation but exposed as query for safety check
    // Real deletion handled by mutation below
    const scan = await ctx.db.get(args.scanId);
    const user = await getCurrentUser(ctx);
    if (!scan || !user || scan.userId !== user._id) return false;
    return true;
  },
});

export const getUserFindingStats = query({
  args: {},
  handler: async (ctx) => {
    const user = await getCurrentUser(ctx);
    if (!user) return [];
    const scans = await ctx.db
      .query("scans")
      .withIndex("by_userId", (q) => q.eq("userId", user._id))
      .collect();
    const scanIds = scans.map((s) => s._id);
    const result: { category: string; severity: string; count: number }[] = [];
    const tally: Record<string, Record<string, number>> = {};
    for (const scanId of scanIds) {
      const findings = await ctx.db
        .query("scanFindings")
        .withIndex("by_scanId", (q) => q.eq("scanId", scanId))
        .collect();
      for (const f of findings) {
        if (f.dismissed) continue;
        if (!tally[f.category]) tally[f.category] = {};
        tally[f.category][f.severity] = (tally[f.category][f.severity] || 0) + 1;
      }
    }
    for (const category of Object.keys(tally)) {
      for (const severity of Object.keys(tally[category])) {
        result.push({ category, severity, count: tally[category][severity] });
      }
    }
    return result;
  },
});
