import { v } from "convex/values";
import { mutation, internalMutation } from "../_generated/server";
import { internal } from "../_generated/api";
import { getCurrentUserOrThrowForMutation } from "../users";

const FREE_SCAN_LIMIT = 5;

function generateSlug(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let slug = "";
  for (let i = 0; i < 8; i++) {
    slug += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return slug;
}

function parseGitHubUrl(url: string): {
  owner: string;
  repo: string;
  path?: string;
  branch?: string;
} | null {
  // Strip query params, fragments, trailing slashes
  let cleaned = url.split("?")[0].split("#")[0].replace(/\/+$/, "");

  // Reject embedded credentials
  if (cleaned.includes("@") && !cleaned.includes("github.com")) return null;

  const match = cleaned.match(
    /^https:\/\/github\.com\/([a-zA-Z0-9._-]+)\/([a-zA-Z0-9._-]+)(?:\/(?:tree|blob)\/([^/]+)(?:\/(.+))?)?$/
  );
  if (!match) {
    // Try simple owner/repo pattern
    const simple = cleaned.match(
      /^https:\/\/github\.com\/([a-zA-Z0-9._-]+)\/([a-zA-Z0-9._-]+)$/
    );
    if (!simple) return null;
    return { owner: simple[1], repo: simple[2] };
  }

  return {
    owner: match[1],
    repo: match[2],
    branch: match[3],
    path: match[4],
  };
}

export const submitScan = mutation({
  args: {
    url: v.string(),
  },
  handler: async (ctx, args) => {
    const url = args.url.trim();

    // Validate URL
    if (!url.startsWith("https://github.com/")) {
      throw new Error("Only GitHub HTTPS URLs are supported");
    }

    // Reject path traversal
    if (url.includes("..")) {
      throw new Error("Invalid URL: path traversal detected");
    }

    // Reject embedded credentials
    const urlWithoutProtocol = url.replace("https://", "");
    if (urlWithoutProtocol.includes("@")) {
      throw new Error("Invalid URL: embedded credentials detected");
    }

    const parsed = parseGitHubUrl(url);
    if (!parsed) {
      throw new Error("Invalid GitHub URL format. Expected: https://github.com/{owner}/{repo}");
    }

    // If URL pointed to a specific file (via /blob/), navigate up to the parent directory
    if (parsed.path && /\.\w+$/.test(parsed.path)) {
      const parentDir = parsed.path.replace(/\/[^/]+$/, "");
      parsed.path = parentDir || undefined;
    }

    // Require authentication
    const user = await getCurrentUserOrThrowForMutation(ctx);

    // Enforce free scan limit for non-admin users
    const adminEmail = process.env.ADMIN_EMAIL;
    const isAdmin = adminEmail && user.email?.toLowerCase() === adminEmail.toLowerCase();
    if (!isAdmin) {
      const userScans = await ctx.db
        .query("scans")
        .withIndex("by_userId", (q) => q.eq("userId", user._id))
        .collect();
      if (userScans.length >= FREE_SCAN_LIMIT) {
        throw new Error(
          `Free scan limit reached (${FREE_SCAN_LIMIT} scans). Upgrade to a paid plan to continue scanning.`
        );
      }
    }

    // Dedup: same URL within 5 minutes returns existing scan
    const fiveMinAgo = Date.now() - 5 * 60 * 1000;
    const existing = await ctx.db
      .query("scans")
      .withIndex("by_url", (q) => q.eq("url", url))
      .order("desc")
      .first();

    if (existing && existing._creationTime > fiveMinAgo && existing.status !== "failed") {
      return { scanId: existing._id, shareSlug: existing.shareSlug };
    }

    const shareSlug = generateSlug();

    const scanId = await ctx.db.insert("scans", {
      url,
      repoOwner: parsed.owner,
      repoName: parsed.repo,
      repoPath: parsed.path,
      branch: parsed.branch,
      userId: user._id,
      status: "pending",
      shareSlug,
    });

    // Schedule the collection-aware pipeline (handles both single and multi-skill repos)
    await ctx.scheduler.runAfter(
      0,
      internal.scanner.collectionPipeline.runCollectionScan,
      { scanId }
    );

    return { scanId, shareSlug };
  },
});

export const deleteScan = mutation({
  args: { scanId: v.id("scans") },
  handler: async (ctx, args) => {
    const user = await getCurrentUser(ctx);
    if (!user) throw new Error("Authentication required");

    const scan = await ctx.db.get(args.scanId);
    if (!scan) throw new Error("Scan not found");
    if (scan.userId !== user._id) throw new Error("Not authorized");

    // Delete child scans if this is a collection
    const children = await ctx.db
      .query("scans")
      .withIndex("by_collectionId", (q) => q.eq("collectionId", args.scanId))
      .collect();
    for (const child of children) {
      // Delete child findings
      const childFindings = await ctx.db
        .query("scanFindings")
        .withIndex("by_scanId", (q) => q.eq("scanId", child._id))
        .collect();
      for (const f of childFindings) await ctx.db.delete(f._id);
      // Delete child links
      const childLinks = await ctx.db
        .query("scanLinks")
        .withIndex("by_scanId", (q) => q.eq("scanId", child._id))
        .collect();
      for (const l of childLinks) await ctx.db.delete(l._id);
      await ctx.db.delete(child._id);
    }

    // Delete findings
    const findings = await ctx.db
      .query("scanFindings")
      .withIndex("by_scanId", (q) => q.eq("scanId", args.scanId))
      .collect();
    for (const f of findings) {
      await ctx.db.delete(f._id);
    }

    // Delete links
    const links = await ctx.db
      .query("scanLinks")
      .withIndex("by_scanId", (q) => q.eq("scanId", args.scanId))
      .collect();
    for (const l of links) {
      await ctx.db.delete(l._id);
    }

    // Delete scan
    await ctx.db.delete(args.scanId);
  },
});
