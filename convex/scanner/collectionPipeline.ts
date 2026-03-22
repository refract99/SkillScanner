"use node";

import { v } from "convex/values";
import { internalAction } from "../_generated/server";
import { internal } from "../_generated/api";
import { Id } from "../_generated/dataModel";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { discoverSkills } from "./discovery";
import {
  downloadAndExtractRepo,
  downloadSubdirectory,
  getDirSizeMB,
  collectFiles,
  runScanPipeline,
  storeScanResults,
  getLLMConfig,
  MAX_REPO_SIZE_MB,
} from "./pipeline";
import { riskLevel } from "./scanners/index";

const ACTION_TIMEOUT_MS = 9 * 60 * 1000; // 9 min safety margin (Convex limit is 10 min)

export const runCollectionScan = internalAction({
  args: {
    scanId: v.id("scans"),
  },
  handler: async (ctx, args) => {
    const startTime = Date.now();
    const randomSuffix = crypto.randomBytes(4).toString("hex");
    const tmpDir = `/tmp/skillscanner-${args.scanId}-${randomSuffix}`;

    try {
      const scan = await ctx.runQuery(
        internal.scanner.queries.internal_getScan,
        { scanId: args.scanId }
      );
      if (!scan) throw new Error("Scan record not found");

      // 1. Download
      await ctx.runMutation(internal.scanner.store.updateScanStatus, {
        scanId: args.scanId,
        status: "cloning",
      });

      let commitHash: string | undefined;
      try {
        if (scan.repoPath) {
          // Sub-path specified: download only that directory via Contents API
          const result = await downloadSubdirectory(
            scan.repoOwner,
            scan.repoName,
            scan.repoPath,
            scan.branch,
            tmpDir
          );
          commitHash = result.commitHash;
        } else {
          // Full repo: download tarball
          const result = await downloadAndExtractRepo(
            scan.repoOwner,
            scan.repoName,
            scan.branch,
            tmpDir
          );
          commitHash = result.commitHash;

          const totalSize = getDirSizeMB(tmpDir);
          if (totalSize > MAX_REPO_SIZE_MB) {
            throw new Error(
              `Repository is ${Math.round(totalSize)}MB, exceeding the ${MAX_REPO_SIZE_MB}MB limit`
            );
          }
        }
      } catch (dlErr) {
        const msg = dlErr instanceof Error ? dlErr.message : "Download failed";
        if (msg.includes("abort")) {
          throw new Error("Repository download timed out (30s limit)");
        }
        throw dlErr;
      }

      // 2. Discover skills
      await ctx.runMutation(internal.scanner.store.updateScanStatus, {
        scanId: args.scanId,
        status: "scanning",
      });

      // For sub-path downloads, tmpDir IS the scan root (files already extracted there)
      // For full-repo downloads, navigate to sub-path if specified
      const baseDir = tmpDir;

      const skills = discoverSkills(baseDir);

      // If 0-1 skills, run as a normal single scan
      if (skills.length === 0) {
        const statusCallback = async (status: string) => {
          await ctx.runMutation(internal.scanner.store.updateScanStatus, {
            scanId: args.scanId,
            status: status as "scanning" | "triage" | "analyzing",
          });
        };
        const results = await runScanPipeline(baseDir, tmpDir, getLLMConfig(), statusCallback);
        await storeScanResults(ctx, args.scanId, results, startTime, commitHash);
        return;
      }

      // 3. Multi-skill collection scan
      const llmConfig = getLLMConfig();
      const childResults: Array<{
        skillName: string;
        scanId: Id<"scans">;
        riskScore: number;
        risk: string;
        totalFindings: number;
        fileCount: number;
      }> = [];

      for (const skill of skills) {
        // Timeout safety check
        if (Date.now() - startTime > ACTION_TIMEOUT_MS) {
          break;
        }

        // Create child scan record
        const childResult = await ctx.runMutation(
          internal.scanner.store.createChildScan,
          {
            collectionId: args.scanId,
            url: scan.url,
            repoOwner: scan.repoOwner,
            repoName: scan.repoName,
            repoPath: skill.path,
            branch: scan.branch,
            userId: scan.userId,
            skillName: skill.name,
            skillPath: skill.path,
          }
        );

        const childScanId = childResult.scanId;

        try {
          await ctx.runMutation(internal.scanner.store.updateScanStatus, {
            scanId: childScanId,
            status: "scanning",
          });

          const skillRoot = path.join(baseDir, skill.path);
          if (!fs.existsSync(skillRoot)) {
            throw new Error(`Skill directory not found: ${skill.path}`);
          }

          const childStatusCallback = async (status: string) => {
            await ctx.runMutation(internal.scanner.store.updateScanStatus, {
              scanId: childScanId,
              status: status as "scanning" | "triage" | "analyzing",
            });
          };
          const results = await runScanPipeline(skillRoot, skillRoot, llmConfig, childStatusCallback);
          await storeScanResults(
            ctx,
            childScanId,
            results,
            startTime,
            commitHash
          );

          childResults.push({
            skillName: skill.name,
            scanId: childScanId,
            riskScore: results.riskScore,
            risk: results.risk,
            totalFindings: results.findings.length,
            fileCount: results.fileCount,
          });
        } catch (childErr) {
          const msg =
            childErr instanceof Error ? childErr.message : "Unknown error";
          await ctx.runMutation(internal.scanner.store.updateScanStatus, {
            scanId: childScanId,
            status: "failed",
            errorMessage: msg.substring(0, 1000),
          });
          // Continue with other skills
          childResults.push({
            skillName: skill.name,
            scanId: childScanId,
            riskScore: 0,
            risk: "safe",
            totalFindings: 0,
            fileCount: 0,
          });
        }
      }

      // 4. Aggregate and complete parent
      const maxRiskScore = Math.max(
        ...childResults.map((c) => c.riskScore),
        0
      );
      const totalFindings = childResults.reduce(
        (sum, c) => sum + c.totalFindings,
        0
      );
      const totalFiles = childResults.reduce(
        (sum, c) => sum + c.fileCount,
        0
      );

      const worstSkill = childResults.reduce(
        (worst, c) => (c.riskScore > worst.riskScore ? c : worst),
        childResults[0]
      );

      const scannedCount = childResults.length;
      const timedOut = scannedCount < skills.length;
      const summaryParts = [
        `Collection of ${skills.length} skills.`,
        `Scanned ${scannedCount}${timedOut ? ` of ${skills.length}` : ""}.`,
        `Highest risk: ${worstSkill.skillName} (${worstSkill.riskScore}/100).`,
        `Total findings: ${totalFindings}.`,
      ];
      if (timedOut) {
        summaryParts.push(
          `${skills.length - scannedCount} skills skipped due to timeout.`
        );
      }

      await ctx.runMutation(internal.scanner.store.completeCollection, {
        scanId: args.scanId,
        overallRisk: riskLevel(maxRiskScore),
        riskScore: maxRiskScore,
        summary: summaryParts.join(" "),
        fileCount: totalFiles,
        totalFindings,
        scanDurationMs: Date.now() - startTime,
        commitHash,
      });
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      await ctx.runMutation(internal.scanner.store.updateScanStatus, {
        scanId: args.scanId,
        status: "failed",
        errorMessage: errorMessage.substring(0, 1000),
      });
    } finally {
      try {
        if (fs.existsSync(tmpDir)) {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        }
      } catch {
        // Best effort cleanup
      }
    }
  },
});
