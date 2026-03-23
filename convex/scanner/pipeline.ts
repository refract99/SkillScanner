"use node";

import { v } from "convex/values";
import { internalAction } from "../_generated/server";
import { internal } from "../_generated/api";
import { FileEntry, ScanContext } from "./scanners/types";
import {
  runPreFilter,
  runHardStopChecks,
  runCodePatternChecks,
  runSecretsDetection,
  calculateRiskScore,
  riskLevel,
  generateSummary,
} from "./scanners/index";
import { aiFirstReview, AiFirstResult } from "./scanners/aiFirstReview";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import * as zlib from "zlib";
import * as tar from "tar";

export const MAX_REPO_SIZE_MB = 50;
export const DOWNLOAD_TIMEOUT_MS = 30000;
export const MAX_FILE_COUNT = 1000;
export const MAX_FILE_SIZE = 512 * 1024; // 512KB per file for reading

/** Download and extract a GitHub repo tarball. Returns commit hash if available. */
export async function downloadAndExtractRepo(
  repoOwner: string,
  repoName: string,
  branch: string | undefined,
  tmpDir: string
): Promise<{ commitHash?: string }> {
  const ref = branch || "HEAD";
  const tarballUrl = `https://api.github.com/repos/${repoOwner}/${repoName}/tarball/${ref}`;
  let commitHash: string | undefined;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DOWNLOAD_TIMEOUT_MS);

  const response = await fetch(tarballUrl, {
    signal: controller.signal,
    headers: getGitHubHeaders(),
    redirect: "follow",
  });
  clearTimeout(timeout);

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error(
        "Repository not found or is private. Only public GitHub repositories are supported."
      );
    }
    throw new Error(
      `GitHub API error: ${response.status} ${response.statusText}`
    );
  }

  const contentLength = response.headers.get("content-length");
  if (contentLength) {
    const sizeMB = parseInt(contentLength, 10) / (1024 * 1024);
    if (sizeMB > MAX_REPO_SIZE_MB) {
      throw new Error(
        `Repository is ${Math.round(sizeMB)}MB, exceeding the ${MAX_REPO_SIZE_MB}MB limit`
      );
    }
  }

  fs.mkdirSync(tmpDir, { recursive: true });

  const arrayBuffer = await response.arrayBuffer();
  const buffer = Buffer.from(arrayBuffer);
  const decompressed = zlib.gunzipSync(buffer);

  const tarPath = `${tmpDir}.tar`;
  fs.writeFileSync(tarPath, decompressed);

  await tar.extract({
    file: tarPath,
    cwd: tmpDir,
    strip: 1,
  });

  fs.unlinkSync(tarPath);

  const contentDisposition = response.headers.get("content-disposition");
  if (contentDisposition) {
    const shaMatch = contentDisposition.match(/[a-f0-9]{40}/);
    if (shaMatch) {
      commitHash = shaMatch[0];
    }
  }

  return { commitHash };
}

function getGitHubHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "SkillScanner/1.0",
  };
  const token = process.env.GITHUB_TOKEN;
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

interface GitHubContentEntry {
  name: string;
  path: string;
  type: "file" | "dir" | "symlink";
  size: number;
  sha: string;
  download_url: string | null;
}

/**
 * Download only a subdirectory from a GitHub repo using the Contents API.
 * Used when repoPath is specified, to avoid downloading the entire repo.
 */
export async function downloadSubdirectory(
  repoOwner: string,
  repoName: string,
  repoPath: string,
  branch: string | undefined,
  tmpDir: string
): Promise<{ commitHash?: string }> {
  fs.mkdirSync(tmpDir, { recursive: true });

  const ref = branch || "HEAD";
  let commitHash: string | undefined;
  let totalSize = 0;
  const maxBytes = MAX_REPO_SIZE_MB * 1024 * 1024;

  // Get the latest commit SHA for this ref
  try {
    const refResponse = await fetch(
      `https://api.github.com/repos/${repoOwner}/${repoName}/commits/${ref}`,
      { headers: getGitHubHeaders() }
    );
    if (refResponse.ok) {
      const refData = await refResponse.json() as { sha: string };
      commitHash = refData.sha;
    }
  } catch {
    // Non-critical, skip
  }

  // Recursively fetch directory contents
  async function fetchDir(dirPath: string, localDir: string, depth: number) {
    if (depth > 10) return;

    const url = `https://api.github.com/repos/${repoOwner}/${repoName}/contents/${dirPath}?ref=${ref}`;
    const response = await fetch(url, { headers: getGitHubHeaders() });

    if (!response.ok) {
      if (response.status === 404) {
        throw new Error(
          "Path not found in repository. Check that the URL path exists."
        );
      }
      throw new Error(
        `GitHub API error: ${response.status} ${response.statusText}`
      );
    }

    const json = await response.json();
    // GitHub returns an object (not array) when the path points to a single file
    const entries: GitHubContentEntry[] = Array.isArray(json) ? json : [json as GitHubContentEntry];

    for (const entry of entries) {
      if (entry.type === "dir") {
        const subDir = path.join(localDir, entry.name);
        fs.mkdirSync(subDir, { recursive: true });
        await fetchDir(entry.path, subDir, depth + 1);
      } else if (entry.type === "file" && entry.download_url) {
        totalSize += entry.size;
        if (totalSize > maxBytes) {
          throw new Error(
            `Subdirectory exceeds ${MAX_REPO_SIZE_MB}MB limit`
          );
        }

        // Only download files we can scan (skip very large files)
        if (entry.size <= MAX_FILE_SIZE) {
          const fileResponse = await fetch(entry.download_url);
          if (fileResponse.ok) {
            const content = await fileResponse.text();
            fs.writeFileSync(path.join(localDir, entry.name), content);
          }
        } else {
          // Create empty placeholder so file is counted
          fs.writeFileSync(path.join(localDir, entry.name), "");
        }
      }
    }
  }

  await fetchDir(repoPath, tmpDir, 0);

  return { commitHash };
}

/** Collect files recursively from a directory for scanning. */
export function collectFiles(
  dir: string,
  rootDir: string,
  fileList: FileEntry[] = [],
  depth = 0
): FileEntry[] {
  if (depth > 10 || fileList.length >= MAX_FILE_COUNT) return fileList;

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return fileList;
  }

  for (const entry of entries) {
    if (fileList.length >= MAX_FILE_COUNT) break;

    const fullPath = path.join(dir, entry.name);
    const relativePath = path.relative(rootDir, fullPath);

    if (entry.name === ".git") continue;
    if (entry.name === "node_modules") continue;
    if (!fullPath.startsWith(rootDir)) continue;

    const isSymlink = entry.isSymbolicLink();

    if (entry.isDirectory() && !isSymlink) {
      collectFiles(fullPath, rootDir, fileList, depth + 1);
    } else if (entry.isFile() || isSymlink) {
      try {
        const stats = fs.lstatSync(fullPath);
        let content = "";

        if (!isSymlink && stats.size <= MAX_FILE_SIZE) {
          try {
            content = fs.readFileSync(fullPath, "utf-8");
          } catch {
            // Binary or unreadable file
          }
        }

        fileList.push({
          relativePath,
          absolutePath: fullPath,
          content,
          size: stats.size,
          isSymlink,
        });
      } catch {
        // Skip unreadable files
      }
    }
  }

  return fileList;
}

export function getDirSizeMB(dir: string): number {
  let totalBytes = 0;
  function walk(d: string) {
    try {
      const entries = fs.readdirSync(d, { withFileTypes: true });
      for (const entry of entries) {
        const full = path.join(d, entry.name);
        if (entry.isDirectory() && !entry.isSymbolicLink()) {
          walk(full);
        } else if (entry.isFile()) {
          try {
            totalBytes += fs.statSync(full).size;
          } catch {
            // skip
          }
        }
      }
    } catch {
      // skip
    }
  }
  walk(dir);
  return totalBytes / (1024 * 1024);
}

/** Get LLM config from environment variables. */
export function getLLMConfig() {
  return {
    apiKey: process.env.LLM_API_KEY,
    baseUrl: process.env.LLM_BASE_URL || "https://openrouter.ai/api/v1",
    model: process.env.LLM_MODEL || "anthropic/claude-sonnet-4",
    timeoutMs: parseInt(process.env.LLM_TIMEOUT_MS || "30000", 10),
  };
}

/** Calculate a hard-stop boost to add to the AI risk score */
function hardStopBoost(hardStopFindings: { severity: string }[]): number {
  let boost = 0;
  for (const f of hardStopFindings) {
    if (f.severity === "critical") boost += 25;
    else if (f.severity === "high") boost += 10;
    else if (f.severity === "medium") boost += 3;
  }
  return boost;
}

/** Escalate verdict when hard-stops are present */
function escalateVerdict(
  aiVerdict: "SAFE TO USE" | "USE WITH CAUTION" | "DO NOT USE"
): "SAFE TO USE" | "USE WITH CAUTION" | "DO NOT USE" {
  if (aiVerdict === "SAFE TO USE") return "USE WITH CAUTION";
  return aiVerdict;
}

export type StatusCallback = (status: string) => Promise<void>;

/** Run the full scan pipeline for a single scan root. Returns results for storage. */
export async function runScanPipeline(
  scanRoot: string,
  rootDir: string,
  llmConfig: { apiKey?: string; baseUrl: string; model: string; timeoutMs: number },
  onStatus?: StatusCallback
) {
  const files = collectFiles(scanRoot, rootDir);
  const context: ScanContext = { rootDir: scanRoot, files };

  // Stage 1: Pre-filter (fast, factual metadata)
  const preFilter = await runPreFilter(context);

  // Stage 2: Hard-stops + code pattern checks + secrets detection (deterministic, non-dismissable)
  const [hardStops, codePatterns, secretsResult] = await Promise.all([
    runHardStopChecks(context),
    runCodePatternChecks(context),
    runSecretsDetection(context),
  ]);

  // Stage 3: AI-first analysis
  let aiResult: AiFirstResult | null = null;
  if (llmConfig.apiKey) {
    try {
      aiResult = await aiFirstReview(
        context,
        {
          apiKey: llmConfig.apiKey,
          baseUrl: llmConfig.baseUrl,
          model: llmConfig.model,
          timeoutMs: llmConfig.timeoutMs,
        },
        preFilter,
        onStatus
      );
    } catch {
      // AI unavailable — aiResult stays null
    }
  }

  // Combine findings
  const allFindings = [
    ...hardStops.findings,
    ...codePatterns.findings,
    ...secretsResult.findings,
    ...(aiResult?.findings ?? []),
    ...preFilter.complianceFindings,
    ...preFilter.platformFindings,
  ];

  // Scoring
  let riskScore: number;
  let verdict: "SAFE TO USE" | "USE WITH CAUTION" | "DO NOT USE" | undefined;
  let verdictReason: string | undefined;
  let aiSummary: string | undefined;

  if (aiResult && aiResult.riskScore >= 0) {
    // AI score + hard-stop boost
    const deterministicFindings = [...hardStops.findings, ...codePatterns.findings, ...secretsResult.findings];
    riskScore = Math.min(100, aiResult.riskScore + hardStopBoost(deterministicFindings));
    verdict = deterministicFindings.length > 0
      ? escalateVerdict(aiResult.verdict)
      : aiResult.verdict;
    verdictReason = aiResult.verdictReason;
    aiSummary = aiResult.aiSummary;
  } else {
    // AI unavailable or unparseable: score from hard-stops only (0 for legitimate skills)
    const deterministicOnly = [...hardStops.findings, ...codePatterns.findings, ...secretsResult.findings];
    riskScore = calculateRiskScore(deterministicOnly);
    verdict = deterministicOnly.length > 0 ? "USE WITH CAUTION" : "SAFE TO USE";
    verdictReason = aiResult?.verdictReason
      || "AI analysis unavailable. Only deterministic hard-stop checks applied.";
    aiSummary = aiResult?.aiSummary || "AI analysis was not completed.";
  }

  const risk = riskLevel(riskScore);
  const summary = generateSummary(allFindings, preFilter.platform, riskScore);

  return {
    findings: allFindings,
    links: preFilter.links,
    platform: preFilter.platform,
    riskScore,
    rawRiskScore: riskScore,
    adjustedRiskScore: undefined as number | undefined,
    risk,
    summary,
    aiSummary,
    verdict,
    verdictReason,
    fileCount: files.length,
  };
}

/** Store scan results (findings + links) and complete the scan. */
export async function storeScanResults(
  ctx: { runMutation: (ref: any, args: any) => Promise<any> },
  scanId: any,
  results: Awaited<ReturnType<typeof runScanPipeline>>,
  startTime: number,
  commitHash?: string
) {
  const { findings, links, platform, riskScore, risk, summary, aiSummary, verdict, verdictReason, adjustedRiskScore, fileCount } = results;

  for (let i = 0; i < findings.length; i += 100) {
    const batch = findings.slice(i, i + 100).map((f) => ({
      scanId,
      category: f.category,
      ruleId: f.ruleId,
      severity: f.severity,
      confidence: f.confidence,
      title: f.title,
      description: f.description,
      filePath: f.filePath,
      lineNumber: f.lineNumber,
      matchedPattern: f.matchedPattern,
      snippet: f.snippet,
      dismissed: (f as any).dismissed || undefined,
      dismissReason: (f as any).dismissReason || undefined,
    }));
    await ctx.runMutation(internal.scanner.store.batchInsertFindings, {
      findings: batch,
    });
  }

  for (let i = 0; i < links.length; i += 100) {
    const batch = links.slice(i, i + 100).map((l) => ({
      scanId,
      url: l.url,
      domain: l.domain,
      filePath: l.filePath,
      lineNumber: l.lineNumber,
      classification: l.classification,
      context: l.context?.substring(0, 500),
    }));
    await ctx.runMutation(internal.scanner.store.batchInsertLinks, {
      links: batch,
    });
  }

  await ctx.runMutation(internal.scanner.store.completeScan, {
    scanId,
    platform,
    overallRisk: risk,
    riskScore,
    adjustedRiskScore: adjustedRiskScore,
    verdict,
    verdictReason,
    summary,
    aiReviewSummary: aiSummary,
    fileCount,
    totalFindings: findings.length,
    scanDurationMs: Date.now() - startTime,
    commitHash,
  });
}

// Keep the original runScan for backward compatibility (single-skill direct scans)
export const runScan = internalAction({
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

      await ctx.runMutation(internal.scanner.store.updateScanStatus, {
        scanId: args.scanId,
        status: "cloning",
      });

      let commitHash: string | undefined;
      try {
        if (scan.repoPath) {
          // Sub-path: download only that directory via Contents API
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

      await ctx.runMutation(internal.scanner.store.updateScanStatus, {
        scanId: args.scanId,
        status: "scanning",
      });

      // For sub-path downloads, tmpDir IS the scan root
      const scanRoot = tmpDir;

      const statusCallback = async (status: string) => {
        await ctx.runMutation(internal.scanner.store.updateScanStatus, {
          scanId: args.scanId,
          status: status as "scanning" | "triage" | "analyzing",
        });
      };

      const results = await runScanPipeline(scanRoot, tmpDir, getLLMConfig(), statusCallback);
      await storeScanResults(ctx, args.scanId, results, startTime, commitHash);
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
