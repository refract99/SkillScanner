"use client";

import { useParams } from "next/navigation";
import { useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import { Doc } from "@/convex/_generated/dataModel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Shield,
  ExternalLink,
  Copy,
  Check,
  Clock,
  FileText,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  GitCommit,
  Loader2,
  XCircle,
  CheckCircle2,
  AlertCircle,
  Info,
  KeyRound,
  Package,
} from "lucide-react";
import Link from "next/link";
import { useState, useMemo } from "react";

const STATUS_STEPS = [
  { key: "pending", label: "Queued" },
  { key: "cloning", label: "Cloning" },
  { key: "scanning", label: "Scanning" },
  { key: "triage", label: "AI Triage" },
  { key: "analyzing", label: "Deep Analysis" },
  { key: "complete", label: "Complete" },
] as const;

const CATEGORY_LABELS: Record<string, string> = {
  standard_compliance: "Standard Compliance",
  prompt_injection: "Prompt Injection",
  credential_access: "Credential Access",
  network_exfiltration: "Network & Exfiltration",
  dangerous_operations: "Dangerous Operations",
  code_injection: "Code Injection",
  obfuscation: "Obfuscation",
  dependency_risks: "Dependency Risks",
  bundled_payloads: "Bundled Payloads",
  external_links: "External Links",
  ai_semantic: "AI Semantic Review",
  cross_platform: "Cross-Platform",
  secrets_detection: "Secrets Detection",
  dependency_audit: "Dependency Audit",
};

const SEVERITY_CONFIG: Record<string, { color: string; icon: typeof AlertTriangle }> = {
  critical: { color: "bg-red-600 text-white", icon: XCircle },
  high: { color: "bg-orange-500 text-white", icon: AlertTriangle },
  medium: { color: "bg-yellow-500 text-black", icon: AlertCircle },
  low: { color: "bg-blue-500 text-white", icon: Info },
  info: { color: "bg-gray-500 text-white", icon: Info },
};

const RISK_COLORS: Record<string, string> = {
  safe: "bg-green-500",
  low: "bg-blue-500",
  medium: "bg-yellow-500",
  high: "bg-orange-500",
  critical: "bg-red-600",
};

export default function ScanReportPage() {
  const params = useParams();
  const slug = params.slug as string;
  const scan = useQuery(api.scanner.queries.getScanBySlug, { slug });
  const findings = useQuery(
    api.scanner.queries.getScanFindings,
    scan && !scan.collectionId ? { scanId: scan._id } : "skip"
  );
  const links = useQuery(
    api.scanner.queries.getScanLinks,
    scan && !scan.collectionId ? { scanId: scan._id } : "skip"
  );
  const stats = useQuery(
    api.scanner.queries.getScanSummaryStats,
    scan && !scan.collectionId ? { scanId: scan._id } : "skip"
  );
  // For child scans, also load findings/links/stats
  const childFindings = useQuery(
    api.scanner.queries.getScanFindings,
    scan?.collectionId ? { scanId: scan._id } : "skip"
  );
  const childLinks = useQuery(
    api.scanner.queries.getScanLinks,
    scan?.collectionId ? { scanId: scan._id } : "skip"
  );
  const childStats = useQuery(
    api.scanner.queries.getScanSummaryStats,
    scan?.collectionId ? { scanId: scan._id } : "skip"
  );
  // For collections, load children
  const children = useQuery(
    api.scanner.queries.getCollectionChildren,
    scan && scan.status === "complete" && !scan.collectionId ? { scanId: scan._id } : "skip"
  );

  if (scan === undefined) {
    return <ReportSkeleton />;
  }

  if (scan === null) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Card className="max-w-md">
          <CardHeader>
            <CardTitle>Scan Not Found</CardTitle>
            <CardDescription>This scan report does not exist or has been deleted.</CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/scan">
              <Button>Start a New Scan</Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    );
  }

  const isInProgress = !["complete", "failed"].includes(scan.status);
  const isCollection = !scan.collectionId && children && children.length > 0;
  const isChildScan = !!scan.collectionId;

  return (
    <div className="min-h-screen bg-background">
      <nav className="border-b bg-background/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-6 py-3 flex items-center justify-between">
          <Link href="/scan" className="flex items-center gap-2 font-semibold">
            <Shield className="h-5 w-5" />
            SkillScanner
          </Link>
          <ShareButton slug={slug} />
        </div>
      </nav>

      <main className="max-w-6xl mx-auto px-6 py-8">
        {isInProgress ? (
          <ScanProgress scan={scan} />
        ) : scan.status === "failed" ? (
          <ScanFailed scan={scan} />
        ) : isCollection ? (
          <CollectionReport scan={scan} children={children} />
        ) : isChildScan ? (
          <>
            <BackToCollection collectionId={scan.collectionId!} />
            <ScanReport scan={scan} findings={childFindings} links={childLinks} stats={childStats} />
          </>
        ) : (
          <ScanReport scan={scan} findings={findings} links={links} stats={stats} />
        )}
      </main>
    </div>
  );
}

function ScanProgress({ scan }: { scan: Doc<"scans"> }) {
  const currentIdx = STATUS_STEPS.findIndex((s) => s.key === scan.status);

  return (
    <div className="max-w-2xl mx-auto pt-12">
      <div className="text-center mb-12">
        <Loader2 className="h-12 w-12 animate-spin text-primary mx-auto mb-4" />
        <h1 className="text-2xl font-bold mb-2">Scanning in progress...</h1>
        <p className="text-muted-foreground">
          {scan.repoOwner}/{scan.repoName}
        </p>
      </div>

      <div className="space-y-4">
        {STATUS_STEPS.map((step, i) => {
          const isActive = i === currentIdx;
          const isDone = i < currentIdx;
          return (
            <div key={step.key} className="flex items-center gap-4">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                  isDone
                    ? "bg-primary text-primary-foreground"
                    : isActive
                    ? "bg-primary/20 text-primary animate-pulse ring-2 ring-primary"
                    : "bg-muted text-muted-foreground"
                }`}
              >
                {isDone ? <Check className="h-4 w-4" /> : i + 1}
              </div>
              <span
                className={`text-sm ${
                  isActive ? "font-medium text-foreground" : isDone ? "text-muted-foreground" : "text-muted-foreground/60"
                }`}
              >
                {step.label}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ScanFailed({ scan }: { scan: Doc<"scans"> }) {
  return (
    <div className="max-w-2xl mx-auto pt-12 text-center">
      <XCircle className="h-12 w-12 text-destructive mx-auto mb-4" />
      <h1 className="text-2xl font-bold mb-2">Scan Failed</h1>
      <p className="text-muted-foreground mb-4">
        {scan.repoOwner}/{scan.repoName}
      </p>
      <Card>
        <CardContent className="pt-6">
          <p className="text-sm text-destructive">{scan.errorMessage}</p>
        </CardContent>
      </Card>
      <Link href="/scan" className="inline-block mt-6">
        <Button>Try Another Scan</Button>
      </Link>
    </div>
  );
}

function ScanReport({
  scan,
  findings,
  links,
  stats,
}: {
  scan: Doc<"scans">;
  findings: Doc<"scanFindings">[] | undefined;
  links: Doc<"scanLinks">[] | undefined;
  stats: { bySeverity: Record<string, number>; byCategory: Record<string, number>; total: number; dismissedCount?: number } | undefined;
}) {
  const riskScore = scan.riskScore || 0;
  const overallRisk = scan.overallRisk || "safe";
  const riskColor = RISK_COLORS[overallRisk] || RISK_COLORS.safe;

  const hasFindings = stats && Object.values(stats.byCategory).some((c) => c > 0);

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold mb-1">
            {scan.repoOwner}/{scan.repoName}
          </h1>
          <a
            href={scan.url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-muted-foreground hover:text-foreground underline break-all"
          >
            {scan.url}
          </a>
          <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
            {scan.commitHash && (
              <span className="flex items-center gap-1">
                <GitCommit className="h-3.5 w-3.5" />
                {scan.commitHash!.substring(0, 7)}
              </span>
            )}
            {scan.scanDurationMs && (
              <span className="flex items-center gap-1">
                <Clock className="h-3.5 w-3.5" />
                {(scan.scanDurationMs! / 1000).toFixed(1)}s
              </span>
            )}
            {scan.platform && scan.platform !== "unknown" && (
              <Badge variant="outline">{scan.platform!.replace(/_/g, " ")}</Badge>
            )}
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* Risk Score Gauge */}
          <div className="text-center">
            <div
              className={`w-20 h-20 rounded-full flex items-center justify-center text-white font-bold text-xl ${riskColor}`}
            >
              {riskScore}
            </div>
            <p className="text-xs text-muted-foreground mt-1 capitalize">{overallRisk}</p>
          </div>
        </div>
      </div>

      {/* Verdict Banner */}
      {scan.verdict && (
        <VerdictBanner verdict={scan.verdict} reason={scan.verdictReason} aiSummary={scan.aiReviewSummary} />
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {["critical", "high", "medium", "low", "info"].map((sev) => {
          const count = stats?.bySeverity[sev] || 0;
          const config = SEVERITY_CONFIG[sev];
          return (
            <Card key={sev}>
              <CardContent className="pt-4 pb-4 text-center">
                <div className="text-2xl font-bold">{count}</div>
                <Badge className={config.color} variant="secondary">
                  {sev}
                </Badge>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Secrets & Dependency Badges */}
      {((scan.secretsCount ?? 0) > 0 || (scan.depVulnCount ?? 0) > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {(scan.secretsCount ?? 0) > 0 && (
            <Card className={(scan.secretsCriticalCount ?? 0) > 0 ? "border-red-300 dark:border-red-800" : "border-yellow-300 dark:border-yellow-800"}>
              <CardContent className="pt-4 pb-4 flex items-center gap-3">
                <div className={(scan.secretsCriticalCount ?? 0) > 0 ? "p-2 rounded-full bg-red-100 dark:bg-red-900/40" : "p-2 rounded-full bg-yellow-100 dark:bg-yellow-900/40"}>
                  <KeyRound className={(scan.secretsCriticalCount ?? 0) > 0 ? "h-5 w-5 text-red-600 dark:text-red-400" : "h-5 w-5 text-yellow-600 dark:text-yellow-400"} />
                </div>
                <div>
                  <p className="font-semibold text-sm">
                    {scan.secretsCount} Secret{scan.secretsCount !== 1 ? "s" : ""} Detected
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {(scan.secretsCriticalCount ?? 0) > 0
                      ? `${scan.secretsCriticalCount} high/critical — credentials may be exposed`
                      : "Lower severity findings — review recommended"}
                    {scan.secretsBoostApplied && " · Minimum risk score applied"}
                  </p>
                </div>
              </CardContent>
            </Card>
          )}
          {(scan.depVulnCount ?? 0) > 0 && (
            <Card className={(scan.depCriticalCount ?? 0) > 0 ? "border-red-300 dark:border-red-800" : "border-orange-300 dark:border-orange-800"}>
              <CardContent className="pt-4 pb-4 flex items-center gap-3">
                <div className={(scan.depCriticalCount ?? 0) > 0 ? "p-2 rounded-full bg-red-100 dark:bg-red-900/40" : "p-2 rounded-full bg-orange-100 dark:bg-orange-900/40"}>
                  <Package className={(scan.depCriticalCount ?? 0) > 0 ? "h-5 w-5 text-red-600 dark:text-red-400" : "h-5 w-5 text-orange-600 dark:text-orange-400"} />
                </div>
                <div>
                  <p className="font-semibold text-sm">
                    {scan.depVulnCount} Known Vulnerabilit{scan.depVulnCount !== 1 ? "ies" : "y"}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {(scan.depCriticalCount ?? 0) > 0 && `${scan.depCriticalCount} critical`}
                    {(scan.depCriticalCount ?? 0) > 0 && (scan.depHighCount ?? 0) > 0 && ", "}
                    {(scan.depHighCount ?? 0) > 0 && `${scan.depHighCount} high`}
                    {((scan.depCriticalCount ?? 0) > 0 || (scan.depHighCount ?? 0) > 0) && " severity — "}
                    update dependencies to patch
                    {(scan.cveBoostTotal ?? 0) > 0 && ` · +${scan.cveBoostTotal} CVE boost applied`}
                  </p>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Risk Breakdown by Source */}
      {scan.sourceBreakdown && scan.sourceBreakdown.length > 0 && (
        <RiskBreakdown sourceBreakdown={scan.sourceBreakdown} />
      )}

      {/* Findings by Category — Donut Chart */}
      {hasFindings && (
        <CategoryDonut stats={stats} />
      )}

      {/* Category Accordions */}
      <FindingsSection
        findings={findings}
        stats={stats}
        repoUrl={scan.url as string}
        commitHash={scan.commitHash as string | undefined}
      />

      {/* External Links Table */}
      {links && links.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">External Links ({links.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="pb-2 pr-4">Domain</th>
                    <th className="pb-2 pr-4">URL</th>
                    <th className="pb-2 pr-4">File</th>
                    <th className="pb-2">Classification</th>
                  </tr>
                </thead>
                <tbody>
                  {links.map((link, i) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-mono text-xs">{link.domain}</td>
                      <td className="py-2 pr-4 font-mono text-xs max-w-[300px] truncate">
                        {link.url}
                      </td>
                      <td className="py-2 pr-4 text-xs">{link.filePath}</td>
                      <td className="py-2">
                        <Badge
                          variant={
                            link.classification === "safe"
                              ? "secondary"
                              : link.classification === "suspicious"
                              ? "destructive"
                              : "outline"
                          }
                        >
                          {link.classification}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

    </div>
  );
}

function BackToCollection({ collectionId }: { collectionId: any }) {
  return (
    <div className="mb-6">
      <button
        onClick={() => window.history.back()}
        className="text-sm text-muted-foreground hover:text-foreground flex items-center gap-1"
      >
        <ChevronRight className="h-3.5 w-3.5 rotate-180" />
        Back to collection
      </button>
    </div>
  );
}

function CollectionReport({
  scan,
  children,
}: {
  scan: Doc<"scans">;
  children: Doc<"scans">[];
}) {
  const riskScore = scan.riskScore || 0;
  const overallRisk = scan.overallRisk || "safe";
  const riskColor = RISK_COLORS[overallRisk] || RISK_COLORS.safe;

  // Sort children by risk score descending
  const sortedChildren = useMemo(
    () => [...children].sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0)),
    [children]
  );

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold mb-1">
            {scan.repoOwner}/{scan.repoName}
          </h1>
          <a
            href={scan.url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-muted-foreground hover:text-foreground underline break-all"
          >
            {scan.url}
          </a>
          <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
            {scan.scanDurationMs && (
              <span className="flex items-center gap-1">
                <Clock className="h-3.5 w-3.5" />
                {(scan.scanDurationMs / 1000).toFixed(1)}s
              </span>
            )}
            <Badge variant="outline">
              {children.length} skills
            </Badge>
          </div>
        </div>

        <div className="text-center">
          <div
            className={`w-20 h-20 rounded-full flex items-center justify-center text-white font-bold text-xl ${riskColor}`}
          >
            {riskScore}
          </div>
          <p className="text-xs text-muted-foreground mt-1 capitalize">{overallRisk}</p>
        </div>
      </div>

      {/* Summary */}
      {scan.summary && (
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm">{scan.summary}</p>
          </CardContent>
        </Card>
      )}

      {/* Skills Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Skills</CardTitle>
          <CardDescription>
            Individual scan results for each discovered skill. Click view to see the individual skill.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2 pr-4">Skill</th>
                  <th className="pb-2 pr-4">Path</th>
                  <th className="pb-2 pr-4">Platform</th>
                  <th className="pb-2 pr-4">Risk</th>
                  <th className="pb-2 pr-4">Findings</th>
                  <th className="pb-2 pr-4">Status</th>
                  <th className="pb-2"></th>
                </tr>
              </thead>
              <tbody>
                {sortedChildren.map((child) => {
                  const childRisk = child.overallRisk || "safe";
                  const childRiskColor = RISK_COLORS[childRisk] || RISK_COLORS.safe;
                  return (
                    <tr key={child._id} className="border-b last:border-0">
                      <td className="py-3 pr-4 font-medium">
                        {child.skillName || child.repoPath || "Unknown"}
                      </td>
                      <td className="py-3 pr-4 text-xs text-muted-foreground font-mono">
                        {child.skillPath || child.repoPath || ""}
                      </td>
                      <td className="py-3 pr-4">
                        {child.platform && child.platform !== "unknown" && (
                          <Badge variant="outline" className="text-xs">
                            {child.platform.replace(/_/g, " ")}
                          </Badge>
                        )}
                      </td>
                      <td className="py-3 pr-4">
                        <div className="flex items-center gap-2">
                          <div
                            className={`w-8 h-8 rounded-full flex items-center justify-center text-white text-xs font-bold ${childRiskColor}`}
                          >
                            {child.riskScore || 0}
                          </div>
                          <span className="text-xs text-muted-foreground capitalize">
                            {childRisk}
                          </span>
                        </div>
                      </td>
                      <td className="py-3 pr-4 text-center">
                        {child.totalFindings || 0}
                      </td>
                      <td className="py-3 pr-4">
                        {child.status === "complete" ? (
                          <Badge variant="secondary" className="bg-green-100 text-green-700">
                            Complete
                          </Badge>
                        ) : child.status === "failed" ? (
                          <Badge variant="destructive">Failed</Badge>
                        ) : (
                          <Badge variant="outline">{child.status}</Badge>
                        )}
                      </td>
                      <td className="py-3">
                        {child.status === "complete" && (
                          <Link href={`/scan/${child.shareSlug}`}>
                            <Button variant="ghost" size="sm">
                              View
                              <ChevronRight className="h-3.5 w-3.5 ml-1" />
                            </Button>
                          </Link>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

const CONFIDENCE_CONFIG = {
  high: { label: "High", color: "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300", dotColor: "bg-blue-500" },
  medium: { label: "Medium", color: "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300", dotColor: "bg-blue-500" },
  low: { label: "Low", color: "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300", dotColor: "bg-blue-500" },
} as const;

/** Visual confidence indicator: 3 dots, filled based on level */
function ConfidenceDots({ level }: { level: "high" | "medium" | "low" }) {
  const filled = level === "high" ? 3 : level === "medium" ? 2 : 1;
  const conf = CONFIDENCE_CONFIG[level];
  return (
    <div className="flex items-center gap-0.5" title={`Confidence: ${conf?.label || level}`}>
      {[1, 2, 3].map((i) => (
        <span
          key={i}
          className={`inline-block w-1.5 h-1.5 rounded-full ${
            i <= filled ? (conf?.dotColor || "bg-gray-500") : "bg-gray-300 dark:bg-gray-600"
          }`}
        />
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Donut chart for findings by category
// ---------------------------------------------------------------------------

const DONUT_SEVERITY_PRIORITY: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1, info: 0,
};

const DONUT_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
};

function CategoryDonut({
  stats,
}: {
  stats: { byCategory: Record<string, number>; bySeverity: Record<string, number>; total: number } | undefined;
}) {
  if (!stats) return null;

  const categories = Object.entries(CATEGORY_LABELS)
    .map(([key, label]) => ({ key, label, count: stats.byCategory[key] || 0 }))
    .filter((d) => d.count > 0)
    .sort((a, b) => b.count - a.count);

  const total = categories.reduce((s, c) => s + c.count, 0);
  if (total === 0) return null;

  // Determine worst severity for coloring
  const worstSeverity = (["critical", "high", "medium", "low", "info"] as const)
    .find((s) => (stats.bySeverity[s] || 0) > 0) || "info";

  // Build donut segments — color by severity distribution
  const severities = ["critical", "high", "medium", "low", "info"] as const;
  const segments: { severity: string; count: number; color: string }[] = [];
  for (const sev of severities) {
    const count = stats.bySeverity[sev] || 0;
    if (count > 0) {
      segments.push({ severity: sev, count, color: DONUT_COLORS[sev] });
    }
  }

  // SVG donut
  const size = 160;
  const strokeWidth = 28;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;

  let offset = 0;
  const arcs = segments.map((seg) => {
    const pct = seg.count / total;
    const dashLength = pct * circumference;
    const gap = circumference - dashLength;
    const rotation = (offset / total) * 360 - 90;
    offset += seg.count;
    return { ...seg, dashLength, gap, rotation };
  });

  return (
    <Card>
      <CardContent className="pt-6">
        <div className="flex flex-col sm:flex-row items-center gap-6">
          {/* Donut SVG */}
          <div className="relative flex-shrink-0">
            <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
              {/* Background ring */}
              <circle
                cx={size / 2}
                cy={size / 2}
                r={radius}
                fill="none"
                stroke="currentColor"
                strokeWidth={strokeWidth}
                className="text-muted/30"
              />
              {/* Severity segments */}
              {arcs.map((arc, i) => (
                <circle
                  key={i}
                  cx={size / 2}
                  cy={size / 2}
                  r={radius}
                  fill="none"
                  stroke={arc.color}
                  strokeWidth={strokeWidth}
                  strokeDasharray={`${arc.dashLength} ${arc.gap}`}
                  strokeLinecap="butt"
                  transform={`rotate(${arc.rotation} ${size / 2} ${size / 2})`}
                />
              ))}
            </svg>
            {/* Center text */}
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-2xl font-bold">{total}</span>
              <span className="text-xs text-muted-foreground">finding{total !== 1 ? "s" : ""}</span>
            </div>
          </div>

          {/* Category legend */}
          <div className="flex-1 space-y-1.5">
            {categories.map((cat) => (
              <div key={cat.key} className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">{cat.label}</span>
                <span className="font-medium tabular-nums">{cat.count}</span>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Risk breakdown by scanner source (horizontal bar chart)
// ---------------------------------------------------------------------------

const SOURCE_BAR_COLORS: Record<string, string> = {
  hard_stop: "bg-red-500",
  secrets_detection: "bg-orange-500",
  dependency_audit: "bg-amber-500",
  dependency_risks: "bg-yellow-500",
  standard_compliance: "bg-yellow-500",
  cross_platform: "bg-yellow-500",
  ai_semantic: "bg-blue-500",
  external_links: "bg-gray-400",
};

function RiskBreakdown({
  sourceBreakdown,
}: {
  sourceBreakdown: Array<{
    source: string;
    label: string;
    weight: number;
    rawPoints: number;
    weightedPoints: number;
    findingCount: number;
  }>;
}) {
  const maxPoints = Math.max(...sourceBreakdown.map((s) => s.weightedPoints), 1);

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-lg">Risk Breakdown by Source</CardTitle>
        <CardDescription>Contribution of each scanner to the overall risk score (weighted)</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {sourceBreakdown.map((src) => {
          const pct = (src.weightedPoints / maxPoints) * 100;
          const barColor = SOURCE_BAR_COLORS[src.source] || "bg-gray-400";
          return (
            <div key={src.source} className="space-y-1">
              <div className="flex items-center justify-between text-sm">
                <span className="font-medium">{src.label}</span>
                <span className="text-muted-foreground text-xs">
                  {src.findingCount} finding{src.findingCount !== 1 ? "s" : ""} · {Math.round(src.weightedPoints)} pts (×{src.weight})
                </span>
              </div>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all ${barColor}`}
                  style={{ width: `${Math.max(pct, 2)}%` }}
                />
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

function FindingsSection({
  findings,
  stats,
  repoUrl,
  commitHash,
}: {
  findings: Doc<"scanFindings">[] | undefined;
  stats: { dismissedCount?: number } | undefined;
  repoUrl: string;
  commitHash?: string;
}) {
  const [showDismissed, setShowDismissed] = useState(false);
  const [confidenceFilter, setConfidenceFilter] = useState<"all" | "high" | "medium" | "low">("all");

  const activeFindings = useMemo(
    () => findings?.filter((f) => !f.dismissed) || [],
    [findings]
  );
  const dismissedFindings = useMemo(
    () => findings?.filter((f) => f.dismissed) || [],
    [findings]
  );

  // Count findings by confidence level
  const confidenceCounts = useMemo(() => {
    const counts = { high: 0, medium: 0, low: 0 };
    for (const f of activeFindings) {
      const c = f.confidence as keyof typeof counts;
      if (c in counts) counts[c]++;
    }
    return counts;
  }, [activeFindings]);

  // Apply confidence filter
  const filteredFindings = useMemo(() => {
    if (confidenceFilter === "all") return activeFindings;
    // "high" shows high only; "medium" shows high+medium; "low" shows all
    const levels = confidenceFilter === "high"
      ? ["high"]
      : confidenceFilter === "medium"
        ? ["high", "medium"]
        : ["high", "medium", "low"];
    return activeFindings.filter((f) => levels.includes(f.confidence));
  }, [activeFindings, confidenceFilter]);

  const dismissedCount = stats?.dismissedCount || dismissedFindings.length;
  const hasMultipleConfidences = Object.values(confidenceCounts).filter((c) => c > 0).length > 1;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <h2 className="text-lg font-semibold">Findings by Category</h2>
        <div className="flex items-center gap-2">
          {/* Confidence filter buttons — only show when there are multiple levels */}
          {hasMultipleConfidences && activeFindings.length > 0 && (
            <div className="flex items-center gap-1 text-xs">
              <span className="text-muted-foreground mr-1">Confidence:</span>
              {(["all", "high", "medium", "low"] as const).map((level) => {
                const isActive = confidenceFilter === level;
                const count = level === "all"
                  ? activeFindings.length
                  : confidenceCounts[level];
                if (level !== "all" && count === 0) return null;
                return (
                  <button
                    key={level}
                    onClick={() => setConfidenceFilter(level)}
                    className={`px-2 py-0.5 rounded-md transition-colors flex items-center gap-1 ${
                      isActive
                        ? "bg-foreground text-background"
                        : "hover:bg-muted text-muted-foreground"
                    }`}
                  >
                    {level !== "all" && (
                      <span className={`inline-block w-1.5 h-1.5 rounded-full ${CONFIDENCE_CONFIG[level].dotColor}`} />
                    )}
                    {level === "all" ? "All" : `${CONFIDENCE_CONFIG[level].label}`}
                    <span className="opacity-60">({count})</span>
                  </button>
                );
              })}
            </div>
          )}
          {dismissedCount > 0 && (
            <button
              onClick={() => setShowDismissed(!showDismissed)}
              className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1.5 px-2 py-1 rounded-md hover:bg-muted transition-colors"
            >
              <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />
              {dismissedCount} false positive{dismissedCount !== 1 ? "s" : ""} suppressed
              {showDismissed ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
            </button>
          )}
        </div>
      </div>

      {/* Show filter info when filtering */}
      {confidenceFilter !== "all" && (
        <p className="text-xs text-muted-foreground">
          Showing {filteredFindings.length} of {activeFindings.length} findings with {confidenceFilter === "high" ? "high" : confidenceFilter === "medium" ? "high or medium" : "any"} confidence.
          {confidenceFilter === "high" && confidenceCounts.medium + confidenceCounts.low > 0 && (
            <span> {confidenceCounts.medium + confidenceCounts.low} lower-confidence finding{confidenceCounts.medium + confidenceCounts.low !== 1 ? "s" : ""} hidden (may be mitigated by framework context).</span>
          )}
        </p>
      )}

      {Object.keys(CATEGORY_LABELS).map((cat) => {
        const catFindings = filteredFindings.filter((f) => f.category === cat);
        if (catFindings.length === 0) return null;
        return (
          <CategoryAccordion
            key={cat}
            category={cat}
            label={CATEGORY_LABELS[cat]}
            findings={catFindings}
            repoUrl={repoUrl}
            commitHash={commitHash}
          />
        );
      })}

      {filteredFindings.length === 0 && (
        <Card>
          <CardContent className="pt-6 text-center text-muted-foreground">
            <CheckCircle2 className="h-8 w-8 mx-auto mb-2 text-green-500" />
            {confidenceFilter !== "all" && activeFindings.length > 0
              ? `No ${confidenceFilter}-confidence findings. ${activeFindings.length} lower-confidence finding${activeFindings.length !== 1 ? "s" : ""} hidden by filter.`
              : "No security issues detected."}
            {dismissedCount > 0 && confidenceFilter === "all" && (
              <p className="text-xs mt-1">
                {dismissedCount} pattern match{dismissedCount !== 1 ? "es" : ""} reviewed and dismissed as false positive{dismissedCount !== 1 ? "s" : ""} by AI analysis.
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {/* Dismissed findings (collapsed by default) */}
      {showDismissed && dismissedFindings.length > 0 && (
        <Card className="border-dashed opacity-70">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-green-500" />
              Suppressed False Positives ({dismissedFindings.length})
            </CardTitle>
            <CardDescription className="text-xs">
              These pattern matches were reviewed by AI analysis and determined to be false positives.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {dismissedFindings.map((f, i) => (
              <div key={i} className="border border-dashed rounded-md p-3 space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium line-through decoration-green-500/50">{f.title}</span>
                  <Badge variant="outline" className="text-xs text-green-600 border-green-300">dismissed</Badge>
                </div>
                {f.dismissReason && (
                  <p className="text-xs text-muted-foreground italic">{f.dismissReason}</p>
                )}
                {f.filePath && (
                  <p className="text-xs text-muted-foreground">
                    {f.filePath}{f.lineNumber ? `:${f.lineNumber}` : ""}
                  </p>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-muted-foreground border rounded-md px-4 py-2.5 mt-2">
        <span className="font-medium">Severity:</span>
        <span className="flex items-center gap-1"><XCircle className="h-3.5 w-3.5 text-red-600" />Critical</span>
        <span className="flex items-center gap-1"><AlertTriangle className="h-3.5 w-3.5 text-orange-500" />High</span>
        <span className="flex items-center gap-1"><AlertCircle className="h-3.5 w-3.5 text-yellow-500" />Medium</span>
        <span className="flex items-center gap-1"><Info className="h-3.5 w-3.5 text-blue-500" />Low</span>
        <span className="flex items-center gap-1"><Info className="h-3.5 w-3.5 text-gray-500" />Info</span>
        <span className="text-border">|</span>
        <span className="font-medium">Confidence:</span>
        <span className="flex items-center gap-1"><ConfidenceDots level="high" />High</span>
        <span className="flex items-center gap-1"><ConfidenceDots level="medium" />Medium</span>
        <span className="flex items-center gap-1"><ConfidenceDots level="low" />Low</span>
      </div>
    </div>
  );
}

function CategoryAccordion({
  category,
  label,
  findings,
  repoUrl,
  commitHash,
}: {
  category: string;
  label: string;
  findings: Doc<"scanFindings">[];
  repoUrl: string;
  commitHash?: string;
}) {
  const [open, setOpen] = useState(false);

  const severityCounts: Record<string, number> = {};
  for (const f of findings) {
    const sev = f.severity;
    severityCounts[sev] = (severityCounts[sev] || 0) + 1;
  }

  return (
    <Card>
      <button
        onClick={() => setOpen(!open)}
        className="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-muted/50 transition-colors"
      >
        <div className="flex items-center gap-3">
          {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          <span className="font-medium">{label}</span>
          <span className="text-sm text-muted-foreground">({findings.length})</span>
        </div>
        <div className="flex gap-1.5">
          {Object.entries(severityCounts).map(([sev, count]) => (
            <Badge key={sev} className={SEVERITY_CONFIG[sev]?.color || ""} variant="secondary">
              {count} {sev}
            </Badge>
          ))}
        </div>
      </button>
      {open && (
        <div className="px-6 pb-4 space-y-3">
          {findings.map((f, i) => (
            <FindingCard key={i} finding={f} repoUrl={repoUrl} commitHash={commitHash} />
          ))}
        </div>
      )}
    </Card>
  );
}

function FindingCard({
  finding,
  repoUrl,
  commitHash,
}: {
  finding: Doc<"scanFindings">;
  repoUrl: string;
  commitHash?: string;
}) {
  const severity = finding.severity;
  const config = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.info;
  const SevIcon = config.icon;

  const fileLink = finding.filePath
    ? `${repoUrl}/blob/${commitHash || "main"}/${finding.filePath}${finding.lineNumber ? `#L${finding.lineNumber}` : ""}`
    : null;

  return (
    <div className="border rounded-lg p-4 space-y-2">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <SevIcon className="h-4 w-4 flex-shrink-0" />
          <span className="font-medium text-sm">{finding.title}</span>
        </div>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          <Badge className={config.color} variant="secondary">
            {severity}
          </Badge>
          <ConfidenceDots level={finding.confidence as "high" | "medium" | "low"} />
        </div>
      </div>
      <p className="text-sm text-muted-foreground">{finding.description}</p>
      {finding.filePath && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <FileText className="h-3.5 w-3.5" />
          {fileLink ? (
            <a
              href={fileLink}
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-foreground underline"
            >
              {finding.filePath}
              {finding.lineNumber ? `:${finding.lineNumber}` : ""}
            </a>
          ) : (
            <span>
              {finding.filePath}
              {finding.lineNumber ? `:${finding.lineNumber}` : ""}
            </span>
          )}
        </div>
      )}
      {finding.snippet && (
        <pre className="bg-muted rounded-md p-3 text-xs overflow-x-auto font-mono">
          <code>{finding.snippet}</code>
        </pre>
      )}
    </div>
  );
}

const VERDICT_CONFIG = {
  "SAFE TO USE": {
    bg: "bg-green-50 border-green-200 dark:bg-green-950/30 dark:border-green-800",
    text: "text-green-800 dark:text-green-200",
    icon: CheckCircle2,
    iconColor: "text-green-600 dark:text-green-400",
  },
  "USE WITH CAUTION": {
    bg: "bg-yellow-50 border-yellow-200 dark:bg-yellow-950/30 dark:border-yellow-800",
    text: "text-yellow-800 dark:text-yellow-200",
    icon: AlertCircle,
    iconColor: "text-yellow-600 dark:text-yellow-400",
  },
  "DO NOT USE": {
    bg: "bg-red-50 border-red-200 dark:bg-red-950/30 dark:border-red-800",
    text: "text-red-800 dark:text-red-200",
    icon: XCircle,
    iconColor: "text-red-600 dark:text-red-400",
  },
} as const;

function VerdictBanner({
  verdict,
  reason,
  aiSummary,
}: {
  verdict: "SAFE TO USE" | "USE WITH CAUTION" | "DO NOT USE";
  reason?: string;
  aiSummary?: string;
}) {
  const config = VERDICT_CONFIG[verdict];
  const Icon = config.icon;

  return (
    <div className={`rounded-lg border-2 p-4 flex items-start gap-3 ${config.bg}`}>
      <Icon className={`h-6 w-6 flex-shrink-0 mt-0.5 ${config.iconColor}`} />
      <div className="min-w-0">
        <p className={`font-bold text-lg ${config.text}`}>{verdict}</p>
        {reason && (
          <p className={`text-sm mt-1 ${config.text} opacity-80`}>{reason}</p>
        )}
        {aiSummary && (
          <p className="text-sm mt-3 text-muted-foreground whitespace-pre-wrap">{aiSummary}</p>
        )}
      </div>
    </div>
  );
}

function ShareButton({ slug }: { slug: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(`${window.location.origin}/scan/${slug}`);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Button variant="outline" size="sm" onClick={handleCopy}>
      {copied ? (
        <>
          <Check className="h-4 w-4 mr-1" /> Copied
        </>
      ) : (
        <>
          <Copy className="h-4 w-4 mr-1" /> Share
        </>
      )}
    </Button>
  );
}

function ReportSkeleton() {
  return (
    <div className="min-h-screen bg-background">
      <nav className="border-b bg-background/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-6 py-3">
          <Skeleton className="h-6 w-32" />
        </div>
      </nav>
      <main className="max-w-6xl mx-auto px-6 py-8 space-y-6">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-5 gap-4">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
        <Skeleton className="h-80" />
        <Skeleton className="h-40" />
      </main>
    </div>
  );
}
