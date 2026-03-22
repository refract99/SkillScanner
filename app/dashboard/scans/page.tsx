"use client";

import { useQuery, useMutation } from "convex/react";
import { api } from "@/convex/_generated/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Shield,
  ExternalLink,
  Trash2,
  Layers,
  Search,
  Filter,
  ArrowUpDown,
  ChevronDown,
} from "lucide-react";
import Link from "next/link";
import { useState, useMemo } from "react";
import { Id } from "@/convex/_generated/dataModel";

const RISK_COLORS: Record<string, string> = {
  safe: "bg-green-500 text-white",
  low: "bg-blue-500 text-white",
  medium: "bg-yellow-500 text-black",
  high: "bg-orange-500 text-white",
  critical: "bg-red-600 text-white",
};

const STATUS_COLORS: Record<string, string> = {
  pending: "bg-gray-500 text-white",
  cloning: "bg-blue-400 text-white",
  scanning: "bg-blue-500 text-white",
  analyzing: "bg-purple-500 text-white",
  complete: "bg-green-500 text-white",
  failed: "bg-red-500 text-white",
};

const RISK_ORDER = ["critical", "high", "medium", "low", "safe"];
const PLATFORM_LABELS: Record<string, string> = {
  claude_code: "Claude Code",
  openclaw: "OpenClaw",
  cursor: "Cursor",
  windsurf: "Windsurf",
  cline: "Cline",
  agentskills: "AgentSkills",
  unknown: "Unknown",
};

type SortField = "date" | "risk" | "findings" | "name";
type SortDir = "asc" | "desc";

export default function ScanHistoryPage() {
  const allScans = useQuery(api.scanner.queries.getUserScans);
  const deleteScan = useMutation(api.scanner.submit.deleteScan);

  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [platformFilter, setPlatformFilter] = useState<string>("all");
  const [sortField, setSortField] = useState<SortField>("date");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  // Filter out child scans
  const topLevelScans = useMemo(
    () => allScans?.filter((s) => !s.collectionId) || [],
    [allScans]
  );

  // Derive available filter options from data
  const availablePlatforms = useMemo(() => {
    const platforms = new Set<string>();
    topLevelScans.forEach((s) => {
      if (s.platform && s.platform !== "unknown") platforms.add(s.platform);
    });
    return Array.from(platforms).sort();
  }, [topLevelScans]);

  // Apply filters and search
  const filteredScans = useMemo(() => {
    let result = topLevelScans;

    // Search
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (s) =>
          s.repoOwner.toLowerCase().includes(q) ||
          s.repoName.toLowerCase().includes(q) ||
          (s.repoPath && s.repoPath.toLowerCase().includes(q)) ||
          (s.skillName && s.skillName.toLowerCase().includes(q)) ||
          s.url.toLowerCase().includes(q)
      );
    }

    // Status filter
    if (statusFilter !== "all") {
      result = result.filter((s) => s.status === statusFilter);
    }

    // Risk filter
    if (riskFilter !== "all") {
      result = result.filter((s) => s.overallRisk === riskFilter);
    }

    // Platform filter
    if (platformFilter !== "all") {
      result = result.filter((s) => s.platform === platformFilter);
    }

    // Sort
    result = [...result].sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case "date":
          cmp = a._creationTime - b._creationTime;
          break;
        case "risk":
          cmp =
            RISK_ORDER.indexOf(a.overallRisk || "safe") -
            RISK_ORDER.indexOf(b.overallRisk || "safe");
          break;
        case "findings":
          cmp = (a.totalFindings || 0) - (b.totalFindings || 0);
          break;
        case "name":
          cmp = `${a.repoOwner}/${a.repoName}`.localeCompare(
            `${b.repoOwner}/${b.repoName}`
          );
          break;
      }
      return sortDir === "desc" ? -cmp : cmp;
    });

    return result;
  }, [topLevelScans, searchQuery, statusFilter, riskFilter, platformFilter, sortField, sortDir]);

  // Stats
  const stats = useMemo(() => {
    const total = topLevelScans.length;
    const complete = topLevelScans.filter((s) => s.status === "complete").length;
    const failed = topLevelScans.filter((s) => s.status === "failed").length;
    const highRisk = topLevelScans.filter(
      (s) => s.overallRisk === "high" || s.overallRisk === "critical"
    ).length;
    return { total, complete, failed, highRisk };
  }, [topLevelScans]);

  const handleDelete = async (scanId: Id<"scans">) => {
    if (!confirm("Delete this scan and all its findings?")) return;
    await deleteScan({ scanId });
  };

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir(sortDir === "desc" ? "asc" : "desc");
    } else {
      setSortField(field);
      setSortDir("desc");
    }
  };

  const isCollection = (scanId: Id<"scans">) =>
    allScans?.some((s) => s.collectionId === scanId) ?? false;

  if (allScans === undefined) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-10 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
        <Skeleton className="h-12" />
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-16" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Scan History</h1>
          <p className="text-sm text-muted-foreground">
            Your past skill security scans
          </p>
        </div>
        <Link href="/scan">
          <Button>
            <Shield className="h-4 w-4 mr-2" />
            New Scan
          </Button>
        </Link>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 pb-4">
            <p className="text-xs text-muted-foreground">Total Scans</p>
            <p className="text-2xl font-bold">{stats.total}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <p className="text-xs text-muted-foreground">Complete</p>
            <p className="text-2xl font-bold text-green-600">{stats.complete}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <p className="text-xs text-muted-foreground">Failed</p>
            <p className="text-2xl font-bold text-red-600">{stats.failed}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <p className="text-xs text-muted-foreground">High/Critical Risk</p>
            <p className="text-2xl font-bold text-orange-600">{stats.highRisk}</p>
          </CardContent>
        </Card>
      </div>

      {topLevelScans.length === 0 ? (
        <Card>
          <CardContent className="pt-12 pb-12 text-center">
            <Shield className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
            <h3 className="font-medium mb-1">No scans yet</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Submit a GitHub URL to scan your first AI agent skill.
            </p>
            <Link href="/scan">
              <Button>Start Scanning</Button>
            </Link>
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Search & Filters */}
          <div className="flex flex-wrap gap-3">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search by repo, owner, or path..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="h-9 rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="all">All Statuses</option>
              <option value="complete">Complete</option>
              <option value="failed">Failed</option>
              <option value="pending">Pending</option>
              <option value="scanning">Scanning</option>
              <option value="analyzing">Analyzing</option>
            </select>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="h-9 rounded-md border border-input bg-background px-3 text-sm"
            >
              <option value="all">All Risk Levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="safe">Safe</option>
            </select>
            {availablePlatforms.length > 0 && (
              <select
                value={platformFilter}
                onChange={(e) => setPlatformFilter(e.target.value)}
                className="h-9 rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="all">All Platforms</option>
                {availablePlatforms.map((p) => (
                  <option key={p} value={p}>
                    {PLATFORM_LABELS[p] || p}
                  </option>
                ))}
              </select>
            )}
          </div>

          {/* Results count */}
          <p className="text-xs text-muted-foreground">
            {filteredScans.length} of {topLevelScans.length} scans
            {searchQuery && ` matching "${searchQuery}"`}
          </p>

          {/* Table */}
          {filteredScans.length === 0 ? (
            <Card>
              <CardContent className="pt-8 pb-8 text-center text-muted-foreground">
                No scans match your filters.
              </CardContent>
            </Card>
          ) : (
            <div className="overflow-x-auto border rounded-lg">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b bg-muted/50 text-left text-muted-foreground">
                    <th className="py-3 px-4">
                      <button
                        onClick={() => toggleSort("name")}
                        className="flex items-center gap-1 hover:text-foreground"
                      >
                        Repository
                        {sortField === "name" && (
                          <ArrowUpDown className="h-3 w-3" />
                        )}
                      </button>
                    </th>
                    <th className="py-3 px-4">Platform</th>
                    <th className="py-3 px-4">
                      <button
                        onClick={() => toggleSort("risk")}
                        className="flex items-center gap-1 hover:text-foreground"
                      >
                        Risk
                        {sortField === "risk" && (
                          <ArrowUpDown className="h-3 w-3" />
                        )}
                      </button>
                    </th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">
                      <button
                        onClick={() => toggleSort("findings")}
                        className="flex items-center gap-1 hover:text-foreground"
                      >
                        Findings
                        {sortField === "findings" && (
                          <ArrowUpDown className="h-3 w-3" />
                        )}
                      </button>
                    </th>
                    <th className="py-3 px-4">
                      <button
                        onClick={() => toggleSort("date")}
                        className="flex items-center gap-1 hover:text-foreground"
                      >
                        Date
                        {sortField === "date" && (
                          <ArrowUpDown className="h-3 w-3" />
                        )}
                      </button>
                    </th>
                    <th className="py-3 px-4"></th>
                  </tr>
                </thead>
                <tbody>
                  {filteredScans.map((scan) => (
                    <tr
                      key={scan._id}
                      className="border-b last:border-0 hover:bg-muted/30 transition-colors"
                    >
                      <td className="py-3 px-4">
                        <Link
                          href={`/scan/${scan.shareSlug}`}
                          className="font-medium hover:underline"
                        >
                          {scan.repoOwner}/{scan.repoName}
                        </Link>
                        {scan.repoPath && (
                          <span className="text-xs text-muted-foreground block">
                            /{scan.repoPath}
                          </span>
                        )}
                        {isCollection(scan._id) && (
                          <Badge
                            variant="outline"
                            className="text-xs mt-1"
                          >
                            <Layers className="h-3 w-3 mr-1" />
                            Collection
                          </Badge>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {scan.platform && scan.platform !== "unknown" ? (
                          <Badge variant="outline">
                            {PLATFORM_LABELS[scan.platform] || scan.platform}
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {scan.overallRisk ? (
                          <Badge
                            className={RISK_COLORS[scan.overallRisk]}
                            variant="secondary"
                          >
                            {scan.riskScore}/100
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <Badge
                          className={STATUS_COLORS[scan.status]}
                          variant="secondary"
                        >
                          {scan.status}
                        </Badge>
                      </td>
                      <td className="py-3 px-4 text-center">
                        {scan.totalFindings !== undefined
                          ? scan.totalFindings
                          : "—"}
                      </td>
                      <td className="py-3 px-4 text-muted-foreground whitespace-nowrap">
                        {new Date(scan._creationTime).toLocaleDateString(
                          undefined,
                          {
                            month: "short",
                            day: "numeric",
                            year: "numeric",
                          }
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-1">
                          <Link href={`/scan/${scan.shareSlug}`}>
                            <Button variant="ghost" size="sm">
                              <ExternalLink className="h-3.5 w-3.5" />
                            </Button>
                          </Link>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDelete(scan._id)}
                          >
                            <Trash2 className="h-3.5 w-3.5 text-destructive" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
