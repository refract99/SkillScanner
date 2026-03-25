"use client"

import { useQuery } from "convex/react"
import { api } from "@/convex/_generated/api"
import Link from "next/link"
import { useState } from "react"

import { ChartAreaInteractive } from "@/app/dashboard/chart-area-interactive"
import { SectionCards } from "@/app/dashboard/section-cards"
import { RiskDonut } from "@/app/dashboard/widgets/risk-donut"
import { FindingCategoryBar } from "@/app/dashboard/widgets/finding-category-bar"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { ExternalLink } from "lucide-react"

const RISK_COLORS: Record<string, string> = {
  safe: "bg-green-500 text-white",
  low: "bg-blue-500 text-white",
  medium: "bg-yellow-500 text-black",
  high: "bg-orange-500 text-white",
  critical: "bg-red-600 text-white",
}

const STATUS_COLORS: Record<string, string> = {
  pending: "bg-gray-500 text-white",
  cloning: "bg-blue-400 text-white",
  scanning: "bg-blue-500 text-white",
  triage: "bg-purple-400 text-white",
  analyzing: "bg-purple-500 text-white",
  complete: "bg-green-500 text-white",
  failed: "bg-red-500 text-white",
}

const PLATFORM_LABELS: Record<string, string> = {
  claude_code: "Claude Code",
  openclaw: "OpenClaw",
  cursor: "Cursor",
  windsurf: "Windsurf",
  cline: "Cline",
  agentskills: "AgentSkills",
  unknown: "Unknown",
}

export default function Page() {
  const scans = useQuery(api.scanner.queries.getUserScans)
  const findingStats = useQuery(api.scanner.queries.getUserFindingStats)
  const [activeRisk, setActiveRisk] = useState<string | null>(null)

  const topLevel = scans?.filter((s) => !s.collectionId) ?? []

  const recentScans = topLevel
    .slice()
    .sort((a, b) => b._creationTime - a._creationTime)
    .slice(0, 10)

  return (
    <>
      <SectionCards />

      {/* Chart area + risk donut side by side */}
      <div className="px-4 lg:px-6 grid grid-cols-1 gap-4 lg:grid-cols-[1fr_280px]">
        <ChartAreaInteractive />
        {scans === undefined ? (
          <Skeleton className="h-[300px] rounded-xl" />
        ) : (
          <RiskDonut
            scans={topLevel}
            onRiskClick={setActiveRisk}
            activeRisk={activeRisk}
          />
        )}
      </div>

      {/* Finding category bar */}
      <div className="px-4 lg:px-6">
        {findingStats === undefined ? (
          <Skeleton className="h-[200px] rounded-xl" />
        ) : (
          <FindingCategoryBar stats={findingStats} />
        )}
      </div>

      {/* Recent scans table */}
      <div className="px-4 lg:px-6">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-base font-semibold">Recent Scans</h2>
          <Link href="/dashboard/scans">
            <Button variant="outline" size="sm">
              View All →
            </Button>
          </Link>
        </div>
        {scans === undefined ? (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-12 rounded-lg" />
            ))}
          </div>
        ) : recentScans.length === 0 ? (
          <p className="text-sm text-muted-foreground">No scans yet.</p>
        ) : (
          <div className="overflow-x-auto border rounded-lg">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/50 text-left text-muted-foreground">
                  <th className="py-3 px-4">Repository</th>
                  <th className="py-3 px-4">Platform</th>
                  <th className="py-3 px-4">Risk</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Findings</th>
                  <th className="py-3 px-4">Date</th>
                  <th className="py-3 px-4"></th>
                </tr>
              </thead>
              <tbody>
                {recentScans
                  .filter(
                    (s) => !activeRisk || s.overallRisk === activeRisk
                  )
                  .map((scan) => (
                    <tr
                      key={scan._id}
                      className="border-b last:border-0 hover:bg-muted/30 transition-colors"
                    >
                      <td className="py-3 px-4 font-medium">
                        <Link
                          href={`/scan/${scan.shareSlug}`}
                          className="hover:underline"
                        >
                          {scan.repoOwner}/{scan.repoName}
                        </Link>
                        {scan.repoPath && (
                          <span className="text-xs text-muted-foreground block">
                            /{scan.repoPath}
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {scan.platform && scan.platform !== "unknown" ? (
                          <Badge variant="outline">
                            {PLATFORM_LABELS[scan.platform] ?? scan.platform}
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
                        {scan.totalFindings ?? "—"}
                      </td>
                      <td className="py-3 px-4 text-muted-foreground whitespace-nowrap">
                        {new Date(scan._creationTime).toLocaleDateString(
                          undefined,
                          { month: "short", day: "numeric", year: "numeric" }
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <Link href={`/scan/${scan.shareSlug}`}>
                          <Button variant="ghost" size="sm">
                            <ExternalLink className="h-3.5 w-3.5" />
                          </Button>
                        </Link>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}
