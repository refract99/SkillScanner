"use client"

import { useQuery } from "convex/react"
import { api } from "@/convex/_generated/api"
import { IconTrendingDown, IconTrendingUp } from "@tabler/icons-react"
import { Shield, AlertTriangle, KeyRound, Package } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardAction,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"

function computeTrend(scans: { _creationTime: number }[], now: number) {
  const day7 = now - 7 * 24 * 60 * 60 * 1000
  const day14 = now - 14 * 24 * 60 * 60 * 1000
  const current = scans.filter((s) => s._creationTime >= day7).length
  const prior = scans.filter(
    (s) => s._creationTime >= day14 && s._creationTime < day7
  ).length
  if (prior === 0) return current > 0 ? 100 : 0
  return Math.round(((current - prior) / prior) * 100)
}

export function SectionCards() {
  const scans = useQuery(api.scanner.queries.getUserScans)
  const now = Date.now()

  if (scans === undefined) {
    return (
      <div className="grid grid-cols-1 gap-4 px-4 lg:px-6 @xl/main:grid-cols-2 @5xl/main:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-32 rounded-xl" />
        ))}
      </div>
    )
  }

  const topLevel = scans.filter((s) => !s.collectionId)

  const totalScans = topLevel.length
  const totalTrend = computeTrend(topLevel, now)

  const highCritical = topLevel.filter(
    (s) => s.overallRisk === "high" || s.overallRisk === "critical"
  )
  const highCriticalTrend = computeTrend(highCritical, now)

  const secretsScans = topLevel.filter((s) => (s.secretsCount ?? 0) > 0)
  const secretsTrend = computeTrend(secretsScans, now)

  const depCveScans = topLevel.filter(
    (s) => (s.depHighCount ?? 0) + (s.depCriticalCount ?? 0) > 0
  )
  const depCveTrend = computeTrend(depCveScans, now)

  const cards = [
    {
      label: "Total Scans",
      value: totalScans,
      trend: totalTrend,
      icon: Shield,
      footer: "All time scans",
    },
    {
      label: "High/Critical Risk",
      value: highCritical.length,
      trend: highCriticalTrend,
      icon: AlertTriangle,
      footer: "Scans with high or critical risk",
    },
    {
      label: "Secrets Found",
      value: secretsScans.length,
      trend: secretsTrend,
      icon: KeyRound,
      footer: "Scans with detected secrets",
    },
    {
      label: "Dependency CVEs",
      value: depCveScans.length,
      trend: depCveTrend,
      icon: Package,
      footer: "Scans with high/critical CVEs",
    },
  ]

  return (
    <div className="*:data-[slot=card]:from-primary/5 *:data-[slot=card]:to-card dark:*:data-[slot=card]:bg-card grid grid-cols-1 gap-4 px-4 *:data-[slot=card]:bg-gradient-to-t *:data-[slot=card]:shadow-xs lg:px-6 @xl/main:grid-cols-2 @5xl/main:grid-cols-4">
      {cards.map(({ label, value, trend, icon: Icon, footer }) => (
        <Card key={label} className="@container/card">
          <CardHeader>
            <CardDescription className="flex items-center gap-1.5">
              <Icon className="size-4" />
              {label}
            </CardDescription>
            <CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
              {value}
            </CardTitle>
            <CardAction>
              <Badge variant="outline">
                {trend >= 0 ? <IconTrendingUp /> : <IconTrendingDown />}
                {trend >= 0 ? "+" : ""}
                {trend}%
              </Badge>
            </CardAction>
          </CardHeader>
          <CardFooter className="flex-col items-start gap-1.5 text-sm">
            <div className="line-clamp-1 flex gap-2 font-medium">
              {trend >= 0 ? "Up" : "Down"} {Math.abs(trend)}% vs prior 7 days{" "}
              {trend >= 0 ? (
                <IconTrendingUp className="size-4" />
              ) : (
                <IconTrendingDown className="size-4" />
              )}
            </div>
            <div className="text-muted-foreground">{footer}</div>
          </CardFooter>
        </Card>
      ))}
    </div>
  )
}
