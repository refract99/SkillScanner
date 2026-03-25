"use client"

import * as React from "react"
import { useQuery } from "convex/react"
import { api } from "@/convex/_generated/api"
import { Area, AreaChart, CartesianGrid, XAxis, YAxis } from "recharts"

import { useIsMobile } from "@/hooks/use-mobile"
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  ChartConfig,
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/ui/chart"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  ToggleGroup,
  ToggleGroupItem,
} from "@/components/ui/toggle-group"
import { Skeleton } from "@/components/ui/skeleton"

const chartConfig = {
  safe: { label: "Safe", color: "#22c55e" },
  low: { label: "Low", color: "#3b82f6" },
  medium: { label: "Medium", color: "#eab308" },
  high: { label: "High", color: "#f97316" },
  critical: { label: "Critical", color: "#dc2626" },
} satisfies ChartConfig

type RiskLevel = "safe" | "low" | "medium" | "high" | "critical"
const RISK_LEVELS: RiskLevel[] = ["safe", "low", "medium", "high", "critical"]

function toDateKey(ts: number): string {
  const d = new Date(ts)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`
}

function buildChartData(
  scans: { _creationTime: number; overallRisk?: string; collectionId?: string }[],
  days: number
) {
  const now = Date.now()
  const startTs = now - days * 24 * 60 * 60 * 1000
  const relevant = scans.filter(
    (s) => !s.collectionId && s._creationTime >= startTs
  )

  // Build bucket map
  const buckets: Record<string, Record<RiskLevel, number>> = {}
  for (let i = 0; i < days; i++) {
    const ts = now - (days - 1 - i) * 24 * 60 * 60 * 1000
    const key = toDateKey(ts)
    buckets[key] = { safe: 0, low: 0, medium: 0, high: 0, critical: 0 }
  }

  for (const scan of relevant) {
    const key = toDateKey(scan._creationTime)
    if (!buckets[key]) continue
    const risk = (scan.overallRisk ?? "safe") as RiskLevel
    if (RISK_LEVELS.includes(risk)) {
      buckets[key][risk]++
    }
  }

  return Object.entries(buckets)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([date, counts]) => ({ date, ...counts }))
}

export function ChartAreaInteractive() {
  const isMobile = useIsMobile()
  const [timeRange, setTimeRange] = React.useState("30d")
  const scans = useQuery(api.scanner.queries.getUserScans)

  React.useEffect(() => {
    if (isMobile) setTimeRange("7d")
  }, [isMobile])

  const days = timeRange === "7d" ? 7 : timeRange === "30d" ? 30 : 90
  const chartData = React.useMemo(
    () => (scans ? buildChartData(scans, days) : []),
    [scans, days]
  )

  if (scans === undefined) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-40" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[250px] w-full" />
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="@container/card">
      <CardHeader>
        <CardTitle>Scan Activity</CardTitle>
        <CardDescription>
          <span className="hidden @[540px]/card:block">
            Scans by risk level over time
          </span>
          <span className="@[540px]/card:hidden">Scan activity</span>
        </CardDescription>
        <CardAction>
          <ToggleGroup
            type="single"
            value={timeRange}
            onValueChange={(v) => v && setTimeRange(v)}
            variant="outline"
            className="hidden *:data-[slot=toggle-group-item]:!px-4 @[767px]/card:flex"
          >
            <ToggleGroupItem value="90d">Last 90 days</ToggleGroupItem>
            <ToggleGroupItem value="30d">Last 30 days</ToggleGroupItem>
            <ToggleGroupItem value="7d">Last 7 days</ToggleGroupItem>
          </ToggleGroup>
          <Select value={timeRange} onValueChange={setTimeRange}>
            <SelectTrigger
              className="flex w-40 **:data-[slot=select-value]:block **:data-[slot=select-value]:truncate @[767px]/card:hidden"
              size="sm"
              aria-label="Select time range"
            >
              <SelectValue placeholder="Last 30 days" />
            </SelectTrigger>
            <SelectContent className="rounded-xl">
              <SelectItem value="90d" className="rounded-lg">Last 90 days</SelectItem>
              <SelectItem value="30d" className="rounded-lg">Last 30 days</SelectItem>
              <SelectItem value="7d" className="rounded-lg">Last 7 days</SelectItem>
            </SelectContent>
          </Select>
        </CardAction>
      </CardHeader>
      <CardContent className="px-2 pt-4 sm:px-6 sm:pt-6">
        <ChartContainer config={chartConfig} className="aspect-auto h-[250px] w-full">
          <AreaChart data={chartData}>
            <defs>
              {RISK_LEVELS.map((level) => (
                <linearGradient key={level} id={`fill-${level}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={chartConfig[level].color} stopOpacity={0.8} />
                  <stop offset="95%" stopColor={chartConfig[level].color} stopOpacity={0.1} />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid vertical={false} />
            <XAxis
              dataKey="date"
              tickLine={false}
              axisLine={false}
              tickMargin={8}
              minTickGap={32}
              tickFormatter={(value) =>
                new Date(value).toLocaleDateString("en-US", {
                  month: "short",
                  day: "numeric",
                })
              }
            />
            <YAxis hide allowDecimals={false} />
            <ChartTooltip
              cursor={false}
              content={
                <ChartTooltipContent
                  labelFormatter={(value) =>
                    new Date(value).toLocaleDateString("en-US", {
                      month: "short",
                      day: "numeric",
                    })
                  }
                  indicator="dot"
                />
              }
            />
            {RISK_LEVELS.map((level) => (
              <Area
                key={level}
                dataKey={level}
                type="monotone"
                fill={`url(#fill-${level})`}
                stroke={chartConfig[level].color}
                stackId="a"
              />
            ))}
          </AreaChart>
        </ChartContainer>
      </CardContent>
    </Card>
  )
}
