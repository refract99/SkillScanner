"use client"

import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

const RISK_COLORS: Record<string, string> = {
  safe: "#22c55e",
  low: "#3b82f6",
  medium: "#eab308",
  high: "#f97316",
  critical: "#dc2626",
}

type Scan = {
  overallRisk?: string
  collectionId?: string
}

interface RiskDonutProps {
  scans: Scan[]
  onRiskClick?: (risk: string | null) => void
  activeRisk?: string | null
}

export function RiskDonut({ scans, onRiskClick, activeRisk }: RiskDonutProps) {
  const topLevel = scans.filter((s) => !s.collectionId)

  const counts: Record<string, number> = {}
  for (const scan of topLevel) {
    const risk = scan.overallRisk ?? "safe"
    counts[risk] = (counts[risk] || 0) + 1
  }

  const data = Object.entries(counts)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  if (data.length === 0) {
    return (
      <Card className="flex flex-col">
        <CardHeader>
          <CardTitle className="text-base">Risk Distribution</CardTitle>
        </CardHeader>
        <CardContent className="flex items-center justify-center h-[180px] text-sm text-muted-foreground">
          No scan data yet
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="flex flex-col">
      <CardHeader>
        <CardTitle className="text-base">Risk Distribution</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col items-center gap-3">
        <ResponsiveContainer width="100%" height={180}>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={80}
              paddingAngle={2}
              dataKey="value"
              onClick={(entry) => {
                if (onRiskClick) {
                  onRiskClick(
                    activeRisk === entry.name ? null : entry.name
                  )
                }
              }}
              style={{ cursor: onRiskClick ? "pointer" : "default" }}
            >
              {data.map((entry) => (
                <Cell
                  key={entry.name}
                  fill={RISK_COLORS[entry.name] ?? "#6b7280"}
                  opacity={
                    activeRisk && activeRisk !== entry.name ? 0.4 : 1
                  }
                />
              ))}
            </Pie>
            <Tooltip
              formatter={(value: number, name: string) => [value, name]}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="flex flex-wrap gap-2 justify-center text-xs">
          {data.map((entry) => (
            <span key={entry.name} className="flex items-center gap-1">
              <span
                className="inline-block w-2 h-2 rounded-full"
                style={{ background: RISK_COLORS[entry.name] ?? "#6b7280" }}
              />
              <span className="capitalize">{entry.name}</span>
              <span className="text-muted-foreground">({entry.value})</span>
            </span>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
