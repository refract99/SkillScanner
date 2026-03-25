"use client"

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

const CATEGORY_LABELS: Record<string, string> = {
  secrets_detection: "Secrets",
  dependency_audit: "Dep. Audit",
  credential_access: "Credentials",
  prompt_injection: "Prompt Inj.",
  code_injection: "Code Inj.",
  ai_semantic: "AI Semantic",
  external_links: "Ext. Links",
  standard_compliance: "Compliance",
  network_exfiltration: "Exfiltration",
  dangerous_operations: "Dangerous Ops",
  obfuscation: "Obfuscation",
  dependency_risks: "Dep. Risks",
  bundled_payloads: "Payloads",
  cross_platform: "Cross-Platform",
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
}

type FindingStat = { category: string; severity: string; count: number }

interface FindingCategoryBarProps {
  stats: FindingStat[]
}

export function FindingCategoryBar({ stats }: FindingCategoryBarProps) {
  // Aggregate: for each category pick dominant severity color + total count
  const byCategory: Record<
    string,
    { total: number; dominant: string }
  > = {}

  for (const { category, severity, count } of stats) {
    if (!byCategory[category]) {
      byCategory[category] = { total: 0, dominant: severity }
    }
    byCategory[category].total += count
    // dominant = highest severity seen
    const order = ["critical", "high", "medium", "low", "info"]
    if (
      order.indexOf(severity) <
      order.indexOf(byCategory[category].dominant)
    ) {
      byCategory[category].dominant = severity
    }
  }

  const data = Object.entries(byCategory)
    .sort(([, a], [, b]) => b.total - a.total)
    .map(([category, { total, dominant }]) => ({
      category: CATEGORY_LABELS[category] ?? category,
      count: total,
      color: SEVERITY_COLORS[dominant] ?? "#6b7280",
    }))

  if (data.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Finding Categories</CardTitle>
        </CardHeader>
        <CardContent className="flex items-center justify-center h-[180px] text-sm text-muted-foreground">
          No findings yet
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Finding Categories</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={Math.max(180, data.length * 32)}>
          <BarChart
            layout="vertical"
            data={data}
            margin={{ top: 0, right: 16, left: 0, bottom: 0 }}
          >
            <CartesianGrid horizontal={false} />
            <XAxis type="number" allowDecimals={false} tickLine={false} axisLine={false} />
            <YAxis
              type="category"
              dataKey="category"
              tickLine={false}
              axisLine={false}
              width={90}
              tick={{ fontSize: 12 }}
            />
            <Tooltip
              formatter={(value: number) => [value, "Findings"]}
            />
            <Bar dataKey="count" radius={[0, 4, 4, 0]}>
              {data.map((entry) => (
                <Cell key={entry.category} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  )
}
