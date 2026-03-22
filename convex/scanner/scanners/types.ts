export type ScanCategory =
  | "standard_compliance"
  | "prompt_injection"
  | "credential_access"
  | "network_exfiltration"
  | "dangerous_operations"
  | "code_injection"
  | "obfuscation"
  | "dependency_risks"
  | "bundled_payloads"
  | "external_links"
  | "ai_semantic"
  | "cross_platform";

export interface Finding {
  category: ScanCategory;
  ruleId: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: "high" | "medium" | "low";
  title: string;
  description: string;
  filePath?: string;
  lineNumber?: number;
  matchedPattern?: string;
  snippet?: string;
}

export interface ExternalLink {
  url: string;
  domain: string;
  filePath: string;
  lineNumber?: number;
  classification: "safe" | "unknown" | "suspicious";
  context?: string;
}

export interface ScannerResult {
  findings: Finding[];
  links?: ExternalLink[];
}

export type Platform =
  | "claude_code"
  | "openclaw"
  | "cursor"
  | "windsurf"
  | "cline"
  | "agentskills"
  | "unknown";

export interface ScanContext {
  rootDir: string;
  files: FileEntry[];
}

export interface FileEntry {
  relativePath: string;
  absolutePath: string;
  content: string;
  size: number;
  isSymlink: boolean;
}

// Simple path utilities (avoid importing Node.js 'path' module in Convex runtime)
export function basename(filePath: string): string {
  const parts = filePath.split("/");
  return parts[parts.length - 1] || "";
}

export function dirname(filePath: string): string {
  const parts = filePath.split("/");
  parts.pop();
  return parts.join("/") || ".";
}

export function extname(filePath: string): string {
  const base = basename(filePath);
  const dot = base.lastIndexOf(".");
  return dot > 0 ? base.substring(dot) : "";
}

export function joinPath(...parts: string[]): string {
  return parts.filter(Boolean).join("/").replace(/\/+/g, "/");
}

// Simple YAML frontmatter parser (avoid importing gray-matter in Convex runtime)
export function parseFrontmatter(content: string): {
  data: Record<string, unknown>;
  content: string;
} {
  const match = content.match(/^---\s*\n([\s\S]*?)\n---\s*\n?([\s\S]*)$/);
  if (!match) {
    return { data: {}, content };
  }

  const yamlStr = match[1];
  const body = match[2];
  const data: Record<string, unknown> = {};

  // Simple YAML key-value parser (handles top-level string/boolean/number values)
  for (const line of yamlStr.split("\n")) {
    const kvMatch = line.match(/^(\S[^:]*?):\s*(.*)$/);
    if (kvMatch) {
      const key = kvMatch[1].trim();
      let value: unknown = kvMatch[2].trim();

      // Remove quotes
      if (
        (typeof value === "string" && value.startsWith('"') && value.endsWith('"')) ||
        (typeof value === "string" && value.startsWith("'") && value.endsWith("'"))
      ) {
        value = (value as string).slice(1, -1);
      } else if (value === "true") {
        value = true;
      } else if (value === "false") {
        value = false;
      } else if (typeof value === "string" && /^\d+$/.test(value)) {
        value = parseInt(value, 10);
      }

      data[key] = value;
    }
  }

  return { data, content: body };
}

/** Sanitize a code snippet for safe storage (HTML entity escaping, length truncation) */
export function sanitizeSnippet(text: string, maxLength = 500): string {
  const escaped = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
  return escaped.length > maxLength
    ? escaped.substring(0, maxLength) + "..."
    : escaped;
}

/** Extract a snippet of surrounding lines from content at a given line number */
export function getSnippet(
  content: string,
  lineNumber: number,
  contextLines = 2
): string {
  const lines = content.split("\n");
  const start = Math.max(0, lineNumber - 1 - contextLines);
  const end = Math.min(lines.length, lineNumber + contextLines);
  return sanitizeSnippet(
    lines
      .slice(start, end)
      .map((line, i) => `${start + i + 1}: ${line}`)
      .join("\n")
  );
}
