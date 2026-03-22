import { z } from "zod";

export const githubUrlSchema = z
  .string()
  .url("Please enter a valid URL")
  .regex(
    /^https:\/\/github\.com\/[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+(\/.*)?$/,
    "Must be a GitHub URL (https://github.com/owner/repo)"
  )
  .refine((url) => !url.includes(".."), "Invalid URL: path traversal detected")
  .refine(
    (url) => !url.replace("https://", "").includes("@"),
    "Invalid URL: embedded credentials detected"
  );

export function parseGitHubUrl(url: string) {
  const cleaned = url.split("?")[0].split("#")[0].replace(/\/+$/, "");
  const match = cleaned.match(
    /^https:\/\/github\.com\/([a-zA-Z0-9._-]+)\/([a-zA-Z0-9._-]+)(?:\/tree\/([^/]+)(?:\/(.+))?)?$/
  );
  if (match) {
    return { owner: match[1], repo: match[2], branch: match[3], path: match[4] };
  }
  const simple = cleaned.match(
    /^https:\/\/github\.com\/([a-zA-Z0-9._-]+)\/([a-zA-Z0-9._-]+)$/
  );
  if (simple) {
    return { owner: simple[1], repo: simple[2] };
  }
  return null;
}

export function detectPlatformFromUrl(url: string): string | null {
  if (url.includes(".claude/skills/") || url.includes(".claude/commands/")) return "Claude Code";
  if (url.includes(".cursor/rules/")) return "Cursor";
  if (url.includes(".windsurf/rules/")) return "Windsurf";
  if (url.includes(".clinerules/")) return "Cline";
  if (url.includes("skills/")) return "AgentSkills";
  return null;
}
