import { describe, it, expect } from "vitest";
import {
  githubUrlSchema,
  parseGitHubUrl,
  detectPlatformFromUrl,
} from "@/lib/scan-validation";

// =============================================================================
// parseGitHubUrl
// =============================================================================
describe("parseGitHubUrl", () => {
  it("parses simple owner/repo URL", () => {
    const result = parseGitHubUrl("https://github.com/user/repo");
    expect(result).toEqual({ owner: "user", repo: "repo" });
  });

  it("parses URL with branch", () => {
    const result = parseGitHubUrl("https://github.com/user/repo/tree/main");
    expect(result).toEqual({ owner: "user", repo: "repo", branch: "main", path: undefined });
  });

  it("parses URL with branch and path", () => {
    const result = parseGitHubUrl("https://github.com/user/repo/tree/main/src/utils");
    expect(result).toEqual({ owner: "user", repo: "repo", branch: "main", path: "src/utils" });
  });

  it("strips query params", () => {
    const result = parseGitHubUrl("https://github.com/user/repo?tab=readme");
    expect(result).toEqual({ owner: "user", repo: "repo" });
  });

  it("strips hash fragments", () => {
    const result = parseGitHubUrl("https://github.com/user/repo#readme");
    expect(result).toEqual({ owner: "user", repo: "repo" });
  });

  it("strips trailing slashes", () => {
    const result = parseGitHubUrl("https://github.com/user/repo/");
    expect(result).toEqual({ owner: "user", repo: "repo" });
  });

  it("handles dots in repo name", () => {
    const result = parseGitHubUrl("https://github.com/user/my.repo");
    expect(result).toEqual({ owner: "user", repo: "my.repo" });
  });

  it("handles underscores and hyphens", () => {
    const result = parseGitHubUrl("https://github.com/my-org/my_repo-name");
    expect(result).toEqual({ owner: "my-org", repo: "my_repo-name" });
  });

  it("returns null for non-GitHub URLs", () => {
    expect(parseGitHubUrl("https://gitlab.com/user/repo")).toBeNull();
  });

  it("returns null for GitHub profile pages (no repo)", () => {
    expect(parseGitHubUrl("https://github.com/user")).toBeNull();
  });

  it("returns null for empty string", () => {
    expect(parseGitHubUrl("")).toBeNull();
  });

  it("returns null for malformed URLs", () => {
    expect(parseGitHubUrl("not-a-url")).toBeNull();
  });
});

// =============================================================================
// detectPlatformFromUrl
// =============================================================================
describe("detectPlatformFromUrl", () => {
  it("detects Claude Code from .claude/skills/ path", () => {
    expect(
      detectPlatformFromUrl("https://github.com/user/repo/tree/main/.claude/skills/my-skill")
    ).toBe("Claude Code");
  });

  it("detects Claude Code from .claude/commands/ path", () => {
    expect(
      detectPlatformFromUrl("https://github.com/user/repo/tree/main/.claude/commands/cmd")
    ).toBe("Claude Code");
  });

  it("detects Cursor from .cursor/rules/ path", () => {
    expect(
      detectPlatformFromUrl("https://github.com/user/repo/tree/main/.cursor/rules/")
    ).toBe("Cursor");
  });

  it("detects Windsurf from .windsurf/rules/ path", () => {
    expect(
      detectPlatformFromUrl("https://github.com/user/repo/tree/main/.windsurf/rules/")
    ).toBe("Windsurf");
  });

  it("detects Cline from .clinerules/ path", () => {
    expect(
      detectPlatformFromUrl("https://github.com/user/repo/tree/main/.clinerules/rule")
    ).toBe("Cline");
  });

  it("detects AgentSkills from skills/ path", () => {
    expect(
      detectPlatformFromUrl("https://github.com/user/repo/tree/main/skills/my-skill")
    ).toBe("AgentSkills");
  });

  it("returns null for generic repo URL", () => {
    expect(
      detectPlatformFromUrl("https://github.com/user/repo")
    ).toBeNull();
  });
});

// =============================================================================
// githubUrlSchema (Zod validation)
// =============================================================================
describe("githubUrlSchema", () => {
  it("accepts valid GitHub repo URL", () => {
    const result = githubUrlSchema.safeParse("https://github.com/user/repo");
    expect(result.success).toBe(true);
  });

  it("accepts URL with tree path", () => {
    const result = githubUrlSchema.safeParse("https://github.com/user/repo/tree/main/src");
    expect(result.success).toBe(true);
  });

  it("rejects non-GitHub URLs", () => {
    const result = githubUrlSchema.safeParse("https://gitlab.com/user/repo");
    expect(result.success).toBe(false);
  });

  it("rejects non-URL strings", () => {
    const result = githubUrlSchema.safeParse("not-a-url");
    expect(result.success).toBe(false);
  });

  it("rejects path traversal (..)", () => {
    const result = githubUrlSchema.safeParse("https://github.com/user/repo/../etc/passwd");
    expect(result.success).toBe(false);
  });

  it("rejects embedded credentials (@)", () => {
    const result = githubUrlSchema.safeParse("https://github.com/user@evil.com/repo");
    expect(result.success).toBe(false);
  });

  it("rejects empty string", () => {
    const result = githubUrlSchema.safeParse("");
    expect(result.success).toBe(false);
  });

  it("rejects HTTP (non-HTTPS) GitHub URL", () => {
    const result = githubUrlSchema.safeParse("http://github.com/user/repo");
    expect(result.success).toBe(false);
  });
});
