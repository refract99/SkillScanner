import { describe, it, expect } from "vitest";
import { scan } from "@/convex/scanner/scanners/crossPlatform";
import { makeFile, makeContext, makeSkillMd } from "../helpers/fixtures";

describe("Platform detection by file path", () => {
  it("detects claude_code from .claude/skills/ path", async () => {
    const ctx = makeContext([
      makeFile(".claude/skills/my-skill/SKILL.md", "---\nname: my-skill\n---\nBody"),
    ]);
    const { platform } = await scan(ctx);
    expect(platform).toBe("claude_code");
  });

  it("detects claude_code from .claude/commands/ path", async () => {
    const ctx = makeContext([
      makeFile(".claude/commands/my-cmd.md", "# Command"),
    ]);
    const { platform } = await scan(ctx);
    expect(platform).toBe("claude_code");
  });

  it("detects cursor from .cursor/rules/ path with .mdc", async () => {
    const ctx = makeContext([
      makeFile(".cursor/rules/my-rule.mdc", "---\nglobs: **/*.ts\n---\nRule content"),
    ]);
    const { platform } = await scan(ctx);
    expect(platform).toBe("cursor");
  });

  it("detects windsurf from .windsurf/rules/ path", async () => {
    const ctx = makeContext([
      makeFile(".windsurf/rules/rule.md", "# Rule"),
    ]);
    const { platform } = await scan(ctx);
    expect(platform).toBe("windsurf");
  });

  it("detects cline from .clinerules/ path", async () => {
    const ctx = makeContext([
      makeFile(".clinerules/my-rule.md", "# Rule"),
    ]);
    const { platform } = await scan(ctx);
    expect(platform).toBe("cline");
  });

  it("detects agentskills from skills/SKILL.md", async () => {
    const ctx = makeContext([
      makeFile("skills/my-skill/SKILL.md", "---\nname: my-skill\ndescription: test\n---\nBody"),
    ]);
    const { platform } = await scan(ctx);
    expect(platform).toBe("agentskills");
  });
});

describe("Platform detection by frontmatter", () => {
  it("detects claude_code from allowed-tools field", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "my-skill", description: "test", "allowed-tools": "Read, Grep" }, "Body"),
    ]);
    const { platform } = await scan(ctx);
    expect(platform).toBe("claude_code");
  });

  it("detects claude_code from model field", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "my-skill", description: "test", model: "claude-sonnet-4-5" }, "Body"),
    ]);
    const { platform } = await scan(ctx);
    expect(platform).toBe("claude_code");
  });

  it("detects agentskills from name + description only", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "generic-skill", description: "A generic skill" }, "Body"),
    ]);
    const { platform } = await scan(ctx);
    expect(platform).toBe("agentskills");
  });
});

describe("Platform priority resolution", () => {
  it("prefers claude_code over agentskills when both detected", async () => {
    const ctx = makeContext([
      makeFile(".claude/skills/my-skill/SKILL.md", "---\nname: my-skill\ndescription: test\n---\nBody"),
    ]);
    const { platform } = await scan(ctx);
    // .claude/skills/ triggers claude_code, skills/SKILL.md triggers agentskills
    expect(platform).toBe("claude_code");
  });

  it("returns unknown when no platform detected", async () => {
    const ctx = makeContext([
      makeFile("readme.md", "# Hello World"),
    ]);
    const { platform } = await scan(ctx);
    expect(platform).toBe("unknown");
  });
});

describe("Platform findings", () => {
  it("generates CP001 finding for detected platform", async () => {
    const ctx = makeContext([
      makeFile(".windsurf/rules/rule.md", "# Rule"),
    ]);
    const { findings } = await scan(ctx);
    const platformFindings = findings.filter((f) => f.ruleId === "CP001");
    expect(platformFindings.length).toBeGreaterThan(0);
    expect(platformFindings[0].title).toContain("windsurf");
  });

  it("generates CP003 finding for Claude Code-specific fields", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "test", description: "test", "allowed-tools": "Read" }, "Body"),
    ]);
    const { findings } = await scan(ctx);
    const cp003 = findings.filter((f) => f.ruleId === "CP003");
    expect(cp003.length).toBeGreaterThan(0);
  });

  it("generates CP003 for Cursor-specific fields", async () => {
    const ctx = makeContext([
      makeFile("rules.mdc", "---\nglobs: **/*.ts\nalwaysApply: true\n---\nContent"),
    ]);
    const { findings } = await scan(ctx);
    const cp003 = findings.filter((f) => f.ruleId === "CP003");
    expect(cp003.some((f) => f.title.includes("Cursor"))).toBe(true);
  });
});
