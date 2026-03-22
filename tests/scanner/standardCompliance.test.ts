import { describe, it, expect } from "vitest";
import { scan } from "@/convex/scanner/scanners/standardCompliance";
import { makeFile, makeContext, makeSkillMd } from "../helpers/fixtures";
import {
  expectFinding,
  expectNoFinding,
  findingsByRule,
} from "../helpers/assertions";

// =============================================================================
// STD001: Missing or wrong-case SKILL.md
// =============================================================================
describe("STD001 — Missing or wrong-case SKILL.md", () => {
  it("flags when no SKILL.md exists", async () => {
    const ctx = makeContext([makeFile("readme.md", "# Hello")]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD001", { severity: "medium" });
    expect(findings.find((f) => f.ruleId === "STD001")?.title).toContain("Missing");
  });

  it("flags wrong case (skill.md)", async () => {
    const ctx = makeContext([makeFile("skill.md", "---\nname: test\n---\nBody")]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD001");
    expect(findings.find((f) => f.ruleId === "STD001")?.title).toContain("wrong case");
  });

  it("flags wrong case (Skill.MD)", async () => {
    const ctx = makeContext([makeFile("Skill.MD", "---\nname: test\n---\nBody")]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD001");
  });

  it("does NOT flag correct SKILL.md", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "test-skill", description: "A test" }, "Body content"),
    ]);
    const { findings } = await scan(ctx);
    expectNoFinding(findings, "STD001");
  });
});

// =============================================================================
// STD002: Invalid/empty frontmatter
// =============================================================================
describe("STD002 — Invalid frontmatter", () => {
  it("flags empty frontmatter", async () => {
    const ctx = makeContext([makeFile("SKILL.md", "---\n---\nBody")]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD002");
  });

  it("does NOT flag valid frontmatter", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "valid", description: "ok" }, "Body"),
    ]);
    const { findings } = await scan(ctx);
    expectNoFinding(findings, "STD002");
  });
});

// =============================================================================
// STD003: Missing name field
// =============================================================================
describe("STD003 — Missing name", () => {
  it("flags missing name field", async () => {
    const ctx = makeContext([
      makeSkillMd({ description: "has desc but no name" }, "Body"),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD003", { severity: "low" });
  });

  it("does NOT flag when name is present", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "my-skill", description: "ok" }, "Body"),
    ]);
    const { findings } = await scan(ctx);
    expectNoFinding(findings, "STD003");
  });
});

// =============================================================================
// STD004: Missing/long description
// =============================================================================
describe("STD004 — Missing or long description", () => {
  it("flags missing description", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "my-skill" }, "Body"),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD004", { severity: "low" });
  });

  it("flags description over 1024 chars", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "my-skill", description: "a".repeat(1025) }, "Body"),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD004", { severity: "info" });
  });

  it("does NOT flag normal description", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "my-skill", description: "A normal description" }, "Body"),
    ]);
    const { findings } = await scan(ctx);
    expectNoFinding(findings, "STD004");
  });
});

// =============================================================================
// STD005: Name validation
// =============================================================================
describe("STD005 — Name validation", () => {
  it("flags non-kebab-case name", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "MySkill", description: "test" }, "Body"),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD005");
  });

  it("flags name with underscores", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "my_skill", description: "test" }, "Body"),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD005");
  });

  it("flags name over 64 characters", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "a".repeat(65), description: "test" }, "Body"),
    ]);
    const { findings } = await scan(ctx);
    const std005s = findingsByRule(findings, "STD005");
    expect(std005s.some((f) => f.title.includes("64"))).toBe(true);
  });

  it("does NOT flag valid kebab-case name", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "my-cool-skill", description: "test" }, "Body"),
    ]);
    const { findings } = await scan(ctx);
    expectNoFinding(findings, "STD005");
  });
});

// =============================================================================
// STD006: XML angle brackets in frontmatter
// =============================================================================
describe("STD006 — XML in frontmatter", () => {
  it("flags < in frontmatter", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "evil", description: "<script>xss</script>" }, "Body"),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD006", { severity: "high" });
  });

  it("does NOT flag < in body only", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "safe", description: "test" }, "Some <html> in body"),
    ]);
    const { findings } = await scan(ctx);
    expectNoFinding(findings, "STD006");
  });
});

// =============================================================================
// STD007: Body too long
// =============================================================================
describe("STD007 — Body exceeds 5000 words", () => {
  it("flags body over 5000 words", async () => {
    const longBody = ("word ".repeat(5001)).trim();
    const ctx = makeContext([
      makeSkillMd({ name: "long-skill", description: "test" }, longBody),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD007", { severity: "info" });
  });

  it("does NOT flag normal length body", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "normal", description: "test" }, "Short body content"),
    ]);
    const { findings } = await scan(ctx);
    expectNoFinding(findings, "STD007");
  });
});

// =============================================================================
// STD008: README.md alongside SKILL.md
// =============================================================================
describe("STD008 — README.md in skill folder", () => {
  it("flags README.md in same directory as SKILL.md", async () => {
    const ctx = makeContext([
      makeFile("skills/my-skill/SKILL.md", "---\nname: my-skill\n---\nBody"),
      makeFile("skills/my-skill/README.md", "# My Skill"),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD008", { severity: "info" });
  });

  it("does NOT flag README.md without SKILL.md", async () => {
    const ctx = makeContext([
      makeFile("skills/other/README.md", "# Other"),
      makeSkillMd({ name: "root-skill", description: "test" }, "Body"),
    ]);
    const { findings } = await scan(ctx);
    expectNoFinding(findings, "STD008");
  });
});

// =============================================================================
// STD009: Reserved name
// =============================================================================
describe("STD009 — Reserved name", () => {
  it("flags name containing 'claude'", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "claude-helper", description: "test" }, "Body"),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD009", { severity: "medium" });
  });

  it("flags name containing 'anthropic'", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "anthropic-tool", description: "test" }, "Body"),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD009");
  });

  it("does NOT flag unrelated name", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "git-helper", description: "test" }, "Body"),
    ]);
    const { findings } = await scan(ctx);
    expectNoFinding(findings, "STD009");
  });
});

// =============================================================================
// STD010: Missing allowed-tools
// =============================================================================
describe("STD010 — Missing allowed-tools", () => {
  it("flags when allowed-tools not declared", async () => {
    const ctx = makeContext([
      makeSkillMd({ name: "my-skill", description: "test" }, "Body"),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD010", { severity: "medium" });
  });

  it("does NOT flag when allowed-tools is present", async () => {
    const ctx = makeContext([
      makeSkillMd(
        { name: "my-skill", description: "test", "allowed-tools": "Read, Grep" },
        "Body"
      ),
    ]);
    const { findings } = await scan(ctx);
    expectNoFinding(findings, "STD010");
  });
});

// =============================================================================
// STD011: Excessive tool permissions
// =============================================================================
describe("STD011 — Excessive tool permissions", () => {
  it("flags shell + write combo as high severity", async () => {
    const ctx = makeContext([
      makeSkillMd(
        { name: "dangerous", description: "test", "allowed-tools": "Bash, Write, Read" },
        "Body"
      ),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD011", { severity: "high" });
  });

  it("flags shell-only as medium severity", async () => {
    const ctx = makeContext([
      makeSkillMd(
        { name: "shell-user", description: "test", "allowed-tools": "Bash, Read" },
        "Body"
      ),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD011", { severity: "medium" });
  });

  it("does NOT flag safe tools only", async () => {
    const ctx = makeContext([
      makeSkillMd(
        { name: "safe", description: "test", "allowed-tools": "Read, Grep, Glob" },
        "Body"
      ),
    ]);
    const { findings } = await scan(ctx);
    expectNoFinding(findings, "STD011");
  });
});

// =============================================================================
// STD012: Broad tool access
// =============================================================================
describe("STD012 — Broad tool access", () => {
  it("flags more than 8 tools", async () => {
    const tools = "Read, Grep, Glob, Write, Edit, Bash, Agent, WebFetch, WebSearch";
    const ctx = makeContext([
      makeSkillMd(
        { name: "broad", description: "test", "allowed-tools": tools },
        "Body"
      ),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "STD012", { severity: "medium" });
  });

  it("does NOT flag 8 or fewer tools", async () => {
    const tools = "Read, Grep, Glob, Write, Edit, Bash, Agent, WebFetch";
    const ctx = makeContext([
      makeSkillMd(
        { name: "ok", description: "test", "allowed-tools": tools },
        "Body"
      ),
    ]);
    const { findings } = await scan(ctx);
    expectNoFinding(findings, "STD012");
  });
});
