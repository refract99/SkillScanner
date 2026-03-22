import { describe, it, expect } from "vitest";
import { scan } from "@/convex/scanner/scanners/externalLinks";
import { classifyDomain } from "@/convex/scanner/scanners/domainSafelist";
import { makeFile, makeContext } from "../helpers/fixtures";
import {
  expectFinding,
  expectNoFinding,
  findingsByRule,
} from "../helpers/assertions";

// =============================================================================
// Domain classification
// =============================================================================
describe("classifyDomain", () => {
  it("classifies github.com as safe", () => {
    expect(classifyDomain("github.com")).toBe("safe");
  });

  it("classifies subdomain of safe domain as safe", () => {
    expect(classifyDomain("docs.github.com")).toBe("safe");
  });

  it("classifies npmjs.com as safe", () => {
    expect(classifyDomain("npmjs.com")).toBe("safe");
  });

  it("classifies anthropic.com as safe", () => {
    expect(classifyDomain("anthropic.com")).toBe("safe");
  });

  it("classifies .tk TLD as suspicious", () => {
    expect(classifyDomain("evil.tk")).toBe("suspicious");
  });

  it("classifies .xyz TLD as suspicious", () => {
    expect(classifyDomain("random.xyz")).toBe("suspicious");
  });

  it("classifies bit.ly as suspicious (URL shortener)", () => {
    expect(classifyDomain("bit.ly")).toBe("suspicious");
  });

  it("classifies tinyurl.com as suspicious", () => {
    expect(classifyDomain("tinyurl.com")).toBe("suspicious");
  });

  it("classifies IP address as suspicious", () => {
    expect(classifyDomain("192.168.1.1")).toBe("suspicious");
  });

  it("classifies unknown domains as unknown", () => {
    expect(classifyDomain("mycompany.com")).toBe("unknown");
  });

  it("is case-insensitive", () => {
    expect(classifyDomain("GitHub.COM")).toBe("safe");
  });
});

// =============================================================================
// URL extraction
// =============================================================================
describe("URL extraction", () => {
  it("extracts HTTPS URLs", async () => {
    const ctx = makeContext([
      makeFile("SKILL.md", "Visit https://github.com/user/repo for details"),
    ]);
    const { links } = await scan(ctx);
    expect(links?.length).toBe(1);
    expect(links?.[0].domain).toBe("github.com");
  });

  it("extracts HTTP URLs", async () => {
    const ctx = makeContext([
      makeFile("SKILL.md", "See http://example.com/docs"),
    ]);
    const { links } = await scan(ctx);
    expect(links?.length).toBe(1);
  });

  it("extracts multiple URLs from one line", async () => {
    const ctx = makeContext([
      makeFile("SKILL.md", "See https://github.com and https://npmjs.com"),
    ]);
    const { links } = await scan(ctx);
    expect(links?.length).toBe(2);
  });

  it("deduplicates URLs across lines", async () => {
    const ctx = makeContext([
      makeFile("SKILL.md", "See https://github.com/repo\nAlso https://github.com/repo"),
    ]);
    const { links } = await scan(ctx);
    expect(links?.length).toBe(1);
  });

  it("strips trailing punctuation from URLs", async () => {
    const ctx = makeContext([
      makeFile("SKILL.md", "See https://github.com/repo, and more."),
    ]);
    const { links } = await scan(ctx);
    // Trailing comma and period should be stripped
    expect(links?.[0].url).toBe("https://github.com/repo");
  });
});

// =============================================================================
// Link classification findings
// =============================================================================
describe("Link classification findings", () => {
  it("creates EL001 (info) for safe domains", async () => {
    const ctx = makeContext([
      makeFile("SKILL.md", "See https://github.com/user/repo"),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "EL001", { severity: "info" });
  });

  it("creates EL002 (medium) for unknown domains", async () => {
    const ctx = makeContext([
      makeFile("SKILL.md", "See https://randomsite.com/data"),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "EL002", { severity: "medium" });
  });

  it("creates EL003 (high) for suspicious domains", async () => {
    const ctx = makeContext([
      makeFile("SKILL.md", "See https://evil.tk/payload"),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "EL003", { severity: "high" });
  });

  it("creates EL003 for URL shorteners", async () => {
    const ctx = makeContext([
      makeFile("SKILL.md", "See https://bit.ly/abc123"),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "EL003");
  });
});

// =============================================================================
// IP address detection
// =============================================================================
describe("IP address detection (EL004)", () => {
  it("flags IPv4 addresses", async () => {
    const ctx = makeContext([
      makeFile("SKILL.md", "Connect to 192.168.1.100 for data"),
    ]);
    const { findings } = await scan(ctx);
    expectFinding(findings, "EL004", { severity: "medium" });
  });

  it("does NOT flag 127.0.0.1 (localhost)", async () => {
    const ctx = makeContext([
      makeFile("SKILL.md", "Running on 127.0.0.1:3000"),
    ]);
    const { findings } = await scan(ctx);
    expectNoFinding(findings, "EL004");
  });

  it("does NOT flag 0.0.0.0", async () => {
    const ctx = makeContext([
      makeFile("SKILL.md", "Bind to 0.0.0.0:8080"),
    ]);
    const { findings } = await scan(ctx);
    expectNoFinding(findings, "EL004");
  });

  it("does NOT flag 0.x patterns (version numbers)", async () => {
    const ctx = makeContext([
      makeFile("SKILL.md", "Version 0.1.2.3 released"),
    ]);
    const { findings } = await scan(ctx);
    expectNoFinding(findings, "EL004");
  });
});

// =============================================================================
// Edge cases
// =============================================================================
describe("Edge cases", () => {
  it("handles files with no URLs", async () => {
    const ctx = makeContext([
      makeFile("SKILL.md", "This file has no URLs at all"),
    ]);
    const { findings, links } = await scan(ctx);
    expect(links?.length ?? 0).toBe(0);
    expect(findings.length).toBe(0);
  });

  it("tracks correct line numbers", async () => {
    const ctx = makeContext([
      makeFile("SKILL.md", "line 1\nline 2\nhttps://github.com\nline 4"),
    ]);
    const { findings } = await scan(ctx);
    const el001 = findings.find((f) => f.ruleId === "EL001");
    expect(el001?.lineNumber).toBe(3);
  });

  it("handles multiple files", async () => {
    const ctx = makeContext([
      makeFile("SKILL.md", "https://github.com/repo"),
      makeFile("scripts/setup.sh", "https://npmjs.com/package"),
    ]);
    const { links } = await scan(ctx);
    expect(links?.length).toBe(2);
  });
});
