import { describe, it, expect } from "vitest";
import {
  basename,
  dirname,
  extname,
  joinPath,
  parseFrontmatter,
  sanitizeSnippet,
  getSnippet,
} from "@/convex/scanner/scanners/types";

describe("basename", () => {
  it("returns filename from path", () => {
    expect(basename("src/utils/helper.ts")).toBe("helper.ts");
  });

  it("returns filename when no directory", () => {
    expect(basename("file.txt")).toBe("file.txt");
  });

  it("returns empty string for trailing slash", () => {
    expect(basename("src/")).toBe("");
  });

  it("handles deeply nested paths", () => {
    expect(basename("a/b/c/d/e.js")).toBe("e.js");
  });
});

describe("dirname", () => {
  it("returns directory portion", () => {
    expect(dirname("src/utils/helper.ts")).toBe("src/utils");
  });

  it("returns dot for bare filename", () => {
    expect(dirname("file.txt")).toBe(".");
  });

  it("handles nested paths", () => {
    expect(dirname("a/b/c.ts")).toBe("a/b");
  });
});

describe("extname", () => {
  it("returns extension with dot", () => {
    expect(extname("file.ts")).toBe(".ts");
  });

  it("returns last extension for double extensions", () => {
    expect(extname("file.test.ts")).toBe(".ts");
  });

  it("returns empty for no extension", () => {
    expect(extname("Makefile")).toBe("");
  });

  it("returns empty for dotfiles", () => {
    expect(extname(".gitignore")).toBe("");
  });

  it("handles paths with directories", () => {
    expect(extname("src/utils/helper.ts")).toBe(".ts");
  });
});

describe("joinPath", () => {
  it("joins path segments", () => {
    expect(joinPath("src", "utils", "helper.ts")).toBe("src/utils/helper.ts");
  });

  it("removes double slashes", () => {
    expect(joinPath("src/", "/utils")).toBe("src/utils");
  });

  it("filters empty segments", () => {
    expect(joinPath("src", "", "file.ts")).toBe("src/file.ts");
  });
});

describe("parseFrontmatter", () => {
  it("extracts key-value pairs from YAML frontmatter", () => {
    const content = `---\nname: my-skill\ndescription: A test skill\n---\nBody content`;
    const result = parseFrontmatter(content);
    expect(result.data.name).toBe("my-skill");
    expect(result.data.description).toBe("A test skill");
    expect(result.content).toBe("Body content");
  });

  it("handles boolean values", () => {
    const content = `---\nenabled: true\ndisabled: false\n---\n`;
    const result = parseFrontmatter(content);
    expect(result.data.enabled).toBe(true);
    expect(result.data.disabled).toBe(false);
  });

  it("handles numeric values", () => {
    const content = `---\nversion: 42\n---\n`;
    const result = parseFrontmatter(content);
    expect(result.data.version).toBe(42);
  });

  it("strips quotes from string values", () => {
    const content = `---\nname: "quoted-name"\nalt: 'single-quoted'\n---\n`;
    const result = parseFrontmatter(content);
    expect(result.data.name).toBe("quoted-name");
    expect(result.data.alt).toBe("single-quoted");
  });

  it("returns empty data for no frontmatter", () => {
    const content = "Just regular content";
    const result = parseFrontmatter(content);
    expect(result.data).toEqual({});
    expect(result.content).toBe("Just regular content");
  });

  it("returns empty data for malformed frontmatter", () => {
    const content = "---\nno closing delimiter\nSome content";
    const result = parseFrontmatter(content);
    expect(result.data).toEqual({});
  });
});

describe("sanitizeSnippet", () => {
  it("escapes HTML entities", () => {
    expect(sanitizeSnippet('<script>alert("xss")</script>')).toBe(
      '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
    );
  });

  it("escapes ampersands", () => {
    expect(sanitizeSnippet("a & b")).toBe("a &amp; b");
  });

  it("truncates long strings", () => {
    const long = "a".repeat(600);
    const result = sanitizeSnippet(long);
    expect(result.length).toBe(503); // 500 + "..."
    expect(result.endsWith("...")).toBe(true);
  });

  it("respects custom max length", () => {
    const result = sanitizeSnippet("hello world", 5);
    expect(result).toBe("hello...");
  });
});

describe("getSnippet", () => {
  const content = "line1\nline2\nline3\nline4\nline5\nline6\nline7";

  it("extracts surrounding lines with line numbers", () => {
    const snippet = getSnippet(content, 4);
    expect(snippet).toContain("2: line2");
    expect(snippet).toContain("4: line4");
    expect(snippet).toContain("6: line6");
  });

  it("handles first line (no lines before)", () => {
    const snippet = getSnippet(content, 1);
    expect(snippet).toContain("1: line1");
    expect(snippet).toContain("2: line2");
    expect(snippet).toContain("3: line3");
  });

  it("handles last line (no lines after)", () => {
    const snippet = getSnippet(content, 7);
    expect(snippet).toContain("7: line7");
    expect(snippet).toContain("5: line5");
  });

  it("sanitizes HTML in snippets", () => {
    const htmlContent = "safe\n<script>alert(1)</script>\nsafe";
    const snippet = getSnippet(htmlContent, 2);
    expect(snippet).toContain("&lt;script&gt;");
    expect(snippet).not.toContain("<script>");
  });
});
