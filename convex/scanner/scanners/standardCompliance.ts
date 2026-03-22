import { Finding, ScannerResult, ScanContext, getSnippet, basename, dirname, joinPath, parseFrontmatter } from "./types";

export async function scan(context: ScanContext): Promise<ScannerResult> {
  const findings: Finding[] = [];

  // Find SKILL.md files
  const skillFiles = context.files.filter(
    (f) => basename(f.relativePath) === "SKILL.md"
  );

  if (skillFiles.length === 0) {
    // Check for case-insensitive matches
    const caseInsensitive = context.files.filter(
      (f) => basename(f.relativePath).toLowerCase() === "skill.md"
    );
    if (caseInsensitive.length > 0) {
      findings.push({
        category: "standard_compliance",
        ruleId: "STD001",
        severity: "medium",
        confidence: "high",
        title: "SKILL.md file has wrong case",
        description: `Found "${basename(caseInsensitive[0].relativePath)}" but the AgentSkills spec requires exactly "SKILL.md" (case-sensitive).`,
        filePath: caseInsensitive[0].relativePath,
      });
    } else {
      findings.push({
        category: "standard_compliance",
        ruleId: "STD001",
        severity: "medium",
        confidence: "high",
        title: "Missing SKILL.md file",
        description: "No SKILL.md file found. The AgentSkills specification requires a SKILL.md file with YAML frontmatter.",
      });
    }
    return { findings };
  }

  for (const skillFile of skillFiles) {
    // Parse YAML frontmatter
    let frontmatter: Record<string, unknown>;
    let body: string;
    try {
      const parsed = parseFrontmatter(skillFile.content);
      frontmatter = parsed.data;
      body = parsed.content as string;
    } catch {
      findings.push({
        category: "standard_compliance",
        ruleId: "STD002",
        severity: "medium",
        confidence: "high",
        title: "Invalid YAML frontmatter",
        description: "Failed to parse YAML frontmatter. Ensure the file starts with valid --- delimiters and YAML content.",
        filePath: skillFile.relativePath,
      });
      continue;
    }

    // Check empty frontmatter
    if (!frontmatter || Object.keys(frontmatter).length === 0) {
      findings.push({
        category: "standard_compliance",
        ruleId: "STD002",
        severity: "medium",
        confidence: "high",
        title: "Empty YAML frontmatter",
        description: "The YAML frontmatter contains no fields. At minimum, 'name' and 'description' are required.",
        filePath: skillFile.relativePath,
      });
    }

    // Check name field
    const name = frontmatter?.name as string | undefined;
    if (!name) {
      findings.push({
        category: "standard_compliance",
        ruleId: "STD003",
        severity: "low",
        confidence: "high",
        title: "Missing 'name' field in frontmatter",
        description: "The 'name' field is required by the AgentSkills specification.",
        filePath: skillFile.relativePath,
      });
    } else {
      // Validate kebab-case
      if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(name)) {
        findings.push({
          category: "standard_compliance",
          ruleId: "STD005",
          severity: "medium",
          confidence: "high",
          title: "Name is not kebab-case",
          description: `Name "${name}" should be lowercase alphanumeric with hyphens only (kebab-case).`,
          filePath: skillFile.relativePath,
        });
      }

      // Max 64 chars
      if (name.length > 64) {
        findings.push({
          category: "standard_compliance",
          ruleId: "STD005",
          severity: "low",
          confidence: "high",
          title: "Name exceeds 64 characters",
          description: `Name is ${name.length} characters; maximum is 64.`,
          filePath: skillFile.relativePath,
        });
      }

      // Reserved names
      if (/\b(claude|anthropic)\b/i.test(name)) {
        findings.push({
          category: "standard_compliance",
          ruleId: "STD009",
          severity: "medium",
          confidence: "high",
          title: "Reserved name used",
          description: `Name "${name}" contains a reserved word ("claude" or "anthropic").`,
          filePath: skillFile.relativePath,
        });
      }

      // Check name matches directory name
      const dirName = basename(dirname(skillFile.relativePath));
      if (dirName !== "." && dirName !== name) {
        findings.push({
          category: "standard_compliance",
          ruleId: "STD005",
          severity: "low",
          confidence: "medium",
          title: "Name doesn't match directory",
          description: `Frontmatter name "${name}" doesn't match directory name "${dirName}".`,
          filePath: skillFile.relativePath,
        });
      }
    }

    // Check description field
    const description = frontmatter?.description as string | undefined;
    if (!description) {
      findings.push({
        category: "standard_compliance",
        ruleId: "STD004",
        severity: "low",
        confidence: "high",
        title: "Missing 'description' field",
        description: "The 'description' field is required by the AgentSkills specification.",
        filePath: skillFile.relativePath,
      });
    } else if (description.length > 1024) {
      findings.push({
        category: "standard_compliance",
        ruleId: "STD004",
        severity: "info",
        confidence: "high",
        title: "Description exceeds 1024 characters",
        description: `Description is ${description.length} characters; maximum recommended is 1024.`,
        filePath: skillFile.relativePath,
      });
    }

    // Check allowed-tools for excessive agency (OWASP LLM06 / ASI03)
    const allowedTools = frontmatter?.["allowed-tools"] as string | undefined;
    if (!allowedTools) {
      findings.push({
        category: "standard_compliance",
        ruleId: "STD010",
        severity: "medium",
        confidence: "high",
        title: "No 'allowed-tools' declared",
        description: "Skill does not declare an 'allowed-tools' field. Without tool restrictions, the skill may be granted excessive agency (OWASP LLM06). Skills should follow the principle of least privilege.",
        filePath: skillFile.relativePath,
      });
    } else {
      const tools = allowedTools.split(",").map((t: string) => t.trim().toLowerCase());
      const highRiskTools = ["bash", "execute", "shell", "terminal", "run"];
      const writeTools = ["write", "edit"];
      const hasHighRisk = tools.some((t: string) => highRiskTools.some((hr) => t.includes(hr)));
      const hasWrite = tools.some((t: string) => writeTools.some((w) => t.includes(w)));

      if (hasHighRisk && hasWrite) {
        findings.push({
          category: "standard_compliance",
          ruleId: "STD011",
          severity: "high",
          confidence: "high",
          title: "Excessive tool permissions: shell + file write access",
          description: `Skill requests both shell execution and file write tools (${allowedTools}). This combination grants near-complete system access (OWASP LLM06 Excessive Agency / ASI03 Identity & Privilege Abuse).`,
          filePath: skillFile.relativePath,
        });
      } else if (hasHighRisk) {
        findings.push({
          category: "standard_compliance",
          ruleId: "STD011",
          severity: "medium",
          confidence: "high",
          title: "Shell execution tool requested",
          description: `Skill requests shell execution access (${allowedTools}). Verify this is necessary for the skill's stated purpose (OWASP LLM06).`,
          filePath: skillFile.relativePath,
        });
      }

      // Check if tool count is unusually high
      if (tools.length > 8) {
        findings.push({
          category: "standard_compliance",
          ruleId: "STD012",
          severity: "medium",
          confidence: "medium",
          title: `Broad tool access: ${tools.length} tools requested`,
          description: `Skill requests ${tools.length} tools. Skills should follow the principle of least agency and only request tools they need (OWASP LLM06).`,
          filePath: skillFile.relativePath,
        });
      }
    }

    // Check for XML angle brackets in frontmatter
    const frontmatterStr = skillFile.content.split("---")[1] || "";
    if (/<|>/.test(frontmatterStr)) {
      findings.push({
        category: "standard_compliance",
        ruleId: "STD006",
        severity: "high",
        confidence: "high",
        title: "XML angle brackets in frontmatter",
        description: "Found < or > characters in YAML frontmatter. These are injection vectors into system prompts and are prohibited.",
        filePath: skillFile.relativePath,
      });
    }

    // Body length check (5000 words)
    const wordCount = body.trim().split(/\s+/).length;
    if (wordCount > 5000) {
      findings.push({
        category: "standard_compliance",
        ruleId: "STD007",
        severity: "info",
        confidence: "high",
        title: `Body exceeds 5,000 words (${wordCount} words)`,
        description: "The body is longer than the recommended 5,000 word limit.",
        filePath: skillFile.relativePath,
      });
    }
  }

  // Check for README.md inside skill folders
  const readmeFiles = context.files.filter(
    (f) => basename(f.relativePath) === "README.md"
  );
  for (const readme of readmeFiles) {
    const dir = dirname(readme.relativePath);
    const hasSkillMd = context.files.some(
      (f) => f.relativePath === joinPath(dir, "SKILL.md")
    );
    if (hasSkillMd) {
      findings.push({
        category: "standard_compliance",
        ruleId: "STD008",
        severity: "info",
        confidence: "high",
        title: "README.md inside skill folder",
        description: "A README.md should not be inside a skill folder that contains SKILL.md.",
        filePath: readme.relativePath,
      });
    }
  }

  return { findings };
}
