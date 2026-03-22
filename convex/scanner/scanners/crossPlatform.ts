import { Finding, ScannerResult, ScanContext, Platform, basename, parseFrontmatter } from "./types";

export async function scan(context: ScanContext): Promise<ScannerResult & { platform: Platform }> {
  const findings: Finding[] = [];
  const detectedPlatforms = new Set<Platform>();

  // Detect by file path patterns
  for (const file of context.files) {
    const p = file.relativePath;

    if (p.includes(".claude/skills/") || p.includes(".claude/commands/")) {
      detectedPlatforms.add("claude_code");
    }
    if (p.includes(".cursor/rules/") && p.endsWith(".mdc")) {
      detectedPlatforms.add("cursor");
    }
    if (p.includes(".windsurf/rules/")) {
      detectedPlatforms.add("windsurf");
    }
    if (p.includes(".clinerules/")) {
      detectedPlatforms.add("cline");
    }
    if (p.includes("skills/") && basename(p) === "SKILL.md") {
      // Could be openclaw or agentskills
      detectedPlatforms.add("agentskills");
    }
  }

  // Detect by frontmatter fields
  const skillFiles = context.files.filter(
    (f) => basename(f.relativePath) === "SKILL.md"
  );

  for (const file of skillFiles) {
    try {
      const { data } = parseFrontmatter(file.content);

      // Claude Code specific fields
      const claudeFields = [
        "argument-hint", "disable-model-invocation", "user-invocable",
        "allowed-tools", "model", "context", "agent", "hooks",
      ];
      for (const field of claudeFields) {
        if (field in data) {
          detectedPlatforms.add("claude_code");
          findings.push({
            category: "cross_platform",
            ruleId: "CP003",
            severity: "info",
            confidence: "high",
            title: `Claude Code field: ${field}`,
            description: `Uses Claude Code-specific frontmatter field "${field}".`,
            filePath: file.relativePath,
          });
        }
      }

      // OpenClaw specific
      if ((data.metadata as Record<string, unknown>)?.openclaw) {
        detectedPlatforms.add("openclaw");
        findings.push({
          category: "cross_platform",
          ruleId: "CP003",
          severity: "info",
          confidence: "high",
          title: "OpenClaw metadata detected",
          description: "Uses OpenClaw-specific metadata gating.",
          filePath: file.relativePath,
        });
      }

      // AgentSkills compliance
      if (data.name && data.description) {
        detectedPlatforms.add("agentskills");
      }

      // Check allowed-tools (experimental)
      if ("allowed-tools" in data) {
        findings.push({
          category: "cross_platform",
          ruleId: "CP002",
          severity: "low",
          confidence: "high",
          title: "Uses experimental 'allowed-tools'",
          description: "The 'allowed-tools' field is experimental in the AgentSkills specification and may not be supported by all platforms.",
          filePath: file.relativePath,
        });
      }
    } catch {
      // Invalid frontmatter, handled by standardCompliance scanner
    }
  }

  // Cursor .mdc files
  const mdcFiles = context.files.filter(
    (f) => f.relativePath.endsWith(".mdc")
  );
  for (const file of mdcFiles) {
    detectedPlatforms.add("cursor");
    try {
      const { data } = parseFrontmatter(file.content);
      if ("globs" in data || "alwaysApply" in data) {
        findings.push({
          category: "cross_platform",
          ruleId: "CP003",
          severity: "info",
          confidence: "high",
          title: "Cursor-specific fields detected",
          description: `Uses Cursor-specific fields: ${Object.keys(data).join(", ")}`,
          filePath: file.relativePath,
        });
      }
    } catch {
      // skip
    }
  }

  // Determine primary platform
  let platform: Platform = "unknown";
  if (detectedPlatforms.size === 1) {
    platform = [...detectedPlatforms][0];
  } else if (detectedPlatforms.size > 1) {
    // Priority: claude_code > openclaw > cursor > windsurf > cline > agentskills
    const priority: Platform[] = ["claude_code", "openclaw", "cursor", "windsurf", "cline", "agentskills"];
    for (const p of priority) {
      if (detectedPlatforms.has(p)) {
        platform = p;
        break;
      }
    }
  }

  // Report detected platforms
  for (const p of detectedPlatforms) {
    findings.push({
      category: "cross_platform",
      ruleId: "CP001",
      severity: "info",
      confidence: "high",
      title: `Platform detected: ${p}`,
      description: `This skill appears to target the ${p} platform.`,
    });
  }

  return { findings, platform };
}
