"use node";

import * as fs from "fs";
import * as path from "path";

export interface DiscoveredSkill {
  name: string;
  path: string; // relative path from repo root
  platform: string;
}

const MAX_DISCOVERY_DEPTH = 6;

/**
 * Discovers individual skills within a repository by looking for
 * platform-specific marker files and directories.
 * Returns empty array if 0 or 1 skills found (no collection needed).
 */
export function discoverSkills(rootDir: string): DiscoveredSkill[] {
  const skills: DiscoveredSkill[] = [];
  const seenPaths = new Set<string>();

  function addSkill(name: string, relPath: string, platform: string) {
    const normalized = relPath.replace(/\/$/, "");
    if (seenPaths.has(normalized)) return;
    seenPaths.add(normalized);
    skills.push({ name, path: normalized, platform });
  }

  function walk(dir: string, depth: number) {
    if (depth > MAX_DISCOVERY_DEPTH) return;

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (entry.name === ".git" || entry.name === "node_modules") continue;

      const fullPath = path.join(dir, entry.name);
      const relPath = path.relative(rootDir, fullPath);

      if (entry.isFile()) {
        // SKILL.md marks a skill directory
        if (entry.name === "SKILL.md") {
          const skillDir = path.dirname(fullPath);
          const skillRelDir = path.relative(rootDir, skillDir);
          // Don't add root-level SKILL.md as a sub-skill
          if (skillRelDir !== "" && skillRelDir !== ".") {
            const skillName = path.basename(skillDir);
            addSkill(skillName, skillRelDir, "agentskills");
          }
        }

        // .mdc files in .cursor/rules/
        if (entry.name.endsWith(".mdc") && relPath.includes(".cursor/rules")) {
          const name = entry.name.replace(/\.mdc$/, "");
          addSkill(name, path.dirname(relPath), "cursor");
        }
      }

      if (entry.isDirectory() && !entry.isSymbolicLink()) {
        // .claude/skills/*/ directories
        if (relPath.match(/^\.claude\/skills\/[^/]+$/)) {
          addSkill(entry.name, relPath, "claude_code");
        }
        // Nested .claude/skills/*/* (e.g., .claude/skills/security/csrf-protection)
        const claudeSkillsMatch = relPath.match(
          /^\.claude\/skills\/[^/]+\/([^/]+)$/
        );
        if (claudeSkillsMatch) {
          addSkill(claudeSkillsMatch[1], relPath, "claude_code");
        }

        // .windsurf/rules/* directories
        if (relPath.match(/^\.windsurf\/rules\/[^/]+$/)) {
          addSkill(entry.name, relPath, "windsurf");
        }

        // .clinerules/* directories
        if (relPath.match(/^\.clinerules\/[^/]+$/)) {
          addSkill(entry.name, relPath, "cline");
        }

        walk(fullPath, depth + 1);
      }
    }
  }

  walk(rootDir, 0);

  // Only return skills if 2+ found (otherwise no collection needed)
  if (skills.length < 2) return [];

  return skills;
}
