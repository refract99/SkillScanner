import type { FileEntry, ScanContext } from "@/convex/scanner/scanners/types";

const MOCK_ROOT = "/mock/repo";

export function makeFile(
  relativePath: string,
  content: string,
  opts?: Partial<FileEntry>
): FileEntry {
  return {
    relativePath,
    absolutePath: `${MOCK_ROOT}/${relativePath}`,
    content,
    size: content.length,
    isSymlink: false,
    ...opts,
  };
}

export function makeContext(files: FileEntry[]): ScanContext {
  return { rootDir: MOCK_ROOT, files };
}

export function makeSkillMd(
  frontmatter: Record<string, unknown>,
  body: string
): FileEntry {
  const yaml = Object.entries(frontmatter)
    .map(([k, v]) => `${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`)
    .join("\n");
  const content = `---\n${yaml}\n---\n${body}`;
  return makeFile("SKILL.md", content);
}

export function makeCodeFile(name: string, content: string): FileEntry {
  const ext = name.includes(".") ? "" : ".ts";
  return makeFile(`${name}${ext}`, content);
}

export function makeShellScript(name: string, content: string): FileEntry {
  const ext = name.includes(".") ? "" : ".sh";
  return makeFile(`${name}${ext}`, content);
}

export function makeMdcFile(
  path: string,
  frontmatter: Record<string, unknown>,
  body: string
): FileEntry {
  const yaml = Object.entries(frontmatter)
    .map(([k, v]) => `${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`)
    .join("\n");
  const content = `---\n${yaml}\n---\n${body}`;
  return makeFile(path.endsWith(".mdc") ? path : `${path}.mdc`, content);
}
