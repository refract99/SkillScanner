import { Finding, ScanContext, ExternalLink, Platform, extname, basename } from "./types";
import * as crossPlatform from "./crossPlatform";
import * as externalLinks from "./externalLinks";
import * as standardCompliance from "./standardCompliance";

export interface FileManifestEntry {
  path: string;
  size: number;
  ext: string;
  isSymlink: boolean;
  isBinary: boolean;
}

export interface PreFilterResult {
  platform: Platform;
  links: ExternalLink[];
  fileManifest: FileManifestEntry[];
  complianceFindings: Finding[];
  platformFindings: Finding[];
}

const BINARY_EXTENSIONS = new Set([
  ".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".o", ".obj",
  ".class", ".pyc", ".pyo", ".wasm", ".pyd",
  ".zip", ".tar", ".gz", ".tgz", ".bz2", ".7z", ".rar", ".xz",
  ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
  ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx",
  ".ttf", ".otf", ".woff", ".woff2", ".eot",
]);

function isBinaryExt(filePath: string): boolean {
  return BINARY_EXTENSIONS.has(extname(filePath).toLowerCase());
}

/**
 * Pre-filter: extract factual metadata from the scan context.
 * No security judgments — just facts for the AI to reason about.
 */
export async function runPreFilter(context: ScanContext): Promise<PreFilterResult> {
  // Run existing modules for platform detection and link extraction
  const [cpResult, elResult, scResult] = await Promise.all([
    crossPlatform.scan(context),
    externalLinks.scan(context),
    standardCompliance.scan(context),
  ]);

  // Build file manifest
  const fileManifest: FileManifestEntry[] = context.files.map((f) => ({
    path: f.relativePath,
    size: f.size,
    ext: extname(f.relativePath).toLowerCase(),
    isSymlink: f.isSymlink,
    isBinary: isBinaryExt(f.relativePath) || (f.size > 0 && f.content === ""),
  }));

  // Reclassify compliance findings to INFO (except STD006 which stays as hard-stop)
  const complianceFindings: Finding[] = scResult.findings
    .filter((f) => f.ruleId !== "STD006") // STD006 goes to hard-stops
    .map((f) => ({
      ...f,
      severity: "info" as const,
    }));

  return {
    platform: cpResult.platform,
    links: elResult.links || [],
    fileManifest,
    complianceFindings,
    platformFindings: cpResult.findings,
  };
}

/** Format pre-filter results as context for the AI prompt */
export function formatPreFilterContext(result: PreFilterResult): string {
  const parts: string[] = [];

  parts.push(`Platform: ${result.platform}`);
  parts.push(`Files: ${result.fileManifest.length}`);

  const binaryFiles = result.fileManifest.filter((f) => f.isBinary);
  if (binaryFiles.length > 0) {
    parts.push(`Binary files: ${binaryFiles.map((f) => f.path).join(", ")}`);
  } else {
    parts.push("Binary files: none");
  }

  const symlinks = result.fileManifest.filter((f) => f.isSymlink);
  if (symlinks.length > 0) {
    parts.push(`Symlinks: ${symlinks.map((f) => f.path).join(", ")}`);
  } else {
    parts.push("Symlinks: none");
  }

  // Summarize external domains by classification
  if (result.links.length > 0) {
    const byClassification: Record<string, string[]> = {};
    for (const link of result.links) {
      if (!byClassification[link.classification]) {
        byClassification[link.classification] = [];
      }
      if (!byClassification[link.classification].includes(link.domain)) {
        byClassification[link.classification].push(link.domain);
      }
    }
    const domainParts: string[] = [];
    if (byClassification.safe?.length) {
      domainParts.push(`safe: ${byClassification.safe.join(", ")}`);
    }
    if (byClassification.unknown?.length) {
      domainParts.push(`unknown: ${byClassification.unknown.join(", ")}`);
    }
    if (byClassification.suspicious?.length) {
      domainParts.push(`suspicious: ${byClassification.suspicious.join(", ")}`);
    }
    parts.push(`External domains: ${domainParts.join("; ")}`);
  } else {
    parts.push("External domains: none");
  }

  // Compliance notes
  const nonInfoCompliance = result.complianceFindings.filter((f) => f.severity !== "info");
  if (nonInfoCompliance.length > 0) {
    parts.push(`Compliance: ${nonInfoCompliance.map((f) => f.title).join("; ")}`);
  } else {
    parts.push("Compliance: no issues");
  }

  return parts.join("\n");
}
