import { Finding, ScanContext, ScannerResult, basename, getSnippet } from "./types";

/**
 * Dependency Auditing Scanner
 *
 * Parses package manifests from scanned repos, extracts dependency names and
 * version constraints, checks against the OSV (Open Source Vulnerabilities)
 * database for known CVEs, detects known malicious / typosquatted packages,
 * and flags loose version constraints.
 *
 * Rule IDs:
 *   DA001 — Known CVE (from OSV database)
 *   DA002 — Malicious or typosquatted package name
 *   DA003 — Loose version constraint
 */

export interface DependencyAuditResult extends ScannerResult {
  findings: Finding[];
}

// ---------------------------------------------------------------------------
// Dependency extraction per ecosystem
// ---------------------------------------------------------------------------

interface Dependency {
  name: string;
  version: string;
  ecosystem: string;
  filePath: string;
  lineNumber?: number;
}

/** Parse package.json dependencies */
function parsePackageJson(content: string, filePath: string): Dependency[] {
  const deps: Dependency[] = [];
  try {
    const pkg = JSON.parse(content);
    const sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
    for (const section of sections) {
      const sectionDeps = pkg[section];
      if (sectionDeps && typeof sectionDeps === "object") {
        for (const [name, version] of Object.entries(sectionDeps)) {
          if (typeof version === "string") {
            // Find line number for this dependency
            const lineNum = findLineNumber(content, `"${name}"`);
            deps.push({ name, version, ecosystem: "npm", filePath, lineNumber: lineNum });
          }
        }
      }
    }
  } catch {
    // Invalid JSON, skip
  }
  return deps;
}

/** Parse requirements.txt (Python) */
function parseRequirementsTxt(content: string, filePath: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    // Match: package==1.0, package>=1.0, package~=1.0, package (no version)
    const match = line.match(/^([a-zA-Z0-9_.-]+)\s*(?:([><=!~]+)\s*([^\s;,#]+))?/);
    if (match) {
      deps.push({
        name: match[1],
        version: match[2] ? `${match[2]}${match[3]}` : "*",
        ecosystem: "PyPI",
        filePath,
        lineNumber: i + 1,
      });
    }
  }
  return deps;
}

/** Parse Pipfile (Python) */
function parsePipfile(content: string, filePath: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");
  let inPackages = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === "[packages]" || line === "[dev-packages]") {
      inPackages = true;
      continue;
    }
    if (line.startsWith("[") && line.endsWith("]")) {
      inPackages = false;
      continue;
    }
    if (!inPackages || !line || line.startsWith("#")) continue;
    const match = line.match(/^([a-zA-Z0-9_.-]+)\s*=\s*"([^"]*)"$/);
    if (match) {
      deps.push({
        name: match[1],
        version: match[2],
        ecosystem: "PyPI",
        filePath,
        lineNumber: i + 1,
      });
    }
  }
  return deps;
}

/** Parse Gemfile (Ruby) */
function parseGemfile(content: string, filePath: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith("#")) continue;
    // Match: gem 'name', '~> 1.0'  or  gem "name"
    const match = line.match(/^gem\s+['"]([a-zA-Z0-9_.-]+)['"]\s*(?:,\s*['"]([^'"]*)['"]\s*)?/);
    if (match) {
      deps.push({
        name: match[1],
        version: match[2] || "*",
        ecosystem: "RubyGems",
        filePath,
        lineNumber: i + 1,
      });
    }
  }
  return deps;
}

/** Parse Cargo.toml (Rust) */
function parseCargoToml(content: string, filePath: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");
  let inDeps = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (/^\[(dev-)?dependencies\]$/.test(line) || /^\[build-dependencies\]$/.test(line)) {
      inDeps = true;
      continue;
    }
    if (line.startsWith("[") && line.endsWith("]")) {
      inDeps = false;
      continue;
    }
    if (!inDeps || !line || line.startsWith("#")) continue;
    // Simple version: name = "version"
    const simpleMatch = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]*)"$/);
    if (simpleMatch) {
      deps.push({
        name: simpleMatch[1],
        version: simpleMatch[2],
        ecosystem: "crates.io",
        filePath,
        lineNumber: i + 1,
      });
      continue;
    }
    // Table version: name = { version = "..." }
    const tableMatch = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*\{.*version\s*=\s*"([^"]*)".*\}$/);
    if (tableMatch) {
      deps.push({
        name: tableMatch[1],
        version: tableMatch[2],
        ecosystem: "crates.io",
        filePath,
        lineNumber: i + 1,
      });
    }
  }
  return deps;
}

/** Parse go.mod (Go) */
function parseGoMod(content: string, filePath: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split("\n");
  let inRequire = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === "require (") {
      inRequire = true;
      continue;
    }
    if (line === ")") {
      inRequire = false;
      continue;
    }
    // Single-line require
    const singleMatch = line.match(/^require\s+(\S+)\s+(\S+)/);
    if (singleMatch) {
      deps.push({
        name: singleMatch[1],
        version: singleMatch[2],
        ecosystem: "Go",
        filePath,
        lineNumber: i + 1,
      });
      continue;
    }
    if (inRequire) {
      const match = line.match(/^(\S+)\s+(\S+)/);
      if (match && !line.startsWith("//")) {
        deps.push({
          name: match[1],
          version: match[2],
          ecosystem: "Go",
          filePath,
          lineNumber: i + 1,
        });
      }
    }
  }
  return deps;
}

// ---------------------------------------------------------------------------
// Manifest file routing
// ---------------------------------------------------------------------------

const MANIFEST_PARSERS: Record<string, (content: string, filePath: string) => Dependency[]> = {
  "package.json": parsePackageJson,
  "requirements.txt": parseRequirementsTxt,
  "Pipfile": parsePipfile,
  "Gemfile": parseGemfile,
  "Cargo.toml": parseCargoToml,
  "go.mod": parseGoMod,
};

// ---------------------------------------------------------------------------
// DA002: Known malicious / typosquatted package detection
// ---------------------------------------------------------------------------

/** Well-known typosquatting targets and their common misspellings */
const TYPOSQUAT_MAP: Record<string, string[]> = {
  // npm
  lodash: ["lodahs", "lodashs", "l0dash", "1odash", "lodash-utils"],
  express: ["expres", "expresss", "exppress", "expr3ss"],
  react: ["r3act", "raect", "reacct"],
  axios: ["axi0s", "axois", "axio5"],
  chalk: ["cha1k", "chalkk", "chalks"],
  commander: ["comander", "comanderjs", "c0mmander"],
  webpack: ["webpak", "w3bpack", "webpackk"],
  "cross-env": ["crossenv", "cross-env.js"],
  "event-stream": ["event_stream", "events-stream"],
  colors: ["colour", "co1ors"],
  // Python
  requests: ["requets", "reqeusts", "request", "r3quests"],
  urllib3: ["urllib", "urlib3", "urllib4"],
  setuptools: ["setuptool", "set-up-tools", "setup-tools"],
  flask: ["f1ask", "flaask", "flaskk"],
  django: ["djang0", "djangoo", "dj4ngo"],
  numpy: ["numppy", "num-py", "nump1"],
  pandas: ["pandsa", "pand4s", "panddas"],
  // Ruby
  rails: ["rai1s", "raills"],
  nokogiri: ["nokogirii", "n0kogiri"],
};

/** Known malicious package names that have been reported */
const KNOWN_MALICIOUS_PACKAGES = new Set([
  // npm - historically reported malicious packages
  "flatmap-stream",
  "event-stream-dep",
  "getcookies",
  "mailparser-mit",
  "mongose",
  "babelcli",
  "crossenv",
  "cross-env.js",
  "d3.js",
  "fabric-js",
  "ffmpegs",
  "gruntcli",
  "http-proxy.js",
  "jquery.js",
  "mariadb",
  "mongose",
  "mssql-node",
  "mssql.js",
  "mysqljs",
  "node-hierarchical-softmax",
  "node-opencv",
  "node-opensl",
  "node-openssl",
  "node-tkinter",
  "nodecaffe",
  "nodefabric",
  "nodeffmpeg",
  "nodemailer-js",
  "noderequest",
  "nodesass",
  "nodesqlite",
  "opencv.js",
  "openssl.js",
  "proxy.js",
  "shadowsock",
  "smb",
  "sqlite.js",
  "sqliter",
  "sqlserver",
  "tkinter",
  // Python - historically reported
  "python-dateutil2",
  "python3-dateutil",
  "jeIlyfish",   // with capital I instead of l
  "python-openssl",
  "coloura",
  "requestts",
  "requesocks",
]);

function checkTyposquatting(name: string, ecosystem: string): string | null {
  const lower = name.toLowerCase();

  // Check known malicious
  if (KNOWN_MALICIOUS_PACKAGES.has(lower)) {
    return `"${name}" is a known malicious package`;
  }

  // Check typosquatting against popular packages
  for (const [legitimate, typos] of Object.entries(TYPOSQUAT_MAP)) {
    for (const typo of typos) {
      if (lower === typo.toLowerCase()) {
        return `"${name}" appears to be a typosquat of "${legitimate}"`;
      }
    }
  }

  // Homoglyph detection: check for common character substitutions
  const homoglyphs: Record<string, string> = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
  };
  let normalized = lower;
  for (const [from, to] of Object.entries(homoglyphs)) {
    normalized = normalized.replace(new RegExp(from, "g"), to);
  }
  if (normalized !== lower) {
    // Check if the normalized name matches a popular package
    for (const legitimate of Object.keys(TYPOSQUAT_MAP)) {
      if (normalized === legitimate.toLowerCase() && lower !== legitimate.toLowerCase()) {
        return `"${name}" uses character substitution resembling "${legitimate}" (potential homoglyph attack)`;
      }
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// DA003: Loose version constraint detection
// ---------------------------------------------------------------------------

function isLooseVersionConstraint(version: string, ecosystem: string): boolean {
  const v = version.trim();

  // Universal wildcards
  if (v === "*" || v === "" || v === "latest" || v === ">=0.0.0") return true;

  if (ecosystem === "npm") {
    // npm-specific loose patterns
    if (v === "x" || v === "X" || v === "x.x.x") return true;
    if (/^>=\s*0(\.\d+)*$/.test(v)) return true; // >=0, >=0.0.0
  }

  if (ecosystem === "PyPI") {
    if (v === ">=0" || v === ">=0.0.0") return true;
  }

  if (ecosystem === "RubyGems") {
    if (v === ">= 0" || v === ">= 0.0.0") return true;
  }

  if (ecosystem === "crates.io") {
    if (v === ">=0.0.0" || v === "*") return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// DA001: OSV database lookup
// ---------------------------------------------------------------------------

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  aliases?: string[];
}

interface OsvQueryResult {
  vulns?: OsvVulnerability[];
}

/** Query the OSV API for known vulnerabilities in a batch of packages */
async function queryOsvBatch(
  deps: Dependency[]
): Promise<Map<number, OsvVulnerability[]>> {
  const results = new Map<number, OsvVulnerability[]>();
  if (deps.length === 0) return results;

  // OSV batch endpoint accepts up to 1000 queries
  const queries = deps.map((dep) => ({
    package: {
      name: dep.name,
      ecosystem: dep.ecosystem,
    },
    version: cleanVersion(dep.version, dep.ecosystem),
  }));

  // Filter out deps with unparseable versions for OSV (wildcards, etc.)
  const validIndices: number[] = [];
  const validQueries: typeof queries = [];
  for (let i = 0; i < queries.length; i++) {
    if (queries[i].version) {
      validIndices.push(i);
      validQueries.push(queries[i]);
    }
  }

  if (validQueries.length === 0) return results;

  // Batch in chunks of 1000
  for (let i = 0; i < validQueries.length; i += 1000) {
    const batch = validQueries.slice(i, i + 1000);
    const batchIndices = validIndices.slice(i, i + 1000);

    try {
      const response = await fetch("https://api.osv.dev/v1/querybatch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ queries: batch }),
        signal: AbortSignal.timeout(15000),
      });

      if (!response.ok) continue;

      const data = (await response.json()) as { results: OsvQueryResult[] };
      if (data.results) {
        for (let j = 0; j < data.results.length; j++) {
          const vulns = data.results[j].vulns;
          if (vulns && vulns.length > 0) {
            results.set(batchIndices[j], vulns);
          }
        }
      }
    } catch {
      // OSV API unavailable — skip CVE checks gracefully
    }
  }

  return results;
}

/** Clean a version string into a bare semver-ish version for OSV lookup */
function cleanVersion(version: string, ecosystem: string): string {
  let v = version.trim();

  // Remove common prefixes: ^, ~, >=, <=, ~=, ==, =
  v = v.replace(/^[\^~>=<!]+\s*/, "");
  // Remove trailing wildcards
  v = v.replace(/\.\*$/, ".0");
  // Remove v prefix
  v = v.replace(/^v/, "");

  // If it doesn't look like a version at all, return empty
  if (!v || v === "*" || v === "latest" || v === "x" || v === "X") return "";
  if (!/\d/.test(v)) return "";

  return v;
}

/** Map OSV severity to our severity levels */
function osvSeverityToFindingSeverity(
  vuln: OsvVulnerability
): "info" | "low" | "medium" | "high" | "critical" {
  if (vuln.severity && vuln.severity.length > 0) {
    for (const sev of vuln.severity) {
      if (sev.type === "CVSS_V3" || sev.type === "CVSS_V4") {
        const score = parseFloat(sev.score);
        if (!isNaN(score)) {
          if (score >= 9.0) return "critical";
          if (score >= 7.0) return "high";
          if (score >= 4.0) return "medium";
          return "low";
        }
      }
    }
  }
  // Default to high for known CVEs without score
  return "high";
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function findLineNumber(content: string, searchStr: string): number | undefined {
  const idx = content.indexOf(searchStr);
  if (idx === -1) return undefined;
  return content.substring(0, idx).split("\n").length;
}

// ---------------------------------------------------------------------------
// Main scanner entry point
// ---------------------------------------------------------------------------

export async function runDependencyAudit(context: ScanContext): Promise<DependencyAuditResult> {
  const findings: Finding[] = [];
  const allDeps: Dependency[] = [];

  // Step 1: Parse all manifest files
  for (const file of context.files) {
    if (!file.content) continue;
    const base = basename(file.relativePath);

    const parser = MANIFEST_PARSERS[base];
    if (parser) {
      const deps = parser(file.content, file.relativePath);
      allDeps.push(...deps);
    }
  }

  if (allDeps.length === 0) {
    return { findings };
  }

  // Step 2: DA002 — Check for malicious / typosquatted packages
  for (const dep of allDeps) {
    const typosquatResult = checkTyposquatting(dep.name, dep.ecosystem);
    if (typosquatResult) {
      findings.push({
        category: "dependency_audit",
        ruleId: "DA002",
        severity: "critical",
        confidence: "high",
        title: "Potentially malicious package",
        description: `${typosquatResult}. This package may attempt to steal credentials, exfiltrate data, or execute malicious code during installation.`,
        filePath: dep.filePath,
        lineNumber: dep.lineNumber,
        matchedPattern: dep.name,
        snippet: dep.lineNumber
          ? getSnippet(
              context.files.find((f) => f.relativePath === dep.filePath)?.content || "",
              dep.lineNumber
            )
          : undefined,
      });
    }
  }

  // Step 3: DA003 — Check for loose version constraints
  for (const dep of allDeps) {
    if (isLooseVersionConstraint(dep.version, dep.ecosystem)) {
      findings.push({
        category: "dependency_audit",
        ruleId: "DA003",
        severity: "low",
        confidence: "high",
        title: "Loose version constraint",
        description: `Package "${dep.name}" uses a loose version constraint ("${dep.version}"). This allows any version to be installed, including potentially malicious releases. Pin to a specific version or use a tighter range.`,
        filePath: dep.filePath,
        lineNumber: dep.lineNumber,
        matchedPattern: `${dep.name}@${dep.version}`,
        snippet: dep.lineNumber
          ? getSnippet(
              context.files.find((f) => f.relativePath === dep.filePath)?.content || "",
              dep.lineNumber
            )
          : undefined,
      });
    }
  }

  // Step 4: DA001 — Query OSV database for known CVEs
  const osvResults = await queryOsvBatch(allDeps);
  for (const [depIndex, vulns] of osvResults.entries()) {
    const dep = allDeps[depIndex];
    // Limit to top 5 vulns per package to avoid flooding
    const topVulns = vulns.slice(0, 5);
    for (const vuln of topVulns) {
      const aliases = vuln.aliases?.filter((a) => a.startsWith("CVE-")) || [];
      const cveId = aliases.length > 0 ? aliases[0] : vuln.id;
      const severity = osvSeverityToFindingSeverity(vuln);

      findings.push({
        category: "dependency_audit",
        ruleId: "DA001",
        severity,
        confidence: "high",
        title: `Known vulnerability in ${dep.name}: ${cveId}`,
        description: vuln.summary
          || vuln.details?.substring(0, 300)
          || `${dep.name}@${dep.version} has a known vulnerability (${vuln.id}).`,
        filePath: dep.filePath,
        lineNumber: dep.lineNumber,
        matchedPattern: `${dep.name}@${dep.version} (${vuln.id})`,
        snippet: dep.lineNumber
          ? getSnippet(
              context.files.find((f) => f.relativePath === dep.filePath)?.content || "",
              dep.lineNumber
            )
          : undefined,
      });
    }
  }

  return { findings };
}
