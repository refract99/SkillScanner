import { Finding, ScanContext, getSnippet, extname } from "./types";

/**
 * Semgrep-style code pattern scanner.
 * Regex-based rules targeting dangerous patterns in bundled scripts.
 * These run as part of hard-stops — findings are non-dismissable.
 */

export interface CodePatternResult {
  findings: Finding[];
}

// File extensions we consider "code" (not markdown/config)
const CODE_EXTENSIONS = new Set([
  ".sh", ".bash", ".zsh", ".fish",
  ".py", ".py3", ".pyw",
  ".js", ".mjs", ".cjs", ".ts", ".mts",
  ".rb", ".pl", ".pm",
  ".php", ".lua", ".go", ".rs",
  ".ps1", ".psm1", ".bat", ".cmd",
]);

function isCodeFile(path: string): boolean {
  return CODE_EXTENSIONS.has(extname(path).toLowerCase());
}

// ---------------------------------------------------------------------------
// Rule definitions
// ---------------------------------------------------------------------------

interface CodeRule {
  id: string;
  severity: "critical" | "high" | "medium";
  title: string;
  description: string;
  pattern: RegExp;
  category: "code_injection" | "credential_access" | "network_exfiltration" | "obfuscation";
}

const CODE_RULES: CodeRule[] = [
  // ── Payload delivery ──────────────────────────────────────────────────
  {
    id: "CP001",
    severity: "critical",
    title: "Base64 decode + execute",
    description: "Decodes a base64 string and immediately executes it. Classic payload delivery technique.",
    pattern: /eval\s*\(\s*(atob|Buffer\.from)\s*\(/g,
    category: "code_injection",
  },
  {
    id: "CP001",
    severity: "critical",
    title: "Base64 decode + execute (Python)",
    description: "Decodes a base64 string and executes it via exec/eval.",
    pattern: /(exec|eval)\s*\(\s*base64\.(b64decode|decodebytes)\s*\(/g,
    category: "code_injection",
  },
  {
    id: "CP002",
    severity: "critical",
    title: "Download and execute",
    description: "Downloads content from a URL and pipes it into a shell or interpreter for execution.",
    pattern: /curl\s+[^\n|]*\|\s*(sh|bash|zsh|python|perl|ruby|node)/g,
    category: "code_injection",
  },
  {
    id: "CP002",
    severity: "critical",
    title: "Download and execute (wget)",
    description: "Downloads content from a URL and pipes it into a shell or interpreter for execution.",
    pattern: /wget\s+.*-O\s*-\s*\|\s*(sh|bash|zsh|python|perl|ruby|node)/g,
    category: "code_injection",
  },
  {
    id: "CP002",
    severity: "critical",
    title: "Download and execute (Python)",
    description: "Downloads content from a URL and executes it dynamically.",
    pattern: /exec\s*\(\s*(requests\.get|urllib\.request\.urlopen)\s*\(/g,
    category: "code_injection",
  },

  // ── Suspicious network patterns in code ───────────────────────────────
  {
    id: "CP003",
    severity: "high",
    title: "Hardcoded IP in network call",
    description: "Network request to a hardcoded IP address. Legitimate APIs use domain names.",
    pattern: /(fetch|requests\.(get|post)|urllib|http\.get|axios\.(get|post)|curl|wget)\s*\(?\s*['"`]https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g,
    category: "network_exfiltration",
  },
  {
    id: "CP004",
    severity: "high",
    title: "Pastebin/gist content execution",
    description: "Fetches content from a paste site and potentially executes it.",
    pattern: /(fetch|requests\.get|curl|wget)\s*\(?\s*['"`]https?:\/\/(pastebin\.com\/raw|gist\.githubusercontent\.com|hastebin\.com\/raw|paste\.ee\/r|dpaste\.org)/g,
    category: "code_injection",
  },
  {
    id: "CP005",
    severity: "medium",
    title: "Non-standard port connection",
    description: "Network connection to a non-standard port, which may indicate C2 communication.",
    pattern: /(fetch|requests\.(get|post)|WebSocket|net\.connect|socket\.connect)\s*\(?\s*['"`].*:\d{4,5}[/'"`]/g,
    category: "network_exfiltration",
  },

  // ── Credential harvesting in code ─────────────────────────────────────
  {
    id: "CP006",
    severity: "critical",
    title: "Environment variable dumping",
    description: "Iterates over all environment variables, which may be used to harvest credentials.",
    pattern: /\b(printenv|env\b(?!\s*=)|os\.environ\.items\(\)|Object\.keys\(process\.env\)|Object\.entries\(process\.env\))/g,
    category: "credential_access",
  },
  {
    id: "CP007",
    severity: "high",
    title: "Credential file search",
    description: "Searches the filesystem for credential files like private keys or tokens.",
    pattern: /\b(find|grep|rg|ag)\b.*(-name\s+['"]?\*\.(pem|key|p12|pfx)|-r\s+.*\b(API_KEY|SECRET|TOKEN|PASSWORD)\b)/g,
    category: "credential_access",
  },
  {
    id: "CP008",
    severity: "high",
    title: "Credential file read + write to temp",
    description: "Reads a credential file and writes it to a temp location, suggesting staging for exfiltration.",
    pattern: /(cat|read|open)\s+.*\.(pem|key|env|credentials).*>\s*\/tmp\//g,
    category: "credential_access",
  },

  // ── Code obfuscation patterns ─────────────────────────────────────────
  {
    id: "CP009",
    severity: "high",
    title: "Eval with string concatenation",
    description: "Uses eval/exec with string concatenation, likely to avoid pattern detection.",
    pattern: /(eval|exec)\s*\(\s*(['"`].*['"`]\s*\+|\w+\s*\+\s*['"`])/g,
    category: "obfuscation",
  },
  {
    id: "CP010",
    severity: "high",
    title: "Hex/octal escape command construction",
    description: "Builds strings from hex or octal escapes, commonly used to hide malicious commands.",
    pattern: /(eval|exec|system|popen)\s*\(\s*['"`](\\x[0-9a-fA-F]{2}|\\[0-7]{3}){4,}/g,
    category: "obfuscation",
  },
  {
    id: "CP011",
    severity: "medium",
    title: "Minified/packed code in skill",
    description: "Detected a very long line of code (>500 chars) which suggests minified or packed code. Skills should contain readable code.",
    pattern: /^.{500,}$/gm,
    category: "obfuscation",
  },

  // ── Hidden functionality ──────────────────────────────────────────────
  {
    id: "CP012",
    severity: "medium",
    title: "Code after exit/return",
    description: "Found code after an exit/return statement. Unreachable code in a skill script is suspicious.",
    pattern: /(sys\.exit|process\.exit|exit\s*\(|return\s*$)\s*\n+\s*\S/gm,
    category: "code_injection",
  },
  {
    id: "CP013",
    severity: "medium",
    title: "Environment-conditional code path",
    description: "Script behaves differently based on environment variables like CI or NODE_ENV. May hide malicious behavior in specific environments.",
    pattern: /if\s+.*\b(os\.getenv\s*\(\s*['"]CI|process\.env\.CI|process\.env\.NODE_ENV\s*===?\s*['"]production|os\.environ\.get\s*\(\s*['"]CI)/g,
    category: "code_injection",
  },
  // ── Untrusted content ingestion (fetch/read + execute) ────────────────
  {
    id: "CP014",
    severity: "critical",
    title: "Fetch URL + eval/exec",
    description: "Fetches content from a URL and executes it dynamically. The URL content can change at any time — this is an indirect code injection vector.",
    pattern: /(fetch|axios\.\w+|requests\.get|urllib\.request\.urlopen|http\.get)\s*\(.*\)[\s\S]{0,100}\b(eval|exec|Function)\s*\(/g,
    category: "code_injection",
  },
  {
    id: "CP014",
    severity: "critical",
    title: "Source from URL",
    description: "Sources/executes a remote script via shell. The URL content can change at any time.",
    pattern: /source\s+<\(\s*(curl|wget)/g,
    category: "code_injection",
  },
  {
    id: "CP015",
    severity: "critical",
    title: "Read file + eval/exec",
    description: "Reads a file and executes its contents dynamically. If the file path is external or user-controlled, this is a code injection vector.",
    pattern: /(eval|exec)\s*\(\s*(fs\.readFileSync|open\s*\(|readFileSync|read\(\))/g,
    category: "code_injection",
  },
  {
    id: "CP015",
    severity: "critical",
    title: "Read file + exec (Python)",
    description: "Reads a file and executes its contents. The file could contain injected code.",
    pattern: /exec\s*\(\s*open\s*\([^)]+\)\s*\.read\s*\(\)/g,
    category: "code_injection",
  },
  {
    id: "CP016",
    severity: "high",
    title: "Dynamic import from variable path",
    description: "Imports/requires a module from a variable path. If the path is user-controlled or fetched from an external source, this enables code injection.",
    pattern: /(require|import)\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)/g,
    category: "code_injection",
  },
  {
    id: "CP017",
    severity: "high",
    title: "Fetch URL content as instructions",
    description: "Fetches content from a URL and processes it as configuration, instructions, or rules — the fetched content effectively becomes agent instructions.",
    pattern: /(fetch|requests\.get|axios\.get|urllib)\s*\(.*\)[\s\S]{0,200}(\.ya?ml|\.json|config|rules|instructions|prompt|template)/gi,
    category: "code_injection",
  },
  {
    id: "CP018",
    severity: "high",
    title: "Read external file as instructions",
    description: "Reads a file from outside the skill directory and processes it as configuration or instructions.",
    pattern: /(readFileSync|open)\s*\(\s*['"`](\/|~\/|\.\.\/)/g,
    category: "code_injection",
  },
];

// ---------------------------------------------------------------------------
// Scanner entry point
// ---------------------------------------------------------------------------

export async function runCodePatternChecks(context: ScanContext): Promise<CodePatternResult> {
  const findings: Finding[] = [];

  for (const file of context.files) {
    if (!isCodeFile(file.relativePath)) continue;
    if (!file.content) continue;

    const lines = file.content.split("\n");

    for (const rule of CODE_RULES) {
      // For multiline patterns, run against full content
      if (rule.pattern.multiline) {
        rule.pattern.lastIndex = 0;
        let match;
        while ((match = rule.pattern.exec(file.content)) !== null) {
          const lineNumber = file.content.substring(0, match.index).split("\n").length;
          findings.push({
            category: rule.category,
            ruleId: rule.id,
            severity: rule.severity,
            confidence: "high",
            title: rule.title,
            description: rule.description,
            filePath: file.relativePath,
            lineNumber,
            snippet: getSnippet(file.content, lineNumber),
          });
        }
        continue;
      }

      // Line-by-line matching
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        rule.pattern.lastIndex = 0;
        if (rule.pattern.test(line)) {
          findings.push({
            category: rule.category,
            ruleId: rule.id,
            severity: rule.severity,
            confidence: "high",
            title: rule.title,
            description: rule.description,
            filePath: file.relativePath,
            lineNumber: i + 1,
            snippet: getSnippet(file.content, i + 1),
          });
        }
      }
    }
  }

  return { findings };
}
