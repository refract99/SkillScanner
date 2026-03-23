import { Finding, ScanContext, ScannerResult, getSnippet, extname, basename } from "./types";

/**
 * Secrets Detection Scanner
 *
 * Detects hardcoded credentials, API keys, tokens, and private keys
 * using regex patterns and Shannon entropy analysis.
 * Includes false-positive filtering for documentation examples and placeholders.
 *
 * Rule IDs: SD001–SD012
 */

export interface SecretsDetectionResult extends ScannerResult {
  findings: Finding[];
}

// ---------------------------------------------------------------------------
// Binary extensions to skip (same as hardStops)
// ---------------------------------------------------------------------------
const BINARY_EXTENSIONS = new Set([
  ".ttf", ".otf", ".woff", ".woff2", ".eot",
  ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
  ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac", ".ogg",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
  ".zip", ".tar", ".gz", ".tgz", ".bz2", ".7z", ".rar", ".xz",
  ".so", ".dll", ".dylib", ".bin", ".dat", ".o", ".obj",
  ".class", ".pyc", ".pyo", ".wasm", ".pyd",
  ".exe", ".com", ".msi", ".app",
]);

// ---------------------------------------------------------------------------
// Shannon entropy calculation
// ---------------------------------------------------------------------------
function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// High-entropy thresholds
const HEX_ENTROPY_THRESHOLD = 3.0;
const BASE64_ENTROPY_THRESHOLD = 4.0;

// ---------------------------------------------------------------------------
// False-positive filtering
// ---------------------------------------------------------------------------

/** Common placeholder / example values that should not trigger findings */
const PLACEHOLDER_PATTERNS = [
  /^[x]+$/i,                          // xxxxx
  /^[0]+$/,                            // 00000
  /^your[-_]?(api[-_]?key|token|secret|password)/i,
  /^<.*>$/,                            // <YOUR_KEY>
  /^\{.*\}$/,                          // {API_KEY}
  /^example[-_]?/i,
  /^test[-_]?/i,
  /^dummy[-_]?/i,
  /^fake[-_]?/i,
  /^placeholder/i,
  /^sample[-_]?/i,
  /^changeme$/i,
  /^replace[-_]?me/i,
  /^insert[-_]?/i,
  /^todo/i,
  /^my[-_]?(api[-_]?key|token|secret|password)/i,
  /^sk[-_]test[-_]/i,                  // Stripe test keys
  /^pk[-_]test[-_]/i,                  // Stripe test keys
  /^AKIA[A-Z0-9]{12}EXAMPLE/i,        // AWS example key
];

function isPlaceholder(value: string): boolean {
  const trimmed = value.trim();
  for (const pattern of PLACEHOLDER_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(trimmed)) return true;
  }
  // All same character
  if (trimmed.length > 1 && new Set(trimmed).size === 1) return true;
  return false;
}

/** Lines that look like documentation or comments */
function isDocumentationContext(line: string): boolean {
  const trimmed = line.trimStart();
  // Markdown example blocks or comments
  if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*") || trimmed.startsWith("<!--")) {
    // Only filter if it also contains example/placeholder language
    if (/\b(example|placeholder|sample|test|demo|dummy|your[_ ])\b/i.test(trimmed)) {
      return true;
    }
  }
  return false;
}

/** Skip lockfiles, minified bundles, and similar non-source files */
function shouldSkipFile(relativePath: string): boolean {
  const base = basename(relativePath).toLowerCase();
  if (base === "package-lock.json" || base === "yarn.lock" || base === "pnpm-lock.yaml") return true;
  if (base.endsWith(".min.js") || base.endsWith(".min.css")) return true;
  if (base.endsWith(".map")) return true;
  if (relativePath.includes("node_modules/")) return true;
  if (relativePath.includes("vendor/")) return true;
  if (relativePath.includes(".git/")) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Secret patterns (SD001–SD012)
// ---------------------------------------------------------------------------

interface SecretPattern {
  ruleId: string;
  title: string;
  description: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: "high" | "medium" | "low";
  pattern: RegExp;
  /** Optional validator: return false to suppress the finding */
  validate?: (match: string, line: string) => boolean;
}

const SECRET_PATTERNS: SecretPattern[] = [
  // SD001: AWS Access Key IDs
  {
    ruleId: "SD001",
    title: "AWS Access Key ID",
    description: "Found what appears to be an AWS Access Key ID (starts with AKIA). These keys grant programmatic access to AWS services.",
    severity: "critical",
    confidence: "high",
    pattern: /(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])/g,
  },
  // SD002: AWS Secret Access Key
  {
    ruleId: "SD002",
    title: "AWS Secret Access Key",
    description: "Found what appears to be an AWS Secret Access Key. Combined with an Access Key ID, this provides full AWS API access.",
    severity: "critical",
    confidence: "medium",
    pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/g,
    validate: (match) => shannonEntropy(match) >= HEX_ENTROPY_THRESHOLD,
  },
  // SD003: GCP Service Account JSON
  {
    ruleId: "SD003",
    title: "GCP Service Account Key",
    description: "Found a pattern matching Google Cloud Platform service account JSON credentials. These provide access to GCP resources.",
    severity: "critical",
    confidence: "high",
    pattern: /"type"\s*:\s*"service_account"/g,
  },
  // SD004: Azure Connection String / Storage Key
  {
    ruleId: "SD004",
    title: "Azure Connection String or Storage Key",
    description: "Found what appears to be an Azure connection string or storage account key.",
    severity: "critical",
    confidence: "high",
    pattern: /(?:AccountKey|SharedAccessSignature)\s*=\s*([A-Za-z0-9/+=]{44,})/g,
  },
  // SD005: Slack Token
  {
    ruleId: "SD005",
    title: "Slack Token",
    description: "Found a Slack Bot, User, or Webhook token. These can be used to read messages, post content, or access workspace data.",
    severity: "high",
    confidence: "high",
    pattern: /(?<![A-Za-z0-9])(xox[bpors]-[0-9a-zA-Z-]{10,})(?![A-Za-z0-9])/g,
  },
  // SD006: Discord Bot Token
  {
    ruleId: "SD006",
    title: "Discord Bot Token",
    description: "Found what appears to be a Discord bot token. These tokens grant full bot access to Discord servers.",
    severity: "high",
    confidence: "medium",
    pattern: /(?<![A-Za-z0-9])([MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})(?![A-Za-z0-9])/g,
    validate: (match) => shannonEntropy(match) >= BASE64_ENTROPY_THRESHOLD,
  },
  // SD007: GitHub Token (classic PAT, fine-grained, OAuth)
  {
    ruleId: "SD007",
    title: "GitHub Token",
    description: "Found a GitHub personal access token, fine-grained token, or OAuth token. These grant access to repositories and GitHub APIs.",
    severity: "critical",
    confidence: "high",
    pattern: /(?<![A-Za-z0-9])(gh[ps]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|gho_[A-Za-z0-9]{36,}|ghu_[A-Za-z0-9]{36,})(?![A-Za-z0-9])/g,
  },
  // SD008: Generic API Key assignment
  {
    ruleId: "SD008",
    title: "Generic API Key",
    description: "Found a hardcoded value assigned to an API key variable. Secrets should be loaded from environment variables or a secrets manager.",
    severity: "high",
    confidence: "medium",
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[=:]\s*["']([A-Za-z0-9_\-/+=]{16,})["']/gi,
    validate: (match, line) => {
      if (isPlaceholder(match)) return false;
      if (shannonEntropy(match) < HEX_ENTROPY_THRESHOLD) return false;
      return true;
    },
  },
  // SD009: Private Key (RSA, EC, OpenSSH, PGP)
  {
    ruleId: "SD009",
    title: "Private Key",
    description: "Found a private key header. Private keys should never be stored in source code.",
    severity: "critical",
    confidence: "high",
    pattern: /-----BEGIN\s+(RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
  },
  // SD010: Database Connection String with Password
  {
    ruleId: "SD010",
    title: "Database Connection String with Credentials",
    description: "Found a database connection string containing embedded credentials. Use environment variables or a secrets manager instead.",
    severity: "high",
    confidence: "high",
    pattern: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mssql|redis|amqp):\/\/[^:\s]+:[^@\s]+@[^\s"']+/gi,
    validate: (match) => {
      // Filter out example/localhost with obvious placeholder passwords
      if (/:(password|pass|secret|changeme|test|example|12345|admin)@/i.test(match)) {
        // localhost with placeholder = likely dev config, lower severity but still flag
        if (/localhost|127\.0\.0\.1|0\.0\.0\.0/.test(match)) return false;
      }
      return true;
    },
  },
  // SD011: JWT / Bearer Token (hardcoded)
  {
    ruleId: "SD011",
    title: "Hardcoded JWT or Bearer Token",
    description: "Found what appears to be a hardcoded JWT or Bearer token. Tokens should be dynamically obtained, not embedded in source.",
    severity: "high",
    confidence: "medium",
    pattern: /(?:bearer|token|jwt|authorization)\s*[=:]\s*["'](eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})["']/gi,
  },
  // SD012: High-entropy hex/base64 strings assigned to secret-like variables
  {
    ruleId: "SD012",
    title: "High-entropy Secret Value",
    description: "Found a high-entropy string assigned to a variable with a secret-like name. This may be a hardcoded credential.",
    severity: "medium",
    confidence: "low",
    pattern: /(?:secret|password|passwd|pwd|token|credential|private[_-]?key|signing[_-]?key|encryption[_-]?key)\s*[=:]\s*["']([A-Za-z0-9_\-/+=]{20,})["']/gi,
    validate: (match) => {
      if (isPlaceholder(match)) return false;
      if (shannonEntropy(match) < BASE64_ENTROPY_THRESHOLD) return false;
      return true;
    },
  },
];

// ---------------------------------------------------------------------------
// High-entropy string detection (standalone, not tied to variable names)
// Catches long hex/base64 blobs that look like secrets in .env or config files
// ---------------------------------------------------------------------------
const ENV_CONFIG_FILES = new Set([
  ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
  ".env.example", ".env.sample", ".env.test",
]);

function isEnvOrConfigFile(relativePath: string): boolean {
  const base = basename(relativePath).toLowerCase();
  if (ENV_CONFIG_FILES.has(base)) return true;
  if (base.endsWith(".env")) return true;
  return false;
}

// Matches KEY=VALUE lines in .env files with high-entropy values
const ENV_LINE_PATTERN = /^([A-Z_][A-Z0-9_]*)\s*=\s*["']?([^\s"'#]+)["']?/;

function checkEnvFileSecrets(file: { relativePath: string; content: string }): Finding[] {
  const findings: Finding[] = [];
  if (!isEnvOrConfigFile(file.relativePath)) return findings;

  const lines = file.content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith("#")) continue;

    const match = ENV_LINE_PATTERN.exec(line);
    if (!match) continue;

    const key = match[1];
    const value = match[2];

    // Only flag if key suggests a secret
    if (!/(?:key|secret|token|password|passwd|pwd|credential|auth|private)/i.test(key)) continue;
    if (isPlaceholder(value)) continue;
    if (value.length < 8) continue;

    const entropy = shannonEntropy(value);
    if (entropy >= HEX_ENTROPY_THRESHOLD) {
      findings.push({
        category: "secrets_detection",
        ruleId: "SD012",
        severity: "high",
        confidence: "medium",
        title: `Secret in env file: ${key}`,
        description: `Environment variable "${key}" contains a high-entropy value (entropy: ${entropy.toFixed(1)}) that appears to be a real credential. Env files with secrets should not be committed to source control.`,
        filePath: file.relativePath,
        lineNumber: i + 1,
        matchedPattern: `${key}=<redacted>`,
        snippet: getSnippet(file.content, i + 1, 1),
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Main scanner entry point
// ---------------------------------------------------------------------------
export async function runSecretsDetection(context: ScanContext): Promise<SecretsDetectionResult> {
  const findings: Finding[] = [];

  for (const file of context.files) {
    // Skip binary and non-content files
    if (!file.content) continue;
    const ext = extname(file.relativePath).toLowerCase();
    if (BINARY_EXTENSIONS.has(ext)) continue;
    if (shouldSkipFile(file.relativePath)) continue;

    // Check .env files for high-entropy secrets
    const envFindings = checkEnvFileSecrets(file);
    findings.push(...envFindings);

    // Run regex-based secret pattern detection
    const lines = file.content.split("\n");

    for (const secretDef of SECRET_PATTERNS) {
      // Reset regex state
      secretDef.pattern.lastIndex = 0;

      // For multi-line patterns (like GCP service account), check full content
      if (secretDef.ruleId === "SD003") {
        secretDef.pattern.lastIndex = 0;
        const fullMatch = secretDef.pattern.exec(file.content);
        if (fullMatch) {
          // Find line number
          const matchIndex = fullMatch.index;
          const lineNum = file.content.substring(0, matchIndex).split("\n").length;

          if (!isDocumentationContext(lines[lineNum - 1] || "")) {
            findings.push({
              category: "secrets_detection",
              ruleId: secretDef.ruleId,
              severity: secretDef.severity,
              confidence: secretDef.confidence,
              title: secretDef.title,
              description: secretDef.description,
              filePath: file.relativePath,
              lineNumber: lineNum,
              snippet: getSnippet(file.content, lineNum),
            });
          }
        }
        continue;
      }

      // Line-by-line matching for all other patterns
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNum = i + 1;

        secretDef.pattern.lastIndex = 0;
        const match = secretDef.pattern.exec(line);
        if (!match) continue;

        // Extract the captured group (secret value) or full match
        const secretValue = match[1] || match[0];

        // Skip documentation / comment contexts
        if (isDocumentationContext(line)) continue;

        // Skip placeholders
        if (isPlaceholder(secretValue)) continue;

        // Run custom validation if present
        if (secretDef.validate && !secretDef.validate(secretValue, line)) continue;

        findings.push({
          category: "secrets_detection",
          ruleId: secretDef.ruleId,
          severity: secretDef.severity,
          confidence: secretDef.confidence,
          title: secretDef.title,
          description: secretDef.description,
          filePath: file.relativePath,
          lineNumber: lineNum,
          matchedPattern: redactSecret(secretValue),
          snippet: getSnippet(file.content, lineNum),
        });
      }
    }
  }

  return { findings };
}

/** Redact the middle of a secret value, showing only prefix/suffix for identification */
function redactSecret(value: string): string {
  if (value.length <= 8) return value.substring(0, 2) + "***";
  const prefixLen = Math.min(4, Math.floor(value.length * 0.2));
  const suffixLen = Math.min(4, Math.floor(value.length * 0.2));
  return value.substring(0, prefixLen) + "***" + value.substring(value.length - suffixLen);
}
