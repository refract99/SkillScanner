/**
 * Framework-aware context detection.
 *
 * Identifies when code snippets appear inside framework-safe contexts
 * (e.g. Django auto-escaping, React JSX, ORM parameterized queries)
 * so that scanners can downgrade confidence on pattern matches that
 * are likely false positives.
 */

// ---------------------------------------------------------------------------
// Framework-safe pattern definitions
// ---------------------------------------------------------------------------

interface FrameworkSafePattern {
  /** Regex that matches the safe usage pattern */
  pattern: RegExp;
  /** Human-readable description */
  description: string;
  /** Which scanner categories this safe pattern applies to */
  mitigates: string[];
}

/**
 * Patterns that indicate a framework is mitigating the risk.
 * When one of these appears on the same line (or in surrounding context)
 * as a flagged pattern, the finding confidence should be downgraded.
 */
const FRAMEWORK_SAFE_PATTERNS: FrameworkSafePattern[] = [
  // ── Template auto-escaping (XSS / code injection) ──────────────────
  {
    pattern: /\{\{\s*\w+\s*\}\}/,
    description: "Django/Jinja2/Vue template variable (auto-escaped by default)",
    mitigates: ["code_injection", "prompt_injection"],
  },
  {
    pattern: /\{\s*\w+\s*\}/,
    description: "React JSX expression (auto-escaped by default)",
    mitigates: ["code_injection"],
  },
  {
    pattern: /<%=\s*.*?\s*%>/,
    description: "ERB escaped output tag (auto-escaped)",
    mitigates: ["code_injection"],
  },
  {
    pattern: /\{\{\s*\w+\s*\|\s*escape\s*\}\}/,
    description: "Explicit escape filter in template",
    mitigates: ["code_injection"],
  },

  // ── ORM / parameterized queries (SQL injection) ─────────────────────
  {
    pattern: /\.objects\.(filter|get|exclude|create|update|annotate|aggregate)\s*\(/,
    description: "Django ORM query (parameterized)",
    mitigates: ["code_injection"],
  },
  {
    pattern: /cursor\.execute\s*\(\s*["'].*?%s/,
    description: "Python DB-API parameterized query (%s placeholder)",
    mitigates: ["code_injection"],
  },
  {
    pattern: /cursor\.execute\s*\(\s*["'].*?\?\s*["']\s*,/,
    description: "Parameterized query (? placeholder)",
    mitigates: ["code_injection"],
  },
  {
    pattern: /\$\d+/,
    description: "PostgreSQL parameterized placeholder ($1, $2, ...)",
    mitigates: ["code_injection"],
  },
  {
    pattern: /\.query\s*\(\s*["'].*?\$\d+/,
    description: "Node.js pg parameterized query",
    mitigates: ["code_injection"],
  },
  {
    pattern: /prisma\.\w+\.(find|create|update|delete|upsert|aggregate)/,
    description: "Prisma ORM query (parameterized)",
    mitigates: ["code_injection"],
  },
  {
    pattern: /\.where\s*\(\s*\{/,
    description: "ORM where-clause with object (parameterized)",
    mitigates: ["code_injection"],
  },

  // ── Safe XSS patterns (explicit escaping / sanitization) ────────────
  {
    pattern: /DOMPurify\.sanitize/,
    description: "DOMPurify sanitization",
    mitigates: ["code_injection"],
  },
  {
    pattern: /bleach\.(clean|sanitize)/,
    description: "Python bleach sanitization",
    mitigates: ["code_injection"],
  },
  {
    pattern: /escape(Html|Xml|Regex)\s*\(/,
    description: "Explicit escape utility function",
    mitigates: ["code_injection"],
  },
  {
    pattern: /html\.escape\s*\(/,
    description: "Python html.escape()",
    mitigates: ["code_injection"],
  },

  // ── Safe credential patterns (reading config, not exfiltrating) ─────
  {
    pattern: /settings\.\w+/,
    description: "Django/framework settings access (server-controlled)",
    mitigates: ["credential_access", "network_exfiltration"],
  },
  {
    pattern: /app\.config\[/,
    description: "Flask app config access (server-controlled)",
    mitigates: ["credential_access", "network_exfiltration"],
  },
  {
    pattern: /process\.env\.\w+.*\|\|.*["']/,
    description: "Environment variable with fallback default (configuration pattern)",
    mitigates: ["credential_access"],
  },
  {
    pattern: /os\.environ\.get\s*\(\s*["']\w+["']\s*,\s*["']/,
    description: "Python os.environ.get with default (configuration pattern)",
    mitigates: ["credential_access"],
  },
  {
    pattern: /convex\s+env/i,
    description: "Convex environment variable reference (server-controlled)",
    mitigates: ["credential_access"],
  },

  // ── Safe network patterns (documentation / internal APIs) ───────────
  {
    pattern: /fetch\s*\(\s*["']\/api\//,
    description: "Fetch to relative /api/ path (same-origin)",
    mitigates: ["network_exfiltration"],
  },
  {
    pattern: /fetch\s*\(\s*`\$\{.*BASE_URL\}/,
    description: "Fetch using BASE_URL config (server-controlled)",
    mitigates: ["network_exfiltration"],
  },
  {
    pattern: /axios\.\w+\s*\(\s*["']\/api\//,
    description: "Axios to relative /api/ path (same-origin)",
    mitigates: ["network_exfiltration"],
  },

  // ── Safe dangerous operations (documentation context) ───────────────
  {
    pattern: /```[\s\S]*?(rm|chmod|sudo|kill)[\s\S]*?```/,
    description: "Command inside markdown code block (documentation)",
    mitigates: ["dangerous_operations", "code_injection", "credential_access"],
  },
  {
    pattern: /example:|e\.g\.|for instance|usage:/i,
    description: "Appears in example/documentation context",
    mitigates: [
      "dangerous_operations",
      "code_injection",
      "credential_access",
      "network_exfiltration",
    ],
  },
  {
    pattern: /do\s+not|don't|never|avoid|warning|caution/i,
    description: "Appears in warning/prohibition context",
    mitigates: [
      "dangerous_operations",
      "code_injection",
      "credential_access",
      "network_exfiltration",
      "prompt_injection",
    ],
  },

  // ── Framework-specific safe patterns ────────────────────────────────
  {
    pattern: /subprocess\.run\s*\(\s*\[/,
    description: "Python subprocess.run with list args (no shell injection)",
    mitigates: ["code_injection", "dangerous_operations"],
  },
  {
    pattern: /child_process\.execFile\s*\(/,
    description: "Node.js execFile (no shell, safe)",
    mitigates: ["code_injection"],
  },
  {
    pattern: /child_process\.spawn\s*\(/,
    description: "Node.js spawn (no shell by default, safer)",
    mitigates: ["code_injection"],
  },
  {
    pattern: /shlex\.quote/,
    description: "Python shlex.quote (shell escaping)",
    mitigates: ["code_injection", "dangerous_operations"],
  },
];

// ---------------------------------------------------------------------------
// Dangerous patterns that override framework context (always flag)
// ---------------------------------------------------------------------------

const ALWAYS_DANGEROUS: RegExp[] = [
  // XSS bypass patterns — these explicitly disable auto-escaping
  /dangerouslySetInnerHTML/,
  /v-html\s*=/,
  /\|\s*safe\b/,          // Django |safe filter
  /mark_safe\s*\(/,       // Django mark_safe()
  /\{%\s*autoescape\s+off/,  // Django autoescape off
  /<%\s*-\s*/,            // ERB unescaped output
  /innerHTML\s*=/,
  // SQL injection — raw/extra bypass ORM
  /\.raw\s*\(/,
  /\.extra\s*\(/,
  /RawSQL\s*\(/,
  // Command injection — shell=True negates list args
  /shell\s*=\s*True/,
  // Deserialization
  /pickle\.loads?\s*\(/,
  /yaml\.load\s*\(\s*[^)]*(?!Loader)/,  // yaml.load without Loader=
  /unserialize\s*\(/,
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface FrameworkContextResult {
  /** Whether framework-safe context was detected */
  hasSafeContext: boolean;
  /** Description of the safe framework pattern found */
  safePatternDescription?: string;
  /** Whether an always-dangerous override was also detected */
  hasExplicitBypass: boolean;
  /** Recommended confidence level after framework analysis */
  recommendedConfidence: "high" | "medium" | "low";
}

/**
 * Analyze a line and its surrounding context for framework-safe patterns.
 *
 * @param line        The line containing the flagged pattern
 * @param context     Surrounding lines (±2-3 lines) for broader context
 * @param category    The scanner category of the finding
 * @param originalConfidence  The confidence the scanner would assign without context
 * @returns Framework context analysis result
 */
export function analyzeFrameworkContext(
  line: string,
  context: string,
  category: string,
  originalConfidence: "high" | "medium" | "low"
): FrameworkContextResult {
  const textToCheck = `${line}\n${context}`;

  // 1. Check for always-dangerous overrides first
  for (const dangerousPattern of ALWAYS_DANGEROUS) {
    dangerousPattern.lastIndex = 0;
    if (dangerousPattern.test(textToCheck)) {
      return {
        hasSafeContext: false,
        hasExplicitBypass: true,
        recommendedConfidence: "high",
      };
    }
  }

  // 2. Check for framework-safe patterns that apply to this category
  for (const safe of FRAMEWORK_SAFE_PATTERNS) {
    if (!safe.mitigates.includes(category)) continue;

    safe.pattern.lastIndex = 0;
    if (safe.pattern.test(textToCheck)) {
      // Downgrade confidence: high → medium, medium → low, low stays low
      const downgraded: "high" | "medium" | "low" =
        originalConfidence === "high"
          ? "medium"
          : originalConfidence === "medium"
            ? "low"
            : "low";

      return {
        hasSafeContext: true,
        safePatternDescription: safe.description,
        hasExplicitBypass: false,
        recommendedConfidence: downgraded,
      };
    }
  }

  // 3. No framework context detected — keep original confidence
  return {
    hasSafeContext: false,
    hasExplicitBypass: false,
    recommendedConfidence: originalConfidence,
  };
}

/**
 * Check if a line contains an always-dangerous bypass pattern.
 * Use this for scanners that want to flag framework bypass as a separate finding.
 */
export function detectFrameworkBypass(
  line: string
): { bypassed: boolean; pattern?: string } {
  for (const dangerousPattern of ALWAYS_DANGEROUS) {
    dangerousPattern.lastIndex = 0;
    if (dangerousPattern.test(line)) {
      return { bypassed: true, pattern: dangerousPattern.source };
    }
  }
  return { bypassed: false };
}
