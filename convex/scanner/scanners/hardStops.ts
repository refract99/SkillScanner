import { Finding, ScanContext, getSnippet, extname, basename } from "./types";

/**
 * Hard-stop rules: non-dismissable deterministic checks.
 * These patterns are ALWAYS bad regardless of context.
 * Tightened from original regex scanners to minimize false positives.
 */

export interface HardStopResult {
  findings: Finding[];
}

// ---------------------------------------------------------------------------
// Asset/binary extensions to skip for content-based pattern checks
// These files may contain byte sequences that match text patterns but are not code
// ---------------------------------------------------------------------------
const BINARY_ASSET_EXTENSIONS = new Set([
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
// BP001: Executable files outside scripts/ directory
// ---------------------------------------------------------------------------
const EXECUTABLE_EXTENSIONS = new Set([
  ".exe", ".sh", ".bat", ".cmd", ".ps1", ".com", ".msi", ".app", ".run",
]);

// ---------------------------------------------------------------------------
// BP002: Binary/compiled files
// ---------------------------------------------------------------------------
const BINARY_COMPILED_EXTENSIONS = new Set([
  ".so", ".dll", ".dylib", ".bin", ".o", ".obj",
  ".class", ".pyc", ".pyo", ".wasm", ".pyd",
]);

// ---------------------------------------------------------------------------
// CI002: Reverse shell patterns
// ---------------------------------------------------------------------------
const REVERSE_SHELL_PATTERNS = [
  { pattern: /bash\s+-i\s+>&\s*\/dev\/tcp\//g, desc: "Bash reverse shell" },
  { pattern: /nc\s+-e\s/g, desc: "Netcat reverse shell" },
  { pattern: /ncat\s+-e\s/g, desc: "Ncat reverse shell" },
  { pattern: /python[23]?\s+-c\s+["']import\s+socket/g, desc: "Python reverse shell" },
  { pattern: /ruby\s+-rsocket\s+-e/g, desc: "Ruby reverse shell" },
  { pattern: /perl\s+-e\s+.*socket/gi, desc: "Perl reverse shell" },
  { pattern: /php\s+-r\s+.*fsockopen/g, desc: "PHP reverse shell" },
  { pattern: /mkfifo\s+.*\/tmp\//g, desc: "Named pipe for shell redirection" },
  { pattern: /\/dev\/tcp\/[0-9]/g, desc: "/dev/tcp device connection to IP" },
];

// ---------------------------------------------------------------------------
// CI005: Framework safety bypass (always dangerous)
// ---------------------------------------------------------------------------
const FRAMEWORK_BYPASS_PATTERNS = [
  { pattern: /dangerouslySetInnerHTML/g, desc: "React dangerouslySetInnerHTML" },
  { pattern: /v-html\s*=/g, desc: "Vue v-html directive" },
  { pattern: /\|\s*safe\b/g, desc: "Django |safe filter" },
  { pattern: /mark_safe\s*\(/g, desc: "Django mark_safe()" },
  { pattern: /\{%\s*autoescape\s+off/g, desc: "Django autoescape off" },
  { pattern: /innerHTML\s*=/g, desc: "innerHTML assignment" },
  { pattern: /\.raw\s*\(/g, desc: "Raw SQL query" },
  { pattern: /shell\s*=\s*True/g, desc: "Python subprocess shell=True" },
];

// ---------------------------------------------------------------------------
// DR003: Install from URL (bypasses registry verification)
// ---------------------------------------------------------------------------
const URL_INSTALL_PATTERNS = [
  { pattern: /pip3?\s+install\s+https?:\/\//g, desc: "pip install from URL" },
  { pattern: /npm\s+install\s+https?:\/\//g, desc: "npm install from URL" },
  { pattern: /npm\s+i\s+https?:\/\//g, desc: "npm install from URL (short)" },
  { pattern: /yarn\s+add\s+https?:\/\//g, desc: "yarn add from URL" },
  { pattern: /pip3?\s+install\s+git\+/g, desc: "pip install from git" },
  { pattern: /npm\s+install\s+git\+/g, desc: "npm install from git" },
];

// ---------------------------------------------------------------------------
// NE002: Data exfiltration patterns (tightened)
// ---------------------------------------------------------------------------
const EXFIL_PATTERNS = [
  { pattern: /curl\s+.*-d\s+@/g, desc: "curl file upload" },
  { pattern: /\bnc\s+-l/g, desc: "netcat listener" },
  { pattern: /\.post\s*\(.*\benv\b/gi, desc: "Posting environment data" },
  { pattern: /\.send\s*\(.*\benv\b/gi, desc: "Sending environment data" },
];

// ---------------------------------------------------------------------------
// OB005: Zero-width Unicode chars and Cyrillic homoglyphs
// ---------------------------------------------------------------------------
const ZERO_WIDTH_REGEX = /[\u200B\u200C\u200D\u2060\uFEFF\u00AD\u034F\u061C\u180E\u2028\u2029\u202A-\u202E\u2066-\u2069]/;

const CYRILLIC_LOOKALIKES: Record<string, string> = {
  "\u0430": "a", "\u0435": "e", "\u043E": "o", "\u0440": "p",
  "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0410": "A",
  "\u0412": "B", "\u0415": "E", "\u041A": "K", "\u041C": "M",
  "\u041D": "H", "\u041E": "O", "\u0420": "P", "\u0421": "C",
  "\u0422": "T", "\u0425": "X",
};

function hasHomoglyphs(text: string): boolean {
  for (const char of text) {
    if (char in CYRILLIC_LOOKALIKES) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// PI001: Full-phrase prompt injection (tightened — full phrases only)
// ---------------------------------------------------------------------------
const INJECTION_PHRASE_PATTERNS = [
  { pattern: /ignore\s+(all\s+)?previous\s+instructions/gi, desc: "Ignore previous instructions" },
  { pattern: /disregard\s+(all\s+)?prior\s+instructions/gi, desc: "Disregard prior instructions" },
  { pattern: /\[INST\]/gi, desc: "Instruction tag injection" },
  { pattern: /<<SYS>>/gi, desc: "System tag injection" },
  { pattern: /<\|im_start\|>/gi, desc: "Chat template injection" },
];

// ---------------------------------------------------------------------------
// PI002: Conditional triggers with stealth (tightened)
// ---------------------------------------------------------------------------
const STEALTH_TRIGGER_PATTERNS = [
  { pattern: /silently\s+(run|send|execute|upload|download)/gi, desc: "Silent execution instruction" },
  { pattern: /without\s+(the\s+)?user('s)?\s+(knowledge|knowing|awareness)/gi, desc: "Stealth instruction" },
  { pattern: /secretly\s+(run|send|execute|upload|install|modify|write)/gi, desc: "Secret action instruction" },
];

// ---------------------------------------------------------------------------
// PI007: Memory poisoning (tightened — require verb+target)
// ---------------------------------------------------------------------------
const MEMORY_POISONING_PATTERNS = [
  { pattern: /(write|modify|append|update|inject|add)\s+.{0,30}(\.claude\/memory|CLAUDE\.md)/gi, desc: "Write to Claude Code memory/config" },
  { pattern: /(write|modify|append|update|inject|add)\s+.{0,30}\.cursor\/rules/gi, desc: "Write to Cursor rules" },
  { pattern: /(write|modify|append|update|inject|add)\s+.{0,30}\.(bashrc|zshrc|profile|bash_profile)/gi, desc: "Write to shell profile" },
];

// ---------------------------------------------------------------------------
// PI008: System prompt leakage (tightened)
// ---------------------------------------------------------------------------
const PROMPT_LEAKAGE_PATTERNS = [
  { pattern: /print\s+.*system\s*prompt/gi, desc: "Print system prompt" },
  { pattern: /reveal\s+.*system\s*(prompt|instructions)/gi, desc: "Reveal system instructions" },
  { pattern: /send\s+.*system\s*prompt\s+to/gi, desc: "Send system prompt to external" },
  { pattern: /exfiltrate\s+.*prompt/gi, desc: "Exfiltrate prompt" },
];

// ---------------------------------------------------------------------------
// UC001: Untrusted content ingestion — fetch/read + execute/follow as instructions
// These fire on markdown/SKILL.md too, not just code files
// ---------------------------------------------------------------------------
const UNTRUSTED_CONTENT_PATTERNS = [
  { pattern: /fetch\s+.*\band\s+(execute|run|eval|follow|apply|source)\b/gi, desc: "Fetch URL and execute/follow content" },
  { pattern: /download\s+.*\band\s+(execute|run|eval|follow|apply|source)\b/gi, desc: "Download and execute/follow content" },
  { pattern: /read\s+.*\bfrom\s+(url|http|https)\b.*\b(follow|apply|execute|run)\b/gi, desc: "Read from URL and follow as instructions" },
  { pattern: /curl\s+.*\|\s*(sh|bash|zsh|python|perl|ruby|node)\b/g, desc: "Pipe downloaded content to interpreter" },
  { pattern: /wget\s+.*-O\s*-\s*\|\s*(sh|bash|zsh|python|perl|ruby|node)\b/g, desc: "Pipe downloaded content to interpreter" },
  { pattern: /source\s+<\(\s*(curl|wget)\b/g, desc: "Source remote script via shell" },
];

// ---------------------------------------------------------------------------
// STD006: XML angle brackets in YAML frontmatter
// ---------------------------------------------------------------------------

export async function runHardStopChecks(context: ScanContext): Promise<HardStopResult> {
  const findings: Finding[] = [];

  for (const file of context.files) {
    const ext = extname(file.relativePath).toLowerCase();
    const base = basename(file.relativePath);
    const dirParts = file.relativePath.split("/");
    const inScriptsDir = dirParts.some((p) => p === "scripts");

    // BP001: Executable files outside scripts/ dir
    if (EXECUTABLE_EXTENSIONS.has(ext) && !inScriptsDir) {
      findings.push({
        category: "bundled_payloads",
        ruleId: "BP001",
        severity: "high",
        confidence: "high",
        title: `Executable file: ${base}`,
        description: `Executable file "${file.relativePath}" found outside scripts/ directory. Executables in skills could deliver malicious payloads.`,
        filePath: file.relativePath,
      });
    }

    // BP002: Binary/compiled files
    if (BINARY_COMPILED_EXTENSIONS.has(ext)) {
      findings.push({
        category: "bundled_payloads",
        ruleId: "BP002",
        severity: "high",
        confidence: "high",
        title: `Binary/compiled file: ${base}`,
        description: `Binary file "${file.relativePath}" cannot be reviewed and may contain hidden payloads.`,
        filePath: file.relativePath,
      });
    }

    // Skip content-based checks for binary/empty files
    if (!file.content) continue;
    if (BINARY_ASSET_EXTENSIONS.has(ext)) continue;

    const lines = file.content.split("\n");

    // STD006: XML angle brackets in YAML frontmatter (only for SKILL.md / .mdc files)
    if (base === "SKILL.md" || file.relativePath.endsWith(".mdc")) {
      const frontmatterStr = file.content.split("---")[1] || "";
      if (/<|>/.test(frontmatterStr)) {
        findings.push({
          category: "standard_compliance",
          ruleId: "STD006",
          severity: "high",
          confidence: "high",
          title: "XML angle brackets in frontmatter",
          description: "Found < or > characters in YAML frontmatter. These are injection vectors into system prompts.",
          filePath: file.relativePath,
        });
      }
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // CI002: Reverse shells
      for (const { pattern, desc } of REVERSE_SHELL_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          findings.push({
            category: "code_injection",
            ruleId: "CI002",
            severity: "critical",
            confidence: "high",
            title: `Reverse shell: ${desc}`,
            description: `Detected reverse shell pattern. This is a strong indicator of malicious intent.`,
            filePath: file.relativePath,
            lineNumber: lineNum,
            snippet: getSnippet(file.content, lineNum),
          });
        }
      }

      // CI005: Framework safety bypass
      for (const { pattern, desc } of FRAMEWORK_BYPASS_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          findings.push({
            category: "code_injection",
            ruleId: "CI005",
            severity: "high",
            confidence: "high",
            title: `Framework safety bypass: ${desc}`,
            description: `Explicitly disables framework auto-escaping or safety features.`,
            filePath: file.relativePath,
            lineNumber: lineNum,
            snippet: getSnippet(file.content, lineNum),
          });
        }
      }

      // DR003: Install from URL
      for (const { pattern, desc } of URL_INSTALL_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          findings.push({
            category: "dependency_risks",
            ruleId: "DR003",
            severity: "high",
            confidence: "high",
            title: `Install from URL: ${desc}`,
            description: `Installing packages from URLs bypasses registry verification and could deliver malicious code.`,
            filePath: file.relativePath,
            lineNumber: lineNum,
            snippet: getSnippet(file.content, lineNum),
          });
        }
      }

      // NE002: Data exfiltration
      for (const { pattern, desc } of EXFIL_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          findings.push({
            category: "network_exfiltration",
            ruleId: "NE002",
            severity: "critical",
            confidence: "high",
            title: `Data exfiltration: ${desc}`,
            description: `Detected data exfiltration pattern that could send sensitive data to an external server.`,
            filePath: file.relativePath,
            lineNumber: lineNum,
            snippet: getSnippet(file.content, lineNum),
          });
        }
      }

      // OB005: Zero-width characters
      if (ZERO_WIDTH_REGEX.test(line)) {
        findings.push({
          category: "obfuscation",
          ruleId: "OB005",
          severity: "critical",
          confidence: "high",
          title: "Zero-width/invisible Unicode characters",
          description: "Found invisible Unicode characters that may hide malicious content or alter displayed text.",
          filePath: file.relativePath,
          lineNumber: lineNum,
          snippet: getSnippet(file.content, lineNum),
        });
      }

      // OB005: Homoglyphs
      if (hasHomoglyphs(line)) {
        findings.push({
          category: "obfuscation",
          ruleId: "OB005",
          severity: "critical",
          confidence: "high",
          title: "Unicode homoglyph/lookalike characters",
          description: "Found Cyrillic or other lookalike characters mixed with Latin text. Common obfuscation technique.",
          filePath: file.relativePath,
          lineNumber: lineNum,
          snippet: getSnippet(file.content, lineNum),
        });
      }

      // PI001: Injection phrases
      for (const { pattern, desc } of INJECTION_PHRASE_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          findings.push({
            category: "prompt_injection",
            ruleId: "PI001",
            severity: "critical",
            confidence: "high",
            title: `Prompt injection: ${desc}`,
            description: `Detected adversarial instruction pattern that attempts to override AI agent behavior.`,
            filePath: file.relativePath,
            lineNumber: lineNum,
            snippet: getSnippet(file.content, lineNum),
          });
        }
      }

      // PI002: Stealth triggers
      for (const { pattern, desc } of STEALTH_TRIGGER_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          findings.push({
            category: "prompt_injection",
            ruleId: "PI002",
            severity: "critical",
            confidence: "high",
            title: `Stealth trigger: ${desc}`,
            description: `Found instruction that triggers hidden behavior without the user's knowledge.`,
            filePath: file.relativePath,
            lineNumber: lineNum,
            snippet: getSnippet(file.content, lineNum),
          });
        }
      }

      // PI007: Memory poisoning (verb + target)
      for (const { pattern, desc } of MEMORY_POISONING_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          findings.push({
            category: "prompt_injection",
            ruleId: "PI007",
            severity: "critical",
            confidence: "high",
            title: `Memory poisoning: ${desc}`,
            description: `Detected instruction to modify persistent agent state. This could poison future agent behavior across sessions.`,
            filePath: file.relativePath,
            lineNumber: lineNum,
            snippet: getSnippet(file.content, lineNum),
          });
        }
      }

      // PI008: System prompt leakage
      for (const { pattern, desc } of PROMPT_LEAKAGE_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          findings.push({
            category: "prompt_injection",
            ruleId: "PI008",
            severity: "high",
            confidence: "high",
            title: `System prompt leakage: ${desc}`,
            description: `Detected instruction to extract or expose system prompts or agent configuration.`,
            filePath: file.relativePath,
            lineNumber: lineNum,
            snippet: getSnippet(file.content, lineNum),
          });
        }
      }

      // UC001: Untrusted content ingestion
      for (const { pattern, desc } of UNTRUSTED_CONTENT_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          findings.push({
            category: "code_injection",
            ruleId: "UC001",
            severity: "critical",
            confidence: "high",
            title: `Untrusted content execution: ${desc}`,
            description: `Detected a pattern that fetches or downloads external content and executes or follows it as instructions. The content at the source can change at any time, making this an indirect injection vector.`,
            filePath: file.relativePath,
            lineNumber: lineNum,
            snippet: getSnippet(file.content, lineNum),
          });
        }
      }
    }
  }

  return { findings };
}
