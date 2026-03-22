# SkillScanner Product Requirements Document

**Version:** 1.0.0
**Date:** March 20, 2026
**Status:** Draft

---

## 1. Executive Summary

SkillScanner is a web application that performs comprehensive security analysis of AI coding agent skills (Claude Code, OpenClaw, Cursor, Windsurf, Cline, and other AgentSkills-compatible platforms) *before* installation. Users submit a GitHub URL; the system clones the repository into a sandbox, runs 12 categories of deterministic and AI-powered security scans without executing any code, and delivers a detailed, shareable report on a web page.

No equivalent open-source tool combines static analysis, AI semantic review, cross-platform standard validation, and web-based reporting into a single product. The closest existing tools are:

- **skill-security-scan** (huifer) -- regex-only CLI, no AI analysis, no web UI, 47/100 quality score on Shyft marketplace
- **Repello SkillCheck** -- browser-based but closed-source, requires uploading to a third party
- **getsentry/skills@security-review** -- excellent methodology but runs inside Claude itself, not standalone

SkillScanner fills this gap as an open, self-hosted, web-accessible scanner with both deterministic and AI-powered analysis.

---

## 2. Problem Statement

AI coding agent skills are executable instruction sets with access to the user's filesystem, shell, environment variables, and API keys. The community marketplaces (ClawHub with 13,729+ skills, GitHub repositories, forum links) have no automated vetting. This creates a supply chain attack surface evidenced by:

- The **ClawHavoc campaign**: 335 malicious skills planted across ClawHub targeting 300,000 OpenClaw users
- Widespread **skill plagiarism**: popular security skills are verbatim copies of others, inflating install counts without review
- Common attack vectors: prompt injection, environment variable exfiltration, payload delivery, Unicode obfuscation, conditional activation

Users currently have no easy way to assess a skill's safety before installing it.

---

## 3. Target Users

| User | Need |
|------|------|
| **Developers** installing community skills | Quick safety check before `npx skills install` or manual installation |
| **Security teams** vetting skills for org-wide deployment | Detailed findings with severity, confidence, and evidence |
| **Skill authors** publishing to marketplaces | Pre-publication quality and security validation |
| **Platform operators** (ClawHub, SkillsMP, Killer-Skills) | Automated intake scanning for marketplace submissions |

---

## 4. Supported Platforms & Standards

### 4.1 AgentSkills Open Standard

The [AgentSkills specification](https://agentskills.io/specification) is the cross-platform standard adopted by 26+ platforms. SkillScanner validates against this spec as the baseline.

**Required structure:**
```
skill-name/
  SKILL.md          # Required -- YAML frontmatter + markdown body
  scripts/          # Optional
  references/       # Optional
  assets/           # Optional
```

**Required frontmatter fields:**
- `name` -- 1-64 chars, lowercase alphanumeric + hyphens, must match directory name
- `description` -- 1-1024 chars, describes what + when

**Validation rules:**
- SKILL.md must be exactly `SKILL.md` (case-sensitive)
- Folder name must be kebab-case
- No XML angle brackets (`<` `>`) anywhere (injection vector into system prompts)
- No `README.md` inside the skill folder
- Body should be under 5,000 words
- No "claude" or "anthropic" in the skill name (reserved)

### 4.2 Platform-Specific Extensions

| Platform | Location | Format | Extra Fields |
|----------|----------|--------|-------------|
| **Claude Code** | `.claude/skills/<name>/` | SKILL.md + YAML frontmatter | `argument-hint`, `disable-model-invocation`, `user-invocable`, `allowed-tools`, `model`, `context`, `agent`, `hooks` |
| **OpenClaw** | `<workspace>/skills/` or `~/.openclaw/skills/` | SKILL.md + YAML frontmatter | `metadata.openclaw.requires` (OS, binaries, env, config gating) |
| **Cursor** | `.cursor/rules/*.mdc` | Markdown Cursor format | `description`, `globs`, `alwaysApply` |
| **Windsurf** | `.windsurf/rules/*.md` | Markdown | GUI-managed metadata |
| **Cline** | `.clinerules/*.md` or `.txt` | Markdown/text | All files combined into unified rules |
| **Aider** | `AGENTS.md` | Single markdown file | Informal, no registry |

SkillScanner auto-detects the platform based on file paths and frontmatter fields.

---

## 5. Architecture

### 5.1 Technology Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| **Frontend** | Next.js 15 (App Router, Turbopack) | Already in place; SSR for SEO on report pages |
| **UI** | shadcn/ui, Radix, Tailwind CSS 4, Recharts | Already in place; consistent design system |
| **Backend** | Convex (serverless database + functions) | Already in place; reactive queries for real-time scan status |
| **Auth** | Clerk | Already in place; optional auth for scan submission |
| **AI Analysis** | OpenAI-compatible SDK with configurable provider | Semantic prompt injection detection, intent analysis; supports OpenRouter (production, model-agnostic) and Z.AI/GLM-5 (testing) |
| **Scanning** | Custom TypeScript scanner modules | Regex-based pattern matching, file structure validation |

### 5.2 System Context Diagram

```
                        +------------------+
                        |     Browser      |
                        |  (User submits   |
                        |   GitHub URL)    |
                        +--------+---------+
                                 |
                                 v
                   +-------------+--------------+
                   |   Next.js 15 App Router    |
                   |                            |
                   |  /scan        (submit)     |
                   |  /scan/[slug] (report)     |
                   |  /dashboard/scans (history)|
                   +-------------+--------------+
                                 |
                          Convex SDK
                                 |
                                 v
              +------------------+------------------+
              |           Convex Backend            |
              |                                     |
              |  Mutations: submitScan, store*      |
              |  Actions:   runScan (Node.js)       |
              |  Queries:   getScan*, getFindings*   |
              |                                     |
              |  Tables: scans, scanFindings,        |
              |          scanLinks                   |
              +--------+----------------+-----------+
                       |                |
                       v                v
              +--------+------+  +------+---------+
              |  Git Clone    |  |  OpenRouter    |
              |  (shallow,    |  |  API (model-   |
              |   /tmp dir)   |  |  agnostic)     |
              +--------------+  +----------------+
```

### 5.3 Scan Pipeline

```
User submits URL
       |
       v
[submitScan mutation]
  - Validate URL (GitHub HTTPS only)
  - Parse owner/repo/path
  - Deduplicate (same URL within 5 min returns existing scan)
  - Generate 8-char shareSlug
  - Insert scan record (status: "pending")
  - Schedule runScan action
  - Return { scanId, shareSlug }
       |
       v
[Frontend redirects to /scan/{slug}]
  - Reactive Convex query auto-updates UI as status changes
       |
       v
[runScan action] (Convex Node.js action, up to 10-min timeout)
  |
  |-- 1. Status -> "cloning"
  |      git clone --depth 1 --single-branch to /tmp/skillscanner-{id}/
  |      30-second timeout, 50MB size limit
  |      Capture commit SHA
  |
  |-- 2. Status -> "scanning"
  |      Run Categories 1-10 (deterministic scanners)
  |      All scanners are pure TypeScript functions
  |      Each returns Finding[] arrays
  |      Expected: 2-5 seconds
  |
  |-- 3. Status -> "analyzing"
  |      Run Category 11 (AI semantic review via configured LLM provider)
  |      Send SKILL.md + key files (truncated to 50KB each)
  |      Structured prompt requesting confidence-scored findings
  |      Model-agnostic: defaults to Claude Sonnet via OpenRouter, or GLM-5 via Z.AI for testing
  |      Expected: 5-15 seconds (OpenRouter/Claude), 15-60 seconds (Z.AI/GLM-5)
  |      Timeout configurable via LLM_TIMEOUT_MS env var
  |
  |-- 4. Run Category 12 (cross-platform compatibility)
  |
  |-- 5. Aggregate risk score (0-100)
  |      Weight: CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1
  |      Clamp to 0-100 range
  |
  |-- 6. Batch-insert findings and links via mutations
  |
  |-- 7. Status -> "complete"
  |      Store summary, riskScore, overallRisk, scanDurationMs
  |
  |-- 8. rm -rf /tmp/skillscanner-{id}/ (in finally block)
       |
       v
[Report page reactively shows full results]
```

Total expected scan time: **15-45 seconds** (OpenRouter/Claude), **30-90 seconds** (Z.AI/GLM-5).

### 5.4 Database Schema

Three new tables added to the existing Convex schema:

#### `scans`

| Field | Type | Purpose |
|-------|------|---------|
| `url` | `string` | Submitted GitHub URL |
| `repoOwner` | `string` | Parsed GitHub owner |
| `repoName` | `string` | Parsed GitHub repo name |
| `repoPath` | `optional(string)` | Sub-path within repo |
| `commitHash` | `optional(string)` | SHA of scanned commit |
| `branch` | `optional(string)` | Branch that was cloned |
| `userId` | `optional(id("users"))` | Null for anonymous scans |
| `status` | `union("pending", "cloning", "scanning", "analyzing", "complete", "failed")` | Pipeline stage |
| `platform` | `optional(union("claude_code", "openclaw", "cursor", "windsurf", "cline", "agentskills", "unknown"))` | Detected platform |
| `overallRisk` | `optional(union("safe", "low", "medium", "high", "critical"))` | Aggregate risk level |
| `riskScore` | `optional(number)` | Numeric 0-100 score |
| `summary` | `optional(string)` | Human-readable summary |
| `aiReviewSummary` | `optional(string)` | Claude's semantic analysis summary |
| `fileCount` | `optional(number)` | Files scanned |
| `totalFindings` | `optional(number)` | Total finding count |
| `scanDurationMs` | `optional(number)` | Total scan time |
| `errorMessage` | `optional(string)` | Error details if failed |
| `shareSlug` | `string` | 8-char alphanumeric for shareable URL |

**Indexes:** `by_shareSlug`, `by_userId`, `by_status`, `by_url`

#### `scanFindings`

| Field | Type | Purpose |
|-------|------|---------|
| `scanId` | `id("scans")` | Parent scan |
| `category` | `union(12 category literals)` | Scan category (see Section 6) |
| `ruleId` | `string` | Rule identifier (e.g., "NET001", "INJ002") |
| `severity` | `union("info", "low", "medium", "high", "critical")` | Finding severity |
| `confidence` | `union("high", "medium", "low")` | Detection confidence |
| `title` | `string` | Short finding title |
| `description` | `string` | Detailed explanation |
| `filePath` | `optional(string)` | File where found |
| `lineNumber` | `optional(number)` | Line number |
| `matchedPattern` | `optional(string)` | Regex or pattern that matched |
| `snippet` | `optional(string)` | Code snippet (max 500 chars, sanitized) |

**Indexes:** `by_scanId`, `by_scanId_category`, `by_scanId_severity`

#### `scanLinks`

| Field | Type | Purpose |
|-------|------|---------|
| `scanId` | `id("scans")` | Parent scan |
| `url` | `string` | The URL found |
| `domain` | `string` | Extracted domain |
| `filePath` | `string` | File where found |
| `lineNumber` | `optional(number)` | Line number |
| `classification` | `union("safe", "unknown", "suspicious")` | Domain classification |
| `context` | `optional(string)` | Surrounding text context |

**Index:** `by_scanId`

---

## 6. Scan Categories

### Category 1: Standard Compliance (`standard_compliance`)

Validates the skill against the AgentSkills specification and platform-specific requirements.

**Checks:**
- SKILL.md file exists (exact case)
- YAML frontmatter present with valid `---` delimiters
- `name` field: kebab-case, max 64 chars, matches directory name
- `description` field: present, max 1024 chars
- No XML angle brackets (`<` `>`) in frontmatter
- No reserved names ("claude", "anthropic")
- Folder naming: kebab-case only
- Body length: warn if over 5,000 words
- No README.md inside skill folder
- Platform-specific field validation (Claude Code extensions, OpenClaw gating, etc.)

### Category 2: Prompt Injection (`prompt_injection`)

Detects adversarial instructions embedded in skill files.

**Checks:**
- Hidden instruction patterns ("ignore previous instructions", "system:", "you are now")
- Conditional trigger patterns ("when user asks X, also do Y")
- Scope escalation ("also include", "append to", "in addition to what was asked")
- Role manipulation ("you are a", "act as", "pretend to be")
- Unicode/emoji obfuscation (zero-width characters, homoglyphs, invisible codepoints)
- Multi-language instruction mixing (non-ASCII in predominantly ASCII files)
- HTML/markdown comment injection (`<!-- hidden instructions -->`)

### Category 3: Credential & Environment Access (`credential_access`)

Detects references to sensitive files and environment variables.

**Checks:**
- Sensitive file paths: `~/.ssh/`, `~/.env`, `~/.aws/`, `~/.gnupg/`, `~/.config/gcloud/`
- Key files: `.pem`, `.key`, `id_rsa`, `id_ed25519`, `credentials.json`, `service-account.json`
- Environment variable patterns: `$API_KEY`, `$ANTHROPIC_API_KEY`, `$AWS_SECRET_ACCESS_KEY`, `$GITHUB_TOKEN`, `$OPENAI_API_KEY`, `process.env.*KEY`, `process.env.*SECRET`, `process.env.*TOKEN`
- Credential file patterns: `.env`, `.env.local`, `.env.production`, `config.json`, `secrets.*`
- Cloud provider credential paths: AWS, GCP, Azure default locations

### Category 4: Network & Exfiltration (`network_exfiltration`)

Detects external network requests and data exfiltration patterns.

**Checks:**
- Network request commands: `curl`, `wget`, `fetch()`, `requests.*`, `urllib`, `httpx`, `http.get`
- Data posting: `curl -d @`, `curl --data`, `wget --post-data`, `nc -l`, `netcat`
- URL construction with credential-shaped parameters
- WebSocket connections to external hosts
- DNS exfiltration patterns
- Allowed domain safelist: `anthropic.com`, `github.com`, `pypi.org`, `npmjs.com`, `registry.npmjs.org`
- All discovered URLs are also logged to the `scanLinks` table

### Category 5: Dangerous Operations (`dangerous_operations`)

Detects destructive or privilege-escalating system commands.

**Checks:**
- Destructive commands: `rm -rf /`, `rm -rf ~`, `rm -rf .`, `chmod 777`, `chown`, `dd of=/`
- Privilege escalation: `sudo`, `su`, `doas`
- System directory writes: `/etc/`, `/usr/`, `/bin/`, `/sbin/`, `/var/`, `/opt/`
- Process manipulation: `kill -9`, `killall`, fork bombs
- Disk operations: `mkfs`, `fdisk`, `mount`
- Cron/scheduled task manipulation

### Category 6: Code Injection (`code_injection`)

Detects dynamic code execution and backdoor patterns.

**Checks:**
- Dynamic execution: `eval()`, `exec()`, `Function()`, `setTimeout(string)`, `setInterval(string)`
- Import manipulation: `__import__()`, `importlib`, `require()` with variable
- Backdoor patterns: `bash -i >& /dev/tcp/`, `nc -e`, `python -c "import socket"`, reverse shell patterns
- "Inject into file" instruction patterns
- Code generation and execution instructions ("write a script that", "create and run")
- Compile and execute: `compile()`, `execfile()`

### Category 7: Obfuscation (`obfuscation`)

Detects attempts to hide malicious intent.

**Checks:**
- Base64 encoding: `base64.decode`, `atob()`, `Buffer.from(*, 'base64')`
- Character code construction: `chr()` chains, `String.fromCharCode()`, `\x` hex escapes
- String concatenation to build commands
- Hidden attribute access: `getattr()`, `vars()[]`, `globals()[]`
- Encoded payloads in data URIs
- Hex-encoded strings
- Unicode lookalike characters (Cyrillic 'а' vs Latin 'a')
- Zero-width joiners and non-joiners between visible characters

### Category 8: Dependency Risks (`dependency_risks`)

Detects dependency manipulation patterns.

**Checks:**
- Global package installation: `pip install`, `npm install -g`, `yarn global add`, `gem install`
- Force flags: `--force-reinstall`, `--force`, `--legacy-peer-deps`
- Version pinning overrides: `--upgrade`, `--ignore-installed`
- Install from URL (not registry): `pip install https://`, `npm install https://`
- Post-install scripts referenced
- Typosquatting indicators (similar names to popular packages)

### Category 9: Bundled Payloads (`bundled_payloads`)

Detects suspicious files included in the skill.

**Checks:**
- Executable files: `.exe`, `.sh`, `.bat`, `.cmd`, `.ps1`, `.py` (outside `scripts/`)
- Binary files: `.so`, `.dll`, `.dylib`, `.bin`, `.dat`
- Compiled artifacts: `.class`, `.pyc`, `.wasm`
- Archive files: `.zip`, `.tar`, `.gz`, `.7z`
- Unusually large files (> 1MB in a skill directory)
- Hidden files (dotfiles other than standard ones)
- Symlinks pointing outside the skill directory

### Category 10: External Links (`external_links`)

Inventories all external references found in the skill.

**Extracts:**
- All URLs (http://, https://, ftp://)
- All domain references
- API endpoint patterns
- IP addresses (IPv4 and IPv6)
- Email addresses

**Classifies each as:**
- **Safe**: Known trusted domains (anthropic.com, github.com, pypi.org, npmjs.com, stackoverflow.com, developer.mozilla.org)
- **Unknown**: Not on the safelist but no suspicious indicators
- **Suspicious**: Known malicious hosting, URL shorteners, IP addresses, unusual TLDs

### Category 11: AI Semantic Review (`ai_semantic`)

Uses the OpenRouter API for deep semantic analysis beyond pattern matching. OpenRouter provides access to multiple LLM providers (Claude, GPT, Gemini, Llama, etc.) through a single OpenAI-compatible API, allowing model selection based on cost, speed, or capability needs.

**Default model:** `anthropic/claude-sonnet-4` (configurable via environment variable)

**Analysis prompt structure:**
1. Send the full SKILL.md content (truncated to 50KB)
2. Send any bundled scripts (truncated to 10KB each, max 5 files)
3. Request structured JSON response with:
   - Overall risk assessment
   - Findings with HIGH/MEDIUM/LOW confidence (following Sentry's methodology)
   - Intent classification of instructions
   - Data flow reasoning (does input reach dangerous sinks?)
   - Framework awareness (is a flagged pattern actually safe in context?)
   - Subtle prompt injection detection
4. Only HIGH confidence findings are surfaced as findings; MEDIUM as informational

**What AI catches that regex cannot:**
- Conditional activation logic ("when deploying to production, also...")
- Semantic prompt injection (instructions that sound helpful but have hidden effects)
- Multi-step attack chains split across files
- Context-dependent risk (legitimate `fetch()` vs exfiltration `fetch()`)
- Social engineering in instructions ("for full functionality, please also grant...")

### Category 12: Cross-Platform Compatibility (`cross_platform`)

Identifies which platform(s) the skill targets and compatibility.

**Checks:**
- File path detection (`.claude/skills/`, `.cursor/rules/`, `.clinerules/`, etc.)
- Frontmatter field analysis (Claude-specific fields, OpenClaw gating, Cursor globs)
- AgentSkills spec compliance level
- Platform-specific feature usage
- Compatibility warnings (e.g., `allowed-tools` is experimental in AgentSkills)

---

## 7. Frontend Design

### 7.1 Routes

| Route | Auth | Purpose |
|-------|------|---------|
| `/scan` | Public | Scan submission page with URL input |
| `/scan/[slug]` | Public | Shareable scan report page |
| `/dashboard/scans` | Required | User's scan history |

### 7.2 Scan Submission Page (`/scan`)

- Hero-style layout with a prominent URL input field
- GitHub URL validation with real-time feedback
- Platform auto-detection badge shown after URL parsing
- "Scan" button with loading state
- Rate limit notice for anonymous users
- Recent public scans sidebar (optional, future)

### 7.3 Scan Report Page (`/scan/[slug]`)

**Header section:**
- Repository name, owner, and GitHub link
- Scan date and duration
- Overall risk badge (color-coded: green/yellow/orange/red/dark-red)
- Risk score gauge (0-100, circular radial chart via Recharts)
- Platform badge(s)
- Share button (copy URL)
- Commit SHA with link

**Summary cards row:**
- Total findings count
- Critical/High/Medium/Low/Info breakdown
- Files scanned
- External links found

**Risk radar chart:**
- Recharts RadarChart showing normalized risk scores across all 12 categories
- Visual "shape" of the skill's risk profile

**Category sections:**
- One expandable accordion per category
- Category header: name, finding count, severity badges
- Expanded view: individual finding cards with:
  - Severity + confidence badges
  - Rule ID
  - Title and description
  - File path and line number (clickable to GitHub source)
  - Code snippet in styled code block

**External Links table:**
- Sortable/filterable data table using @tanstack/react-table
- Columns: URL, Domain, File, Line, Classification
- Color-coded classification badges

**AI Analysis section:**
- Claude's narrative summary
- Confidence-scored findings
- Data flow analysis results

**Status states (during scan):**
- Animated progress stepper: Pending -> Cloning -> Scanning -> Analyzing -> Complete
- Each step shows elapsed time
- Pulsing animation on active step
- Error state with message display

### 7.4 Dashboard Scan History (`/dashboard/scans`)

- Data table with columns: URL, Platform, Risk, Status, Date, Actions
- Sortable and filterable
- Link to report page for each scan
- Delete scan action (user's own scans only)

### 7.5 Navigation Updates

- Landing page header: add "Scan" link
- Dashboard sidebar: add "Skill Scanner" item under main navigation

---

## 8. Security Considerations

### 8.1 Sandbox Isolation

The cloned repository is treated as **untrusted, hostile input** at every stage:

- **Clone target**: `/tmp/skillscanner-{scanId}-{randomSuffix}/` -- ephemeral, unique, unpredictable
- **Shallow clone**: `git clone --depth 1 --single-branch` minimizes data transferred
- **Size limit**: Post-clone `du -sm` check; reject repos over 50MB
- **Clone timeout**: 30-second `execSync` timeout prevents hanging on slow/adversarial repos
- **No execution**: All analysis is read-only. No file in the cloned repo is ever executed, imported, or `require()`-ed. Scanners read file contents as strings only.
- **Cleanup**: `rm -rf` of temp directory in a `finally` block, guaranteed even on errors
- **No symlink following**: Scanners use `lstat` and skip symlinks to prevent traversal
- **Path validation**: All file paths are validated to stay within the clone directory

### 8.2 Input Validation

- **URL validation**: Only `https://github.com/{owner}/{repo}` patterns accepted
- **Owner/repo format**: Alphanumeric, hyphens, dots, underscores only; validated via regex
- **No embedded credentials**: Reject URLs containing `@` before the host
- **No query parameters or fragments**: Strip before processing
- **No path traversal**: Reject `..` in repo paths

### 8.3 Rate Limiting

| Context | Limit | Window |
|---------|-------|--------|
| Anonymous scans | 5 | per hour per IP |
| Authenticated scans | 20 | per hour per user |
| Same URL dedup | 1 | per 5 minutes (returns existing scan) |

Implemented via a Next.js API route (`/api/scan`) wrapping the Convex mutation with the existing `withRateLimit` infrastructure and CSRF validation.

### 8.4 API Key Protection

- `LLM_API_KEY` stored in Convex environment variables (server-side only)
- Never exposed to the client
- Text sent to the LLM is truncated (SKILL.md: 50KB, scripts: 10KB each, max 5 files)
- LLM response is validated against expected JSON structure before storing
- OpenRouter provides per-key spend limits and usage tracking via their dashboard
- Z.AI provides usage monitoring at [z.ai](https://z.ai) dashboard

### 8.5 Report Access Control

- Reports are accessible via `shareSlug` (8-char alphanumeric, 62^8 = ~218 trillion combinations)
- No authentication required to view a report (shareable by design)
- Slugs are not enumerable (no listing endpoint for anonymous users)
- Users can only see their own scan history in the dashboard

### 8.6 Stored Content Safety

- Code snippets stored in `scanFindings` are truncated to 500 characters
- Snippets are sanitized (HTML entities escaped) before storage
- Report page renders snippets inside `<code>` blocks with no `dangerouslySetInnerHTML`
- URLs from `scanLinks` are displayed as text, not rendered as clickable links (prevents XSS via crafted URLs)

---

## 9. Convex Function Design

### 9.1 File Organization

```
convex/
  schema.ts                          # MODIFY: add 3 new tables
  scanner/
    submit.ts                        # submitScan (public mutation)
    pipeline.ts                      # runScan (internal action, "use node")
    store.ts                         # Internal mutations for persisting results
    queries.ts                       # Public queries for reading results
    scanners/
      types.ts                       # Finding, ScannerResult, ScanContext types
      index.ts                       # runAllScanners() orchestrator
      standardCompliance.ts          # Category 1
      promptInjection.ts             # Category 2
      credentialAccess.ts            # Category 3
      networkExfiltration.ts         # Category 4
      dangerousOperations.ts         # Category 5
      codeInjection.ts              # Category 6
      obfuscation.ts                # Category 7
      dependencyRisks.ts            # Category 8
      bundledPayloads.ts            # Category 9
      externalLinks.ts              # Category 10
      aiSemanticReview.ts           # Category 11
      crossPlatform.ts             # Category 12
      domainSafelist.ts            # Known-safe domain list
```

### 9.2 Function Types

| Function | Type | Auth | Purpose |
|----------|------|------|---------|
| `submitScan` | mutation | Optional | Create scan record, schedule pipeline |
| `runScan` | internalAction | N/A | Orchestrate clone + scan + AI + store |
| `updateScanStatus` | internalMutation | N/A | Update scan status field |
| `batchInsertFindings` | internalMutation | N/A | Insert findings (batches of 100) |
| `batchInsertLinks` | internalMutation | N/A | Insert external links |
| `completeScan` | internalMutation | N/A | Set final results |
| `getScanBySlug` | query | Public | Fetch scan by shareSlug |
| `getScanFindings` | query | Public | Fetch findings, optional category filter |
| `getScanLinks` | query | Public | Fetch external links for a scan |
| `getScanStatus` | query | Public | Lightweight status polling |
| `getUserScans` | query | Required | Current user's scan history |
| `getScanSummaryStats` | query | Public | Aggregated counts by category/severity |

### 9.3 Scanner Module Interface

All scanner modules are plain TypeScript functions (not Convex functions). They are imported and called directly within the `runScan` action.

```typescript
// convex/scanner/scanners/types.ts

export interface Finding {
  category: ScanCategory;
  ruleId: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: "high" | "medium" | "low";
  title: string;
  description: string;
  filePath?: string;
  lineNumber?: number;
  matchedPattern?: string;
  snippet?: string;
}

export interface ExternalLink {
  url: string;
  domain: string;
  filePath: string;
  lineNumber?: number;
  classification: "safe" | "unknown" | "suspicious";
  context?: string;
}

export interface ScannerResult {
  findings: Finding[];
  links?: ExternalLink[];
}

export type ScanCategory =
  | "standard_compliance"
  | "prompt_injection"
  | "credential_access"
  | "network_exfiltration"
  | "dangerous_operations"
  | "code_injection"
  | "obfuscation"
  | "dependency_risks"
  | "bundled_payloads"
  | "external_links"
  | "ai_semantic"
  | "cross_platform";
```

Each scanner exports:
```typescript
export async function scan(rootDir: string): Promise<ScannerResult>;
```

The AI scanner additionally requires:
```typescript
export async function scan(
  rootDir: string,
  config: { apiKey: string; baseUrl: string; model: string; timeoutMs: number }
): Promise<ScannerResult>;
```

---

## 10. Prerequisites

### 10.1 Required Accounts & Keys

| Service | Purpose | How to Obtain |
|---------|---------|---------------|
| **Clerk** | Authentication | Already configured in existing app |
| **Convex** | Database + serverless functions | Already configured in existing app |
| **LLM API key** | AI semantic review (Category 11) | OpenRouter: [openrouter.ai/keys](https://openrouter.ai/keys) -- or Z.AI: [z.ai](https://z.ai) for testing with GLM-5 |
| **Vercel** (production) | Hosting | Already configured for deployment |

### 10.2 Environment Variables

**New variables required:**

| Variable | Location | Purpose |
|----------|----------|---------|
| `LLM_API_KEY` | Convex dashboard (Environment Variables) | API key for the configured LLM provider |
| `LLM_BASE_URL` | Convex dashboard (Environment Variables) | Provider base URL. Default: `https://openrouter.ai/api/v1`. For testing: `https://api.z.ai/api/coding/paas/v4` |
| `LLM_MODEL` | Convex dashboard (Environment Variables) | Optional. Model identifier. Default: `anthropic/claude-sonnet-4` (OpenRouter) or `glm-5` (Z.AI) |
| `LLM_TIMEOUT_MS` | Convex dashboard (Environment Variables) | Optional. Per-request timeout in ms. Default: `30000` (OpenRouter) or `120000` (Z.AI/GLM-5) |

**Testing configuration (Z.AI / GLM-5):**
```
LLM_API_KEY=your-z-ai-key
LLM_BASE_URL=https://api.z.ai/api/coding/paas/v4
LLM_MODEL=glm-5
LLM_TIMEOUT_MS=120000
```

**Production configuration (OpenRouter):**
```
LLM_API_KEY=your-openrouter-key
LLM_BASE_URL=https://openrouter.ai/api/v1
LLM_MODEL=anthropic/claude-sonnet-4
LLM_TIMEOUT_MS=30000
```

**Existing variables (no changes needed):**

| Variable | Location | Purpose |
|----------|----------|---------|
| `NEXT_PUBLIC_CLERK_*` | `.env.local` | Clerk auth |
| `NEXT_PUBLIC_CONVEX_URL` | `.env.local` | Convex backend |
| `CSRF_SECRET` | `.env.local` | CSRF token generation |
| `ADMIN_EMAIL` | `.env.local` | Admin user identification |

### 10.3 New Dependencies

| Package | Purpose | Install |
|---------|---------|---------|
| `openai` | OpenAI-compatible SDK (works with OpenRouter and Z.AI APIs) | `npm install openai` |

All other dependencies (gray-matter for YAML frontmatter parsing, zod for validation, recharts for charts, @tanstack/react-table for tables) are already in the project.

### 10.4 System Requirements

- **Git**: Must be available in the Convex action runtime (Node.js environment). Convex actions run in a containerized environment with git available.
- **Disk space**: Temporary storage in `/tmp` for cloned repos (max 50MB per scan, cleaned up after each scan)
- **Network**: Outbound HTTPS to `github.com` (git clone) and the configured LLM provider (`openrouter.ai` or `api.z.ai`)

---

## 11. Assumptions

### 11.1 Technical Assumptions

1. **Convex actions support `child_process`**: Node.js actions with `"use node"` directive have access to `child_process.execSync` for running `git clone`. This is confirmed by Convex documentation for Node.js actions.

2. **Git is available in Convex runtime**: The Convex Node.js action environment includes `git` in the system PATH. If not, fallback to GitHub's REST API (`GET /repos/{owner}/{repo}/tarball`) to download repo contents.

3. **`/tmp` is writable in Convex actions**: Convex Node.js actions have access to a writable temporary filesystem. Files persist only for the duration of the action.

4. **Convex action timeout is sufficient**: The 10-minute timeout for Convex actions is well above the expected 15-45 second scan time.

5. **Convex mutation batch limits**: Convex mutations can handle inserting ~100 documents per call. Findings are batched accordingly. For a skill with 500+ findings, ~5 mutation calls are needed.

6. **LLM API latency**: Response times vary by provider and model. OpenRouter/Claude: 5-15 seconds. Z.AI/GLM-5: 15-60 seconds. The per-request timeout is configurable via `LLM_TIMEOUT_MS` (default 30s for OpenRouter, 120s for Z.AI). The prompt is kept under 100KB to ensure fast responses.

7. **Only public GitHub repos**: The scanner only clones public repositories. Private repos would require GitHub OAuth integration (future scope).

### 11.2 Product Assumptions

1. **Primary use case is pre-installation vetting**: Users scan skills *before* installing them, not after.

2. **Anonymous access is important**: Many users will want to quickly scan a skill without creating an account. Authentication adds features (history, higher rate limits) but is not required.

3. **Reports should be shareable**: The share URL is a key feature -- users share scan results in team chats, GitHub issues, and forum discussions to support or discourage skill adoption.

4. **False positives are acceptable**: Unlike runtime security tools, this is a pre-installation advisory. It is better to flag a potential issue (with appropriate confidence scoring) than to miss it. Users make the final decision.

5. **English-language focus**: Scan patterns and AI prompts are English-oriented. Multi-language skill analysis is future scope.

6. **Scan results are immutable**: Once a scan completes, its findings are not modified. Users can re-scan the same URL to get a new report (which may differ if the repo has changed).

### 11.3 Scope Boundaries

**In scope:**
- Public GitHub repositories containing AI agent skills
- Skills following AgentSkills spec, Claude Code, OpenClaw, Cursor, Windsurf, Cline formats
- Static analysis only (no code execution)
- 12 scan categories as defined in Section 6
- Web-based report delivery

**Out of scope (future considerations):**
- Private repository scanning (requires GitHub OAuth)
- Non-GitHub hosting (GitLab, Bitbucket) -- future platform expansion
- Runtime/dynamic analysis (executing skills in a sandbox)
- Automated re-scanning on repo updates (webhook-triggered)
- API access for CI/CD integration
- Marketplace integration (automated scanning for ClawHub, SkillsMP submissions)
- Browser extension for one-click scanning from GitHub pages
- Comparison reports (diff two scans of the same skill)
- Skill dependency graph analysis (skills that reference other skills)

---

## 12. Build & Deploy Roadmap

### Phase 1: Schema & Backend Foundation (2 sessions)

**Objective:** Database tables and core Convex functions operational.

**Tasks:**
1. Extend `convex/schema.ts` with `scans`, `scanFindings`, `scanLinks` tables
2. Create `convex/scanner/scanners/types.ts` with shared type definitions
3. Create `convex/scanner/store.ts` with internal mutations (`updateScanStatus`, `batchInsertFindings`, `batchInsertLinks`, `completeScan`)
4. Create `convex/scanner/queries.ts` with public queries (`getScanBySlug`, `getScanFindings`, `getScanLinks`, `getScanStatus`, `getUserScans`, `getScanSummaryStats`)
5. Create `convex/scanner/submit.ts` with `submitScan` mutation (URL validation, dedup, slug generation, scheduling)
6. Run `npx convex dev --once --typecheck=enable` to verify schema and types

**Deliverable:** Scan records can be created and queried via the Convex dashboard.

### Phase 2: Deterministic Scanners (3 sessions)

**Objective:** Categories 1-10 and 12 scanning operational.

**Tasks:**
1. Implement `convex/scanner/scanners/domainSafelist.ts`
2. Implement scanner modules in order of complexity:
   - `credentialAccess.ts` (Category 3) -- pure regex, well-defined patterns
   - `dangerousOperations.ts` (Category 5) -- pure regex
   - `codeInjection.ts` (Category 6) -- pure regex
   - `dependencyRisks.ts` (Category 8) -- pure regex
   - `networkExfiltration.ts` (Category 4) -- regex + domain classification
   - `obfuscation.ts` (Category 7) -- regex + Unicode analysis
   - `externalLinks.ts` (Category 10) -- URL extraction + classification
   - `bundledPayloads.ts` (Category 9) -- file stat analysis
   - `promptInjection.ts` (Category 2) -- complex regex patterns
   - `standardCompliance.ts` (Category 1) -- YAML parsing + structure validation
   - `crossPlatform.ts` (Category 12) -- platform detection logic
3. Create `convex/scanner/scanners/index.ts` orchestrator
4. Create `convex/scanner/pipeline.ts` with `runScan` action (git clone + scan orchestration)
5. End-to-end test: submit a known skill URL via Convex dashboard, verify findings are stored

**Deliverable:** Full deterministic scan pipeline operational, testable via Convex dashboard.

### Phase 3: AI Semantic Review (1 session)

**Objective:** Category 11 (Claude-powered analysis) integrated.

**Tasks:**
1. `npm install openai`
2. Add `LLM_API_KEY`, `LLM_BASE_URL`, and optionally `LLM_MODEL` / `LLM_TIMEOUT_MS` to Convex environment variables
3. Implement `convex/scanner/scanners/aiSemanticReview.ts`:
   - Initialize OpenAI client with configurable `baseURL` and `timeout`
   - Construct structured analysis prompt
   - Call LLM API with SKILL.md + key file contents
4. Test with Z.AI/GLM-5 (use `LLM_TIMEOUT_MS=120000` for GLM-5's longer response times)
   - Parse structured JSON response
   - Map to Finding[] with confidence scores
4. Integrate into pipeline after deterministic scanners
5. Test with known-malicious and known-safe skills
6. Verify graceful degradation if API key is missing or API is unavailable

**Deliverable:** AI semantic review produces confidence-scored findings integrated into the scan pipeline.

### Phase 4: Frontend -- Scan Submission & Report (3 sessions)

**Objective:** Users can submit scans and view reports in the browser.

**Tasks:**
1. Create `lib/scan-validation.ts` with Zod schema for GitHub URL validation
2. Create `app/api/scan/route.ts` API route with rate limiting + CSRF
3. Create `app/scan/page.tsx` -- scan submission page:
   - `ScanSubmitForm` component with URL input, validation, submit
   - Platform auto-detection badge
   - Link to this page from landing header
4. Create `app/scan/[slug]/page.tsx` -- report page:
   - `ScanStatusTracker` -- animated pipeline progress
   - `ScanReportHeader` -- risk score gauge, platform badge, share button
   - Summary stats cards (findings by severity)
   - `RiskScoreChart` -- radar chart across 12 categories
   - `CategoryAccordion` -- expandable category sections
   - `FindingCard` -- individual finding display
   - `ExternalLinksTable` -- sortable links table
   - AI analysis summary section
5. Create `app/dashboard/scans/page.tsx` -- scan history:
   - `ScanHistoryTable` using @tanstack/react-table
6. Update `app/dashboard/app-sidebar.tsx` -- add Skill Scanner nav item
7. Update landing page header -- add "Scan" link

**Deliverable:** Full user-facing scan workflow from submission to report viewing.

### Phase 5: Security Hardening & Polish (1-2 sessions)

**Objective:** Production-ready security and UX polish.

**Tasks:**
1. Rate limiting implementation (API route + Convex-side dedup)
2. Input sanitization audit (URL parsing, stored snippets, rendered content)
3. Error state handling (clone failures, API timeouts, invalid repos, private repos)
4. Loading skeletons for report page sections
5. Mobile-responsive report layout
6. SEO metadata for report pages (Open Graph tags for social sharing)
7. CSP header updates if needed for new routes
8. Edge case testing:
   - Very large repos (> 50MB)
   - Repos with no SKILL.md
   - Private repos (graceful error)
   - Malformed YAML frontmatter
   - Empty repos
   - Repos with submodules
   - URLs with trailing slashes, fragments, query params
9. Add scan submission to security event logging

**Deliverable:** Hardened, polished application ready for production traffic.

### Phase 6: Testing & Launch (1 session)

**Objective:** Verified, deployed, operational.

**Tasks:**
1. Test all 12 scan categories against known test cases:
   - Craft a test skill with known vulnerabilities (one per category)
   - Craft a clean skill with no issues
   - Verify all findings are detected with correct severity/confidence
   - Verify clean skill produces no false positives
2. Test sharing flow (generate link, open in incognito, verify report loads)
3. Test anonymous vs authenticated experience
4. Type check: `npx convex dev --once --typecheck=enable`
5. Build check: `npm run build`
6. Deploy with `/deploy-to-dev` for staging verification
7. Deploy with `/deploy-to-prod` for production launch

**Deliverable:** Live, publicly accessible SkillScanner.

---

## 13. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Git not available in Convex runtime | Low | High | Fallback: GitHub REST API tarball download instead of git clone |
| `/tmp` not writable in Convex | Low | High | Fallback: use in-memory file processing via GitHub API content endpoints |
| LLM API rate limits or outage | Medium | Medium | Graceful degradation: skip AI review, mark as "partial scan"; provider-agnostic design allows switching providers via env vars |
| Adversarial repos designed to crash scanner | Medium | Medium | Timeout on clone (30s), size limit (50MB), file count limit (1000 files), line length limit |
| High scan volume exhausts LLM credits | Medium | Medium | Rate limiting, optional AI scan (free tier without AI), per-key spend limits (OpenRouter/Z.AI), usage monitoring |
| Regex evasion by sophisticated attackers | High | Low | AI semantic review catches what regex misses; this is advisory, not enforcement |
| Convex action timeout for large repos | Low | Medium | Shallow clone + file count cap + early termination if scan exceeds 5 minutes |

---

## 14. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Scan completion rate | > 95% | `status === "complete"` / total scans |
| Scan duration (p50) | < 30s (OpenRouter), < 60s (Z.AI/GLM-5) | `scanDurationMs` field |
| Scan duration (p95) | < 60s (OpenRouter), < 120s (Z.AI/GLM-5) | `scanDurationMs` field |
| False positive rate | < 20% of findings | Manual review of sample reports |
| Detection rate for known-bad skills | > 90% | Test suite with crafted malicious skills |
| Report page load time | < 2 seconds | Lighthouse performance audit |

---

## 15. Future Considerations

These are explicitly out of scope for v1 but documented for future planning:

1. **GitHub OAuth integration** -- scan private repos with user's GitHub token
2. **GitLab/Bitbucket support** -- expand beyond GitHub
3. **CI/CD API** -- REST API for automated scanning in pipelines
4. **Webhook-triggered re-scans** -- monitor repos for changes
5. **Marketplace integrations** -- automated intake for ClawHub, SkillsMP
6. **Browser extension** -- one-click scan from any GitHub skill page
7. **Scan comparison** -- diff two scans of the same repo over time
8. **Custom rule sets** -- users define their own scan rules
9. **Organization accounts** -- team scan management and policy enforcement
10. **SBOM generation** -- software bill of materials for skill dependencies
11. **Semgrep integration** -- taint analysis on bundled code files
12. **YARA rule engine** -- pattern matching for encoded/obfuscated payloads

---

## Appendix A: Research Sources

| Source | URL | Key Contribution |
|--------|-----|-----------------|
| Anthropic: Complete Guide to Building Skills for Claude | [PDF](https://resources.anthropic.com/hubfs/The-Complete-Guide-to-Building-Skill-for-Claude.pdf) | Skill structure, naming, frontmatter, validation checklist |
| AgentSkills Specification | [agentskills.io/specification](https://agentskills.io/specification) | Cross-platform open standard, 26+ platform adoption |
| Repello AI: Claude Code Skill Security | [repello.ai/blog/claude-code-skill-security](https://repello.ai/blog/claude-code-skill-security) | Attack vectors, audit checklist, SkillCheck tool, ClawHavoc campaign |
| skill-security-scan (huifer) | [github.com/huifer/skill-security-scan](https://github.com/huifer/skill-security-scan) | Regex rule patterns, severity classification, HTML reporting |
| Shyft AI: skill-security-scan listing | [shyft.ai/skills/skill-security-scan](https://shyft.ai/skills/skill-security-scan) | Marketplace quality scoring (47/100), community distribution |
| TimOnWeb: 5 Security Skills Reviewed | [timonweb.com/ai/i-checked-5-security-skills-for-claude-code](https://timonweb.com/ai/i-checked-5-security-skills-for-claude-code-only-one-is-worth-installing/) | Evaluation criteria, Sentry methodology superiority, false positive analysis |
| Reddit: Security Scanner for SKILL.md | [reddit.com/r/ClaudeCode/comments/1rxij75](https://www.reddit.com/r/ClaudeCode/comments/1rxij75/) | Community feedback, scanner limitations, feature requests |
| Sentry: security-review skill | [github.com/getsentry/skills](https://github.com/getsentry/skills) | HIGH/MEDIUM/LOW confidence methodology, data flow analysis |
| Semgrep: AI Best Practices | [github.com/semgrep/ai-best-practices](https://github.com/semgrep/ai-best-practices) | Taint analysis rules for prompt injection in code |
| OpenClaw Documentation | [docs.openclaw.ai/tools/skills](https://docs.openclaw.ai/tools/skills) | OpenClaw skill format, ClawHub registry, security stance |
| Claude Code Skills Documentation | [code.claude.com/docs/en/skills](https://code.claude.com/docs/en/skills) | Claude-specific extensions, frontmatter fields, progressive disclosure |

## Appendix B: Scan Rule ID Registry

| ID | Category | Severity | Pattern |
|----|----------|----------|---------|
| STD001 | standard_compliance | medium | Missing SKILL.md file |
| STD002 | standard_compliance | medium | Invalid YAML frontmatter |
| STD003 | standard_compliance | low | Missing `name` field |
| STD004 | standard_compliance | low | Missing `description` field |
| STD005 | standard_compliance | medium | Non-kebab-case name |
| STD006 | standard_compliance | high | XML angle brackets in frontmatter |
| STD007 | standard_compliance | info | Body exceeds 5,000 words |
| STD008 | standard_compliance | info | README.md inside skill folder |
| STD009 | standard_compliance | medium | Reserved name ("claude", "anthropic") |
| PI001 | prompt_injection | critical | "Ignore previous instructions" pattern |
| PI002 | prompt_injection | critical | Conditional trigger with hidden secondary action |
| PI003 | prompt_injection | high | Role manipulation instruction |
| PI004 | prompt_injection | critical | Unicode/zero-width character injection |
| PI005 | prompt_injection | high | HTML/markdown comment injection |
| PI006 | prompt_injection | medium | Multi-language instruction mixing |
| CA001 | credential_access | critical | Sensitive file path reference (~/.ssh, ~/.env, ~/.aws) |
| CA002 | credential_access | critical | Environment variable with credential-shaped name |
| CA003 | credential_access | high | Private key file pattern |
| CA004 | credential_access | high | Cloud provider credential path |
| NE001 | network_exfiltration | critical | External network request to non-safelist domain |
| NE002 | network_exfiltration | critical | Data posting/exfiltration pattern |
| NE003 | network_exfiltration | high | URL construction with credential parameters |
| NE004 | network_exfiltration | info | Network request to safelist domain |
| DO001 | dangerous_operations | critical | Destructive file operation (rm -rf /, chmod 777) |
| DO002 | dangerous_operations | critical | Privilege escalation (sudo, su) |
| DO003 | dangerous_operations | high | System directory write |
| DO004 | dangerous_operations | high | Process/disk manipulation |
| CI001 | code_injection | critical | Dynamic code execution (eval, exec) |
| CI002 | code_injection | critical | Backdoor/reverse shell pattern |
| CI003 | code_injection | high | Import manipulation |
| CI004 | code_injection | high | Code generation + execution instruction |
| OB001 | obfuscation | high | Base64 encoded content |
| OB002 | obfuscation | high | Character code construction |
| OB003 | obfuscation | medium | String concatenation command building |
| OB004 | obfuscation | high | Hidden attribute access |
| OB005 | obfuscation | critical | Unicode homoglyph/lookalike characters |
| DR001 | dependency_risks | medium | Global package installation |
| DR002 | dependency_risks | medium | Force install flags |
| DR003 | dependency_risks | high | Install from URL (not registry) |
| DR004 | dependency_risks | medium | Post-install script reference |
| BP001 | bundled_payloads | high | Executable file in skill directory |
| BP002 | bundled_payloads | high | Binary file in skill directory |
| BP003 | bundled_payloads | medium | Archive file in skill directory |
| BP004 | bundled_payloads | medium | Unusually large file (> 1MB) |
| BP005 | bundled_payloads | medium | Symlink pointing outside skill directory |
| EL001 | external_links | info | URL referencing safe domain |
| EL002 | external_links | medium | URL referencing unknown domain |
| EL003 | external_links | high | URL referencing suspicious domain |
| EL004 | external_links | medium | Raw IP address reference |
| AI001 | ai_semantic | varies | AI-detected prompt injection (confidence-scored) |
| AI002 | ai_semantic | varies | AI-detected intent mismatch |
| AI003 | ai_semantic | varies | AI-detected data flow risk |
| CP001 | cross_platform | info | Platform detected |
| CP002 | cross_platform | low | AgentSkills spec deviation |
| CP003 | cross_platform | info | Platform-specific feature usage |
