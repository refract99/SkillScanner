# Refactor: AI-First Scanning Pipeline

## Context

The current scanner runs 11 deterministic regex scanners that produce hundreds of findings (mostly false positives), then asks an AI to review and dismiss them. When AI parsing fails (as with scan `bRZKymFJ`), users see 350 false positives at "critical" risk for a perfectly safe skill. The architecture is backwards — the AI is doing janitorial work cleaning up after noisy pattern matchers.

**Goal:** Flip to an AI-first architecture modeled on [Sentry's security-review skill](https://github.com/getsentry/skills/blob/main/plugins/sentry-skills/skills/security-review/SKILL.md), with modular review documents per category and a small set of non-dismissable deterministic hard-stops.

```
CURRENT:  Files → 11 regex scanners → ~350 findings → AI dismisses false positives → score
NEW:      Files → Pre-filter (metadata) → AI-first analysis → Hard-stop overlay → score
```

---

## Phase 1: Create Review Documents

Create `convex/scanner/scanners/reviewDocs/` with TypeScript string constants (Convex actions can't read filesystem, so markdown must be inlined as TS exports).

**New files:**

| File | Category | Covers |
|------|----------|--------|
| `reviewDocs/promptInjection.ts` | prompt_injection | Hidden instructions, conditional triggers, role manipulation, scope escalation, system prompt leakage |
| `reviewDocs/credentialAccess.ts` | credential_access | Reading/exfiltrating keys, tokens, secrets; sensitive file paths; config vs theft distinction |
| `reviewDocs/dataExfiltration.ts` | network_exfiltration | Sending data to external servers; curl/wget POST; DNS exfil; legitimate API calls vs theft |
| `reviewDocs/codeInjection.ts` | code_injection | eval/exec, reverse shells, framework safety bypass; documentation vs execution |
| `reviewDocs/dangerousOperations.ts` | dangerous_operations | Destructive commands, privilege escalation, system directory writes |
| `reviewDocs/obfuscation.ts` | obfuscation | Base64, char code construction, zero-width chars, homoglyphs |
| `reviewDocs/memoryPoisoning.ts` | prompt_injection | Writing to .claude/memory, CLAUDE.md, .cursor/rules, shell profiles |
| `reviewDocs/excessiveAgency.ts` | standard_compliance | Requesting more tools/permissions than needed, bypassing permission checks |
| `reviewDocs/supplyChain.ts` | dependency_risks | Installing from URLs, force-install flags, post-install scripts |
| `reviewDocs/socialEngineering.ts` | ai_semantic | Tricking users into granting permissions, multi-step trust exploitation |
| `reviewDocs/index.ts` | — | Barrel file: exports `ALL_REVIEW_DOCS` array + `getReviewDocsPrompt()` |

Each review doc module exports:
```typescript
export const CATEGORY_ID = "prompt_injection";
export const REVIEW_DOC = `
## Prompt Injection / Goal Hijack (OWASP LLM01 / ASI01)

### What to Look For
- ...patterns with examples...

### What NOT to Flag
- ...false positive guidance...

### Agentic Skill Context
- ...skill-specific nuance...

### Confidence Guidance
- HIGH: ...
- MEDIUM: ...
- LOW: ...
`;
```

**Verification:** `npm run tsc --noEmit` passes

---

## Phase 2: Create Pre-Filter and Hard-Stops

### 2a: Pre-filter (`convex/scanner/scanners/preFilter.ts`)

Extracts factual metadata only — no security judgments. Reuses existing modules:

- `crossPlatform.scan()` — platform detection (unchanged)
- `externalLinks.scan()` — link extraction (keep links array, drop findings)
- File manifest — name, size, extension, isSymlink, isBinary for each file
- `standardCompliance.scan()` — SKILL.md/frontmatter validation (reclassify as INFO, except STD006 → hard-stop)

```typescript
export interface PreFilterResult {
  platform: Platform;
  links: ExternalLink[];
  fileManifest: { path: string; size: number; ext: string; isSymlink: boolean; isBinary: boolean }[];
  complianceFindings: Finding[];  // INFO-level only
  platformFindings: Finding[];    // INFO-level only
}
```

### 2b: Hard-stops (`convex/scanner/scanners/hardStops.ts`)

Non-dismissable deterministic rules. Extracted and **tightened** from existing scanners:

| Rule | Source | Pattern (tightened) |
|------|--------|---------------------|
| BP001 | bundledPayloads | Executable files (.exe, .sh, .bat) outside scripts/ dir |
| BP002 | bundledPayloads | Binary/compiled files (.so, .dll, .pyc, .wasm) |
| CI002 | codeInjection | Reverse shell patterns (bash -i, nc -e, /dev/tcp/, python -c socket) |
| CI005 | codeInjection | Framework safety bypass (dangerouslySetInnerHTML, mark_safe, shell=True, .raw()) |
| DR003 | dependencyRisks | Install from URL (pip install https://, npm install git+) |
| NE002 | networkExfiltration | Data exfil (curl -d @file, netcat listener, .post(env), .send(env)) |
| OB005 | obfuscation | Zero-width Unicode chars, Cyrillic homoglyphs |
| PI001 | promptInjection | Full-phrase: "ignore previous instructions", "[INST]", "<<SYS>>" |
| PI002 | promptInjection | Conditional triggers: "secretly", "without user knowing", "when asked X also do Y" |
| PI007 | promptInjection | Memory poisoning: write/modify/append + (.claude/memory, CLAUDE.md, .bashrc, .cursor/rules) — require verb+target, not just target mention |
| PI008 | promptInjection | System prompt leakage: "print system prompt", "reveal instructions", "send prompt to" |
| STD006 | standardCompliance | XML angle brackets in YAML frontmatter |

Key tightening vs current scanners:
- PI001: Full phrases only, not individual words like "ignore"
- PI007: Require write-action verb + target path, not bare "CLAUDE.md" mention
- NE002: Require data-sending pattern, not just any curl/wget usage

```typescript
export interface HardStopResult {
  findings: Finding[];  // All marked with confidence: "high"
}
```

**Verification:** Unit test hard-stops against known-safe skills (expect 0 findings) and known-malicious patterns (expect matches)

---

## Phase 3: Create AI-First Review Module

**New file:** `convex/scanner/scanners/aiFirstReview.ts`

Replaces `aiSemanticReview.ts`. The AI receives raw files + pre-filter context + review docs — NOT pre-digested deterministic findings.

### Prompt structure:

```
SYSTEM:
  <METHODOLOGY>
    - Sentry-style: research before report, HIGH confidence only
    - Trace data flow: where does input come from? Where does output go?
    - Attacker-controlled vs server-controlled input distinction
    - Skills ARE system prompts — hidden instructions = prompt injection
    - Confidence: HIGH = flag, MEDIUM = note for review, LOW = don't report
  </METHODOLOGY>

  <REVIEW_CATEGORIES>
    {getReviewDocsPrompt()}  // All 10 category docs concatenated
  </REVIEW_CATEGORIES>

  <FRAMEWORK_CONTEXT>
    {Summary of frameworkContext.ts safe patterns}
    {Summary of domainSafelist.ts}
  </FRAMEWORK_CONTEXT>

USER:
  <SKILL_FILES>
    {SKILL.md truncated to 50KB}
    {Up to 5 script files at 10KB each}
  </SKILL_FILES>

  <PRE_FILTER_CONTEXT>
    Platform: {detected}
    Files: {count} ({manifest summary})
    Binary files: {list or "none"}
    Symlinks: {list or "none"}
    External domains: {classified list}
    Compliance: {notes}
  </PRE_FILTER_CONTEXT>
```

### Response format:
```json
{
  "findings": [{ "severity", "confidence", "title", "description", "filePath", "lineNumber" }],
  "summary": "narrative analysis",
  "verdict": "SAFE TO USE | USE WITH CAUTION | DO NOT USE",
  "riskScore": 0-100,
  "verdictReason": "1-2 sentence explanation"
}
```

Changes from current `aiSemanticReview.ts`:
- No `dismissedFindings` — AI is primary analyzer, not a reviewer of regex output
- No `adjustedRiskScore` — AI's `riskScore` IS the score
- Review docs injected as structured reference material
- Pre-filter metadata replaces deterministic findings context
- Increase `max_tokens` from 4000 to 8000 (more room for analysis)
- Store full `aiSummary` without 1000-char truncation

### Return type:
```typescript
export interface AiFirstResult {
  findings: Finding[];      // category = "ai_semantic", ruleId = "AI0xx"
  aiSummary: string;
  verdict: "SAFE TO USE" | "USE WITH CAUTION" | "DO NOT USE";
  riskScore: number;        // 0-100
  verdictReason: string;
}
```

---

## Phase 4: Rewire the Pipeline

### Modify: `convex/scanner/scanners/index.ts`

- Keep `calculateRiskScore()`, `riskLevel()`, `generateSummary()` — still used
- Replace `runAllDeterministicScanners()` internals or add new `runPreFilter()` + `runHardStops()` exports
- Stop importing the 9 deprecated scanner modules (promptInjection, credentialAccess, networkExfiltration, dangerousOperations, codeInjection, obfuscation, dependencyRisks, bundledPayloads, standardCompliance)

### Modify: `convex/scanner/pipeline.ts` — rewrite `runScanPipeline()`

New flow:
```typescript
async function runScanPipeline(scanRoot, rootDir, llmConfig) {
  const files = collectFiles(scanRoot, rootDir);
  const context = { rootDir: scanRoot, files };

  // Stage 1: Pre-filter (fast, factual)
  const preFilter = await runPreFilter(context);

  // Stage 2: Hard-stops (deterministic, non-dismissable)
  const hardStops = await runHardStopChecks(context);

  // Stage 3: AI-first analysis
  let aiResult: AiFirstResult | null = null;
  if (llmConfig.apiKey) {
    try {
      aiResult = await aiFirstReview(context, llmConfig, preFilter);
    } catch { /* aiResult stays null */ }
  }

  // Combine findings
  const allFindings = [
    ...hardStops.findings,                    // non-dismissable
    ...(aiResult?.findings ?? []),             // AI findings
    ...preFilter.complianceFindings,           // INFO-level
    ...preFilter.platformFindings,             // INFO-level
  ];

  // Scoring
  let riskScore, verdict, verdictReason, aiSummary;
  if (aiResult) {
    // AI score + hard-stop boost (each hard-stop adds to score)
    riskScore = Math.min(100, aiResult.riskScore + hardStopBoost(hardStops));
    verdict = hardStops.findings.length > 0 ? escalateVerdict(aiResult.verdict) : aiResult.verdict;
    verdictReason = aiResult.verdictReason;
    aiSummary = aiResult.aiSummary;
  } else {
    // AI unavailable: score from hard-stops only (0 for legitimate skills)
    riskScore = calculateRiskScore(hardStops.findings);
    verdict = hardStops.findings.length > 0 ? "USE WITH CAUTION" : "SAFE TO USE";
    verdictReason = "AI analysis unavailable. Only deterministic hard-stop checks applied.";
    aiSummary = "AI analysis was not completed.";
  }

  return { findings: allFindings, links: preFilter.links, platform: preFilter.platform,
           riskScore, risk: riskLevel(riskScore), summary: generateSummary(...),
           aiSummary, verdict, verdictReason, fileCount: files.length,
           rawRiskScore: riskScore, adjustedRiskScore: undefined };
}
```

**Key behavioral change:** AI failure → 0 hard-stop findings for legitimate skills (not 350 false positives).

### No changes needed:
- `convex/scanner/store.ts` — same data shapes
- `convex/scanner/collectionPipeline.ts` — imports `runScanPipeline()` with same signature/return type
- `convex/schema.ts` — all fields preserved, `adjustedRiskScore` already optional
- All frontend components — field contracts unchanged

---

## Phase 5: Cleanup

- Move deprecated scanners to `convex/scanner/scanners/_deprecated/` (or delete — they're in git history)
- Rename `aiSemanticReview.ts` → `_deprecated/aiSemanticReview.ts`
- Remove unused imports from `index.ts`

---

## Verification Plan

1. **Type check:** `npm run tsc --noEmit` + `npx convex dev --once --typecheck=enable 2>&1 | tail -20`
2. **Test known-safe skill:** Re-scan `getsentry/skills/.../security-review` — should get ~0 findings, "SAFE TO USE"
3. **Test known-malicious patterns:** Create a test skill with actual reverse shells, memory poisoning — should get hard-stop findings
4. **Test AI failure:** Temporarily break API key — should show only hard-stop results, not false positives
5. **Test collection scan:** Scan a multi-skill repo — verify `collectionPipeline.ts` still works
6. **UI verification:** Load scan results page — all fields render correctly, no console errors

---

## Files Summary

| Action | File |
|--------|------|
| **Create** | `convex/scanner/scanners/reviewDocs/index.ts` |
| **Create** | `convex/scanner/scanners/reviewDocs/promptInjection.ts` |
| **Create** | `convex/scanner/scanners/reviewDocs/credentialAccess.ts` |
| **Create** | `convex/scanner/scanners/reviewDocs/dataExfiltration.ts` |
| **Create** | `convex/scanner/scanners/reviewDocs/codeInjection.ts` |
| **Create** | `convex/scanner/scanners/reviewDocs/dangerousOperations.ts` |
| **Create** | `convex/scanner/scanners/reviewDocs/obfuscation.ts` |
| **Create** | `convex/scanner/scanners/reviewDocs/memoryPoisoning.ts` |
| **Create** | `convex/scanner/scanners/reviewDocs/excessiveAgency.ts` |
| **Create** | `convex/scanner/scanners/reviewDocs/supplyChain.ts` |
| **Create** | `convex/scanner/scanners/reviewDocs/socialEngineering.ts` |
| **Create** | `convex/scanner/scanners/preFilter.ts` |
| **Create** | `convex/scanner/scanners/hardStops.ts` |
| **Create** | `convex/scanner/scanners/aiFirstReview.ts` |
| **Modify** | `convex/scanner/pipeline.ts` |
| **Modify** | `convex/scanner/scanners/index.ts` |
| **Deprecate** | `convex/scanner/scanners/aiSemanticReview.ts` |
| **Deprecate** | `convex/scanner/scanners/promptInjection.ts` |
| **Deprecate** | `convex/scanner/scanners/credentialAccess.ts` |
| **Deprecate** | `convex/scanner/scanners/networkExfiltration.ts` |
| **Deprecate** | `convex/scanner/scanners/dangerousOperations.ts` |
| **Deprecate** | `convex/scanner/scanners/codeInjection.ts` |
| **Deprecate** | `convex/scanner/scanners/obfuscation.ts` |
| **Deprecate** | `convex/scanner/scanners/dependencyRisks.ts` |
| **Deprecate** | `convex/scanner/scanners/bundledPayloads.ts` |
| **Deprecate** | `convex/scanner/scanners/standardCompliance.ts` |
| **Keep** | `convex/scanner/scanners/types.ts` |
| **Keep** | `convex/scanner/scanners/domainSafelist.ts` |
| **Keep** | `convex/scanner/scanners/frameworkContext.ts` |
| **Keep** | `convex/scanner/scanners/crossPlatform.ts` |
| **Keep** | `convex/scanner/scanners/externalLinks.ts` |
| **Keep** | `convex/scanner/store.ts` |
| **Keep** | `convex/scanner/collectionPipeline.ts` |
| **Keep** | `convex/schema.ts` |
