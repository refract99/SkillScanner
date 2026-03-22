/** Known-safe domains that are expected in skills */
export const SAFE_DOMAINS = new Set([
  "anthropic.com",
  "github.com",
  "pypi.org",
  "npmjs.com",
  "registry.npmjs.org",
  "stackoverflow.com",
  "developer.mozilla.org",
  "docs.python.org",
  "nodejs.org",
  "typescriptlang.org",
  "reactjs.org",
  "react.dev",
  "nextjs.org",
  "vercel.com",
  "wikipedia.org",
  "en.wikipedia.org",
  "code.visualstudio.com",
  "marketplace.visualstudio.com",
  "docs.github.com",
  "raw.githubusercontent.com",
  "gitlab.com",
  "bitbucket.org",
  "crates.io",
  "rubygems.org",
  "packagist.org",
  "mvnrepository.com",
  "docs.rs",
  "pkg.go.dev",
  "hex.pm",
  "agentskills.io",
  "claude.ai",
  "code.claude.com",
  "docs.openclaw.ai",
]);

/** Suspicious TLDs and hosting patterns */
export const SUSPICIOUS_TLDS = new Set([
  ".tk",
  ".ml",
  ".ga",
  ".cf",
  ".gq",
  ".buzz",
  ".top",
  ".xyz",
  ".icu",
  ".cam",
]);

/** URL shortener domains */
export const URL_SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "adf.ly",
  "shorte.st",
  "cutt.ly",
  "rebrand.ly",
]);

export function classifyDomain(
  domain: string
): "safe" | "unknown" | "suspicious" {
  const lowerDomain = domain.toLowerCase();

  // Check safe domains (exact or subdomain match)
  for (const safe of SAFE_DOMAINS) {
    if (lowerDomain === safe || lowerDomain.endsWith("." + safe)) {
      return "safe";
    }
  }

  // Check URL shorteners
  if (URL_SHORTENERS.has(lowerDomain)) return "suspicious";

  // Check suspicious TLDs
  for (const tld of SUSPICIOUS_TLDS) {
    if (lowerDomain.endsWith(tld)) return "suspicious";
  }

  // IP addresses are suspicious
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(lowerDomain)) {
    return "suspicious";
  }

  return "unknown";
}
