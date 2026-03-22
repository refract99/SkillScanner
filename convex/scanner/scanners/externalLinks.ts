import { Finding, ScannerResult, ScanContext, ExternalLink } from "./types";
import { classifyDomain } from "./domainSafelist";

const URL_REGEX = /https?:\/\/[^\s"'<>\])\}]+/g;
const IP_V4_REGEX = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
const IP_V6_REGEX = /\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g;
const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const API_ENDPOINT_REGEX = /\/api\/v?\d*\/[a-zA-Z0-9/_-]+/g;

export async function scan(context: ScanContext): Promise<ScannerResult> {
  const findings: Finding[] = [];
  const links: ExternalLink[] = [];
  const seenUrls = new Set<string>();

  for (const file of context.files) {
    const lines = file.content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // Extract URLs
      URL_REGEX.lastIndex = 0;
      let match;
      while ((match = URL_REGEX.exec(line)) !== null) {
        const urlStr = match[0].replace(/[.,;:!?)]+$/, "");
        if (seenUrls.has(urlStr)) continue;
        seenUrls.add(urlStr);

        try {
          const urlObj = new URL(urlStr);
          const domain = urlObj.hostname;
          const classification = classifyDomain(domain);

          links.push({
            url: urlStr,
            domain,
            filePath: file.relativePath,
            lineNumber: lineNum,
            classification,
            context: line.substring(0, 200),
          });

          const ruleId = classification === "safe" ? "EL001"
            : classification === "suspicious" ? "EL003"
            : "EL002";
          const severity = classification === "safe" ? "info"
            : classification === "suspicious" ? "high"
            : "medium";

          findings.push({
            category: "external_links",
            ruleId,
            severity: severity as Finding["severity"],
            confidence: "high",
            title: `External URL: ${domain}`,
            description: `Found URL to ${classification} domain "${domain}": ${urlStr}`,
            filePath: file.relativePath,
            lineNumber: lineNum,
            matchedPattern: urlStr,
          });
        } catch {
          // Invalid URL
        }
      }

      // IPv4 addresses
      IP_V4_REGEX.lastIndex = 0;
      while ((match = IP_V4_REGEX.exec(line)) !== null) {
        // Skip common non-address patterns
        if (match[1].startsWith("0.") || match[1] === "127.0.0.1" || match[1] === "0.0.0.0") continue;
        findings.push({
          category: "external_links",
          ruleId: "EL004",
          severity: "medium",
          confidence: "medium",
          title: `IP address reference: ${match[1]}`,
          description: `Found raw IPv4 address "${match[1]}". Direct IP usage may indicate suspicious communication.`,
          filePath: file.relativePath,
          lineNumber: lineNum,
          matchedPattern: match[1],
        });
      }

      // IPv6 addresses
      IP_V6_REGEX.lastIndex = 0;
      while ((match = IP_V6_REGEX.exec(line)) !== null) {
        findings.push({
          category: "external_links",
          ruleId: "EL004",
          severity: "medium",
          confidence: "medium",
          title: `IPv6 address reference: ${match[0].substring(0, 30)}`,
          description: `Found raw IPv6 address. Direct IP usage may indicate suspicious communication.`,
          filePath: file.relativePath,
          lineNumber: lineNum,
          matchedPattern: match[0],
        });
      }
    }
  }

  return { findings, links };
}
