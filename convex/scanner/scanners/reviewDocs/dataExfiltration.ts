export const CATEGORY_ID = "network_exfiltration";

export const REVIEW_DOC = `
## Data Exfiltration (OWASP ASI06)

### What to Look For
- **Outbound data transfer**: curl -d @file, curl --data, curl -X POST with sensitive data, wget --post-data, netcat listeners (nc -l), ncat
- **Programmatic exfiltration**: .send(env), .post(env), fetch() POST with credential/file data, requests.post() with sensitive content
- **DNS exfiltration**: Encoding data into DNS subdomain queries — patterns like \${data}.attacker.com, dig/nslookup/host commands with variable subdomains
- **Network requests to unknown domains**: curl, wget, fetch(), requests.get/post, urllib, httpx, axios, XMLHttpRequest, WebSocket connections to external servers
- **Data staging**: Instructions to write sensitive data to /tmp or other staging locations before sending
- **Covert channels**: Using DNS, ICMP, or other non-HTTP protocols to exfiltrate data

### What NOT to Flag
- **Requests to known-safe domains**: github.com, npmjs.com, pypi.org, docs.python.org, and other documentation/registry domains. These are legitimate API calls or documentation references
- **Same-origin API calls**: fetch("/api/..."), axios.get("/api/...") — relative paths stay on the same server
- **Configuration-based URLs**: fetch(\`\${BASE_URL}/...\`) where BASE_URL comes from server config
- **Documentation of network commands**: A skill that says "use curl -I to inspect headers" is documenting a debugging technique, not exfiltrating data
- **Commands in markdown code blocks**: Commands inside triple backtick blocks are documentation examples
- **Download-only patterns**: curl/wget used to download public resources (documentation, packages) with no data being sent out

### Agentic Skill Context
- The key distinction is DATA DIRECTION: downloading public resources is different from uploading local data
- Watch for two-step patterns: first read sensitive files, then send their contents somewhere
- Skills that need to make API calls (e.g., a deployment skill calling a cloud API) should be using the user's configured endpoints, not hardcoded external URLs
- A skill that sends data to a specific hardcoded URL (especially non-standard ports or IP addresses) is highly suspicious

### Confidence Guidance
- **HIGH**: curl -d @file, sending environment variables or credential data to external URLs, netcat listeners, DNS exfil with variable subdomains
- **MEDIUM**: Network requests to unknown (but not suspicious) domains, POST requests where the data source isn't clearly sensitive
- **LOW**: Requests to safe domains, same-origin API calls, commands in documentation code blocks, download-only patterns
`;
