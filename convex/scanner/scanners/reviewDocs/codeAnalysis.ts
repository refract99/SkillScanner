export const CATEGORY_ID = "code_injection";

export const REVIEW_DOC = `
## Bundled Code Analysis

Skills may bundle script files (.sh, .py, .js, .ts, .rb, .pl, etc.) alongside their SKILL.md. These scripts run with the agent's full permissions. Review them with extra scrutiny.

### What to Look For in Scripts

**Payload delivery patterns:**
- \`eval(atob(...))\` or \`eval(Buffer.from(..., 'base64'))\` — base64-decode-then-execute is a classic payload technique
- String concatenation to build commands: \`cmd = "r" + "m" + " " + "-rf"\`
- \`String.fromCharCode()\` chains building executable strings
- Hex/octal escape sequences building commands: \`\\x72\\x6d\` = "rm"

**Suspicious network activity in scripts:**
- Hardcoded IP addresses in fetch/curl/requests calls (not documentation)
- URLs pointing to raw pastebin/gist content that gets executed
- Download-and-execute patterns: \`curl URL | sh\`, \`wget -O- URL | python\`
- Websocket connections to non-standard ports

**Hidden functionality:**
- Code after \`exit\` / \`return\` / \`sys.exit()\` — unreachable code that might be activated by modifying the early return
- Conditional execution based on environment detection: \`if os.getenv("CI")\` or \`if process.env.NODE_ENV === "production"\` running different code paths
- Time-delayed execution: \`setTimeout\` / \`sleep\` before dangerous operations
- Commented-out dangerous code that could be un-commented by the agent

**Credential harvesting in scripts:**
- Reading credential files and writing them to /tmp or other staging locations
- Environment variable dumping: \`env\`, \`printenv\`, \`set\`, \`os.environ\` iteration
- Grep/find commands searching for key files: \`find ~ -name "*.pem"\`, \`grep -r API_KEY\`

**Suspicious shebangs and interpreters:**
- \`#!/usr/bin/env python -c\` or other unusual interpreter flags
- Shebangs pointing to non-standard interpreters
- Scripts with no shebang that expect specific interpreter context

**Obfuscation in code:**
- Minified/packed code in a skill context (why would a skill bundle minified code?)
- Variable names that are clearly obfuscated: single letters, random strings
- Heavy use of \`eval\`, \`exec\`, \`__import__\`, \`getattr\` for indirection

### What NOT to Flag in Scripts
- Standard build/test scripts (run tests, lint, format, build)
- Package manager lock files or config (package.json scripts section is normal)
- Well-structured utility scripts with clear purpose matching the skill's stated function
- Scripts that only read/write within the project directory
- Standard shebang lines: \`#!/bin/bash\`, \`#!/usr/bin/env python3\`

### Confidence Guidance
- **HIGH**: eval(atob(...)), download-and-execute, credential harvesting + exfil, reverse shells in scripts
- **MEDIUM**: Hardcoded IPs without clear purpose, minified code, environment-conditional behavior, code after exit
- **LOW**: Standard build scripts, project-scoped file operations, normal interpreter usage
`;
