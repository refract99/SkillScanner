export const CATEGORY_ID = "obfuscation";

export const REVIEW_DOC = `
## Obfuscation

### What to Look For
- **Base64 encoding/decoding**: base64.decode, base64.b64decode, atob(), Buffer.from(x, "base64"), base64 -d command, long base64-like strings (100+ chars of [A-Za-z0-9+/=])
- **Character code construction**: String.fromCharCode(), chr() concatenation chains, hex escape sequences (\\x41\\x42\\x43...), unicode escape sequences (\\u0041\\u0042...)
- **Zero-width / invisible Unicode characters**: Zero-width space (U+200B), zero-width non-joiner (U+200C), zero-width joiner (U+200D), word joiner (U+2060), BOM (U+FEFF), soft hyphen (U+00AD), and other invisible format characters
- **Homoglyph attacks**: Cyrillic characters that look identical to Latin (a/\u0430, e/\u0435, o/\u043E, p/\u0440, c/\u0441, etc.) used to disguise identifiers or URLs
- **Dynamic attribute access**: Python getattr(), vars()[], globals()[], locals()[] — used to hide function calls from static analysis
- **String concatenation to build commands**: Breaking malicious commands into parts and concatenating them to avoid pattern matching

### What NOT to Flag
- **Legitimate data URIs**: Base64-encoded images in data:image/ URIs are standard web practice
- **Encoded configuration**: Base64-encoded JSON/YAML in environment variables or config files is common for deployment
- **Internationalized content**: Files that legitimately contain non-Latin scripts (Chinese, Japanese, Korean, Arabic, etc.) should not be flagged for non-ASCII content
- **Standard Unicode usage**: Emoji, typographic quotes, em dashes, and other standard Unicode characters in prose

### Agentic Skill Context
- Obfuscation in a skill file is inherently suspicious — skills are meant to be readable instructions. Why would legitimate instructions need to be encoded?
- Zero-width characters are especially dangerous because they are completely invisible to human review but may be processed by the AI agent
- Homoglyphs can make malicious URLs or function names look identical to safe ones (e.g., a URL using Cyrillic "c" instead of Latin "c")
- Base64 decoding followed by eval/exec is a classic payload delivery technique

### Confidence Guidance
- **HIGH**: Zero-width Unicode characters, Cyrillic homoglyphs mixed with Latin text, base64 decode + eval/exec chains, character code construction of commands
- **MEDIUM**: Base64 decoding without clear benign purpose, dynamic attribute access in non-standard contexts, long base64 strings without data URI prefix
- **LOW**: Data URIs, base64 in configuration context, legitimate internationalization, standard Unicode characters
`;
