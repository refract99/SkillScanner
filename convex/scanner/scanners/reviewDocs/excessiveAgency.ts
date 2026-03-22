export const CATEGORY_ID = "standard_compliance";

export const REVIEW_DOC = `
## Excessive Agency (OWASP LLM06 / ASI03)

### What to Look For
- **Overly broad tool permissions**: Skills requesting both shell execution (bash, execute, shell, terminal, run) AND file write (write, edit) tools — this combination grants near-complete system access
- **High tool count**: Skills requesting more than 8 tools may be over-privileged. Check if each requested tool is necessary for the skill's stated purpose
- **No tool restrictions**: Skills that don't declare an allowed-tools field at all, leaving the agent with unrestricted tool access
- **Permission bypass instructions**: Instructions to "grant all permissions", "allow all tools", "bypass permission checks", "auto-approve", "run without confirmation"
- **Privilege escalation requests**: Instructions that ask the user to grant more permissions than the skill needs, or that socially engineer the user into relaxing security settings
- **Unrestricted file system access**: Skills that access files far outside their stated scope (e.g., a CSS linter reading /etc/passwd)

### What NOT to Flag
- **Skills that legitimately need broad access**: Development workflow skills, CI/CD skills, and system administration skills may legitimately need shell + file write access. The question is whether the ACCESS matches the PURPOSE
- **Standard tool requests**: Reading files, searching code, running tests — these are normal development operations
- **Single high-risk tool with clear purpose**: A deployment skill requesting bash access to run deploy commands is proportionate

### Agentic Skill Context
- The principle of least privilege applies: skills should request only the tools they need for their stated purpose
- Shell + file write is the most dangerous combination because it allows arbitrary code execution AND persistence
- Skills should declare allowed-tools in their frontmatter to limit the agent's capabilities
- A skill that bypasses the user's permission model is a red flag regardless of its stated purpose

### Confidence Guidance
- **HIGH**: Instructions to bypass permission checks, "auto-approve all", request for shell + write without clear justification in the skill's purpose
- **MEDIUM**: No allowed-tools declaration, shell execution request for a skill that doesn't clearly need it, >8 tools requested
- **LOW**: Appropriate tool requests that match the skill's purpose, standard development tools
`;
