export const CATEGORY_ID = "dangerous_operations";

export const REVIEW_DOC = `
## Dangerous Operations / Tool Misuse (OWASP ASI02)

### What to Look For
- **Destructive commands**: rm -rf from root/home/current directory, dd of=/, mkfs, fdisk, fork bombs
- **Privilege escalation**: sudo, su, doas — skills should not require elevated privileges
- **System directory writes**: Writing to /etc/, /usr/, /bin/, /sbin/, /var/, /opt/ via redirect (>), tee, cp, or mv
- **Process manipulation**: kill -9, killall, pkill -9, crontab manipulation, systemctl start/stop/enable/disable
- **Permission changes**: chmod 777, chmod -R 777, recursive chown
- **Unsafe tool chaining**: Piping untrusted output into shell execution (curl | sh, wget -O- | bash), tool chaining that creates unintended side effects

### What NOT to Flag
- **Commands in documentation context**: A skill explaining "never run rm -rf /" or showing destructive commands as anti-patterns is documenting what NOT to do
- **Commands in markdown code blocks** (triple backticks): These are examples, not execution instructions
- **Development workflow commands**: git commands, npm/pip/cargo install for project dependencies, running tests, building projects
- **Sandboxed operations**: Commands that operate within the project directory with appropriate scope (rm -rf node_modules, cleaning build artifacts)
- **Process management for development**: Starting/stopping dev servers, database instances for local development

### Agentic Skill Context
- The critical question is: does the skill INSTRUCT the agent to run these commands, or does it DOCUMENT them as examples/warnings?
- A deployment skill legitimately needs some system operations — the question is proportionality. Does the scope match the skill's declared purpose?
- Skills that chain tools (read file -> modify -> execute) can create attack sequences that are hard to spot in isolation
- Fork bombs and filesystem format commands have NO legitimate use in skills

### Confidence Guidance
- **HIGH**: Fork bombs, dd writes to disk, mkfs, chmod 777 as actual instructions (not warnings), rm -rf with root/home path as instructions
- **MEDIUM**: sudo/su usage that matches the skill's purpose (e.g., a system administration skill), system directory writes for legitimate deployment
- **LOW**: Commands in markdown code blocks, documentation of anti-patterns, development workflow commands, sandboxed cleanup operations
`;
