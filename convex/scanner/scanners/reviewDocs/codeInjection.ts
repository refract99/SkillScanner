export const CATEGORY_ID = "code_injection";

export const REVIEW_DOC = `
## Code Injection / Remote Code Execution (OWASP ASI05)

### What to Look For
- **Dynamic execution**: eval(), exec(), new Function(), setTimeout/setInterval with string arguments, compile(), execfile()
- **Reverse shells**: bash -i >& /dev/tcp/, nc -e, ncat -e, python -c "import socket", ruby -rsocket -e, perl -e socket, php -r fsockopen, mkfifo /tmp/, /dev/tcp/ references
- **Import manipulation**: Python __import__(), importlib.import_module, dynamic require() with variable argument
- **Code generation + execution**: Instructions like "write a script that", "create and run", "inject into file", "append to .sh/.py/.js"
- **Framework safety bypasses**: dangerouslySetInnerHTML, v-html=, |safe (Django), mark_safe(), {% autoescape off %}, innerHTML=, .raw() (SQL), .extra(), RawSQL(), shell=True (Python subprocess), unescaped ERB (<% - %>)
- **Deserialization attacks**: pickle.load/loads, yaml.load without SafeLoader, unserialize()

### What NOT to Flag
- **Documentation describing code execution**: A security skill explaining "eval() is dangerous because..." is educational, not malicious
- **Framework-safe equivalents**: subprocess.run([...]) with list args (no shell=True), child_process.execFile(), child_process.spawn(), shlex.quote()
- **ORM queries**: Django .objects.filter(), Prisma queries, parameterized queries with %s or $1 placeholders
- **Template variables with auto-escaping**: {{ var }} in Django/Jinja2/Vue (auto-escaped), {var} in JSX (auto-escaped), <%= %> in ERB (escaped)
- **Sanitized output**: DOMPurify.sanitize(), bleach.clean(), html.escape(), escapeHtml/escapeXml utilities
- **Code examples in markdown code blocks**: Commands inside triple backtick blocks are documentation

### Agentic Skill Context
- Reverse shells are ALWAYS malicious in a skill context — there is no legitimate reason for a skill to establish a reverse shell
- eval/exec patterns in skill instructions tell the AI agent to dynamically execute arbitrary code at runtime, which is extremely dangerous
- Framework safety bypasses deserve attention because the skill is instructing the agent to write code that disables protections
- The distinction is: does the skill INSTRUCT the agent to execute dynamic code, or does it WARN about dynamic code?

### Confidence Guidance
- **HIGH**: Reverse shell patterns, eval/exec as actual instructions (not documentation), framework bypass patterns in actual code, pickle.loads with untrusted input
- **MEDIUM**: Dynamic require/import that could be legitimate plugin loading, code generation instructions that have a clear development purpose
- **LOW**: Documentation mentioning code execution risks, framework-safe patterns, ORM queries, sanitized output
`;
