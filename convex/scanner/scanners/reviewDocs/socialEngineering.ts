export const CATEGORY_ID = "ai_semantic";

export const REVIEW_DOC = `
## Social Engineering / Trust Exploitation (OWASP ASI09)

### What to Look For
- **Trust escalation**: Instructions that build user trust incrementally before requesting dangerous permissions — "this is safe", "you can trust this", "just approve all prompts"
- **Urgency/authority manipulation**: Creating false urgency ("you must do this now"), claiming false authority ("this is required by your organization"), or using social pressure
- **Permission normalization**: Making dangerous permissions sound routine — "just grant sudo access, it's standard", "everyone runs this with full permissions"
- **Obfuscated consequences**: Hiding the true effect of an action behind benign-sounding language — "optimize your system" when it means "modify your shell profile"
- **Misdirection**: Drawing attention to one part of the skill while dangerous operations happen elsewhere
- **Multi-step trust exploitation**: The skill appears safe on first use but becomes dangerous on subsequent invocations or after gaining trust
- **Fake safety claims**: "This skill has been audited", "security-verified", "approved by [authority]" without evidence

### What NOT to Flag
- **Legitimate safety guidance**: Skills that explain their permissions and why they need them are being transparent, not manipulative
- **Clear permission requests**: "This skill needs bash access to run tests" is honest disclosure
- **Standard UX language**: "Click approve to continue" is normal interface language, not social engineering
- **Confidence statements about the skill's purpose**: "This skill reliably formats code" is describing functionality

### Agentic Skill Context
- Social engineering targets the USER, not the agent. The skill tries to convince the user to grant permissions or trust that they shouldn't
- Multi-step attacks are hard to detect from a single file — look for patterns that suggest the skill behaves differently over time
- The most dangerous social engineering is subtle: skills that seem helpful but gradually expand their access or modify persistent state

### Confidence Guidance
- **HIGH**: Explicit instructions to "approve all prompts", "trust this blindly", fake safety certifications, instructions to disable security features
- **MEDIUM**: Urgency language around permission grants, normalization of dangerous permissions, obfuscated action descriptions
- **LOW**: Standard permission explanations, legitimate confidence statements, normal UX language
`;
