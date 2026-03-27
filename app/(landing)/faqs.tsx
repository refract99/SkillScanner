const faqs = [
    {
        q: 'What is an AI agent skill?',
        a: 'Skills are instruction files (like SKILL.md or .mdc rules) that extend AI coding agents such as Claude Code, Cursor, Windsurf, and Cline. They can access your filesystem, shell, environment variables, and API keys.',
    },
    {
        q: 'Does SkillScanner execute any code?',
        a: 'No. All analysis is strictly read-only. The repository is downloaded into an isolated temp directory, scanned as text, and immediately deleted.',
    },
    {
        q: 'How does the AI review work?',
        a: 'SkillScanner uses an AI-first architecture. The skill files are sent directly to an LLM along with structured review documents covering 10 threat categories. The AI performs semantic analysis — understanding context, data flow, and intent — rather than just matching patterns. Deterministic hard-stop checks run separately to catch always-bad patterns like reverse shells and zero-width characters.',
    },
    {
        q: 'What happens if the AI is unavailable?',
        a: 'If the AI analysis fails, only hard-stop findings are shown. For legitimate skills this means zero findings instead of a wall of false positives. The report will note that AI analysis was not completed.',
    },
    {
        q: 'Do I need an account?',
        a: 'Yes. A free account is required to use SkillScanner. Sign up in seconds to start scanning skills and access your scan history dashboard.',
    },
    {
        q: 'What platforms are supported?',
        a: 'Claude Code, Cursor, Windsurf, Cline, OpenClaw, and any platform following the AgentSkills open standard. The platform is auto-detected from file paths and frontmatter.',
    },
    {
        q: 'Can I scan private repositories?',
        a: 'Not yet. Only public GitHub repositories are supported. Private repo scanning via GitHub OAuth is planned.',
    },
]

export default function FAQs() {
    return (
        <section className="py-16 md:py-24 border-t border-gray-100 dark:border-border" id="faq">
            <div className="mx-auto max-w-3xl px-6">
                <h2 className="text-center text-2xl font-semibold text-gray-900 dark:text-foreground sm:text-3xl">
                    Frequently asked questions
                </h2>

                <div className="mt-12 divide-y divide-gray-100 dark:divide-border">
                    {faqs.map((faq, i) => (
                        <div key={i} className="py-6">
                            <h3 className="font-medium text-gray-900 dark:text-foreground">{faq.q}</h3>
                            <p className="mt-2 text-sm text-gray-600 dark:text-muted-foreground leading-relaxed">{faq.a}</p>
                        </div>
                    ))}
                </div>
            </div>
        </section>
    )
}
