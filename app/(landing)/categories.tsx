import {
    IconShieldCheck,
    IconLock,
    IconWorld,
    IconCode,
    IconAlertTriangle,
    IconEyeOff,
    IconBrain,
    IconUsers,
    IconPackage,
    IconRobot,
    IconShieldLock,
} from '@tabler/icons-react'

const aiCategories = [
    { icon: IconShieldCheck, name: 'Prompt Injection', desc: 'Hidden instructions, conditional triggers, role manipulation' },
    { icon: IconLock, name: 'Credential Access', desc: 'Keys, tokens, secrets, and credential exfiltration chains' },
    { icon: IconWorld, name: 'Data Exfiltration', desc: 'Outbound data transfer, DNS exfil, covert channels' },
    { icon: IconCode, name: 'Code Injection', desc: 'eval/exec, reverse shells, framework safety bypasses' },
    { icon: IconAlertTriangle, name: 'Dangerous Operations', desc: 'Destructive commands, privilege escalation, unsafe chaining' },
    { icon: IconEyeOff, name: 'Obfuscation', desc: 'Base64, character codes, zero-width Unicode, homoglyphs' },
    { icon: IconBrain, name: 'Memory Poisoning', desc: 'Writes to CLAUDE.md, .cursor/rules, shell profiles' },
    { icon: IconShieldLock, name: 'Excessive Agency', desc: 'Over-privileged tool requests, permission bypass' },
    { icon: IconPackage, name: 'Supply Chain', desc: 'Install from URL, force flags, post-install scripts' },
    { icon: IconUsers, name: 'Social Engineering', desc: 'Trust exploitation, fake safety claims, misdirection' },
]

export default function Categories() {
    return (
        <section className="py-16 md:py-24 bg-gray-50 dark:bg-muted/30">
            <div className="mx-auto max-w-5xl px-6">
                <h2 className="text-center text-2xl font-semibold text-gray-900 dark:text-foreground sm:text-3xl">
                    AI-first analysis across 10 threat categories
                </h2>
                <p className="mt-3 text-center text-gray-600 dark:text-muted-foreground max-w-2xl mx-auto">
                    An LLM reviews every skill using structured review documents per category &mdash; catching context-dependent threats that pattern matching misses. Deterministic hard-stop checks catch always-bad patterns like reverse shells and zero-width characters.
                </p>

                <div className="mt-12 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                    {aiCategories.map((cat) => (
                        <div key={cat.name} className="flex items-start gap-3 rounded-lg bg-white dark:bg-background border border-gray-100 dark:border-border p-4">
                            <cat.icon className="size-5 text-emerald-600 shrink-0 mt-0.5" />
                            <div>
                                <p className="text-sm font-medium text-gray-900 dark:text-foreground">{cat.name}</p>
                                <p className="text-sm text-gray-500 dark:text-muted-foreground mt-0.5">{cat.desc}</p>
                            </div>
                        </div>
                    ))}
                </div>

                <div className="mt-8 text-center">
                    <div className="inline-flex items-center gap-2 text-sm text-gray-500 dark:text-muted-foreground bg-white dark:bg-background border border-gray-100 dark:border-border rounded-full px-4 py-2">
                        <IconRobot className="size-4 text-emerald-600" />
                        <span>Plus platform detection, link classification, and AgentSkills compliance checks</span>
                    </div>
                </div>
            </div>
        </section>
    )
}
