import { IconLink, IconSearch, IconFileCheck } from '@tabler/icons-react'

const steps = [
    {
        icon: IconLink,
        title: 'Paste a URL',
        desc: 'Enter a public GitHub repository URL. SkillScanner auto-detects the AI agent platform.',
    },
    {
        icon: IconSearch,
        title: 'AI-first analysis',
        desc: 'Pre-filter extracts metadata, hard-stop checks catch always-bad patterns, then AI analyzes across 10 threat categories.',
    },
    {
        icon: IconFileCheck,
        title: 'Review the report',
        desc: 'Get a shareable report with a risk score, AI verdict, severity-ranked findings, and confidence indicators.',
    },
]

export default function HowItWorks() {
    return (
        <section className="py-16 md:py-24 border-t border-gray-100 dark:border-border" id="features">
            <div className="mx-auto max-w-4xl px-6">
                <h2 className="text-center text-2xl font-semibold text-gray-900 dark:text-foreground sm:text-3xl">
                    How it works
                </h2>
                <p className="mt-3 text-center text-gray-600 dark:text-muted-foreground">
                    From GitHub URL to security report in under 60 seconds.
                </p>

                <div className="mt-14 grid gap-12 md:grid-cols-3">
                    {steps.map((s, i) => (
                        <div key={i} className="text-center">
                            <div className="mx-auto flex size-12 items-center justify-center rounded-xl bg-emerald-50 dark:bg-emerald-950/30">
                                <s.icon className="size-6 text-emerald-600" />
                            </div>
                            <h3 className="mt-4 font-semibold text-gray-900 dark:text-foreground">{s.title}</h3>
                            <p className="mt-2 text-sm text-gray-600 dark:text-muted-foreground leading-relaxed">{s.desc}</p>
                        </div>
                    ))}
                </div>
            </div>
        </section>
    )
}
