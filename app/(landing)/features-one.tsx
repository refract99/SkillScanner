import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
    IconShare,
    IconClock,
    IconShieldLock,
    IconBrandGithub,
    IconArrowRight,
} from '@tabler/icons-react'

const platforms = [
    { name: 'Claude Code', path: '.claude/skills/' },
    { name: 'OpenClaw', path: 'skills/' },
    { name: 'Cursor', path: '.cursor/rules/' },
    { name: 'Windsurf', path: '.windsurf/rules/' },
    { name: 'Cline', path: '.clinerules/' },
    { name: 'AgentSkills', path: 'SKILL.md' },
]

const steps = [
    {
        step: '1',
        title: 'Paste a GitHub URL',
        desc: 'Submit any public GitHub repository URL containing AI agent skills. SkillScanner auto-detects the platform.',
    },
    {
        step: '2',
        title: 'Automated scanning',
        desc: 'The repository is cloned into a sandbox, scanned across 12 categories, and analyzed by AI. No code is executed.',
    },
    {
        step: '3',
        title: 'Get your report',
        desc: 'View a detailed, shareable report with risk scores, findings by severity, code snippets, and actionable recommendations.',
    },
]

export default function FeaturesOne() {
    return (
        <section className="py-16 md:py-24">
            <div className="mx-auto w-full max-w-5xl px-6">
                {/* How it works */}
                <div className="text-center">
                    <h2 className="text-foreground text-4xl font-semibold">How It Works</h2>
                    <p className="text-muted-foreground mb-12 mt-4 text-balance text-lg">
                        From GitHub URL to security report in under 60 seconds.
                    </p>
                </div>

                <div className="grid gap-8 md:grid-cols-3">
                    {steps.map((s) => (
                        <div key={s.step} className="relative">
                            <div className="bg-primary text-primary-foreground size-10 rounded-full flex items-center justify-center font-bold text-lg mb-4">
                                {s.step}
                            </div>
                            <h3 className="text-foreground text-lg font-semibold">{s.title}</h3>
                            <p className="text-muted-foreground mt-2">{s.desc}</p>
                        </div>
                    ))}
                </div>

                {/* Platform support & key features */}
                <div className="border-foreground/10 relative mt-16 grid gap-12 border-b pb-12 md:grid-cols-2">
                    <div>
                        <h3 className="text-foreground text-xl font-semibold mb-4">Multi-Platform Support</h3>
                        <p className="text-muted-foreground mb-6">
                            SkillScanner auto-detects the target platform based on file paths and frontmatter fields.
                            It validates against the AgentSkills open standard adopted by 26+ platforms.
                        </p>
                        <Card className="p-4">
                            <div className="space-y-3">
                                {platforms.map((p) => (
                                    <div key={p.name} className="flex items-center justify-between text-sm">
                                        <span className="font-medium">{p.name}</span>
                                        <code className="text-muted-foreground text-xs bg-muted px-2 py-0.5 rounded">{p.path}</code>
                                    </div>
                                ))}
                            </div>
                        </Card>
                    </div>
                    <div>
                        <h3 className="text-foreground text-xl font-semibold mb-4">Built for Security</h3>
                        <p className="text-muted-foreground mb-6">
                            Every scan runs in an isolated sandbox with strict security controls.
                        </p>
                        <div className="space-y-4">
                            <Feature
                                icon={<IconShieldLock className="size-5 text-green-600" />}
                                title="Zero execution"
                                desc="No file in the cloned repo is ever executed, imported, or required. Analysis is read-only."
                            />
                            <Feature
                                icon={<IconClock className="size-5 text-blue-600" />}
                                title="Fast results"
                                desc="Deterministic scans complete in 2-5 seconds. AI review adds 5-15 seconds."
                            />
                            <Feature
                                icon={<IconShare className="size-5 text-purple-600" />}
                                title="Shareable reports"
                                desc="Every scan generates a unique URL. Share reports in team chats, PRs, and forum discussions."
                            />
                            <Feature
                                icon={<IconBrandGithub className="size-5" />}
                                title="Open source"
                                desc="Self-hostable. Inspect the scan logic. Contribute new detection rules."
                            />
                        </div>
                    </div>
                </div>

                {/* Risk explanation */}
                <div className="mt-12">
                    <h3 className="text-foreground text-xl font-semibold mb-4">Understanding Risk Scores</h3>
                    <p className="text-muted-foreground text-lg mb-6">
                        SkillScanner assigns a 0-100 risk score based on weighted findings.
                        This is advisory &mdash; you make the final decision.
                    </p>
                    <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                        <RiskBadge label="Safe" range="0" color="bg-green-600" />
                        <RiskBadge label="Low" range="1-10" color="bg-blue-600" />
                        <RiskBadge label="Medium" range="11-30" color="bg-yellow-600" />
                        <RiskBadge label="High" range="31-60" color="bg-orange-600" />
                        <RiskBadge label="Critical" range="61-100" color="bg-red-600" />
                    </div>
                </div>
            </div>
        </section>
    )
}

function Feature({ icon, title, desc }: { icon: React.ReactNode; title: string; desc: string }) {
    return (
        <div className="flex items-start gap-3">
            <div className="shrink-0 mt-0.5">{icon}</div>
            <div>
                <h4 className="font-medium text-sm">{title}</h4>
                <p className="text-muted-foreground text-sm mt-0.5">{desc}</p>
            </div>
        </div>
    )
}

function RiskBadge({ label, range, color }: { label: string; range: string; color: string }) {
    return (
        <div className="rounded-lg border p-3 text-center">
            <div className={`${color} text-white text-xs font-bold px-2 py-0.5 rounded mx-auto w-fit mb-2`}>{label}</div>
            <div className="text-muted-foreground text-xs">{range}</div>
        </div>
    )
}
