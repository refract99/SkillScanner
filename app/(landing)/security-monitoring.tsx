import { Badge } from '@/components/ui/badge'
import {
    IconShieldCheck,
    IconBrain,
    IconWorld,
    IconFileSearch,
    IconLock,
    IconCode,
    IconEyeOff,
    IconPackage,
    IconBug,
    IconLink,
    IconRobot,
    IconDeviceDesktop,
} from '@tabler/icons-react'

const categories = [
    { icon: IconFileSearch, name: 'Standard Compliance', desc: 'AgentSkills spec validation' },
    { icon: IconShieldCheck, name: 'Prompt Injection', desc: 'Adversarial instruction detection' },
    { icon: IconLock, name: 'Credential Access', desc: 'SSH keys, env vars, API tokens' },
    { icon: IconWorld, name: 'Network Exfiltration', desc: 'Data theft and C2 patterns' },
    { icon: IconBug, name: 'Dangerous Operations', desc: 'rm -rf, sudo, privilege escalation' },
    { icon: IconCode, name: 'Code Injection', desc: 'eval(), backdoors, reverse shells' },
    { icon: IconEyeOff, name: 'Obfuscation', desc: 'Base64, Unicode homoglyphs, hex' },
    { icon: IconPackage, name: 'Dependency Risks', desc: 'Typosquatting, force installs' },
    { icon: IconBug, name: 'Bundled Payloads', desc: 'Executables, binaries, archives' },
    { icon: IconLink, name: 'External Links', desc: 'URL inventory and classification' },
    { icon: IconRobot, name: 'AI Semantic Review', desc: 'LLM-powered deep analysis' },
    { icon: IconDeviceDesktop, name: 'Cross-Platform', desc: 'Multi-platform compatibility' },
]

export default function SecurityMonitoring() {
    return (
        <section className="py-12 md:py-20" id="features">
            <div className="mx-auto w-full max-w-5xl px-6">
                <div className="text-center">
                    <h2 className="text-foreground text-4xl font-semibold">12 Categories of Security Analysis</h2>
                    <p className="text-muted-foreground mb-8 mt-4 text-balance text-lg">
                        Every skill is scanned with deterministic pattern matching and AI-powered semantic review.
                        No code is ever executed &mdash; all analysis is read-only.
                    </p>
                </div>

                <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                    {categories.map((cat) => (
                        <div key={cat.name} className="group rounded-xl border bg-background p-5 transition-colors hover:bg-muted/50">
                            <div className="flex items-start gap-3">
                                <div className="rounded-lg bg-primary/10 p-2">
                                    <cat.icon className="size-5 text-primary" />
                                </div>
                                <div>
                                    <h3 className="font-semibold text-sm">{cat.name}</h3>
                                    <p className="text-muted-foreground text-sm mt-1">{cat.desc}</p>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>

                <div className="border-foreground/10 relative mt-14 grid gap-8 border-b pb-8 md:grid-cols-2">
                    <div>
                        <div className="flex items-center gap-2 mb-4">
                            <IconBrain className="size-6 text-purple-600" />
                            <h3 className="text-foreground text-xl font-semibold">AI-Powered Deep Analysis</h3>
                        </div>
                        <p className="text-muted-foreground my-4 text-lg">
                            Beyond regex: the AI semantic review catches conditional activation logic, multi-step attack chains,
                            and social engineering that pattern matching misses.
                        </p>
                        <div className="flex flex-wrap gap-2 mt-4">
                            <Badge variant="outline">Prompt Injection Detection</Badge>
                            <Badge variant="outline">Intent Classification</Badge>
                            <Badge variant="outline">Data Flow Analysis</Badge>
                            <Badge variant="outline">Confidence Scoring</Badge>
                        </div>
                    </div>
                    <div>
                        <div className="flex items-center gap-2 mb-4">
                            <IconShieldCheck className="size-6 text-green-600" />
                            <h3 className="text-foreground text-xl font-semibold">Severity-Based Findings</h3>
                        </div>
                        <p className="text-muted-foreground my-4 text-lg">
                            Every finding includes severity, confidence, evidence, and a risk score.
                            Prioritize what matters and make informed decisions about which skills to trust.
                        </p>
                        <div className="flex flex-wrap gap-2 mt-4">
                            <Badge variant="destructive">Critical</Badge>
                            <Badge variant="outline" className="border-orange-600 text-orange-600">High</Badge>
                            <Badge variant="outline" className="border-yellow-600 text-yellow-600">Medium</Badge>
                            <Badge variant="outline">Low</Badge>
                            <Badge variant="secondary">Info</Badge>
                        </div>
                    </div>
                </div>

                <blockquote className="before:bg-primary relative mt-8 max-w-xl pl-6 before:absolute before:inset-y-0 before:left-0 before:w-1 before:rounded-full">
                    <p className="text-foreground text-lg">
                        The ClawHavoc campaign planted 335 malicious skills across ClawHub targeting 300,000 users.
                        Community marketplaces have no automated vetting. SkillScanner fills that gap.
                    </p>
                    <footer className="mt-4 flex items-center gap-2">
                        <cite className="text-muted-foreground text-sm">Based on Repello AI security research</cite>
                    </footer>
                </blockquote>
            </div>
        </section>
    )
}
