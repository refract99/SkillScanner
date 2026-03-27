'use client'
import Link from 'next/link'
import { Button } from '@/components/ui/button'
import { HeroHeader } from "./header"
import { IconArrowRight } from '@tabler/icons-react'
import { Authenticated, Unauthenticated } from "convex/react"
import { SignInButton, SignUpButton } from "@clerk/nextjs"

const platforms = ['Claude Code', 'OpenClaw', 'Cursor', 'Windsurf', 'Cline']

export default function HeroSection() {
    return (
        <>
            <HeroHeader />
            <main>
                <section className="pt-24 pb-16 md:pt-32 md:pb-24">
                    <div className="mx-auto max-w-3xl px-6 text-center">
                        <p className="text-emerald-600 font-medium text-sm mb-4">Security analysis for AI agent skills</p>
                        <h1 className="text-4xl font-bold tracking-tight sm:text-5xl lg:text-6xl text-gray-900 dark:text-foreground">
                            Know what a skill does<br />before you install it
                        </h1>
                        <p className="mt-6 text-lg text-gray-600 dark:text-muted-foreground max-w-2xl mx-auto leading-relaxed">
                            SkillScanner uses AI-first analysis across 10 threat categories with deterministic hard-stop checks &mdash; without executing any code. Sign up free and get a full security report in seconds.
                        </p>

                        <div className="mt-8 flex items-center justify-center gap-4">
                            <Authenticated>
                                <Button
                                    asChild
                                    size="lg"
                                    className="bg-emerald-600 hover:bg-emerald-700 text-white px-8">
                                    <Link href="/dashboard">
                                        Go to Dashboard
                                        <IconArrowRight className="size-4 ml-1" />
                                    </Link>
                                </Button>
                            </Authenticated>
                            <Unauthenticated>
                                <SignUpButton mode="modal">
                                    <Button size="lg" className="bg-emerald-600 hover:bg-emerald-700 text-white px-8">
                                        Get Started Free
                                        <IconArrowRight className="size-4 ml-1" />
                                    </Button>
                                </SignUpButton>
                                <SignInButton mode="modal">
                                    <Button size="lg" variant="outline">
                                        Sign In
                                    </Button>
                                </SignInButton>
                            </Unauthenticated>
                        </div>

                        <p className="mt-4 text-sm text-gray-500 dark:text-muted-foreground">
                            Free &middot; Sign up in seconds &middot; Public repos
                        </p>

                        <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
                            {platforms.map((p) => (
                                <span key={p} className="text-xs font-medium text-gray-500 dark:text-muted-foreground bg-gray-100 dark:bg-muted px-3 py-1.5 rounded-full">
                                    {p}
                                </span>
                            ))}
                        </div>
                    </div>
                </section>
            </main>
        </>
    )
}
