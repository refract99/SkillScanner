import { Button } from '@/components/ui/button'
import Link from 'next/link'
import { IconArrowRight } from '@tabler/icons-react'

export default function CallToAction() {
    return (
        <section className="py-16 md:py-24">
            <div className="mx-auto max-w-2xl px-6 text-center">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-foreground sm:text-3xl">
                    Don&apos;t install blind
                </h2>
                <p className="mt-3 text-gray-600 dark:text-muted-foreground">
                    Know what a skill does before it touches your filesystem, shell, and API keys.
                </p>
                <div className="mt-8">
                    <Button
                        asChild
                        size="lg"
                        className="bg-emerald-600 hover:bg-emerald-700 text-white px-8">
                        <Link href="/scan">
                            Scan a Skill
                            <IconArrowRight className="size-4 ml-1" />
                        </Link>
                    </Button>
                </div>
            </div>
        </section>
    )
}
