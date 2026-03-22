import Link from 'next/link'
import { IconShieldSearch } from '@tabler/icons-react'

export default function FooterSection() {
    return (
        <footer className="border-t border-gray-100 dark:border-border py-12">
            <div className="mx-auto max-w-5xl px-6">
                <div className="flex flex-col items-center gap-6 sm:flex-row sm:justify-between">
                    <Link href="/" className="flex items-center gap-2">
                        <IconShieldSearch className="size-5 text-emerald-600" />
                        <span className="font-semibold text-sm">{process.env.NEXT_PUBLIC_SITE_NAME || 'SkillScanner'}</span>
                    </Link>

                    <div className="flex gap-6 text-sm text-gray-500 dark:text-muted-foreground">
                        <Link href="/scan" className="hover:text-gray-900 dark:hover:text-foreground transition-colors">Scan</Link>
                        <Link href="/dashboard" className="hover:text-gray-900 dark:hover:text-foreground transition-colors">Dashboard</Link>
                    </div>
                </div>

                <div className="mt-8 text-center text-xs text-gray-400 dark:text-muted-foreground">
                    &copy; {new Date().getFullYear()} {process.env.NEXT_PUBLIC_SITE_NAME || 'SkillScanner'}
                </div>
            </div>
        </footer>
    )
}
