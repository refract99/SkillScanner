"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "convex/react";
import { api } from "@/convex/_generated/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Search, AlertTriangle, ArrowRight, Loader2 } from "lucide-react";
import { detectPlatformFromUrl } from "@/lib/scan-validation";
import Link from "next/link";

export default function ScanPage() {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [detectedPlatform, setDetectedPlatform] = useState<string | null>(null);
  const router = useRouter();
  const submitScan = useMutation(api.scanner.submit.submitScan);

  const handleUrlChange = (value: string) => {
    setUrl(value);
    setError("");
    setDetectedPlatform(detectPlatformFromUrl(value));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const trimmed = url.trim();
      if (!trimmed.startsWith("https://github.com/")) {
        throw new Error("Please enter a valid GitHub URL (https://github.com/owner/repo)");
      }

      const result = await submitScan({ url: trimmed });
      router.push(`/scan/${result.shareSlug}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to submit scan");
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-background to-muted/20">
      <nav className="border-b bg-background/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-6 py-3 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 font-semibold">
            <Shield className="h-5 w-5" />
            SkillScanner
          </Link>
          <Link href="/dashboard/scans">
            <Button variant="ghost" size="sm">Scan History</Button>
          </Link>
        </div>
      </nav>

      <main className="max-w-3xl mx-auto px-6 pt-20 pb-16">
        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-2 bg-primary/10 rounded-full px-4 py-1.5 text-sm text-primary mb-6">
            <Shield className="h-4 w-4" />
            AI Agent Skill Security Scanner
          </div>
          <h1 className="text-4xl font-bold tracking-tight mb-4">
            Scan before you install
          </h1>
          <p className="text-lg text-muted-foreground max-w-xl mx-auto">
            Analyze AI coding agent skills for security vulnerabilities, prompt injection,
            credential access, and more — before they touch your system.
          </p>
        </div>

        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Search className="h-5 w-5" />
              Scan a Skill
            </CardTitle>
            <CardDescription>
              Paste a GitHub URL to a skill repository or directory
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="flex gap-3">
                <div className="flex-1 relative">
                  <Input
                    type="url"
                    placeholder="https://github.com/owner/repo/tree/main/.claude/skills/my-skill"
                    value={url}
                    onChange={(e) => handleUrlChange(e.target.value)}
                    className="pr-24"
                    disabled={loading}
                  />
                  {detectedPlatform && (
                    <Badge variant="secondary" className="absolute right-2 top-1/2 -translate-y-1/2">
                      {detectedPlatform}
                    </Badge>
                  )}
                </div>
                <Button type="submit" disabled={loading || !url.trim()}>
                  {loading ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin mr-2" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      Scan
                      <ArrowRight className="h-4 w-4 ml-2" />
                    </>
                  )}
                </Button>
              </div>
              {error && (
                <div className="flex items-center gap-2 text-sm text-destructive">
                  <AlertTriangle className="h-4 w-4" />
                  {error}
                </div>
              )}
            </form>
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">12 Scan Categories</CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground">
              From prompt injection to credential access, code injection to obfuscation detection.
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">AI-Powered Analysis</CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground">
              Semantic review catches what regex cannot — conditional triggers, social engineering, multi-step attacks.
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">Multi-Platform</CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground">
              Claude Code, OpenClaw, Cursor, Windsurf, Cline, and AgentSkills-compatible platforms.
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}
