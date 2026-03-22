import { NextRequest, NextResponse } from "next/server";
import { withRateLimit } from "@/lib/withRateLimit";
import { withCsrf } from "@/lib/withCsrf";
import { githubUrlSchema } from "@/lib/scan-validation";
import { ConvexHttpClient } from "convex/browser";
import { api } from "@/convex/_generated/api";

const convex = new ConvexHttpClient(process.env.NEXT_PUBLIC_CONVEX_URL!);

async function handler(request: NextRequest) {
  try {
    const body = await request.json();
    const urlResult = githubUrlSchema.safeParse(body.url);

    if (!urlResult.success) {
      return NextResponse.json(
        { error: urlResult.error.errors[0].message },
        { status: 400 }
      );
    }

    // Forward auth token if present
    const token = request.headers.get("authorization")?.replace("Bearer ", "");
    if (token) {
      convex.setAuth(token);
    }

    const result = await convex.mutation(api.scanner.submit.submitScan, {
      url: urlResult.data,
    });

    return NextResponse.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Scan submission failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

export const POST = withRateLimit(withCsrf(handler));
