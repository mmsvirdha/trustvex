import "@/lib/reputation/providers";
import { NextResponse } from "next/server";
import { z } from "zod";
import { runScan, InvalidUrlError } from "@/lib/scanService";
import { listScans } from "@/lib/db";
import { SsrfBlockedError } from "@/lib/security/safeFetch";

const bodySchema = z.object({
  url: z.string().min(1, "A URL is required").max(2048, "URL is too long"),
});

export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Request body must be JSON." }, { status: 400 });
  }

  const parsed = bodySchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: parsed.error.issues[0]?.message ?? "Invalid request." },
      { status: 400 }
    );
  }

  try {
    const report = await runScan(parsed.data.url);
    return NextResponse.json(report, { status: 201 });
  } catch (err) {
    if (err instanceof InvalidUrlError) {
      return NextResponse.json({ error: err.message }, { status: 400 });
    }
    if (err instanceof SsrfBlockedError) {
      return NextResponse.json(
        { error: "This target resolves to a private or internal address and cannot be scanned." },
        { status: 400 }
      );
    }
    console.error("Scan failed:", err);
    return NextResponse.json(
      { error: "The scan could not be completed due to an unexpected error." },
      { status: 500 }
    );
  }
}

export async function GET() {
  const scans = listScans(50);
  return NextResponse.json({ scans });
}
