import { NextResponse } from "next/server";
import { getScanById } from "@/lib/db";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const report = getScanById(id);
  if (!report) {
    return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  }
  return NextResponse.json(report);
}