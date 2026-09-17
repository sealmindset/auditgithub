/**
 * Jira target configuration.
 *
 * Read from the environment at request time rather than exposed as
 * `NEXT_PUBLIC_*`, because those are inlined at build time and this image is
 * built once and deployed to more than one environment.
 *
 * Nothing secret is returned. The Jira integration is a deep link — the user
 * authenticates to Jira themselves and creates the issue on Jira's own screen
 * — so there is no token to leak here.
 */

import { NextResponse } from "next/server";

/** Trim a trailing slash so URL joins do not double up. */
function normalizeBase(value: string | undefined): string | null {
  const trimmed = value?.trim();
  if (!trimmed) return null;
  return trimmed.replace(/\/+$/, "");
}

function nonEmpty(value: string | undefined): string | null {
  const trimmed = value?.trim();
  return trimmed ? trimmed : null;
}

export async function GET() {
  const baseUrl = normalizeBase(process.env.JIRA_BASE_URL);
  const projectId = nonEmpty(process.env.JIRA_PROJECT_ID);
  const issueTypeId = nonEmpty(process.env.JIRA_ISSUE_TYPE_ID);

  // Priority IDs are optional. Without them the create screen opens on the
  // project's default priority and the mapped name is shown in the preview so
  // the user can set it by hand.
  const priorityIds: Record<string, string> = {};
  const priorityEnv: Array<[string, string | undefined]> = [
    ["critical", process.env.JIRA_PRIORITY_CRITICAL],
    ["high", process.env.JIRA_PRIORITY_HIGH],
    ["medium", process.env.JIRA_PRIORITY_MEDIUM],
    ["low", process.env.JIRA_PRIORITY_LOW],
    ["info", process.env.JIRA_PRIORITY_INFO],
  ];
  for (const [severity, id] of priorityEnv) {
    const value = nonEmpty(id);
    if (value) priorityIds[severity] = value;
  }

  return NextResponse.json(
    {
      baseUrl,
      projectId,
      issueTypeId,
      priorityIds,
      configured: !!(baseUrl && projectId && issueTypeId),
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}
