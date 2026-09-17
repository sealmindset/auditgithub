/**
 * Jira-specific fields and the create-issue prefill URL.
 *
 * The finding → issue text is built in `lib/finding-issue.ts` and shared with
 * every other destination. What is Jira's alone lives here: the priority
 * vocabulary, the numeric instance IDs, and the deep link.
 *
 * Standard Jira fields only — project, issue type, summary, description,
 * priority, labels. No `customfield_*` IDs, so this works against any project
 * without first reading that project's createmeta.
 */

import { normalizeSeverity, type Severity } from "./severity";
import {
  buildDescription,
  buildLabels,
  buildSummary,
  occurrenceCount,
  type FindingLike,
  type IssueScope,
  type NormalizeOptions,
} from "./finding-issue";

// Re-exported so a caller needs one import to file to Jira.
export {
  buildDescription,
  buildLabels,
  buildSummary,
  occurrenceCount,
} from "./finding-issue";
export type {
  FindingLike,
  IssueScope,
  NormalizeOptions,
  OccurrenceGroup,
} from "./finding-issue";

/**
 * The two scopes the Jira path files at, matching the exception flow.
 *
 * Narrower than `IssueScope`, which also carries the `project` and `org`
 * tiers. Those measure a defect group server-side before writing a GRC
 * record; a Jira deep link measures nothing and writes nothing, so offering
 * them here would put an unmeasured count in front of a person.
 */
export type JiraScope = Extract<IssueScope, "specific" | "global">;

/* ---------------------------------------------------------------------------
   Limits
   ------------------------------------------------------------------------ */

/**
 * Practical ceiling for the whole prefill URL. Browsers tolerate more, but
 * Jira fronts (and any proxy in between) commonly cap the HTTP request line
 * near 8 KB. Staying under 6 KB leaves room for cookies on the same request.
 */
const MAX_URL = 6000;

/* ---------------------------------------------------------------------------
   Config
   ------------------------------------------------------------------------ */

/**
 * Jira target, resolved at runtime from `/api/jira-config` rather than baked
 * into the bundle — the same image ships to more than one environment.
 *
 * `projectId` / `issueTypeId` / priority IDs are Jira's numeric internal IDs,
 * not keys. The prefill endpoint takes IDs only; a project key will not work.
 */
export interface JiraConfig {
  /** Site root, no trailing slash. e.g. `https://example.atlassian.net` */
  baseUrl: string | null;
  /** Numeric project ID, e.g. "10042". */
  projectId: string | null;
  /** Numeric issue type ID, e.g. "10004". */
  issueTypeId: string | null;
  /** Numeric priority IDs, keyed by our severity ramp. Optional. */
  priorityIds: Partial<Record<Severity, string>>;
  /** True when baseUrl, projectId and issueTypeId are all present. */
  configured: boolean;
}

export const EMPTY_JIRA_CONFIG: JiraConfig = {
  baseUrl: null,
  projectId: null,
  issueTypeId: null,
  priorityIds: {},
  configured: false,
};

/* ---------------------------------------------------------------------------
   Vocabulary mapping
   ------------------------------------------------------------------------ */

/**
 * Our five-step severity ramp onto Jira's default five priorities. Named
 * rather than by ID so the mapping stays readable when the IDs are absent;
 * `priorityIds` supplies the ID when the instance is configured.
 */
export const SEVERITY_TO_PRIORITY: Record<Severity, string> = {
  critical: "Highest",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Lowest",
};

/* ---------------------------------------------------------------------------
   Output
   ------------------------------------------------------------------------ */

/** A finding reduced to standard Jira fields. */
export interface NormalizedIssue {
  summary: string;
  description: string;
  /** Jira priority name, always set. */
  priorityName: string;
  /** Jira numeric priority ID, null when the instance has not supplied one. */
  priorityId: string | null;
  labels: string[];
  /** Canonical severity the priority was derived from. */
  severity: Severity;
  /**
   * `specific` or `global` only. Jira is a prefilled deep link with a person
   * pressing Create on Jira's own screen, so it keeps the exception flow's
   * two scopes; the `project` and `org` tiers exist for the AuditBoard filing
   * endpoint, which writes a record with no confirmation step.
   */
  scope: JiraScope;
  /** Findings this issue speaks for. 1 for specific scope. */
  occurrenceCount: number;
}

/** A finding reduced to the standard Jira fields. */
export function normalizeFinding(
  finding: FindingLike,
  config: JiraConfig = EMPTY_JIRA_CONFIG,
  options: NormalizeOptions = {},
): NormalizedIssue {
  // A tier the Jira path does not speak falls back to `specific` rather than
  // rendering the grouped text with no measured count behind it.
  const requested = options.scope ?? "specific";
  const scope: JiraScope = requested === "global" ? "global" : "specific";
  const scoped: NormalizeOptions = { ...options, scope };
  const severity = normalizeSeverity(finding.severity);
  return {
    summary: buildSummary(finding, scoped),
    description: buildDescription(finding, scoped),
    priorityName: SEVERITY_TO_PRIORITY[severity],
    priorityId: config.priorityIds?.[severity] ?? null,
    labels: buildLabels(finding, scoped),
    severity,
    scope,
    occurrenceCount: occurrenceCount(scope, options.group),
  };
}

/* ---------------------------------------------------------------------------
   Prefill URL
   ------------------------------------------------------------------------ */

export interface CreateIssueUrl {
  url: string;
  /**
   * True when the description had to be shortened to keep the URL under the
   * request-line ceiling. The caller is expected to tell the user, and to put
   * the untruncated text somewhere they can paste it from.
   */
  truncated: boolean;
}

/**
 * Build a Jira create-issue URL with the fields prefilled.
 *
 * Deliberately a deep link and not an API call: no credential is stored in
 * this app, the user authenticates to Jira as themselves, and the issue is
 * only created once they press Create on Jira's own screen. Filing an issue
 * is an outbound action, so a human stays in the loop by construction.
 *
 * Returns null when the instance is not configured — the caller should
 * disable the control rather than open a broken tab.
 */
export function buildCreateIssueUrl(
  config: JiraConfig,
  issue: NormalizedIssue,
): CreateIssueUrl | null {
  if (!config.configured || !config.baseUrl || !config.projectId || !config.issueTypeId) {
    return null;
  }

  const base = `${config.baseUrl.replace(/\/+$/, "")}/secure/CreateIssueDetails!init.jspa`;

  const build = (description: string): string => {
    const params = new URLSearchParams();
    params.set("pid", config.projectId!);
    params.set("issuetype", config.issueTypeId!);
    params.set("summary", issue.summary);
    params.set("description", description);
    if (issue.priorityId) params.set("priority", issue.priorityId);
    // Jira reads `labels` once per value, not as a comma-joined string.
    for (const label of issue.labels) params.append("labels", label);
    return `${base}?${params.toString()}`;
  };

  const full = build(issue.description);
  if (full.length <= MAX_URL) {
    return { url: full, truncated: false };
  }

  // Shrink only the description — every other field is load-bearing for
  // triage. Binary search on the character count, since percent-encoding
  // makes the URL length a non-linear function of the text length.
  const note = "\n\n… truncated for transport. Full detail is in AuditGitHub.";
  let lo = 0;
  let hi = issue.description.length;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (build(issue.description.slice(0, mid) + note).length <= MAX_URL) {
      lo = mid;
    } else {
      hi = mid - 1;
    }
  }
  return { url: build(issue.description.slice(0, lo) + note), truncated: true };
}
