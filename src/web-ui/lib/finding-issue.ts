/**
 * Finding → issue-tracker normalization, shared by every destination.
 *
 * A finding reaches the UI in whatever vocabulary its scanner used — severity
 * as "CRITICAL", "blocker" or a CVSS float; a path that may or may not carry a
 * line number; a description that is sometimes plain text and sometimes
 * AI-generated markdown. A tracker wants one shape. Everything that files a
 * finding resolves it here, so the same finding filed to Jira and to
 * AuditBoard describes itself the same way, and two people filing the same
 * finding produce one issue instead of two to reconcile later.
 *
 * Destination-specific concerns live next to their destination:
 * `lib/jira.ts` for priorities and the prefill URL, `lib/auditboard.ts` for
 * deficiency levels and the API body.
 */

import { normalizeSeverity, severityLabel, type Severity } from "./severity";

/* ---------------------------------------------------------------------------
   Limits
   ------------------------------------------------------------------------ */

/**
 * Summary cap. 255 is Jira's, and the tightest of any destination we file to
 * (AuditBoard allows 500), so one value keeps the text identical everywhere.
 */
export const MAX_SUMMARY = 255;

/** Jira's cap on a single label. */
export const MAX_LABEL = 255;

/** Code snippet budget, so one long file does not crowd out the rest. */
export const MAX_SNIPPET_CHARS = 1500;

/* ---------------------------------------------------------------------------
   Secret snippets
   ------------------------------------------------------------------------ */

/**
 * Scanners whose `code_snippet` *is* the finding.
 *
 * For every other scanner the snippet is context — the unsafe call, the
 * vulnerable version string — and an issue without it is harder to act on.
 * For a secret scanner the snippet is the credential: the line it matched is
 * `"password": "…"` or an API key. Copying it into a tracker publishes a
 * working credential into a second system, with its own audience, its own
 * retention and its own export paths, and AuditBoard issues cannot be deleted
 * and their descriptions cannot be edited after create.
 *
 * Measured on this estate: issue I#1716 carries a live Google API key in its
 * body in plaintext because this list did not exist when it was filed.
 *
 * Withheld entirely rather than masked. Masking means guessing which token on
 * the line is the secret, and a guess that is wrong leaks the whole line while
 * looking safe.
 */
const SECRET_FAMILY_SCANNERS =
  /gitleaks|trufflehog|whispers|detect.?secret|secret|credential|gitsecrets|shhgit|ggshield/i;

/** Whether this scanner's snippets must be withheld from an issue body. */
export function isSecretFamilyScanner(scannerName: string | null | undefined): boolean {
  return SECRET_FAMILY_SCANNERS.test(scannerName ?? "");
}

/** What stands in for a withheld snippet. */
export const SNIPPET_WITHHELD =
  "Withheld. This scanner reports the matched secret itself, and copying it " +
  "into a tracker would put a working credential in a second system. Open the " +
  "finding in AuditGitHub to see the line.";

/** Repositories to name individually before switching to a count. */
export const MAX_REPOS_LISTED = 12;

/* ---------------------------------------------------------------------------
   Scope
   ------------------------------------------------------------------------ */

/**
 * What an issue speaks for, so a scope means one thing in this app rather
 * than one thing per dialog.
 *
 * `specific` — this one finding instance.
 * `project`  — this defect everywhere in this project.
 * `org`      — this defect across every project it was found in.
 * `global`   — every finding sharing this finding's scanner and file path.
 *              The exception flow and the Jira deep link still use it. The
 *              AuditBoard filing path does not: it grouped 11,517 findings
 *              from 1,287 unrelated advisories into one issue because they
 *              shared a path name. See `src/api/services/finding_groups.py`.
 *
 * A defect is identified by its scanner and rule at the `project` and `org`
 * tiers, which is why those two carry a separate group shape below.
 */
export type IssueScope = "specific" | "global" | "project" | "org";

/** True when an issue at this scope speaks for more than one finding. */
export function isGroupedScope(scope: IssueScope): boolean {
  return scope !== "specific";
}

/**
 * Response of `GET /findings/{id}/group`, for the `project` and `org` tiers.
 *
 * Every figure is measured server-side by the same service the filing
 * endpoint uses, so what a dialog previews and what the issue claims cannot
 * disagree. Nothing here is computed in the browser.
 */
export interface GroupSummary {
  tier: IssueScope;
  /** Tier the volume rule points to for this defect. */
  recommended_tier: IssueScope;
  /** `scanner::rule_id`. */
  identity_key: string;
  scanner_name: string;
  rule_id: string | null;
  /** Identities filing under this one; longer than one only after a review. */
  members: string[];
  finding_count: number;
  /** Projects affected organization-wide, whatever the tier. */
  project_count: number;
  location_count: number;
  locations_omitted: number;
  severity: string | null;
  severity_breakdown: Array<{ scanner: string; severity: string; count: number }>;
  projects: Array<{
    repo_name: string;
    finding_count: number;
    location_count: number;
    locations: Array<{ path: string; count: number; line: number | null }>;
  }>;
  /** The location section exactly as the server will write it into the body. */
  location_text: string;
  org_scoped: boolean;
  /** True when the defect spans more projects than the escalation threshold. */
  exceeds_threshold: boolean;
  escalation_threshold: number;
  fileable: boolean;
  blocked_reason: string | null;
}

/**
 * Response of `GET /findings/{id}/occurrences`. Read-only: it reports the
 * population a global action would cover without acting on it.
 */
export interface OccurrenceGroup {
  scope: IssueScope;
  count: number;
  scanner_name: string;
  file_path: string | null;
  repo_names: string[];
  sample_findings: Array<{
    id: string;
    title: string | null;
    file_path: string | null;
    scanner_name: string | null;
    repo_name?: string | null;
  }>;
  /** True when the count was restricted to the caller's current organization. */
  org_scoped: boolean;
}

/* ---------------------------------------------------------------------------
   Input
   ------------------------------------------------------------------------ */

/**
 * The subset of a finding this module reads. Every field is optional because
 * the findings API is untyped and scanners populate different columns.
 */
export interface FindingLike {
  id?: string | null;
  title?: string | null;
  description?: string | null;
  severity?: string | null;
  status?: string | null;
  investigation_status?: string | null;
  repo_name?: string | null;
  repository_id?: string | null;
  scanner_name?: string | null;
  /** Scanner's own rule identifier. With the scanner, it identifies the defect. */
  rule_id?: string | null;
  file_path?: string | null;
  line_start?: number | string | null;
  code_snippet?: string | null;
  risk_score?: number | null;
  risk_level?: string | null;
}

/** Everything the builders need beyond the finding itself. */
export interface NormalizeOptions {
  scope?: IssueScope;
  /** Occurrence group for `global` scope. Ignored when scope is `specific`. */
  group?: OccurrenceGroup | null;
  /**
   * Measured group for the `project` and `org` tiers. Required for them —
   * without it the body would carry no figure, and a grouped issue with no
   * count is one nobody can act on.
   */
  groupSummary?: GroupSummary | null;
  /** Origin of this app, so the issue can link back to the finding. */
  appOrigin?: string | null;
  /**
   * Suppress the trailing provenance block. Set only when the destination
   * derives its own — the AuditBoard API path builds the footer server-side
   * so the occurrence count in it is one the server measured, and two footers
   * disagreeing with each other is worse than one.
   */
  omitProvenance?: boolean;
  /** Extra sections appended after the body, before any provenance block. */
  extraSections?: string[];
}

/* ---------------------------------------------------------------------------
   Helpers
   ------------------------------------------------------------------------ */

/** Collapse all whitespace runs to single spaces and trim. */
function oneLine(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

/**
 * Jira rejects labels containing whitespace and treats case as significant,
 * so every label is lowercased and non-label characters become hyphens.
 * Returns null when nothing usable survives.
 */
function toLabel(prefix: string, value: string | null | undefined): string | null {
  if (!value) return null;
  const slug = String(value)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^[-.]+|[-.]+$/g, "");
  if (!slug) return null;
  return `${prefix}${slug}`.slice(0, MAX_LABEL);
}

/** `path:line` when a line is known, bare path when it is not. */
function formatLocation(finding: FindingLike): string | null {
  const path = finding.file_path?.trim();
  if (!path) return null;
  const line = finding.line_start;
  if (line === null || line === undefined || line === "") return path;
  return `${path}:${line}`;
}

/** Title-case a snake_case or kebab-case value for display. */
function prettify(value: string): string {
  return value.trim().replace(/[_-]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

/** Occurrences in scope. Falls back to 1 when the group has not loaded. */
export function occurrenceCount(
  scope: IssueScope,
  group: OccurrenceGroup | null | undefined,
  groupSummary?: GroupSummary | null,
): number {
  if (scope === "specific") return 1;
  if (scope === "project" || scope === "org") {
    // Never falls back to the occurrences endpoint: it answers a different
    // question (same scanner and path) and would report a number for a
    // population this issue does not cover.
    return groupSummary?.finding_count && groupSummary.finding_count > 0
      ? groupSummary.finding_count
      : 1;
  }
  return group?.count && group.count > 0 ? group.count : 1;
}

/* ---------------------------------------------------------------------------
   Normalization
   ------------------------------------------------------------------------ */

/**
 * Summary line. Severity leads so a backlog sorts usefully on text alone,
 * then the finding title, then what the issue is about — the owning
 * repository for a specific finding, or the occurrence count and file for a
 * grouped one.
 *
 * Truncation is mid-string with an ellipsis rather than a hard cut, so the
 * trailing context a triager needs to route the issue survives even when the
 * title is enormous.
 */
export function buildSummary(
  finding: FindingLike,
  options: NormalizeOptions = {},
): string {
  const scope = options.scope ?? "specific";
  const severity = normalizeSeverity(finding.severity);
  const prefix = `[${severityLabel(severity)}] `;
  const title = oneLine(finding.title || "Untitled finding");

  let suffix = "";
  if (scope === "project" || scope === "org") {
    const summary = options.groupSummary;
    const measured = summary?.finding_count;
    const count =
      measured && measured > 0
        ? `${measured} occurrence${measured === 1 ? "" : "s"}`
        : "all occurrences";
    if (scope === "project") {
      // The project is named, not the file: a project-tier issue covers every
      // location in it, and the body lists them.
      const repo = oneLine(summary?.projects?.[0]?.repo_name || finding.repo_name || "");
      suffix = repo ? ` — ${count} in ${repo}` : ` — ${count}`;
    } else {
      const projects = summary?.project_count;
      suffix = projects
        ? ` — ${count} across ${projects} project${projects === 1 ? "" : "s"}`
        : ` — ${count}`;
    }
  } else if (scope === "global") {
    const path = finding.file_path?.trim();
    const where = path ? ` in ${path}` : "";
    // No measured count means no count in the summary. A fabricated "1
    // occurrence" on a grouped issue is worse than saying "all".
    const measured = options.group?.count;
    suffix =
      measured && measured > 0
        ? ` — ${measured} occurrence${measured === 1 ? "" : "s"}${where}`
        : ` — all occurrences${where}`;
  } else {
    const repo = oneLine(finding.repo_name || "");
    suffix = repo ? ` — ${repo}` : "";
  }

  const full = `${prefix}${title}${suffix}`;
  if (full.length <= MAX_SUMMARY) return full;

  const room = MAX_SUMMARY - prefix.length - suffix.length - 1; // 1 for "…"
  if (room <= 0) {
    // The suffix alone overruns the field. Keep the front of the line.
    return full.slice(0, MAX_SUMMARY - 1) + "…";
  }
  return `${prefix}${title.slice(0, room)}…${suffix}`;
}

/**
 * Description body. Fixed section order, every section omitted rather than
 * emitted empty, so the same finding always renders the same issue text and
 * two issues can be diffed against each other.
 *
 * Written as plain text, not wiki markup or markdown: Jira's team-managed
 * projects open a rich-text editor that pastes prefilled text literally, and
 * AuditBoard's description field is not a markdown renderer either. Either
 * way `{code}` or backticks would show up as characters.
 */
export function buildDescription(
  finding: FindingLike,
  options: NormalizeOptions = {},
): string {
  const scope = options.scope ?? "specific";
  const group = options.group;
  const severity = normalizeSeverity(finding.severity);
  const sections: string[] = [];

  const facts: string[] = [
    `Severity: ${severityLabel(severity)}`,
    `Scanner: ${finding.scanner_name || "unknown"}`,
  ];

  if (scope === "project" || scope === "org") {
    const summary = options.groupSummary;
    const repo = summary?.projects?.[0]?.repo_name || finding.repo_name || "unknown";
    facts.push(
      scope === "project"
        ? `Scope: Project — every occurrence of this defect in ${repo}`
        : `Scope: Organization — every occurrence of this defect in every project`,
    );
    // The rule, not the file. It is what makes two reports the same defect,
    // and it is what a reader needs to look the advisory up.
    if (summary?.identity_key) facts.push(`Defect: ${summary.identity_key}`);
    if (summary?.members && summary.members.length > 1) {
      facts.push(`Merged rules (reviewer-approved): ${summary.members.join(", ")}`);
    }
    facts.push(
      summary?.finding_count
        ? `Occurrences: ${summary.finding_count}`
        : "Occurrences: not counted — see AuditGitHub for the current figure",
    );
    if (summary?.location_count) facts.push(`Distinct locations: ${summary.location_count}`);
    if (scope === "project") {
      facts.push(`Repository: ${repo}`);
      if (summary?.exceeds_threshold) {
        facts.push(
          `Also affects other projects: ${summary.project_count} in total, above the ` +
            `escalation threshold of ${summary.escalation_threshold}. This issue covers ` +
            `one project only.`,
        );
      } else if (summary?.project_count && summary.project_count > 1) {
        facts.push(`Projects affected organization-wide: ${summary.project_count}`);
      }
    } else if (summary?.project_count) {
      facts.push(`Projects affected: ${summary.project_count}`);
    }
    if (summary?.severity_breakdown && summary.severity_breakdown.length > 1) {
      // Shown rather than resolved: the issue is rated at the highest, and a
      // reader is entitled to see that the scanners did not agree.
      facts.push(
        `Severity as reported: ` +
          summary.severity_breakdown
            .map((b) => `${b.scanner} ${b.severity} ×${b.count}`)
            .join("; "),
      );
    }
    if (summary && !summary.org_scoped) {
      facts.push("Count covers the whole tenant — no organization filter was in effect.");
    }
  } else if (scope === "global") {
    facts.push(`Scope: Global — all findings from this scanner in this file path`);
    facts.push(
      group?.count && group.count > 0
        ? `Occurrences: ${group.count}`
        : "Occurrences: not counted — see AuditGitHub for the current figure",
    );
    if (finding.file_path) facts.push(`File path: ${finding.file_path}`);

    const repos = group?.repo_names ?? [];
    if (repos.length > MAX_REPOS_LISTED) {
      facts.push(
        `Repositories: ${repos.length} — ${repos.slice(0, MAX_REPOS_LISTED).join(", ")}, ` +
          `and ${repos.length - MAX_REPOS_LISTED} more`,
      );
    } else if (repos.length > 0) {
      facts.push(`Repositories: ${repos.join(", ")}`);
    } else {
      facts.push(`Repository: ${finding.repo_name || "unknown"}`);
    }
    if (group && !group.org_scoped) {
      facts.push("Count covers the whole tenant — no organization filter was in effect.");
    }
  } else {
    facts.push(`Scope: Specific — this finding instance only`);
    facts.push(`Repository: ${finding.repo_name || "unknown"}`);
    const location = formatLocation(finding);
    if (location) facts.push(`Location: ${location}`);
  }

  if (finding.status) facts.push(`Scan status: ${prettify(finding.status)}`);
  if (finding.investigation_status) {
    facts.push(`Investigation: ${prettify(finding.investigation_status)}`);
  }
  if (typeof finding.risk_score === "number" && !Number.isNaN(finding.risk_score)) {
    const level = finding.risk_level ? ` (${prettify(finding.risk_level)})` : "";
    facts.push(`Risk score: ${finding.risk_score}${level}`);
  }
  sections.push(facts.join("\n"));

  const description = finding.description?.trim();
  if (description) {
    sections.push(`Description\n${description}`);
  }

  const snippet = finding.code_snippet?.trim();
  if (snippet) {
    const heading = isGroupedScope(scope)
      ? "Code context (from the reference finding)"
      : "Code context";
    if (isSecretFamilyScanner(finding.scanner_name)) {
      sections.push(`${heading}\n${SNIPPET_WITHHELD}`);
    } else {
      const clipped =
        snippet.length > MAX_SNIPPET_CHARS
          ? `${snippet.slice(0, MAX_SNIPPET_CHARS)}\n… snippet truncated, see AuditGitHub for the full context`
          : snippet;
      sections.push(`${heading}\n${clipped}`);
    }
  }

  // The location list for a project- or org-tier issue is deliberately not
  // built here. The server appends it from the same measurement it counted
  // from, so the list and the count cannot disagree; a dialog previewing it
  // shows `groupSummary.location_text`, which is that same string.

  // For a grouped issue, name some of what it speaks for. A count nobody can
  // check is a count nobody will act on.
  if (scope === "global" && group?.sample_findings?.length) {
    const lines = group.sample_findings.map((f) => {
      const repo = f.repo_name ? `${f.repo_name}: ` : "";
      return `- ${repo}${f.file_path ?? "unknown path"} (${f.id})`;
    });
    const shown = group.sample_findings.length;
    const heading =
      group.count > shown
        ? `Sample occurrences (${shown} of ${group.count})`
        : `Occurrences (${shown})`;
    sections.push(`${heading}\n${lines.join("\n")}`);
  }

  for (const extra of options.extraSections ?? []) {
    const trimmed = extra?.trim();
    if (trimmed) sections.push(trimmed);
  }

  // Provenance last — an issue with no way back to its source is an issue
  // nobody can verify. Skipped only when the destination writes its own.
  if (!options.omitProvenance) {
    const provenance: string[] = [];
    const idLabel = isGroupedScope(scope)
      ? "AuditGitHub reference finding ID"
      : "AuditGitHub finding ID";
    if (finding.id) provenance.push(`${idLabel}: ${finding.id}`);
    if (options.appOrigin && finding.id) {
      provenance.push(`Source: ${options.appOrigin}/findings/${finding.id}`);
    }
    provenance.push("Filed from AuditGitHub. Fields normalized on export.");
    sections.push(provenance.join("\n"));
  }

  return sections.join("\n\n----\n\n");
}

/* ---------------------------------------------------------------------------
   Executive summary
   ------------------------------------------------------------------------ */

/**
 * Length AuditBoard's form asks the Executive Summary to stay under. Guidance
 * from the field's own tooltip, not a server limit — values in the register
 * run past 90 characters — so it drives a hint, never a truncation.
 */
export const EXECUTIVE_SUMMARY_TARGET = 30;

/** Hard cap, so a runaway title cannot fill a GRC field. */
export const MAX_EXECUTIVE_SUMMARY = 255;

/**
 * Plain-language problem phrase per scanner family.
 *
 * Ordered, first match wins, so a scanner matching two patterns resolves the
 * same way every time. Written for someone who does not work in security: no
 * "SAST", no "SCA", no CWE numbers. The scanner name is deliberately not in
 * the text — "gitleaks found something" tells a non-technical reader nothing.
 */
const PLAIN_PROBLEM: Array<[RegExp, string]> = [
  [/gitleaks|trufflehog|whispers|detect.?secret|secret|credential/i, "Password left in our code"],
  [/trivy|grype|osv|snyk|dependency|npm|yarn|retire|safety|pip.?audit/i, "Outdated software in use"],
  [/checkov|tfsec|terrascan|kics|kubesec|hadolint|cloudsploit|prowler/i, "Unsafe system setup"],
  [/mobsf/i, "Unsafe setting in our mobile app"],
  [/nuclei|zap|nikto|nessus|qualys/i, "Weakness on a public website"],
  [/semgrep|bandit|horusec|codeql|gosec|brakeman|sonar|eslint/i, "Unsafe code in our app"],
];

const FALLBACK_PROBLEM = "Security weakness in our code";

/**
 * Impact clause per severity.
 *
 * Says what it could cost, not how likely it is. A scanner measures neither
 * exploitability nor business context, so "could" is the strongest honest verb
 * available here — anything firmer would be a determination this app has not
 * made.
 */
const PLAIN_IMPACT: Record<Severity, string> = {
  critical: "outsiders could get in",
  high: "outsiders could get in",
  medium: "weakens our defenses",
  low: "small risk, worth tidying",
  info: "no known risk, worth tidying",
};

/**
 * One line a non-technical reader can act on: what is wrong, what it could
 * cost. Written for AuditBoard's Executive Summary field, which a director
 * reads in a register list without opening the issue.
 *
 * Derived from scanner family and severity rather than from the finding title.
 * Titles are written by tools for engineers — "Hard-coded password —
 * Siq.Mobile.Appium/Data/accounts.json" names a file nobody outside the team
 * can place — so reusing one here would just move jargon into the field meant
 * to be free of it.
 *
 * The count is included for a grouped issue because "one place" and "304
 * places" are different problems to a reader deciding whether to fund the fix.
 */
export function buildExecutiveSummary(
  finding: FindingLike,
  options: NormalizeOptions = {},
): string {
  const scope = options.scope ?? "specific";
  const severity = normalizeSeverity(finding.severity);
  const scanner = finding.scanner_name ?? "";

  const problem =
    PLAIN_PROBLEM.find(([pattern]) => pattern.test(scanner))?.[1] ?? FALLBACK_PROBLEM;

  const count =
    scope === "project" || scope === "org"
      ? options.groupSummary?.finding_count
      : scope === "global"
        ? options.group?.count
        : undefined;
  const where = count && count > 1 ? ` in ${count} places` : "";
  // Only at org tier, and only when it is more than one: "4 projects" is the
  // fact that makes a director read on, but repeating it for a single project
  // just lengthens a field meant to be read at a glance.
  const projects = options.groupSummary?.project_count ?? 0;
  const across = scope === "org" && projects > 1 ? ` across ${projects} projects` : "";

  return `${problem}${where}${across} — ${PLAIN_IMPACT[severity]}`.slice(
    0,
    MAX_EXECUTIVE_SUMMARY,
  );
}

/**
 * Deterministic label set. Deduped, order stable, empties dropped.
 *
 * Carries a scope-dependent handle so a repeat filing is findable before
 * someone opens a second ticket for the same thing: the finding ID for a
 * specific issue, the scanner-and-path group key for a global one.
 */
export function buildLabels(
  finding: FindingLike,
  options: NormalizeOptions = {},
): string[] {
  const scope = options.scope ?? "specific";
  const severity = normalizeSeverity(finding.severity);

  const candidates = [
    "auditgithub",
    "security-finding",
    toLabel("sev-", severity),
    toLabel("scanner-", finding.scanner_name),
    toLabel("scope-", scope),
  ];

  if (scope === "project" || scope === "org") {
    // The rule is the handle. A searcher looking for a prior filing of this
    // defect knows the rule or the advisory ID, not the path it happened to
    // be found at first.
    const identity =
      options.groupSummary?.identity_key ??
      `${finding.scanner_name ?? "unknown"}-${finding.rule_id ?? "unknown"}`;
    candidates.push(toLabel("defect-", identity));
    if (scope === "project") candidates.push(toLabel("repo-", finding.repo_name));
  } else if (scope === "global") {
    candidates.push(toLabel("group-", `${finding.scanner_name ?? "unknown"}-${finding.file_path ?? "unknown"}`));
  } else {
    candidates.push(toLabel("repo-", finding.repo_name));
    if (finding.id) candidates.push(toLabel("finding-", finding.id.slice(0, 8)));
  }

  return Array.from(new Set(candidates.filter((l): l is string => !!l)));
}
