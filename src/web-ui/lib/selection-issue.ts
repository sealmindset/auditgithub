/**
 * Issue text for a hand-picked selection of findings.
 *
 * `finding-issue.ts` builds an issue from one finding plus a scope, because
 * every scope it knows about *is* a rule: the scope names a population and the
 * server can re-derive it. A selection is not a rule. It is the rows someone
 * ticked, which can span scanners, rules, severities and projects with nothing
 * in common but the person's judgement — so there is no single finding to
 * normalize from, and no rule to state.
 *
 * What that changes about the text:
 *
 *   * The title cannot name the defect, because there may be several. It names
 *     the count and the severity ceiling instead.
 *   * The body has to enumerate the defects, not describe one. A reader who
 *     cannot tell which defects an issue covers cannot act on it, and an
 *     AuditBoard issue's description cannot be edited after it is created.
 *   * The scope line has to say the issue speaks only for these findings. The
 *     grouped tiers cover future findings of the same defect automatically; a
 *     selection never does, and a reader who assumes otherwise will close it
 *     believing more was fixed than was.
 *
 * The server builds the locations section and the provenance footer. This
 * module deliberately does not, so the count in the footer is one the server
 * measured rather than one the browser guessed from a capped table.
 */

import {
  SEVERITIES,
  SEVERITY_RANK,
  normalizeSeverity,
  severityLabel,
  type Severity,
} from "./severity";
import {
  MAX_SUMMARY,
  MAX_EXECUTIVE_SUMMARY,
  isSecretFamilyScanner,
  type FindingLike,
} from "./finding-issue";

/** Defects to name individually in the body before switching to a count. */
export const MAX_DEFECTS_LISTED = 25;

/** Projects to name individually in the executive summary. */
export const MAX_PROJECTS_NAMED = 6;

/** Measurement of a selection, as returned by `POST /findings/selection/preview`. */
export interface SelectionPreview {
  finding_count: number;
  submitted_count: number;
  project_count: number;
  location_count: number;
  locations_omitted: number;
  severity: string | null;
  severity_breakdown: Array<{ scanner: string; severity: string; count: number }>;
  identity_keys: string[];
  repo_names: string[];
  missing_ids: string[];
  ineligible: Array<{ finding_id: string; reason: string }>;
  already_filed: string[];
}

function oneLine(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

/** Severity ceiling of a set. The merged rating rule: highest of the members. */
export function selectionSeverity(findings: FindingLike[]): Severity {
  // Ranked off the shared table rather than a local order, so the browser and
  // `severity_rank` in finding_groups.py cannot drift apart on which of two
  // severities is worse.
  let worst: Severity = SEVERITIES[SEVERITIES.length - 1];
  for (const finding of findings) {
    const candidate = normalizeSeverity(finding.severity);
    if (SEVERITY_RANK[candidate] < SEVERITY_RANK[worst]) worst = candidate;
  }
  return worst;
}

/**
 * Defect identities in the selection, as `scanner::rule`, deduplicated.
 *
 * Derived in the browser only as a fallback for the preview's `identity_keys`:
 * the server's list is authoritative because it is built from the same service
 * that decides what an issue covers.
 */
export function selectionIdentities(findings: FindingLike[]): string[] {
  const keys = new Set<string>();
  for (const finding of findings) {
    const scanner = (finding.scanner_name || "unknown").trim();
    const rule = (finding.rule_id || "").trim();
    keys.add(rule ? `${scanner}::${rule}` : scanner);
  }
  return Array.from(keys).sort();
}

/**
 * Title for a selection issue.
 *
 * Severity leads, as everywhere else in this app, so a backlog sorted on text
 * alone still sorts usefully. Then the finding count, because that is the only
 * honest single-phrase description of a set the filer assembled by hand. When
 * every ticked row is the same defect the title says which one — that is a
 * common case (one defect, one project, a few files) and naming it beats
 * making a reader open the issue to find out.
 */
export function buildSelectionSummary(
  findings: FindingLike[],
  preview?: SelectionPreview | null,
): string {
  const count = preview?.finding_count ?? findings.length;
  const severity = preview?.severity
    ? normalizeSeverity(preview.severity)
    : selectionSeverity(findings);
  const identities = preview?.identity_keys?.length
    ? preview.identity_keys
    : selectionIdentities(findings);

  const prefix = `[${severityLabel(severity)}] `;
  let subject: string;
  if (identities.length === 1 && findings.length > 0) {
    const title = oneLine(findings[0].title || identities[0]);
    subject = `${title} — ${count} selected finding${count === 1 ? "" : "s"}`;
  } else {
    subject =
      `${count} selected finding${count === 1 ? "" : "s"} across ` +
      `${identities.length} defect${identities.length === 1 ? "" : "s"}`;
  }

  const projects = preview?.project_count ?? 0;
  const suffix = projects > 1 ? ` in ${projects} projects` : "";
  const full = `${prefix}${subject}${suffix}`;
  if (full.length <= MAX_SUMMARY) return full;
  return `${full.slice(0, MAX_SUMMARY - 1)}…`;
}

/**
 * Body for a selection issue, minus locations and provenance.
 *
 * Opens with the scope limit rather than closing with it. A reader who stops
 * after the first two lines must still come away knowing this issue covers a
 * fixed list and not a class of defect, because that is the mistake that
 * causes an issue to be closed while the same bug is still shipping elsewhere.
 */
export function buildSelectionDescription(
  findings: FindingLike[],
  preview?: SelectionPreview | null,
  options: { appOrigin?: string | null } = {},
): string {
  const count = preview?.finding_count ?? findings.length;
  const severity = preview?.severity
    ? normalizeSeverity(preview.severity)
    : selectionSeverity(findings);
  const identities = preview?.identity_keys?.length
    ? preview.identity_keys
    : selectionIdentities(findings);

  const sections: string[] = [];

  sections.push(
    [
      "Scope",
      `This issue covers ${count} specific finding${count === 1 ? "" : "s"}, ` +
        "chosen individually in AuditGitHub. It does NOT cover other " +
        "occurrences of the same defects, and it does not cover findings " +
        "reported by future scans. Closing it means these findings were " +
        "resolved — not that the defect class was eliminated.",
    ].join("\n"),
  );

  const severityLine = `Severity: ${severityLabel(severity)} (highest in the selection)`;
  const projectLine =
    preview?.project_count != null
      ? `Projects affected: ${preview.project_count}`
      : null;
  const locationLine =
    preview?.location_count != null
      ? `Distinct locations: ${preview.location_count}`
      : null;
  sections.push(
    ["Summary", severityLine, projectLine, locationLine]
      .filter(Boolean)
      .join("\n"),
  );

  if (identities.length) {
    const shown = identities.slice(0, MAX_DEFECTS_LISTED);
    const lines = shown.map((key) => `- ${key}`);
    if (identities.length > shown.length) {
      lines.push(
        `- … and ${identities.length - shown.length} further defect(s). ` +
          "The full list is in AuditGitHub.",
      );
    }
    sections.push(
      [
        `Defects in this issue (${identities.length})`,
        "Each line is a scanner and its own rule identifier — the pair that " +
          "identifies one defect.",
        ...lines,
      ].join("\n"),
    );
  }

  // Severity mix, only when it is actually mixed. A single-severity selection
  // already has its rating on the Summary line, and repeating it reads as a
  // second, different figure.
  const breakdown = preview?.severity_breakdown ?? [];
  const severities = new Set(breakdown.map((row) => normalizeSeverity(row.severity)));
  if (severities.size > 1) {
    const rows = breakdown
      .slice()
      .sort((a, b) => b.count - a.count)
      .map(
        (row) =>
          `- ${severityLabel(normalizeSeverity(row.severity))} — ${row.count} ` +
          `from ${row.scanner || "unknown scanner"}`,
      );
    sections.push(
      [
        "Severity mix",
        `Rated at ${severityLabel(severity)}, the highest present. The ` +
          "selection also contains lower-severity findings:",
        ...rows,
      ].join("\n"),
    );
  }

  // Named, not counted. An issue that covers findings the normal severity
  // floor would have refused has to say so, or a reader cannot tell why an
  // informational finding is in a High-rated issue.
  if (preview?.ineligible?.length) {
    sections.push(
      [
        `Included below the filing floor (${preview.ineligible.length})`,
        "These were selected deliberately. The filing policy would not have " +
          "raised an issue for them on their own:",
        ...preview.ineligible
          .slice(0, MAX_DEFECTS_LISTED)
          .map((row) => `- ${row.finding_id} — ${row.reason}`),
      ].join("\n"),
    );
  }

  // Secret-scanner snippets are withheld server-side too, by
  // src/api/services/issue_redaction.py. Said here so the person filing knows
  // before they press, rather than discovering an issue body differs from the
  // preview they approved.
  const secretScanners = Array.from(
    new Set(
      findings
        .filter((f) => isSecretFamilyScanner(f.scanner_name))
        .map((f) => (f.scanner_name || "").trim())
        .filter(Boolean),
    ),
  ).sort();
  if (secretScanners.length) {
    sections.push(
      [
        "Withheld content",
        `${secretScanners.join(", ")} report the matched secret itself. The ` +
          "matched lines are not copied into this issue, because that would " +
          "put a working credential in a second system that cannot delete " +
          "it. Open the findings in AuditGitHub to see them.",
      ].join("\n"),
    );
  }

  const origin = options.appOrigin?.trim();
  if (origin) {
    sections.push(
      ["Where to see the selection", `${origin.replace(/\/+$/, "")}/findings`].join("\n"),
    );
  }

  return sections.join("\n\n");
}

/**
 * One line for a non-technical reader: what is wrong and what it puts at risk.
 *
 * Caps hard at {@link MAX_EXECUTIVE_SUMMARY} because AuditBoard truncates
 * silently, and a sentence cut mid-clause is worse than a shorter one.
 */
export function buildSelectionExecutiveSummary(
  findings: FindingLike[],
  preview?: SelectionPreview | null,
): string {
  const count = preview?.finding_count ?? findings.length;
  const severity = preview?.severity
    ? normalizeSeverity(preview.severity)
    : selectionSeverity(findings);
  const identities = preview?.identity_keys?.length
    ? preview.identity_keys
    : selectionIdentities(findings);
  const repos = preview?.repo_names ?? [];

  const where =
    repos.length === 0
      ? ""
      : repos.length <= MAX_PROJECTS_NAMED
        ? ` in ${repos.join(", ")}`
        : ` across ${repos.length} projects`;

  const what =
    identities.length === 1
      ? `one security defect`
      : `${identities.length} distinct security defects`;

  const line = oneLine(
    `${count} reviewed security finding${count === 1 ? "" : "s"}${where} ` +
      `cover ${what}, the most serious rated ${severityLabel(severity)}. ` +
      `Left unfixed they remain exploitable in code we ship.`,
  );

  if (line.length <= MAX_EXECUTIVE_SUMMARY) return line;
  return `${line.slice(0, MAX_EXECUTIVE_SUMMARY - 1)}…`;
}
