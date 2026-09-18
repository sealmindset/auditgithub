/**
 * AuditBoard-specific fields for filing a finding as a GRC issue.
 *
 * The issue text is built in `lib/finding-issue.ts`, shared with Jira. What is
 * AuditBoard's alone lives here: the deficiency-level vocabulary and the shape
 * of the create request.
 *
 * Two differences from the Jira path drive this module:
 *
 * 1.  There is no prefill-a-form URL. Creating an issue is an authenticated
 *     API write, so the request goes to our own API and the credential stays
 *     server-side. The browser never holds the AuditBoard token.
 * 2.  There is no confirmation screen on the far side. Pressing the button
 *     creates the record, so the dialog has to show the exact body first.
 *
 * `deficiency_level_id` is the severity-shaped field. `issue_rating_id` is
 * not — its values are control-testing outcomes (Cleared, Tested - Remains
 * Deficient, New Deficiency) and mapping a code severity onto it produces
 * nonsense. This module deliberately never sends it.
 */

import { normalizeSeverity, type Severity } from "./severity";
import {
  buildDescription,
  buildExecutiveSummary,
  buildLabels,
  buildSummary,
  occurrenceCount,
  type FindingLike,
  type IssueScope,
  type NormalizeOptions,
} from "./finding-issue";

export {
  buildExecutiveSummary,
  EXECUTIVE_SUMMARY_TARGET,
  MAX_EXECUTIVE_SUMMARY,
} from "./finding-issue";

export type {
  FindingLike,
  GroupSummary,
  IssueScope,
  OccurrenceGroup,
} from "./finding-issue";

/**
 * Tiers the AuditBoard filing endpoint accepts.
 *
 * `global` is absent on purpose. It is still a valid `IssueScope` — the
 * exception flow and the Jira deep link use it — but the filing endpoint
 * refuses it, because grouping on scanner plus file path put 1,287 unrelated
 * advisories behind one issue. Rows filed before 2026-09-16 keep that scope
 * and are still matched on it.
 */
export const FILING_TIERS = ["specific", "project", "org"] as const;
export type FilingTier = (typeof FILING_TIERS)[number];

/** Whether a scope may be sent to the filing endpoint. */
export function isFilingTier(scope: IssueScope): scope is FilingTier {
  return (FILING_TIERS as readonly string[]).includes(scope);
}

/** Label for a tier, in the words the dialog shows. */
export const FILING_TIER_LABELS: Record<FilingTier, string> = {
  specific: "This finding only",
  project: "This defect in this project",
  org: "This defect in every project",
};

/** An `{ id, name }` pair from AuditBoard's reference vocabularies. */
export interface AuditBoardRef {
  id: number;
  name: string;
}

/**
 * Response of `GET /findings/auditboard/config`.
 *
 * Carries no credential by design — the browser only learns whether the
 * integration works and which values a person may choose from.
 */
export interface AuditBoardConfig {
  enabled: boolean;
  /** Why filing is unavailable, in words a UI can show. Null when it works. */
  problem: string | null;
  base_url: string | null;
  issue_category_id: number | null;
  issue_category_name: string | null;
  /** Record type issues attach to when the category is source-backed, e.g. "Risk". */
  source_type: string | null;
  source_id: number | null;
  create_status: string;
  /** Severity → `deficiency_level_id` the server applies when none is sent. */
  default_deficiency_levels: Partial<Record<Severity, number>>;
  deficiency_levels: AuditBoardRef[];
  standalone_categories: AuditBoardRef[];
  /** Length the category's form asks the Executive Summary to stay under. */
  executive_summary_target_chars: number;
  /** True when the category will not hold a complete issue without one. */
  executive_summary_required: boolean;
  /**
   * Category-required fields the server has no configured value for — a
   * senior owner and a vice president on category 10. Filing works anyway
   * because AuditBoard enforces none of them; the record just lands
   * incomplete, so the dialog says so before it is created.
   */
  unstamped_required_fields: string[];
}

export const EMPTY_AUDITBOARD_CONFIG: AuditBoardConfig = {
  enabled: false,
  problem: null,
  base_url: null,
  issue_category_id: null,
  issue_category_name: null,
  source_type: null,
  source_id: null,
  // Not "Draft" — this instance has no such status, and a placeholder that
  // looks like a real value is worse than one that is obviously a default.
  create_status: "Open",
  default_deficiency_levels: {},
  deficiency_levels: [],
  standalone_categories: [],
  executive_summary_target_chars: 30,
  executive_summary_required: false,
  unstamped_required_fields: [],
};

/**
 * Every scope the filing endpoints can return, including the one no tier
 * describes.
 *
 * `selection` is not in {@link FILING_TIERS} on purpose: the three tiers are
 * rules, so the server can re-derive what each covers from the issue row. A
 * selection is a list of rows someone ticked, so its membership is written
 * down in `auditboard_issue_findings` instead. It is filed through its own
 * endpoint, never offered as a tier in a tier picker.
 */
export type FilingScope = FilingTier | "selection";

/** Body of `POST /findings/selection/auditboard-issue`. */
export interface AuditBoardSelectionIssueRequest {
  finding_ids: string[];
  /**
   * How many findings the filer was shown as selected. The server refuses the
   * request if a different number resolves, which is the guard against filing
   * a permanent record for a smaller set than the person saw ticked.
   */
  expected_count?: number | null;
  title: string;
  description: string;
  deficiency_level_id?: number | null;
  executive_summary?: string | null;
  /** File even when the selection holds findings below the severity floor. */
  include_ineligible?: boolean;
}

/** Body of `POST /findings/{id}/auditboard-issue`. */
export interface AuditBoardIssueRequest {
  scope: FilingTier;
  title: string;
  description: string;
  /** Omit to accept the server's severity mapping. */
  deficiency_level_id?: number | null;
  /** Written to custom_text4, the Executive Summary field. */
  executive_summary?: string | null;
}

/** Response of that POST. */
export interface AuditBoardIssueResult {
  issue_id: string | null;
  issue_url: string | null;
  deficiency_level_id: number;
  deficiency_level_name: string;
  scope: FilingScope;
  /** Counted server-side at filing time, not taken from the request. */
  occurrence_count: number;
  /** Projects the defect affected, measured at filing time. */
  project_count: number;
  /** Distinct locations written into the issue body. */
  location_count: number;
  /** Locations the body cap left out. */
  locations_omitted: number;
  /** `scanner::rule_id` the issue was filed on. Null at `specific`. */
  identity_key: string | null;
}

/** Everything the dialog previews and then sends. */
export interface AuditBoardDraft {
  title: string;
  description: string;
  /**
   * Executive Summary, in plain language. Generated as a starting point — the
   * dialog lets a person rewrite it, because the register is read by people
   * who did not file it and a phrase table cannot know the business context.
   */
  executiveSummary: string;
  severity: Severity;
  scope: FilingTier;
  /** Findings this issue speaks for, as the browser understands it. */
  occurrenceCount: number;
  /**
   * The location section the server will append, verbatim. Empty at
   * `specific`. Shown in the preview rather than folded into `description`:
   * the server writes it from the measurement it counted from, so the list
   * and the count cannot drift apart.
   */
  locationText: string;
  /** Level that will be applied — the override if set, else the default. */
  deficiencyLevelId: number | null;
  /** Name of that level, or null when the vocabulary has not loaded. */
  deficiencyLevelName: string | null;
  /** True when the filer chose a level other than the severity default. */
  deficiencyOverridden: boolean;
}

/**
 * Build the AuditBoard issue as it will be sent.
 *
 * `omitProvenance` is set because the API route appends its own footer with a
 * server-measured occurrence count and the filer's identity. Two footers that
 * can disagree about the same number is worse than one that cannot.
 *
 * Labels are not a field AuditBoard's issues API takes, so the label set goes
 * into the body as a Tags line instead — it is what makes a prior filing of
 * the same finding findable by search before someone opens a second issue.
 */
export function buildAuditBoardDraft(
  finding: FindingLike,
  options: NormalizeOptions & {
    config?: AuditBoardConfig;
    /** Filer's chosen deficiency level. Null accepts the default. */
    deficiencyLevelId?: number | null;
  } = {},
): AuditBoardDraft {
  const requested = options.scope ?? "specific";
  // A scope the filing endpoint would refuse never reaches it. 'global' rows
  // still exist and still display; they are just not written any more.
  const scope: FilingTier = isFilingTier(requested) ? requested : "specific";
  const summary = options.groupSummary ?? null;
  // Highest severity in the group, per the filing rule, so the deficiency
  // level matches what the issue actually covers rather than whichever
  // instance the filer happened to open.
  const severity =
    scope === "specific"
      ? normalizeSeverity(finding.severity)
      : normalizeSeverity(summary?.severity ?? finding.severity);
  const config = options.config ?? EMPTY_AUDITBOARD_CONFIG;

  const scopedOptions: NormalizeOptions = { ...options, scope };
  const tags = buildLabels(finding, scopedOptions);
  const normalizeOpts: NormalizeOptions = {
    ...scopedOptions,
    omitProvenance: true,
    extraSections: [
      ...(options.extraSections ?? []),
      `Tags\n${tags.join(" ")}`,
    ],
  };

  const defaultLevel = config.default_deficiency_levels?.[severity] ?? null;
  const chosen = options.deficiencyLevelId ?? null;
  const effective = chosen ?? defaultLevel;
  const name =
    config.deficiency_levels.find((l) => l.id === effective)?.name ?? null;

  return {
    title: buildSummary(finding, normalizeOpts),
    description: buildDescription(finding, normalizeOpts),
    executiveSummary: buildExecutiveSummary(finding, scopedOptions),
    severity,
    scope,
    occurrenceCount: occurrenceCount(scope, options.group, summary),
    locationText: scope === "specific" ? "" : (summary?.location_text ?? ""),
    deficiencyLevelId: effective,
    deficiencyLevelName: name,
    deficiencyOverridden: chosen !== null && chosen !== defaultLevel,
  };
}

/**
 * Levels that assert a SOX determination rather than describe a weakness.
 *
 * "Significant Deficiency" and "Material Weakness" are terms of art with
 * reporting consequences. A static-analysis hit is evidence of a control
 * weakness, not a determination of one, so the server never maps a severity
 * onto these — a person has to choose them, and the dialog says why.
 */
export const ESCALATED_DEFICIENCY_LEVEL_IDS = new Set([3, 4]);

// ---------------------------------------------------------------------------
// Filing index — annotating a list of findings with the issue each one became
// ---------------------------------------------------------------------------

/** One row of `GET /findings/auditboard/filings`. */
export interface AuditBoardFiling {
  finding_id: string;
  /** Public finding ID. Null once the finding itself has been deleted. */
  finding_uuid: string | null;
  scanner_name: string | null;
  file_path: string | null;
  /** Rule the defect is keyed on. Null on pre-2026-09-16 `global` rows. */
  rule_id: string | null;
  /** Project a `project` row is confined to. Null at every other tier. */
  repository_id: string | null;
  /**
   * Every `scanner::rule_id` this row covers, expanded server-side for
   * reviewer-approved cross-scanner merges. Matching against this rather than
   * against `rule_id` is what keeps the browser out of the equivalence table.
   */
  identity_keys: string[];
  scope: IssueScope;
  issue_id: string;
  issue_uid: string | null;
  issue_url: string | null;
  issue_status: string | null;
  deficiency_level_name: string | null;
  occurrence_count: number;
  /** Projects the defect affected when filed. */
  project_count: number | null;
  filed_by: string | null;
  filed_at: string | null;
}

/** A filing matched to a finding, and how it matched. */
export interface FilingMatch {
  filing: AuditBoardFiling;
  /** True when this finding is the one the issue was filed from. */
  direct: boolean;
}

export interface FilingIndex {
  byFinding: Map<string, AuditBoardFiling>;
  /** `project` rows, keyed by identity and project. */
  byProject: Map<string, AuditBoardFiling>;
  /** `org` rows, keyed by identity alone. */
  byIdentity: Map<string, AuditBoardFiling>;
  /** Pre-2026-09-16 `global` rows, keyed by scanner and path. */
  byLegacyGroup: Map<string, AuditBoardFiling>;
}

/** Defect identity. Must stay identical to `Identity.key` on the server. */
export function filingIdentityKey(
  scannerName: string | null | undefined,
  ruleId: string | null | undefined,
): string {
  return `${scannerName ?? ""}::${ruleId ?? ""}`;
}

/** Identity plus project, for a `project`-tier row. */
export function filingProjectKey(
  identityKey: string,
  repositoryId: string | null | undefined,
): string {
  return `${identityKey}@${repositoryId ?? ""}`;
}

/**
 * Legacy group key: scanner + path.
 *
 * Kept because rows filed before 2026-09-16 carry it, and nothing in
 * AuditBoard can be deleted — those issues have to keep matching their
 * findings. Never written to a new row.
 */
export function filingGroupKey(
  scannerName: string | null | undefined,
  filePath: string | null | undefined,
): string {
  return `${scannerName ?? ""}\u0000${filePath ?? ""}`;
}

/**
 * Index filings for per-row lookup.
 *
 * Built once for a whole table rather than queried per row: a findings list
 * runs to thousands of rows while the filing table holds one row per issue,
 * so one fetch and a few maps beat thousands of requests.
 *
 * A row is indexed under every identity it covers, not only its own, so a
 * reviewer-approved cross-scanner merge annotates the other scanner's
 * findings too.
 */
export function buildFilingIndex(rows: AuditBoardFiling[]): FilingIndex {
  const byFinding = new Map<string, AuditBoardFiling>();
  const byProject = new Map<string, AuditBoardFiling>();
  const byIdentity = new Map<string, AuditBoardFiling>();
  const byLegacyGroup = new Map<string, AuditBoardFiling>();

  for (const row of rows) {
    if (row.finding_uuid) byFinding.set(row.finding_uuid, row);

    if (row.scope === "global") {
      byLegacyGroup.set(filingGroupKey(row.scanner_name, row.file_path), row);
      continue;
    }

    const keys =
      row.identity_keys?.length > 0
        ? row.identity_keys
        : [filingIdentityKey(row.scanner_name, row.rule_id)];

    if (row.scope === "project") {
      for (const key of keys) byProject.set(filingProjectKey(key, row.repository_id), row);
    } else if (row.scope === "org") {
      for (const key of keys) byIdentity.set(key, row);
    }
  }

  return { byFinding, byProject, byIdentity, byLegacyGroup };
}

/**
 * Find the issue covering a finding, if any.
 *
 * A direct match wins over a group match when both exist: "this was filed"
 * and "something else covers this" are different statements, and the stronger
 * one is the one worth showing. Group matches are tried narrowest first —
 * project, then organization, then the retired scanner-and-path key — so the
 * issue shown is the one whose scope sits closest to the finding in hand.
 */
export function lookupFiling(
  index: FilingIndex | null,
  finding: {
    id?: string;
    scanner_name?: string | null;
    rule_id?: string | null;
    repository_id?: string | null;
    file_path?: string | null;
  },
): FilingMatch | null {
  if (!index) return null;

  const direct = finding.id ? index.byFinding.get(finding.id) : undefined;
  if (direct) return { filing: direct, direct: true };

  if (finding.rule_id) {
    const identity = filingIdentityKey(finding.scanner_name, finding.rule_id);
    const project = index.byProject.get(filingProjectKey(identity, finding.repository_id));
    if (project) return { filing: project, direct: false };
    const org = index.byIdentity.get(identity);
    if (org) return { filing: org, direct: false };
  }

  const legacy = index.byLegacyGroup.get(
    filingGroupKey(finding.scanner_name, finding.file_path),
  );
  return legacy ? { filing: legacy, direct: false } : null;
}
