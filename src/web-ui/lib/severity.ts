/**
 * Severity and status vocabulary.
 *
 * The app renders severity in ~40 places. Before this module each of them
 * invented its own colours, so "High" was orange in one table, yellow in the
 * next, and a plain grey badge in a third. Everything that names a severity or
 * a lifecycle status now resolves it here, against the design tokens in
 * `app/globals.css`.
 */

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Rank for sorting — lower sorts first (most severe first). */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SEVERITY_ALIASES: Record<string, Severity> = {
  critical: "critical",
  crit: "critical",
  severe: "critical",
  blocker: "critical",
  error: "critical",
  high: "high",
  important: "high",
  major: "high",
  moderate: "medium",
  medium: "medium",
  med: "medium",
  warning: "medium",
  minor: "low",
  low: "low",
  info: "info",
  informational: "info",
  note: "info",
  unknown: "info",
  none: "info",
};

/** Map any casing/synonym the API returns onto the canonical ramp. */
export function normalizeSeverity(value: string | null | undefined): Severity {
  if (!value) return "info";
  return SEVERITY_ALIASES[value.trim().toLowerCase()] ?? "info";
}

/** Human label, title-cased. */
export function severityLabel(value: string | null | undefined): string {
  const s = normalizeSeverity(value);
  return s === "info" ? "Info" : s.charAt(0).toUpperCase() + s.slice(1);
}

/** CVSS-style numeric score to a band. */
export function severityFromScore(score: number | null | undefined): Severity {
  if (score === null || score === undefined || Number.isNaN(score)) return "info";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

/** Risk score (0-100) to a band. */
export function severityFromRisk(score: number | null | undefined): Severity {
  if (score === null || score === undefined || Number.isNaN(score)) return "info";
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

interface ToneClasses {
  /** Tinted surface + readable text + matching hairline. Default badge look. */
  soft: string;
  /** Saturated fill. Reserve for the one thing that must dominate. */
  solid: string;
  /** On-canvas text/icon colour. */
  text: string;
  /** Filled dot / bar / sparkline segment. */
  dot: string;
  /** Border only. */
  line: string;
  /** CSS variable, for Recharts and other libraries that want a raw colour. */
  cssVar: string;
}

export const SEVERITY_TONE: Record<Severity, ToneClasses> = {
  critical: {
    soft: "bg-sev-critical-soft text-sev-critical-text border-sev-critical-line",
    solid: "bg-sev-critical text-sev-critical-foreground border-transparent",
    text: "text-sev-critical-text",
    dot: "bg-sev-critical",
    line: "border-sev-critical-line",
    cssVar: "var(--sev-critical)",
  },
  high: {
    soft: "bg-sev-high-soft text-sev-high-text border-sev-high-line",
    solid: "bg-sev-high text-sev-high-foreground border-transparent",
    text: "text-sev-high-text",
    dot: "bg-sev-high",
    line: "border-sev-high-line",
    cssVar: "var(--sev-high)",
  },
  medium: {
    soft: "bg-sev-medium-soft text-sev-medium-text border-sev-medium-line",
    solid: "bg-sev-medium text-sev-medium-foreground border-transparent",
    text: "text-sev-medium-text",
    dot: "bg-sev-medium",
    line: "border-sev-medium-line",
    cssVar: "var(--sev-medium)",
  },
  low: {
    soft: "bg-sev-low-soft text-sev-low-text border-sev-low-line",
    solid: "bg-sev-low text-sev-low-foreground border-transparent",
    text: "text-sev-low-text",
    dot: "bg-sev-low",
    line: "border-sev-low-line",
    cssVar: "var(--sev-low)",
  },
  info: {
    soft: "bg-sev-info-soft text-sev-info-text border-sev-info-line",
    solid: "bg-sev-info text-sev-info-foreground border-transparent",
    text: "text-sev-info-text",
    dot: "bg-sev-info",
    line: "border-sev-info-line",
    cssVar: "var(--sev-info)",
  },
};

/** Ordered colours for severity-stacked charts. */
export const SEVERITY_CHART_COLORS = SEVERITIES.map(
  (s) => SEVERITY_TONE[s].cssVar,
);

/* ---------------------------------------------------------------------------
   Lifecycle status
   ------------------------------------------------------------------------ */

export type StatusTone = "neutral" | "info" | "success" | "warning" | "danger" | "ai";

export const STATUS_TONE: Record<StatusTone, ToneClasses> = {
  neutral: {
    soft: "bg-muted text-muted-foreground border-border",
    solid: "bg-secondary text-secondary-foreground border-transparent",
    text: "text-muted-foreground",
    dot: "bg-muted-foreground",
    line: "border-border",
    cssVar: "var(--muted-foreground)",
  },
  info: {
    soft: "bg-info-soft text-info-text border-info-line",
    solid: "bg-info text-info-foreground border-transparent",
    text: "text-info-text",
    dot: "bg-info",
    line: "border-info-line",
    cssVar: "var(--info)",
  },
  success: {
    soft: "bg-success-soft text-success-text border-success-line",
    solid: "bg-success text-success-foreground border-transparent",
    text: "text-success-text",
    dot: "bg-success",
    line: "border-success-line",
    cssVar: "var(--success)",
  },
  warning: {
    soft: "bg-warning-soft text-warning-text border-warning-line",
    solid: "bg-warning text-warning-foreground border-transparent",
    text: "text-warning-text",
    dot: "bg-warning",
    line: "border-warning-line",
    cssVar: "var(--warning)",
  },
  danger: {
    soft: "bg-danger-soft text-danger-text border-danger-line",
    solid: "bg-danger text-danger-foreground border-transparent",
    text: "text-danger-text",
    dot: "bg-danger",
    line: "border-danger-line",
    cssVar: "var(--danger)",
  },
  ai: {
    soft: "bg-ai-soft text-ai-text border-ai-line",
    solid: "bg-ai text-ai-foreground border-transparent",
    text: "text-ai-text",
    dot: "bg-ai",
    line: "border-ai-line",
    cssVar: "var(--ai)",
  },
};

const STATUS_MAP: Record<string, StatusTone> = {
  // Resolved / healthy
  resolved: "success",
  fixed: "success",
  closed: "success",
  passed: "success",
  pass: "success",
  success: "success",
  succeeded: "success",
  completed: "success",
  complete: "success",
  healthy: "success",
  active: "success",
  enabled: "success",
  online: "success",
  up: "success",
  verified: "success",
  approved: "success",
  merged: "success",
  // In flight
  running: "info",
  scanning: "info",
  "in_progress": "info",
  "in-progress": "info",
  pending: "info",
  queued: "info",
  scheduled: "info",
  new: "info",
  open: "info",
  // Needs attention
  investigating: "warning",
  triage: "warning",
  triaged: "warning",
  review: "warning",
  "needs_review": "warning",
  warning: "warning",
  degraded: "warning",
  stale: "warning",
  partial: "warning",
  paused: "warning",
  deferred: "warning",
  // Bad
  failed: "danger",
  failure: "danger",
  error: "danger",
  errored: "danger",
  blocked: "danger",
  rejected: "danger",
  revoked: "danger",
  expired: "danger",
  breached: "danger",
  offline: "danger",
  down: "danger",
  vulnerable: "danger",
  // AI-produced
  "ai_analyzed": "ai",
  "ai-analyzed": "ai",
  analyzed: "ai",
  remediated: "ai",
  // Inert
  disabled: "neutral",
  inactive: "neutral",
  archived: "neutral",
  skipped: "neutral",
  ignored: "neutral",
  suppressed: "neutral",
  "false_positive": "neutral",
  "false-positive": "neutral",
  unknown: "neutral",
  draft: "neutral",
  cancelled: "neutral",
  canceled: "neutral",
};

/** Map a lifecycle status string onto a tone. Unrecognised falls back to neutral. */
export function statusTone(value: string | null | undefined): StatusTone {
  if (!value) return "neutral";
  return STATUS_MAP[value.trim().toLowerCase().replace(/\s+/g, "_")] ?? "neutral";
}

/** Title-case a snake_case or kebab-case status for display. */
export function statusLabel(value: string | null | undefined): string {
  if (!value) return "Unknown";
  return value
    .trim()
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

/**
 * Tone for a delta. `higherIsBetter` distinguishes "5 more repositories
 * scanned" (good) from "5 more critical findings" (bad).
 */
export function trendTone(
  delta: number,
  higherIsBetter: boolean,
): StatusTone {
  if (delta === 0) return "neutral";
  return delta > 0 === higherIsBetter ? "success" : "danger";
}
