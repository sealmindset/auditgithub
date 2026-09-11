/**
 * Chart palette.
 *
 * Recharts wants a colour string per series. Passing `var(--chart-1)` lets the
 * SVG follow the theme, so a chart re-colours on light/dark switch instead of
 * staying stuck in whichever mode it was first painted in.
 *
 * Before this module, six files each declared their own severity colour map and
 * they disagreed: "Low" rendered as two different greens in SecurityReportModal,
 * SecurityOverviewWidget and FindingTrendsWidget, and as blue in
 * ContributorsView and app/findings/page.tsx. The exact values are recorded in
 * docs/playbooks/ui-design-system-report.md §1.1. Everything now resolves
 * through `severityColor`.
 */

import { SEVERITY_TONE, normalizeSeverity } from "@/lib/severity";

/** Colour for a severity name in any casing. */
export function severityColor(name: string | null | undefined): string {
  return SEVERITY_TONE[normalizeSeverity(name)].cssVar;
}

/** Ordered severity series, most severe first. */
export const SEVERITY_SERIES = [
  { key: "critical", label: "Critical", color: "var(--sev-critical)" },
  { key: "high", label: "High", color: "var(--sev-high)" },
  { key: "medium", label: "Medium", color: "var(--sev-medium)" },
  { key: "low", label: "Low", color: "var(--sev-low)" },
  { key: "info", label: "Info", color: "var(--sev-info)" },
] as const;

/**
 * Categorical palette for data that is not severity — languages, scan types,
 * contributors. Ordered so that neighbouring series stay distinguishable for
 * the most common colour-vision deficiencies.
 */
export const CATEGORICAL = [
  "var(--chart-1)",
  "var(--chart-2)",
  "var(--chart-3)",
  "var(--chart-4)",
  "var(--chart-5)",
  "var(--chart-6)",
  "var(--chart-7)",
  "var(--chart-8)",
] as const;

/** Stable colour for an arbitrary category label. */
export function categoricalColor(index: number): string {
  return CATEGORICAL[index % CATEGORICAL.length];
}

/**
 * Ten-step ramp for the "worst ten days" dots on the activity heat map.
 *
 * This is the one place the design system keeps literal colours. The five
 * severity tokens cannot express a rank of ten, and the ramp is data rather
 * than chrome: rank 0 must read as hotter than rank 9 at a glance, in both
 * themes, which means it cannot flip lightness with the theme the way a token
 * does. Kept here rather than inline in the component so there is a single
 * definition to review.
 */
export const CRITICAL_RANK_RAMP = [
  { bg: "rgb(139, 92, 246)", glow: "rgba(139, 92, 246, 0.7)" }, // violet
  { bg: "rgb(167, 76, 194)", glow: "rgba(167, 76, 194, 0.6)" },
  { bg: "rgb(194, 60, 142)", glow: "rgba(194, 60, 142, 0.6)" }, // magenta
  { bg: "rgb(220, 56, 100)", glow: "rgba(220, 56, 100, 0.6)" },
  { bg: "rgb(239, 68, 68)", glow: "rgba(239, 68, 68, 0.6)" }, // red
  { bg: "rgb(245, 101, 58)", glow: "rgba(245, 101, 58, 0.5)" },
  { bg: "rgb(251, 134, 48)", glow: "rgba(251, 134, 48, 0.5)" }, // orange
  { bg: "rgb(252, 165, 60)", glow: "rgba(252, 165, 60, 0.4)" },
  { bg: "rgb(253, 196, 90)", glow: "rgba(253, 196, 90, 0.4)" }, // amber
  { bg: "rgb(253, 230, 138)", glow: "rgba(253, 230, 138, 0.3)" },
] as const;

/** Ramp entry for a rank, clamped to the ends. */
export function criticalRankColor(rank: number): (typeof CRITICAL_RANK_RAMP)[number] {
  const i = Math.min(Math.max(rank, 0), CRITICAL_RANK_RAMP.length - 1);
  return CRITICAL_RANK_RAMP[i];
}

/** Shared Recharts chrome so axes and grids match the rest of the UI. */
export const AXIS_PROPS = {
  stroke: "var(--muted-foreground)",
  fontSize: 11,
  tickLine: false,
  axisLine: false,
} as const;

export const GRID_PROPS = {
  stroke: "var(--border)",
  strokeDasharray: "3 3",
  vertical: false,
} as const;

export const TOOLTIP_PROPS = {
  cursor: { fill: "var(--accent)", opacity: 0.4 },
  contentStyle: {
    background: "var(--popover)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius-md)",
    boxShadow: "var(--elev-md)",
    color: "var(--popover-foreground)",
    fontSize: "0.8125rem",
    padding: "0.5rem 0.75rem",
  },
  labelStyle: {
    color: "var(--muted-foreground)",
    fontSize: "0.6875rem",
    fontWeight: 600,
    textTransform: "uppercase" as const,
    letterSpacing: "0.04em",
    marginBottom: "0.25rem",
  },
  itemStyle: { color: "var(--popover-foreground)" },
} as const;
