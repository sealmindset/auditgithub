"use client"

import { useState, useEffect, useCallback } from "react"

const STORAGE_KEY = "auditgh-dashboard-layout"

export type WidgetId =
  | "hero-metrics"
  | "security-overview"
  | "scan-activity"
  | "background-jobs"
  | "repository-health"
  | "finding-trends"
  | "quick-actions"
  | "threat-radar"
  | "scan-schedule-graph"
  | "ai-insights"
  | "executive-summary"
  | "severity-chart"
  | "recent-findings"

export interface WidgetConfig {
  id: WidgetId
  label: string
  description: string
  defaultVisible: boolean
}

export const WIDGET_CONFIGS: WidgetConfig[] = [
  {
    id: "hero-metrics",
    label: "Hero Metrics",
    description: "Top-level security metrics overview",
    defaultVisible: true
  },
  {
    id: "security-overview",
    label: "Security Overview",
    description: "Severity distribution pie chart",
    defaultVisible: true
  },
  {
    id: "scan-activity",
    label: "Scan Activity",
    description: "Recent scan timeline",
    defaultVisible: true
  },
  {
    id: "background-jobs",
    label: "Background Jobs",
    description: "Scheduler job status",
    defaultVisible: true
  },
  {
    id: "repository-health",
    label: "Repository Health",
    description: "Risk scores by repository",
    defaultVisible: true
  },
  {
    id: "finding-trends",
    label: "Finding Trends",
    description: "Findings over time chart",
    defaultVisible: true
  },
  {
    id: "quick-actions",
    label: "Quick Actions",
    description: "Navigation shortcuts",
    defaultVisible: true
  },
  {
    id: "threat-radar",
    label: "Threat Radar",
    description: "Visual threat assessment",
    defaultVisible: true
  },
  {
    id: "scan-schedule-graph",
    label: "Scan Schedule Graph",
    description: "GitHub-style activity heatmap for scheduled scans",
    defaultVisible: true
  },
  {
    id: "ai-insights",
    label: "AI Insights",
    description: "AI-powered analysis feed",
    defaultVisible: true
  },
  {
    id: "executive-summary",
    label: "Executive Summary",
    description: "Key metrics cards",
    defaultVisible: true
  },
  {
    id: "severity-chart",
    label: "Severity Distribution",
    description: "Detailed severity breakdown",
    defaultVisible: true
  },
  {
    id: "recent-findings",
    label: "Recent Findings",
    description: "Critical findings table",
    defaultVisible: true
  }
]

type VisibilityState = Record<WidgetId, boolean>

function getDefaultVisibility(): VisibilityState {
  return WIDGET_CONFIGS.reduce((acc, config) => {
    acc[config.id] = config.defaultVisible
    return acc
  }, {} as VisibilityState)
}

export function useDashboardLayout() {
  const [visibility, setVisibility] = useState<VisibilityState>(getDefaultVisibility)
  const [isLoaded, setIsLoaded] = useState(false)

  // Load from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY)
      if (stored) {
        const parsed = JSON.parse(stored)
        // Merge with defaults to handle new widgets
        setVisibility(prev => ({
          ...getDefaultVisibility(),
          ...parsed
        }))
      }
    } catch (e) {
      console.error("Failed to load dashboard layout:", e)
    }
    setIsLoaded(true)
  }, [])

  // Save to localStorage when visibility changes
  useEffect(() => {
    if (isLoaded) {
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(visibility))
      } catch (e) {
        console.error("Failed to save dashboard layout:", e)
      }
    }
  }, [visibility, isLoaded])

  const isVisible = useCallback((id: WidgetId): boolean => {
    return visibility[id] ?? true
  }, [visibility])

  const toggleWidget = useCallback((id: WidgetId) => {
    setVisibility(prev => ({
      ...prev,
      [id]: !prev[id]
    }))
  }, [])

  const setWidgetVisible = useCallback((id: WidgetId, visible: boolean) => {
    setVisibility(prev => ({
      ...prev,
      [id]: visible
    }))
  }, [])

  const resetToDefaults = useCallback(() => {
    setVisibility(getDefaultVisibility())
  }, [])

  const visibleCount = Object.values(visibility).filter(Boolean).length
  const totalCount = WIDGET_CONFIGS.length

  return {
    visibility,
    isVisible,
    toggleWidget,
    setWidgetVisible,
    resetToDefaults,
    isLoaded,
    visibleCount,
    totalCount,
    configs: WIDGET_CONFIGS
  }
}
