"use client"

import { useState, useEffect, useCallback, useRef } from "react"
import { useSearchParams } from "next/navigation"
import { API_BASE } from "@/lib/api"

interface UseWidgetDataOptions<T> {
  /** Auto-refresh interval in milliseconds (default: none) */
  refreshInterval?: number
  /** Whether to fetch data (default: true) */
  enabled?: boolean
  /** Initial data while loading */
  initialData?: T
}

interface UseWidgetDataResult<T> {
  /** Fetched data or null if not yet loaded */
  data: T | null
  /** Whether initial load is in progress */
  loading: boolean
  /** Error message if fetch failed */
  error: string | null
  /** Manually trigger a refetch */
  refetch: () => Promise<void>
}

/**
 * useWidgetData - Standardized data fetching hook for dashboard widgets
 *
 * Features:
 * - Auto-refresh with configurable interval
 * - Respects org query param from URL
 * - Handles API errors gracefully
 * - Returns refetch function for manual refresh
 *
 * @param endpoint - API endpoint path (e.g., "/analytics/hero-metrics")
 * @param options - Configuration options
 */
export function useWidgetData<T>(
  endpoint: string,
  options: UseWidgetDataOptions<T> = {}
): UseWidgetDataResult<T> {
  const {
    refreshInterval,
    enabled = true,
    initialData,
  } = options

  const [data, setData] = useState<T | null>(initialData ?? null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const searchParams = useSearchParams()
  const currentOrg = searchParams.get("org")

  // Use ref to track if component is mounted (avoid state updates after unmount)
  const isMounted = useRef(true)

  const fetchData = useCallback(async () => {
    if (!enabled) {
      setLoading(false)
      return
    }

    try {
      // Build URL with org param if present
      const url = new URL(`${API_BASE}${endpoint}`)
      if (currentOrg) {
        url.searchParams.set("org", currentOrg)
      }

      const response = await fetch(url.toString(), {
        credentials: "include",
      })

      if (!response.ok) {
        throw new Error(`Failed to fetch: ${response.status} ${response.statusText}`)
      }

      const result = await response.json()

      if (isMounted.current) {
        setData(result)
        setError(null)
      }
    } catch (err) {
      if (isMounted.current) {
        setError(err instanceof Error ? err.message : "An unexpected error occurred")
      }
    } finally {
      if (isMounted.current) {
        setLoading(false)
      }
    }
  }, [endpoint, currentOrg, enabled])

  // Initial fetch and refresh interval
  useEffect(() => {
    isMounted.current = true

    fetchData()

    let intervalId: NodeJS.Timeout | undefined
    if (refreshInterval && refreshInterval > 0) {
      intervalId = setInterval(fetchData, refreshInterval)
    }

    return () => {
      isMounted.current = false
      if (intervalId) {
        clearInterval(intervalId)
      }
    }
  }, [fetchData, refreshInterval])

  // Refetch when org changes
  useEffect(() => {
    if (!loading) {
      setLoading(true)
      fetchData()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentOrg])

  const refetch = useCallback(async () => {
    setLoading(true)
    await fetchData()
  }, [fetchData])

  return {
    data,
    loading,
    error,
    refetch,
  }
}
