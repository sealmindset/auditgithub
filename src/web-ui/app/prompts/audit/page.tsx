"use client"

import { useEffect, useState, useCallback } from "react"
import { API_BASE, apiFetch } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Loader2, History, ChevronLeft, ChevronRight } from "lucide-react"
import Link from "next/link"

interface AuditLogEntry {
  id: string
  action: string
  prompt_id: string
  prompt_slug: string
  version: number | null
  user_id: string | null
  user_email: string | null
  old_value: Record<string, any> | null
  new_value: Record<string, any> | null
  ip_address: string | null
  created_at: string
}

interface AuditLogResponse {
  items: AuditLogEntry[]
  total: number
  skip: number
  limit: number
}

const ACTION_COLORS: Record<string, string> = {
  created: "bg-success/15 text-success-text border-success/20",
  updated: "bg-info/15 text-info-text border-info/20",
  restored: "bg-warning/15 text-warning-text border-warning/20",
  activated: "bg-success/15 text-success-text border-success/20",
  deactivated: "bg-danger/15 text-danger-text border-danger/20",
  locked: "bg-warning/15 text-warning-text border-warning/20",
  unlocked: "bg-info/15 text-info-text border-info/20",
  deleted: "bg-danger/15 text-danger-text border-danger/20",
  tested: "bg-ai/15 text-ai-text border-ai/20",
  imported: "bg-info/15 text-info-text border-info/20",
}

const ACTIONS = [
  "created", "updated", "restored", "activated", "deactivated",
  "locked", "unlocked", "deleted", "tested", "imported",
]

export default function PromptAuditLogPage() {
  const [entries, setEntries] = useState<AuditLogEntry[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(0)
  const [actionFilter, setActionFilter] = useState<string>("all")
  const [slugFilter, setSlugFilter] = useState("")
  const limit = 25

  const fetchAudit = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams({
        skip: String(page * limit),
        limit: String(limit),
      })
      if (actionFilter !== "all") params.set("action", actionFilter)
      if (slugFilter) params.set("slug", slugFilter)

      const res = await apiFetch(`${API_BASE}/prompts/audit?${params}`)
      if (res.ok) {
        const data: AuditLogResponse = await res.json()
        setEntries(data.items)
        setTotal(data.total)
      }
    } catch (err) {
      console.error("Failed to fetch audit log:", err)
    } finally {
      setLoading(false)
    }
  }, [page, actionFilter, slugFilter])

  useEffect(() => {
    fetchAudit()
  }, [fetchAudit])

  const totalPages = Math.ceil(total / limit)

  function formatDate(iso: string) {
    const d = new Date(iso)
    return d.toLocaleDateString("en-US", {
      month: "short", day: "numeric", year: "numeric",
      hour: "2-digit", minute: "2-digit",
    })
  }

  return (
    <PageShell>
      <PageHeader
        icon={History}
        eyebrow="Prompts"
        title="Prompt audit log"
        description="Immutable record of every prompt management action."
        actions={<Badge variant="outline">{total.toLocaleString()} entries</Badge>}
      />

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex gap-4 items-end">
            <div className="flex-1">
              <label className="text-sm font-medium text-muted-foreground mb-1.5 block">
                Filter by prompt slug
              </label>
              <Input aria-label="Filter by slug"
                placeholder="e.g. triage-finding-system"
                value={slugFilter}
                onChange={(e) => { setSlugFilter(e.target.value); setPage(0) }}
              />
            </div>
            <div className="w-48">
              <label className="text-sm font-medium text-muted-foreground mb-1.5 block">
                Action
              </label>
              <Select value={actionFilter} onValueChange={(v) => { setActionFilter(v); setPage(0) }}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All actions</SelectItem>
                  {ACTIONS.map((a) => (
                    <SelectItem key={a} value={a}>{a}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Table */}
      <Card>
        <CardContent className="pt-6">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : entries.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              No audit log entries found.
            </div>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-32">Timestamp</TableHead>
                    <TableHead className="w-28">Action</TableHead>
                    <TableHead>Prompt</TableHead>
                    <TableHead className="w-20">Version</TableHead>
                    <TableHead>User</TableHead>
                    <TableHead className="w-28">IP Address</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {entries.map((entry) => (
                    <TableRow key={entry.id}>
                      <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                        {formatDate(entry.created_at)}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={ACTION_COLORS[entry.action] || ""}
                        >
                          {entry.action}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Link
                          href={`/prompts/${entry.prompt_slug}`}
                          className="font-medium text-primary hover:underline"
                        >
                          {entry.prompt_slug}
                        </Link>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {entry.version != null ? `v${entry.version}` : "—"}
                      </TableCell>
                      <TableCell className="text-sm">
                        {entry.user_email || entry.user_id || "system"}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground font-mono">
                        {entry.ip_address || "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>

              {/* Pagination */}
              <div className="flex items-center justify-between mt-4 pt-4 border-t">
                <p className="text-sm text-muted-foreground">
                  Showing {page * limit + 1}–{Math.min((page + 1) * limit, total)} of {total}
                </p>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage((p) => Math.max(0, p - 1))}
                    disabled={page === 0}
                  >
                    <ChevronLeft className="h-4 w-4" />
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage((p) => p + 1)}
                    disabled={page >= totalPages - 1}
                  >
                    Next
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </PageShell>
  )
}

import { PageHeader, PageShell } from "@/components/ui/page-header"