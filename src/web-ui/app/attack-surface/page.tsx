"use client"

import { useEffect, useState, useMemo } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Progress } from "@/components/ui/progress"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { DataTable } from "@/components/data-table"
import { DataTableColumnHeader } from "@/components/data-table-column-header"
import { ColumnDef } from "@tanstack/react-table"
import Link from "next/link"
import {
  Bar,
  BarChart,
  ResponsiveContainer,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  Legend,
} from "recharts"
import {
  Shield,
  ShieldAlert,
  ShieldX,
  Key,
  Users,
  Globe,
  Archive,
  AlertTriangle,
  Clock,
  TrendingDown,
  Eye,
  Lock,
  Unlock,
  Server,
  Database,
  GitBranch,
  ExternalLink,
  ChevronRight,
} from "lucide-react"
import { ContributorProfileModal } from "@/components/contributor-profile-modal"

const API_BASE = "http://localhost:8000"

interface AttackSurfaceSummary {
  total_repos: number
  public_repos: number
  archived_repos: number
  abandoned_repos: number
  total_findings: number
  total_secrets: number
  total_hardcoded_assets: number
  stale_contributors: number
  high_risk_repos: number
  active_investigations: number
}

interface SecretsByType {
  [key: string]: number
}

interface SecretsData {
  total_secrets: number
  total_hardcoded_assets: number
  secrets_by_type: SecretsByType
  secrets_by_severity: Record<string, number>
  secrets_by_repo: Array<{ repo: string; id: string | null; count: number }>
  recent_secrets: any[]
}

interface AbandonedRepo {
  id: string
  name: string
  url: string
  description: string | null
  language: string | null
  pushed_at: string
  github_created_at: string | null
  is_archived: boolean
  visibility: string
  days_since_push: number
  abandonment_score: number
  abandonment_reasons: string[]
  open_findings_count: number
  critical_findings_count: number
  contributor_count: number
  active_contributors_count: number
}

interface StaleContributor {
  id: string
  name: string
  email: string
  github_username: string | null
  total_repos: number
  repo_names: string[]
  total_commits: number
  last_commit_at: string
  days_since_last_commit: number
  files_with_findings: number
  critical_files_count: number
  risk_score: number
}

interface HighRiskRepo {
  id: string
  name: string
  url: string | null
  description: string | null
  visibility: string
  is_archived: boolean
  is_abandoned: boolean
  last_commit_date: string | null
  days_since_activity: number | null
  open_findings_count: number
  critical_findings_count: number
  high_findings_count: number
  secrets_count: number
  risk_score: number
  risk_level: 'critical' | 'high' | 'medium' | 'low'
  risk_factors: string[]
  primary_language: string | null
  contributors_count: number
}

interface IRFinding {
  id: string
  title: string
  severity: string
  investigation_status: string
  investigation_started_at: string | null
  scanner_name: string | null
  repo_name: string
  repository_id: string | null
  file_path: string | null
  journal_count: number
  last_journal_at: string | null
}

// Color scheme for secrets
const SECRET_COLORS: Record<string, string> = {
  AWS: "#FF9900",
  Azure: "#0089D6",
  AzureStorage: "#0089D6",
  Box: "#0061D5",
  PrivateKey: "#DC2626",
  SQLServer: "#CC2927",
  Postgres: "#336791",
  Docker: "#2496ED",
  Dockerhub: "#2496ED",
  GitHub: "#333333",
  Github: "#333333",
  JWT: "#000000",
  SlackWebhook: "#4A154B",
  Slack: "#4A154B",
  Grafana: "#F46800",
  TatumIO: "#6366F1",
  URI: "#6B7280",
  FTP: "#22C55E",
  FormBucket: "#8B5CF6",
  Gitter: "#ED1965",
  default: "#6B7280",
}

export default function AttackSurfacePage() {
  const [summary, setSummary] = useState<AttackSurfaceSummary | null>(null)
  const [secretsData, setSecretsData] = useState<SecretsData | null>(null)
  const [abandonedRepos, setAbandonedRepos] = useState<AbandonedRepo[]>([])
  const [staleContributors, setStaleContributors] = useState<StaleContributor[]>([])
  const [highRiskRepos, setHighRiskRepos] = useState<HighRiskRepo[]>([])
  const [irFindings, setIRFindings] = useState<IRFinding[]>([])
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState("overview")
  
  // Contributor profile modal state
  const [selectedContributorEmail, setSelectedContributorEmail] = useState<string | null>(null)
  const [contributorModalOpen, setContributorModalOpen] = useState(false)

  const openContributorModal = (email: string) => {
    setSelectedContributorEmail(email)
    setContributorModalOpen(true)
  }

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [summaryRes, secretsRes, abandonedRes, staleRes, highRiskRes, irRes] = await Promise.all([
          fetch(`${API_BASE}/attack-surface/summary`),
          fetch(`${API_BASE}/attack-surface/secrets?limit=20`),
          fetch(`${API_BASE}/attack-surface/abandoned?limit=200`),
          fetch(`${API_BASE}/attack-surface/stale-contributors?limit=200`),
          fetch(`${API_BASE}/attack-surface/high-risk-repos?limit=200`),
          fetch(`${API_BASE}/attack-surface/incident-response`),
        ])

        if (summaryRes.ok) setSummary(await summaryRes.json())
        if (secretsRes.ok) setSecretsData(await secretsRes.json())
        if (abandonedRes.ok) setAbandonedRepos(await abandonedRes.json())
        if (staleRes.ok) setStaleContributors(await staleRes.json())
        if (highRiskRes.ok) setHighRiskRepos(await highRiskRes.json())
        if (irRes.ok) setIRFindings(await irRes.json())
      } catch (error) {
        console.error("Failed to fetch attack surface data:", error)
      } finally {
        setLoading(false)
      }
    }

    fetchData()
    const interval = setInterval(fetchData, 60000) // Refresh every minute
    return () => clearInterval(interval)
  }, [])

  // Prepare chart data
  const secretsChartData = secretsData
    ? Object.entries(secretsData.secrets_by_type)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 10)
        .map(([name, value]) => ({
          name: name.length > 12 ? name.slice(0, 12) + "..." : name,
          fullName: name,
          value,
          color: SECRET_COLORS[name] || SECRET_COLORS.default,
        }))
    : []

  const riskScore = summary
    ? Math.min(
        100,
        Math.round(
          (summary.total_secrets * 3 +
            summary.public_repos * 10 +
            summary.abandoned_repos * 0.5 +
            summary.high_risk_repos * 5) /
            Math.max(summary.total_repos, 1) * 10
        )
      )
    : 0

  // Define columns for stale contributors DataTable
  const staleContributorColumns: ColumnDef<StaleContributor>[] = useMemo(() => [
    {
      accessorKey: "name",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Contributor" />
      ),
      cell: ({ row }) => {
        const mergedCount = (row.original as any).merged_identities || 1
        const allEmails = (row.original as any).all_emails as string[] | undefined
        const email = row.original.email
        return (
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2">
              <button
                onClick={() => openContributorModal(email)}
                className="font-medium text-left hover:text-blue-600 hover:underline cursor-pointer"
              >
                {row.getValue("name")}
              </button>
              {mergedCount > 1 && (
                <Badge variant="secondary" className="text-[10px] px-1.5 py-0">
                  {mergedCount} merged
                </Badge>
              )}
            </div>
            <button
              onClick={() => openContributorModal(email)}
              className="text-xs text-muted-foreground truncate max-w-[200px] text-left hover:text-blue-500 cursor-pointer"
            >
              {email}
            </button>
            {allEmails && allEmails.length > 1 && (
              <span className="text-[10px] text-blue-500 truncate max-w-[200px]">
                Also: {allEmails.filter(e => e !== email).join(', ')}
              </span>
            )}
          </div>
        )
      },
      filterFn: (row, id, value) => {
        const name = (row.getValue(id) as string).toLowerCase()
        const email = (row.original.email || "").toLowerCase()
        const search = value.toLowerCase()
        return name.includes(search) || email.includes(search)
      },
    },
    {
      accessorKey: "total_repos",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Repositories" />
      ),
      cell: ({ row }) => {
        const repoNames = row.original.repo_names || []
        const totalRepos = row.getValue("total_repos") as number || 1
        return (
          <div className="flex flex-col gap-1">
            <Badge variant="outline" className="w-fit">
              {totalRepos} {totalRepos === 1 ? 'repo' : 'repos'}
            </Badge>
            <span className="text-xs text-muted-foreground truncate max-w-[180px]">
              {repoNames.slice(0, 2).join(', ') || 'Unknown'}
              {repoNames.length > 2 && ` +${repoNames.length - 2}`}
            </span>
          </div>
        )
      },
    },
    {
      accessorKey: "total_commits",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Commits" />
      ),
      cell: ({ row }) => (
        <Badge variant="outline">{row.getValue("total_commits") || 0}</Badge>
      ),
    },
    {
      accessorKey: "last_commit_at",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Last Commit" />
      ),
      cell: ({ row }) => {
        const date = row.getValue("last_commit_at") as string
        return date ? (
          <span className="text-sm text-muted-foreground">
            {new Date(date).toLocaleDateString()}
          </span>
        ) : (
          <span className="text-muted-foreground">Unknown</span>
        )
      },
    },
    {
      accessorKey: "days_since_last_commit",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Days Inactive" />
      ),
      cell: ({ row }) => {
        const days = row.getValue("days_since_last_commit") as number
        return (
          <Badge
            variant={
              days > 1000 ? "destructive" : days > 730 ? "secondary" : "outline"
            }
          >
            {days || 0} days
          </Badge>
        )
      },
    },
    {
      accessorKey: "risk_score",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Risk Score" />
      ),
      cell: ({ row }) => {
        const score = row.getValue("risk_score") as number
        return (
          <div className="flex items-center gap-2">
            <Progress value={score} className="w-16 h-2" />
            <span className="text-sm font-medium">{score}</span>
          </div>
        )
      },
    },
  ], [openContributorModal])

  // Define columns for abandoned repos DataTable
  const abandonedRepoColumns: ColumnDef<AbandonedRepo>[] = useMemo(() => [
    {
      accessorKey: "name",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Repository" />
      ),
      cell: ({ row }) => (
        <div className="flex flex-col gap-1">
          <Link
            href={`/projects/${row.original.id}`}
            className="font-medium text-blue-600 hover:underline flex items-center gap-1"
          >
            {row.getValue("name")}
            <ExternalLink className="h-3 w-3" />
          </Link>
          <span className="text-xs text-muted-foreground truncate max-w-[200px]">
            {row.original.description || "No description"}
          </span>
        </div>
      ),
      filterFn: (row, id, value) => {
        const name = (row.getValue(id) as string).toLowerCase()
        const desc = (row.original.description || "").toLowerCase()
        const search = value.toLowerCase()
        return name.includes(search) || desc.includes(search)
      },
    },
    {
      accessorKey: "language",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Language" />
      ),
      cell: ({ row }) => (
        <Badge variant="outline">{row.getValue("language") || "Unknown"}</Badge>
      ),
      filterFn: (row, id, value) => {
        if (!value || !Array.isArray(value) || value.length === 0) return true
        return value.includes(row.getValue(id))
      },
    },
    {
      accessorKey: "pushed_at",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Last Push" />
      ),
      cell: ({ row }) => {
        const date = row.getValue("pushed_at") as string
        return date ? (
          <span className="text-sm text-muted-foreground">
            {new Date(date).toLocaleDateString()}
          </span>
        ) : (
          <span className="text-muted-foreground">Never</span>
        )
      },
    },
    {
      accessorKey: "days_since_push",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Days Inactive" />
      ),
      cell: ({ row }) => {
        const days = row.getValue("days_since_push") as number
        return (
          <Badge
            variant={
              days > 1000 ? "destructive" : days > 730 ? "secondary" : "outline"
            }
          >
            {days || 0} days
          </Badge>
        )
      },
    },
    {
      accessorKey: "abandonment_score",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Risk Score" />
      ),
      cell: ({ row }) => {
        const score = row.getValue("abandonment_score") as number
        return (
          <div className="flex items-center gap-2">
            <Progress value={score} className="w-16 h-2" />
            <span className="text-sm font-medium">{score}</span>
          </div>
        )
      },
    },
    {
      accessorKey: "critical_findings_count",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Findings" />
      ),
      cell: ({ row }) => {
        const critical = row.getValue("critical_findings_count") as number
        const open = row.original.open_findings_count
        return critical > 0 ? (
          <Badge variant="destructive">{critical} critical</Badge>
        ) : (
          <Badge variant="outline">{open || 0}</Badge>
        )
      },
    },
    {
      accessorKey: "abandonment_reasons",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Reasons" />
      ),
      cell: ({ row }) => {
        const reasons = row.getValue("abandonment_reasons") as string[] || []
        return (
          <div className="flex flex-wrap gap-1 max-w-[200px]">
            {reasons.slice(0, 2).map((reason, i) => (
              <Badge key={i} variant="outline" className="text-xs">
                {reason.length > 25 ? reason.slice(0, 25) + "..." : reason}
              </Badge>
            ))}
          </div>
        )
      },
    },
  ], [])

  // High Risk Repos DataTable columns
  const highRiskRepoColumns: ColumnDef<HighRiskRepo>[] = useMemo(() => [
    {
      accessorKey: "name",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Repository" />
      ),
      cell: ({ row }) => (
        <div className="flex flex-col gap-1">
          <Link
            href={`/projects/${row.original.id}`}
            className="font-medium text-blue-600 hover:underline flex items-center gap-1"
          >
            {row.getValue("name")}
            <ExternalLink className="h-3 w-3" />
          </Link>
          <span className="text-xs text-muted-foreground truncate max-w-[200px]">
            {row.original.description || "No description"}
          </span>
        </div>
      ),
      filterFn: (row, id, value) => {
        const name = (row.getValue(id) as string).toLowerCase()
        const desc = (row.original.description || "").toLowerCase()
        const search = value.toLowerCase()
        return name.includes(search) || desc.includes(search)
      },
    },
    {
      accessorKey: "risk_level",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Risk Level" />
      ),
      cell: ({ row }) => {
        const level = row.getValue("risk_level") as string
        const variant = 
          level === 'critical' ? 'destructive' :
          level === 'high' ? 'secondary' :
          level === 'medium' ? 'outline' : 'outline'
        return (
          <Badge variant={variant} className={
            level === 'critical' ? '' :
            level === 'high' ? 'bg-orange-100 text-orange-800 border-orange-200' :
            level === 'medium' ? 'bg-yellow-100 text-yellow-800 border-yellow-200' :
            'bg-blue-100 text-blue-800 border-blue-200'
          }>
            {level.toUpperCase()}
          </Badge>
        )
      },
      filterFn: (row, id, value) => {
        if (!value || !Array.isArray(value) || value.length === 0) return true
        return value.includes(row.getValue(id))
      },
    },
    {
      accessorKey: "risk_score",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Risk Score" />
      ),
      cell: ({ row }) => {
        const score = row.getValue("risk_score") as number
        return (
          <div className="flex items-center gap-2">
            <Progress value={score} className="w-16 h-2" />
            <span className="text-sm font-medium">{score}</span>
          </div>
        )
      },
    },
    {
      accessorKey: "visibility",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Visibility" />
      ),
      cell: ({ row }) => {
        const visibility = row.getValue("visibility") as string
        const isPublic = visibility === 'public'
        return (
          <Badge variant={isPublic ? "destructive" : "outline"} className="flex items-center gap-1 w-fit">
            {isPublic ? <Globe className="h-3 w-3" /> : <Lock className="h-3 w-3" />}
            {visibility}
          </Badge>
        )
      },
      filterFn: (row, id, value) => {
        if (!value || !Array.isArray(value) || value.length === 0) return true
        return value.includes(row.getValue(id))
      },
    },
    {
      accessorKey: "secrets_count",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Secrets" />
      ),
      cell: ({ row }) => {
        const secrets = row.getValue("secrets_count") as number
        return secrets > 0 ? (
          <Badge variant="destructive" className="flex items-center gap-1 w-fit">
            <Key className="h-3 w-3" />
            {secrets}
          </Badge>
        ) : (
          <Badge variant="outline">0</Badge>
        )
      },
    },
    {
      accessorKey: "critical_findings_count",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Critical" />
      ),
      cell: ({ row }) => {
        const critical = row.getValue("critical_findings_count") as number
        const high = row.original.high_findings_count
        return (
          <div className="flex gap-1">
            {critical > 0 && (
              <Badge variant="destructive">{critical}</Badge>
            )}
            {high > 0 && (
              <Badge variant="secondary" className="bg-orange-100 text-orange-800">{high}</Badge>
            )}
            {critical === 0 && high === 0 && (
              <Badge variant="outline">0</Badge>
            )}
          </div>
        )
      },
    },
    {
      accessorKey: "days_since_activity",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Inactive" />
      ),
      cell: ({ row }) => {
        const days = row.getValue("days_since_activity") as number | null
        const isAbandoned = row.original.is_abandoned
        const isArchived = row.original.is_archived
        return (
          <div className="flex flex-col gap-1">
            {days !== null ? (
              <Badge variant={isAbandoned ? "destructive" : days > 365 ? "secondary" : "outline"}>
                {days} days
              </Badge>
            ) : (
              <Badge variant="outline">Unknown</Badge>
            )}
            {isArchived && (
              <Badge variant="outline" className="text-xs flex items-center gap-1 w-fit">
                <Archive className="h-3 w-3" />
                Archived
              </Badge>
            )}
          </div>
        )
      },
    },
    {
      accessorKey: "risk_factors",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Risk Factors" />
      ),
      cell: ({ row }) => {
        const factors = row.getValue("risk_factors") as string[] || []
        return (
          <div className="flex flex-wrap gap-1 max-w-[250px]">
            {factors.slice(0, 2).map((factor, i) => (
              <Badge key={i} variant="outline" className="text-xs">
                {factor.length > 30 ? factor.slice(0, 30) + "..." : factor}
              </Badge>
            ))}
            {factors.length > 2 && (
              <Badge variant="outline" className="text-xs">
                +{factors.length - 2} more
              </Badge>
            )}
          </div>
        )
      },
    },
  ], [])

  if (loading) {
    return (
      <div className="flex flex-1 flex-col gap-4 p-4 pt-0">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-1 flex-col gap-6 p-4 pt-0">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-red-600 to-orange-500 bg-clip-text text-transparent">
            Attack Surface Analysis
          </h2>
          <p className="text-muted-foreground mt-1">
            Real-time visibility into security risks across your organization
          </p>
        </div>
        <Badge variant={riskScore > 60 ? "destructive" : riskScore > 30 ? "secondary" : "default"} className="text-lg px-4 py-2">
          <Shield className="h-5 w-5 mr-2" />
          Risk Score: {riskScore}/100
        </Badge>
      </div>

      {/* Executive Summary Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        {/* Total Secrets Card */}
        <Card className="border-l-4 border-l-red-500 bg-gradient-to-r from-red-500/5 to-transparent">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Hardcoded Secrets
            </CardTitle>
            <Key className="h-5 w-5 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-600">{summary?.total_secrets || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">
              {secretsData?.secrets_by_type ? Object.keys(secretsData.secrets_by_type).length : 0} secret types detected
            </p>
            <Progress value={Math.min((summary?.total_secrets || 0) / 10, 100)} className="mt-2 h-1 bg-red-100" />
          </CardContent>
        </Card>

        {/* Abandoned Repos Card */}
        <Card className="border-l-4 border-l-orange-500 bg-gradient-to-r from-orange-500/5 to-transparent">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Abandoned Repos
            </CardTitle>
            <Archive className="h-5 w-5 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-orange-600">{summary?.abandoned_repos || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">
              {summary ? Math.round((summary.abandoned_repos / summary.total_repos) * 100) : 0}% of total repositories
            </p>
            <Progress
              value={summary ? (summary.abandoned_repos / summary.total_repos) * 100 : 0}
              className="mt-2 h-1 bg-orange-100"
            />
          </CardContent>
        </Card>

        {/* Stale Contributors Card */}
        <Card className="border-l-4 border-l-yellow-500 bg-gradient-to-r from-yellow-500/5 to-transparent">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Stale Contributors
            </CardTitle>
            <Users className="h-5 w-5 text-yellow-600" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-yellow-600">{summary?.stale_contributors || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">
              No commits in 90+ days
            </p>
            <Progress value={75} className="mt-2 h-1 bg-yellow-100" />
          </CardContent>
        </Card>

        {/* High Risk Repos Card */}
        <Card className="border-l-4 border-l-purple-500 bg-gradient-to-r from-purple-500/5 to-transparent">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              High Risk Repos
            </CardTitle>
            <ShieldAlert className="h-5 w-5 text-purple-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-purple-600">{summary?.high_risk_repos || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">
              Public or with exposed secrets
            </p>
            <Progress
              value={summary ? (summary.high_risk_repos / summary.total_repos) * 100 : 0}
              className="mt-2 h-1 bg-purple-100"
            />
          </CardContent>
        </Card>

        {/* Incident Response Card */}
        <Card 
          className="border-l-4 border-l-blue-500 bg-gradient-to-r from-blue-500/5 to-transparent cursor-pointer hover:bg-blue-50/50 dark:hover:bg-blue-950/20 transition-colors"
          onClick={() => setActiveTab("ir")}
        >
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Incident Response
            </CardTitle>
            <Shield className="h-5 w-5 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-blue-600">{summary?.active_investigations || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">
              Active investigations
            </p>
            <Progress
              value={Math.min((summary?.active_investigations || 0) * 10, 100)}
              className="mt-2 h-1 bg-blue-100"
            />
          </CardContent>
        </Card>
      </div>

      {/* Tabbed Content */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full max-w-3xl grid-cols-6">
          <TabsTrigger value="overview" className="flex items-center gap-2">
            <Eye className="h-4 w-4" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="ir" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            IR
          </TabsTrigger>
          <TabsTrigger value="high-risk" className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4" />
            High Risk
          </TabsTrigger>
          <TabsTrigger value="secrets" className="flex items-center gap-2">
            <Key className="h-4 w-4" />
            Secrets
          </TabsTrigger>
          <TabsTrigger value="abandoned" className="flex items-center gap-2">
            <Archive className="h-4 w-4" />
            Abandoned
          </TabsTrigger>
          <TabsTrigger value="contributors" className="flex items-center gap-2">
            <Users className="h-4 w-4" />
            Contributors
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            {/* Secrets by Type Chart */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Key className="h-5 w-5 text-red-500" />
                  Secrets by Type
                </CardTitle>
                <CardDescription>Top 10 secret types detected in codebase</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={secretsChartData} layout="vertical">
                    <XAxis type="number" />
                    <YAxis type="category" dataKey="name" width={100} tick={{ fontSize: 12 }} />
                    <Tooltip
                      content={({ active, payload }) => {
                        if (active && payload && payload.length) {
                          return (
                            <div className="bg-background border rounded-lg shadow-lg p-3">
                              <p className="font-semibold">{payload[0].payload.fullName}</p>
                              <p className="text-sm text-muted-foreground">
                                {payload[0].value} secrets
                              </p>
                            </div>
                          )
                        }
                        return null
                      }}
                    />
                    <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                      {secretsChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Top Repos with Secrets */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-orange-500" />
                  Top Repos with Secrets
                </CardTitle>
                <CardDescription>Repositories requiring immediate attention</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {secretsData?.secrets_by_repo.slice(0, 8).map((repo, i) => (
                    <div key={repo.repo} className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="flex items-center justify-center w-6 h-6 rounded-full bg-red-100 text-red-600 text-xs font-bold">
                          {i + 1}
                        </span>
                        <Link
                          href={repo.id ? `/projects/${repo.id}` : `/repositories`}
                          className="text-sm font-medium hover:underline truncate max-w-[200px]"
                        >
                          {repo.repo}
                        </Link>
                      </div>
                      <Badge variant="destructive">{repo.count} secrets</Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Quick Stats Row */}
          <div className="grid gap-4 md:grid-cols-3">
            <Card className="bg-gradient-to-br from-slate-900 to-slate-800 text-white">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-slate-300">Total Repositories</p>
                    <p className="text-4xl font-bold">{summary?.total_repos || 0}</p>
                  </div>
                  <Database className="h-12 w-12 text-slate-500" />
                </div>
                <div className="flex gap-4 mt-4 text-sm">
                  <div className="flex items-center gap-1">
                    <Globe className="h-4 w-4 text-red-400" />
                    <span>{summary?.public_repos || 0} public</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Archive className="h-4 w-4 text-yellow-400" />
                    <span>{summary?.archived_repos || 0} archived</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-gradient-to-br from-red-900 to-red-800 text-white">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-red-200">Security Findings</p>
                    <p className="text-4xl font-bold">{summary?.total_findings || 0}</p>
                  </div>
                  <ShieldX className="h-12 w-12 text-red-500" />
                </div>
                <div className="flex gap-4 mt-4 text-sm">
                  <div className="flex items-center gap-1">
                    <Key className="h-4 w-4 text-red-300" />
                    <span>{summary?.total_secrets || 0} secrets</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Server className="h-4 w-4 text-red-300" />
                    <span>{summary?.total_hardcoded_assets || 0} IPs</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-gradient-to-br from-amber-900 to-amber-800 text-white">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-amber-200">Risk Contributors</p>
                    <p className="text-4xl font-bold">{summary?.stale_contributors || 0}</p>
                  </div>
                  <Users className="h-12 w-12 text-amber-500" />
                </div>
                <div className="flex gap-4 mt-4 text-sm">
                  <div className="flex items-center gap-1">
                    <Clock className="h-4 w-4 text-amber-300" />
                    <span>90+ days inactive</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <TrendingDown className="h-4 w-4 text-amber-300" />
                    <span>Code ownership risk</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* High Risk Repos Tab */}
        <TabsContent value="high-risk" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ShieldAlert className="h-5 w-5 text-red-500" />
                High Risk Repositories
              </CardTitle>
              <CardDescription>
                Repositories with exposed secrets, critical vulnerabilities, or abandonment issues
              </CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable 
                columns={highRiskRepoColumns} 
                data={highRiskRepos}
                persistFilters={false}
              />
            </CardContent>
          </Card>
        </TabsContent>

        {/* Secrets Tab */}
        <TabsContent value="secrets" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Detected Secrets by Type</CardTitle>
              <CardDescription>
                All hardcoded secrets, API keys, and credentials found in the codebase
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                {secretsData &&
                  Object.entries(secretsData.secrets_by_type)
                    .sort(([, a], [, b]) => b - a)
                    .map(([type, count]) => (
                      <div
                        key={type}
                        className="flex items-center justify-between p-3 rounded-lg border bg-card hover:bg-accent/50 transition-colors"
                      >
                        <div className="flex items-center gap-3">
                          <div
                            className="w-3 h-3 rounded-full"
                            style={{ backgroundColor: SECRET_COLORS[type] || SECRET_COLORS.default }}
                          />
                          <span className="font-medium">{type}</span>
                        </div>
                        <Badge variant={count > 50 ? "destructive" : count > 10 ? "secondary" : "outline"}>
                          {count}
                        </Badge>
                      </div>
                    ))}
              </div>
            </CardContent>
          </Card>

          {/* Secrets by Repository */}
          <Card>
            <CardHeader>
              <CardTitle>Repositories with Most Secrets</CardTitle>
              <CardDescription>Prioritize remediation for these repositories</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-12">#</TableHead>
                    <TableHead>Repository</TableHead>
                    <TableHead className="text-right">Secrets</TableHead>
                    <TableHead className="w-24">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {secretsData?.secrets_by_repo.slice(0, 15).map((repo, i) => (
                    <TableRow key={repo.repo}>
                      <TableCell className="font-medium">{i + 1}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <GitBranch className="h-4 w-4 text-muted-foreground" />
                          <span className="font-medium">{repo.repo}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-right">
                        <Badge variant="destructive">{repo.count}</Badge>
                      </TableCell>
                      <TableCell>
                        <Button variant="ghost" size="sm" asChild>
                          <Link href={repo.id ? `/projects/${repo.id}` : `/repositories`}>
                            View <ChevronRight className="h-4 w-4 ml-1" />
                          </Link>
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Abandoned Tab */}
        <TabsContent value="abandoned" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Abandoned Repositories</CardTitle>
                  <CardDescription>
                    Repositories with no commits in 2+ years that may pose security risks
                  </CardDescription>
                </div>
                <Badge variant="outline" className="text-lg">
                  {summary?.abandoned_repos || abandonedRepos.length} repos
                </Badge>
              </div>
            </CardHeader>
            <CardContent>
              <DataTable 
                columns={abandonedRepoColumns} 
                data={abandonedRepos} 
                searchKey="name"
                tableId="abandoned-repos"
                persistFilters={false}
              />
            </CardContent>
          </Card>
        </TabsContent>

        {/* Contributors Tab */}
        <TabsContent value="contributors" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Stale Contributors</CardTitle>
                  <CardDescription>
                    Contributors who haven't committed to any repo in 90+ days - potential attrition risk
                  </CardDescription>
                </div>
                <Badge variant="outline" className="text-lg">
                  {summary?.stale_contributors || staleContributors.length} contributors
                </Badge>
              </div>
            </CardHeader>
            <CardContent>
              <DataTable 
                columns={staleContributorColumns} 
                data={staleContributors} 
                searchKey="name"
                tableId="stale-contributors"
              />
            </CardContent>
          </Card>
        </TabsContent>

        {/* Incident Response Tab */}
        <TabsContent value="ir" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="h-5 w-5 text-blue-500" />
                    Active Investigations
                  </CardTitle>
                  <CardDescription>
                    Findings currently under triage or incident response
                  </CardDescription>
                </div>
                <Badge variant="outline" className="text-lg">
                  {summary?.active_investigations || irFindings.length} active
                </Badge>
              </div>
            </CardHeader>
            <CardContent>
              {irFindings.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <Shield className="h-12 w-12 mb-4 opacity-30" />
                  <p className="text-lg font-medium">No Active Investigations</p>
                  <p className="text-sm">Start triaging findings to see them here</p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Finding</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Repository</TableHead>
                      <TableHead>Journal</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {irFindings.map((finding) => (
                      <TableRow key={finding.id}>
                        <TableCell className="max-w-[300px]">
                          <Link
                            href={`/findings/${finding.id}`}
                            className="font-medium text-blue-600 hover:underline line-clamp-2"
                          >
                            {finding.title}
                          </Link>
                          <p className="text-xs text-muted-foreground truncate">
                            {finding.file_path}
                          </p>
                        </TableCell>
                        <TableCell>
                          <Badge
                            className={
                              finding.investigation_status === "incident_response"
                                ? "bg-red-500 hover:bg-red-600"
                                : finding.investigation_status === "triage"
                                ? "bg-yellow-500 hover:bg-yellow-600"
                                : "bg-green-500 hover:bg-green-600"
                            }
                          >
                            {finding.investigation_status === "incident_response"
                              ? "IR"
                              : finding.investigation_status === "triage"
                              ? "Triage"
                              : "Resolved"}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={
                              finding.severity === "critical"
                                ? "destructive"
                                : finding.severity === "high"
                                ? "secondary"
                                : "outline"
                            }
                          >
                            {finding.severity}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <span className="text-sm">{finding.repo_name}</span>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1 text-sm text-muted-foreground">
                            <span>{finding.journal_count} entries</span>
                            {finding.last_journal_at && (
                              <span className="text-xs">
                                • {new Date(finding.last_journal_at).toLocaleDateString()}
                              </span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-right">
                          <Button variant="ghost" size="sm" asChild>
                            <Link href={`/findings/${finding.id}`}>
                              View <ChevronRight className="h-4 w-4 ml-1" />
                            </Link>
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Contributor Profile Modal */}
      <ContributorProfileModal
        email={selectedContributorEmail}
        isOpen={contributorModalOpen}
        onClose={() => setContributorModalOpen(false)}
      />
    </div>
  )
}
