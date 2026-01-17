"use client"

import Link from "next/link"
import { Widget } from "@/components/dashboard/Widget"
import {
  PlayCircle,
  AlertTriangle,
  Calendar,
  FileText,
  FolderGit2,
  Settings
} from "lucide-react"
import { cn } from "@/lib/utils"

interface QuickAction {
  label: string
  description: string
  href: string
  icon: React.ReactNode
  color: string
}

const QUICK_ACTIONS: QuickAction[] = [
  {
    label: "Open Scheduler",
    description: "Manage scan schedules",
    href: "/scheduler",
    icon: <Calendar className="h-5 w-5" />,
    color: "text-blue-500"
  },
  {
    label: "View Findings",
    description: "Browse all findings",
    href: "/findings",
    icon: <AlertTriangle className="h-5 w-5" />,
    color: "text-orange-500"
  },
  {
    label: "Repositories",
    description: "Manage tracked repos",
    href: "/projects",
    icon: <FolderGit2 className="h-5 w-5" />,
    color: "text-green-500"
  },
  {
    label: "Scan History",
    description: "View past scans",
    href: "/scans",
    icon: <PlayCircle className="h-5 w-5" />,
    color: "text-purple-500"
  },
  {
    label: "Reports",
    description: "Export & reports",
    href: "/reports",
    icon: <FileText className="h-5 w-5" />,
    color: "text-cyan-500"
  },
  {
    label: "Settings",
    description: "Configure AuditGH",
    href: "/settings",
    icon: <Settings className="h-5 w-5" />,
    color: "text-gray-500"
  }
]

function ActionCard({ action }: { action: QuickAction }) {
  return (
    <Link
      href={action.href}
      className={cn(
        "flex items-center gap-3 p-3 rounded-lg border",
        "bg-card hover:bg-accent/50 transition-colors",
        "group cursor-pointer"
      )}
    >
      <div className={cn(
        "flex items-center justify-center w-10 h-10 rounded-lg",
        "bg-muted group-hover:bg-background transition-colors",
        action.color
      )}>
        {action.icon}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium truncate">{action.label}</p>
        <p className="text-xs text-muted-foreground truncate">{action.description}</p>
      </div>
    </Link>
  )
}

export function QuickActionsWidget() {
  return (
    <Widget
      title="Quick Actions"
      subtitle="Navigate to common tasks"
    >
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        {QUICK_ACTIONS.map((action) => (
          <ActionCard key={action.href} action={action} />
        ))}
      </div>
    </Widget>
  )
}
