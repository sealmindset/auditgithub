"use client"

import * as React from "react"
import { usePathname } from "next/navigation"
import Link from "next/link"
import {
    ShieldCheck,
    ShieldAlert,
    LayoutDashboard,
    FileText,
    Settings,
    Users,
    AlertTriangle,
    GitBranch,
    Search,
    ClipboardList,
    ChevronDown,
    Target,
    Calendar,
    KeyRound,
    MessageSquareText,
    History,
    Bot,
    BarChart3,
} from "lucide-react"

import {
    Sidebar,
    SidebarContent,
    SidebarGroup,
    SidebarGroupContent,
    SidebarGroupLabel,
    SidebarHeader,
    SidebarMenu,
    SidebarMenuButton,
    SidebarMenuItem,
    SidebarMenuSub,
    SidebarMenuSubButton,
    SidebarMenuSubItem,
    SidebarRail,
} from "@/components/ui/sidebar"

import {
    Collapsible,
    CollapsibleContent,
    CollapsibleTrigger,
} from "@/components/ui/collapsible"

import { useAuth } from "@/contexts/AuthContext"
import { requiredRoleForPath, meetsMinimumRole } from "@/lib/rbac"
import { UserNav } from "@/components/UserNav"

interface NavSubItem {
    title: string
    url: string
    icon: React.ComponentType<{ className?: string }>
}

interface NavItem {
    title: string
    url?: string
    icon: React.ComponentType<{ className?: string }>
    isActive?: boolean
    isExpandable?: boolean
    items?: NavSubItem[]
}

interface NavGroup {
    title: string
    url: string
    items: NavItem[]
}

const data: { navMain: NavGroup[] } = {
    navMain: [
        {
            title: "Platform",
            url: "#",
            items: [
                {
                    title: "Dashboard",
                    url: "/",
                    icon: LayoutDashboard,
                },
                {
                    title: "Findings",
                    url: "/findings",
                    icon: AlertTriangle,
                },
                {
                    title: "Repositories",
                    url: "/repositories",
                    icon: GitBranch,
                },
                {
                    title: "Scheduler",
                    url: "/scheduler",
                    icon: Calendar,
                },
                {
                    title: "Attack Surface",
                    url: "/attack-surface",
                    icon: Target,
                },
                {
                    title: "Zero Day Analysis",
                    icon: ShieldCheck,
                    isExpandable: true,
                    items: [
                        {
                            title: "Analysis",
                            url: "/zero-day",
                            icon: Search,
                        },
                        {
                            title: "ZDA Reports",
                            url: "/zero-day/reports",
                            icon: ClipboardList,
                        },
                    ],
                },
            ],
        },
        {
            title: "AI Management",
            url: "#",
            items: [
                {
                    title: "Prompts",
                    icon: MessageSquareText,
                    isExpandable: true,
                    items: [
                        {
                            title: "Registry",
                            url: "/prompts",
                            icon: MessageSquareText,
                        },
                        {
                            title: "Agents",
                            url: "/prompts/agents",
                            icon: Bot,
                        },
                        {
                            title: "Analytics",
                            url: "/prompts/analytics",
                            icon: BarChart3,
                        },
                        {
                            title: "Audit Log",
                            url: "/prompts/audit",
                            icon: History,
                        },
                    ],
                },
            ],
        },
        {
            title: "Settings",
            url: "#",
            items: [
                {
                    title: "Configuration",
                    url: "/settings",
                    icon: Settings,
                },
                {
                    title: "API Audit",
                    url: "/api-audit/settings",
                    icon: FileText,
                },
                {
                    title: "API Keys",
                    url: "/settings/api-keys",
                    icon: KeyRound,
                },
            ],
        },
    ],
}

function isPathActive(pathname: string, itemUrl: string): boolean {
    if (itemUrl === "/") {
        return pathname === "/"
    }
    return pathname === itemUrl || pathname.startsWith(itemUrl + "/")
}

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
    const pathname = usePathname()
    const [openSections, setOpenSections] = React.useState<Record<string, boolean>>({
        "Zero Day Analysis": true,
        "Prompts": pathname.startsWith("/prompts"),
    })
    const toggleSection = (title: string) =>
        setOpenSections((prev) => ({ ...prev, [title]: !prev[title] }))
    const { user } = useAuth()

    const userRole = user?.role ?? "user"

    /** Filter nav items by the user's role. */
    const filteredGroups = React.useMemo(() => {
        return data.navMain
            .map((group) => {
                const filteredItems = group.items.reduce<NavItem[]>((acc, item) => {
                    if (item.isExpandable && item.items) {
                        // For expandable items, filter children first
                        const visibleChildren = item.items.filter((sub) =>
                            meetsMinimumRole(userRole, requiredRoleForPath(sub.url)),
                        )
                        // Only show parent if at least one child is visible
                        if (visibleChildren.length > 0) {
                            acc.push({ ...item, items: visibleChildren })
                        }
                    } else if (item.url) {
                        if (meetsMinimumRole(userRole, requiredRoleForPath(item.url))) {
                            acc.push(item)
                        }
                    }
                    return acc
                }, [])

                return { ...group, items: filteredItems }
            })
            .filter((group) => group.items.length > 0)
    }, [userRole])

    return (
        <Sidebar {...props}>
            <SidebarHeader>
                <div className="flex items-center gap-2 px-4 py-2">
                    <ShieldCheck className="h-6 w-6 text-primary" />
                    <span className="font-bold text-lg">AuditGitHub</span>
                </div>
            </SidebarHeader>
            <SidebarContent>
                {filteredGroups.map((group) => (
                    <SidebarGroup key={group.title}>
                        <SidebarGroupLabel>{group.title}</SidebarGroupLabel>
                        <SidebarGroupContent>
                            <SidebarMenu>
                                {group.items.map((item) => (
                                    item.isExpandable ? (
                                        <Collapsible
                                            key={item.title}
                                            open={openSections[item.title] ?? false}
                                            onOpenChange={() => toggleSection(item.title)}
                                            className="group/collapsible"
                                        >
                                            <SidebarMenuItem>
                                                <CollapsibleTrigger asChild>
                                                    <SidebarMenuButton>
                                                        <item.icon className="h-4 w-4" />
                                                        <span>{item.title}</span>
                                                        <ChevronDown className="ml-auto h-4 w-4 transition-transform group-data-[state=open]/collapsible:rotate-180" />
                                                    </SidebarMenuButton>
                                                </CollapsibleTrigger>
                                                <CollapsibleContent>
                                                    <SidebarMenuSub>
                                                        {item.items?.map((subItem) => (
                                                            <SidebarMenuSubItem key={subItem.title}>
                                                                <SidebarMenuSubButton asChild isActive={isPathActive(pathname, subItem.url)}>
                                                                    <Link href={subItem.url}>
                                                                        <subItem.icon className="h-4 w-4" />
                                                                        <span>{subItem.title}</span>
                                                                    </Link>
                                                                </SidebarMenuSubButton>
                                                            </SidebarMenuSubItem>
                                                        ))}
                                                    </SidebarMenuSub>
                                                </CollapsibleContent>
                                            </SidebarMenuItem>
                                        </Collapsible>
                                    ) : (
                                        <SidebarMenuItem key={item.title}>
                                            <SidebarMenuButton asChild isActive={isPathActive(pathname, item.url || "")}>
                                                <Link href={item.url || "/"}>
                                                    <item.icon className="h-4 w-4" />
                                                    <span>{item.title}</span>
                                                </Link>
                                            </SidebarMenuButton>
                                        </SidebarMenuItem>
                                    )
                                ))}
                            </SidebarMenu>
                        </SidebarGroupContent>
                    </SidebarGroup>
                ))}
            </SidebarContent>
            <UserNav />
            <SidebarRail />
        </Sidebar>
    )
}
