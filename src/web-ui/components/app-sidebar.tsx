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
    ChevronRight,
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
            title: "Administration",
            url: "#",
            items: [
                {
                    title: "User Management",
                    url: "/admin/users",
                    icon: Users,
                },
                {
                    title: "Settings",
                    icon: Settings,
                    isExpandable: true,
                    items: [
                        {
                            title: "Configuration",
                            url: "/settings",
                            icon: Settings,
                        },
                        {
                            title: "API Keys",
                            url: "/settings/api-keys",
                            icon: KeyRound,
                        },
                        {
                            title: "Session",
                            url: "/settings/session",
                            icon: ShieldAlert,
                        },
                    ],
                },
                {
                    title: "API Audit",
                    url: "/api-audit/settings",
                    icon: FileText,
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

/** True when any child of an expandable item is the current route. */
function hasActiveChild(pathname: string, item: NavItem): boolean {
    return (item.items ?? []).some((sub) => isPathActive(pathname, sub.url))
}

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
    const pathname = usePathname()
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

    // Sections the user has explicitly toggled. Anything not in here follows
    // the route, so deep-linking to /prompts/agents opens Prompts on arrival.
    const [overrides, setOverrides] = React.useState<Record<string, boolean>>({})
    const toggleSection = (title: string, open: boolean) =>
        setOverrides((prev) => ({ ...prev, [title]: open }))

    return (
        <Sidebar {...props}>
            <SidebarHeader className="border-b border-sidebar-border">
                <Link
                    href="/"
                    className="flex items-center gap-2.5 rounded-md px-2 py-2 transition-colors hover:bg-sidebar-accent/60 focus-visible:ring-2 focus-visible:ring-sidebar-ring focus-visible:outline-none group-data-[collapsible=icon]:px-1"
                >
                    <span
                        aria-hidden="true"
                        className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-sidebar-primary text-sidebar-primary-foreground shadow-xs"
                    >
                        <ShieldCheck className="size-[1.125rem]" />
                    </span>
                    <span className="flex min-w-0 flex-col leading-tight group-data-[collapsible=icon]:hidden">
                        <span className="truncate text-sm font-semibold tracking-[-0.01em] text-sidebar-foreground">
                            AuditGH
                        </span>
                        <span className="truncate text-[0.6875rem] text-sidebar-foreground/55">
                            Security Platform
                        </span>
                    </span>
                </Link>
            </SidebarHeader>

            <SidebarContent className="gap-0">
                {filteredGroups.map((group) => (
                    <SidebarGroup key={group.url}>
                        <SidebarGroupLabel>{group.title}</SidebarGroupLabel>
                        <SidebarGroupContent>
                            <SidebarMenu>
                                {group.items.map((item) => {
                                    if (item.isExpandable) {
                                        const childActive = hasActiveChild(pathname, item)
                                        const open = overrides[item.title] ?? childActive
                                        return (
                                            <Collapsible
                                                key={item.title}
                                                open={open}
                                                onOpenChange={(next) => toggleSection(item.title, next)}
                                                className="group/collapsible"
                                            >
                                                <SidebarMenuItem>
                                                    <CollapsibleTrigger asChild>
                                                        <SidebarMenuButton
                                                            tooltip={item.title}
                                                            // Parent shows as active only when collapsed, so the
                                                            // rail marker never appears twice in one column.
                                                            isActive={childActive && !open}
                                                        >
                                                            <item.icon className="size-4" />
                                                            <span>{item.title}</span>
                                                            <ChevronRight className="ml-auto size-4 text-sidebar-foreground/50 transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
                                                        </SidebarMenuButton>
                                                    </CollapsibleTrigger>
                                                    <CollapsibleContent>
                                                        <SidebarMenuSub>
                                                            {item.items?.map((subItem) => (
                                                                <SidebarMenuSubItem key={subItem.title}>
                                                                    <SidebarMenuSubButton
                                                                        asChild
                                                                        isActive={isPathActive(pathname, subItem.url)}
                                                                    >
                                                                        <Link href={subItem.url}>
                                                                            <subItem.icon className="size-4" />
                                                                            <span>{subItem.title}</span>
                                                                        </Link>
                                                                    </SidebarMenuSubButton>
                                                                </SidebarMenuSubItem>
                                                            ))}
                                                        </SidebarMenuSub>
                                                    </CollapsibleContent>
                                                </SidebarMenuItem>
                                            </Collapsible>
                                        )
                                    }

                                    return (
                                        <SidebarMenuItem key={item.title}>
                                            <SidebarMenuButton
                                                asChild
                                                tooltip={item.title}
                                                isActive={isPathActive(pathname, item.url || "")}
                                            >
                                                <Link href={item.url || "/"}>
                                                    <item.icon className="size-4" />
                                                    <span>{item.title}</span>
                                                </Link>
                                            </SidebarMenuButton>
                                        </SidebarMenuItem>
                                    )
                                })}
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
