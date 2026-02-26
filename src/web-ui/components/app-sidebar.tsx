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
    const [zdaOpen, setZdaOpen] = React.useState(true)

    return (
        <Sidebar {...props}>
            <SidebarHeader>
                <div className="flex items-center gap-2 px-4 py-2">
                    <ShieldCheck className="h-6 w-6 text-primary" />
                    <span className="font-bold text-lg">AuditGitHub</span>
                </div>
            </SidebarHeader>
            <SidebarContent>
                {data.navMain.map((group) => (
                    <SidebarGroup key={group.title}>
                        <SidebarGroupLabel>{group.title}</SidebarGroupLabel>
                        <SidebarGroupContent>
                            <SidebarMenu>
                                {group.items.map((item) => (
                                    item.isExpandable ? (
                                        <Collapsible
                                            key={item.title}
                                            open={zdaOpen}
                                            onOpenChange={setZdaOpen}
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
            <SidebarRail />
        </Sidebar>
    )
}
