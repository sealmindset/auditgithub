"use client"

import * as React from "react"
import {
    ShieldCheck,
    LayoutDashboard,
    FileText,
    Settings,
    Users,
    AlertTriangle,
    GitBranch,
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
    SidebarRail,
} from "@/components/ui/sidebar"

const data = {
    navMain: [
        {
            title: "Platform",
            url: "#",
            items: [
                {
                    title: "Dashboard",
                    url: "/dashboard",
                    icon: LayoutDashboard,
                    isActive: true,
                },
                {
                    title: "Findings",
                    url: "/dashboard/findings",
                    icon: AlertTriangle,
                },
                {
                    title: "Repositories",
                    url: "/dashboard/repositories",
                    icon: GitBranch,
                },
                {
                    title: "Reports",
                    url: "/dashboard/reports",
                    icon: FileText,
                },
            ],
        },
        {
            title: "Settings",
            url: "#",
            items: [
                {
                    title: "Team",
                    url: "/dashboard/team",
                    icon: Users,
                },
                {
                    title: "Configuration",
                    url: "/dashboard/settings",
                    icon: Settings,
                },
            ],
        },
    ],
}

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
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
                                    <SidebarMenuItem key={item.title}>
                                        <SidebarMenuButton asChild isActive={item.isActive}>
                                            <a href={item.url}>
                                                <item.icon className="h-4 w-4" />
                                                <span>{item.title}</span>
                                            </a>
                                        </SidebarMenuButton>
                                    </SidebarMenuItem>
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
