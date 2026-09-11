"use client";

import { useAuth } from "@/contexts/AuthContext";
import type { RoleName } from "@/lib/rbac";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  SidebarFooter,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
} from "@/components/ui/sidebar";
import { ChevronsUpDown, LogOut, ShieldAlert } from "lucide-react";

// ── Role badge colors ──────────────────────────────────────────────

const ROLE_COLORS: Record<RoleName, string> = {
  super_admin:
    "bg-ai-soft text-ai-text",
  admin: "bg-danger-soft text-danger-text",
  manager:
    "bg-warning-soft text-warning-text",
  analyst: "bg-info-soft text-info-text",
  user: "bg-muted text-foreground dark:text-muted-foreground",
};

const ROLE_LABELS: Record<RoleName, string> = {
  super_admin: "Super Admin",
  admin: "Admin",
  manager: "Manager",
  analyst: "Analyst",
  user: "User",
};

function initials(name: string): string {
  return name
    .split(/\s+/)
    .map((w) => w[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);
}

// ── Component ──────────────────────────────────────────────────────

export function UserNav() {
  const { user, logout } = useAuth();

  if (!user) return null;

  return (
    <SidebarFooter>
      <SidebarMenu>
        <SidebarMenuItem>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <SidebarMenuButton
                size="lg"
                className="data-[state=open]:bg-sidebar-accent"
              >
                <Avatar className="h-8 w-8">
                  <AvatarFallback className="text-xs">
                    {initials(user.name)}
                  </AvatarFallback>
                </Avatar>
                <div className="grid flex-1 text-left text-sm leading-tight">
                  <span className="truncate font-semibold">{user.name}</span>
                  <span className="truncate text-xs text-muted-foreground">
                    {user.email}
                  </span>
                </div>
                <ChevronsUpDown className="ml-auto h-4 w-4 shrink-0 opacity-50" />
              </SidebarMenuButton>
            </DropdownMenuTrigger>

            <DropdownMenuContent
              className="w-56"
              side="top"
              align="start"
              sideOffset={4}
            >
              <DropdownMenuLabel className="font-normal">
                <div className="flex flex-col gap-1.5">
                  <p className="text-sm font-medium leading-none">
                    {user.name}
                  </p>
                  <p className="text-xs leading-none text-muted-foreground">
                    {user.email}
                  </p>
                  <div className="flex items-center gap-1.5 pt-1">
                    <Badge
                      variant="secondary"
                      className={ROLE_COLORS[user.role]}
                    >
                      {ROLE_LABELS[user.role] ?? user.role}
                    </Badge>
                    {user.is_break_glass && (
                      <Badge
                        variant="destructive"
                        className="gap-1 text-[10px]"
                      >
                        <ShieldAlert className="h-3 w-3" />
                        Emergency
                      </Badge>
                    )}
                  </div>
                </div>
              </DropdownMenuLabel>

              <DropdownMenuSeparator />

              <DropdownMenuItem
                onClick={() => logout()}
                className="text-danger-text focus:text-danger-text"
              >
                <LogOut className="mr-2 h-4 w-4" />
                Sign Out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </SidebarMenuItem>
      </SidebarMenu>
    </SidebarFooter>
  );
}
