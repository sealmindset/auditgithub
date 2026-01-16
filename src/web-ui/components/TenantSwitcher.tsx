"use client";

import React from "react";
import { Building2, Check, ChevronsUpDown, RefreshCw } from "lucide-react";
import { useTenant } from "@/contexts/TenantContext";
import { Button } from "@/components/ui/button";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuLabel,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";

interface TenantSwitcherProps {
    className?: string;
}

export function TenantSwitcher({ className }: TenantSwitcherProps) {
    const {
        currentTenant,
        tenants,
        isLoading,
        error,
        isMultiTenantEnabled,
        setTenant,
        refreshTenants
    } = useTenant();

    // Don't render if multi-tenant is not enabled or only one tenant
    if (!isMultiTenantEnabled || tenants.length <= 1) {
        return null;
    }

    if (isLoading) {
        return (
            <div className={className}>
                <Skeleton className="h-9 w-[180px]" />
            </div>
        );
    }

    if (error) {
        return (
            <div className={className}>
                <Button variant="ghost" size="sm" onClick={refreshTenants}>
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Retry
                </Button>
            </div>
        );
    }

    return (
        <DropdownMenu>
            <DropdownMenuTrigger asChild>
                <Button
                    variant="outline"
                    role="combobox"
                    className={`justify-between min-w-[180px] ${className}`}
                >
                    <div className="flex items-center gap-2 truncate">
                        <Building2 className="h-4 w-4 shrink-0 text-muted-foreground" />
                        <span className="truncate">
                            {currentTenant?.name || "Select Organization"}
                        </span>
                    </div>
                    <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
                </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="w-[220px]">
                <DropdownMenuLabel>Organizations</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {tenants.map((tenant) => (
                    <DropdownMenuItem
                        key={tenant.id}
                        onClick={() => setTenant(tenant.slug)}
                        className="flex items-center justify-between cursor-pointer"
                    >
                        <div className="flex flex-col gap-0.5">
                            <span className="font-medium">{tenant.name}</span>
                            <span className="text-xs text-muted-foreground">
                                {tenant.github_org}
                            </span>
                        </div>
                        <div className="flex items-center gap-2">
                            {!tenant.is_provisioned && (
                                <Badge variant="outline" className="text-xs">
                                    Setting up
                                </Badge>
                            )}
                            {currentTenant?.id === tenant.id && (
                                <Check className="h-4 w-4 text-primary" />
                            )}
                        </div>
                    </DropdownMenuItem>
                ))}
                <DropdownMenuSeparator />
                <DropdownMenuItem
                    onClick={refreshTenants}
                    className="cursor-pointer text-muted-foreground"
                >
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Refresh
                </DropdownMenuItem>
            </DropdownMenuContent>
        </DropdownMenu>
    );
}
