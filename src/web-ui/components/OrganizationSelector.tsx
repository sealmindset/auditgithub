"use client";

/**
 * OrganizationSelector Component
 * 
 * Top navigation component for switching between GitHub organizations.
 * Each organization has its own isolated database and credentials.
 * 
 * Features:
 * - Quick organization switching
 * - Scan status indicators
 * - Schema sync status
 * - Credential configuration status
 */

import React, { useState, useEffect, useCallback } from "react";
import {
    Building2,
    Check,
    ChevronsUpDown,
    RefreshCw,
    Loader2,
    AlertCircle,
    Database,
    Zap,
    Settings,
    Plus
} from "lucide-react";
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
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from "@/components/ui/tooltip";
import { API_BASE, apiFetch } from "@/lib/api"

// =============================================================================
// Types
// =============================================================================

interface Organization {
    id: string;
    api_id: number | null;
    name: string;
    display_name: string | null;
    github_org: string;
    database_name: string | null;
    is_active: boolean;
    is_default: boolean;
    total_repos: number;
    total_findings: number;
    created_at: string | null;
    updated_at: string | null;
}

interface OrganizationSelectorProps {
    className?: string;
    onOrganizationChange?: (org: Organization) => void;
}

// =============================================================================
// Component
// =============================================================================

export function OrganizationSelector({
    className,
    onOrganizationChange
}: OrganizationSelectorProps) {
    const [organizations, setOrganizations] = useState<Organization[]>([]);
    const [currentOrg, setCurrentOrg] = useState<Organization | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [isSelecting, setIsSelecting] = useState(false);

    // =========================================================================
    // Data Fetching
    // =========================================================================

    // Fetch all organizations and current org in one effect to avoid race conditions
    useEffect(() => {
        let isMounted = true;

        const fetchData = async () => {
            try {
                setIsLoading(true);
                setError(null);

                // Fetch organizations
                const orgsResponse = await apiFetch(`${API_BASE}/organizations/`);

                if (!orgsResponse.ok) {
                    throw new Error("Failed to fetch organizations");
                }

                const orgsData = await orgsResponse.json();

                if (!isMounted) return;

                setOrganizations(orgsData);

                // Check localStorage for previously selected org
                const savedOrgName = typeof window !== 'undefined' ? localStorage.getItem('selectedOrganization') : null;
                let orgToSelect: Organization | null = null;

                if (savedOrgName) {
                    // Try to find the saved org in the list
                    orgToSelect = orgsData.find((o: Organization) => o.name === savedOrgName);
                }

                // If no saved org or saved org not found, use default
                if (!orgToSelect && orgsData.length > 0) {
                    orgToSelect = orgsData.find((o: Organization) => o.is_default) || orgsData[0];
                }

                // Select the org on the API side and update state
                if (orgToSelect) {
                    try {
                        const selectResponse = await apiFetch(`${API_BASE}/organizations/${orgToSelect.name}/select`, {
                            method: "POST"
                        });
                        if (selectResponse.ok) {
                            const selectedOrg = await selectResponse.json();
                            setCurrentOrg(selectedOrg);
                            // Save to localStorage
                            if (typeof window !== 'undefined') {
                                localStorage.setItem('selectedOrganization', selectedOrg.name);
                            }
                        } else {
                            setCurrentOrg(orgToSelect);
                        }
                    } catch {
                        setCurrentOrg(orgToSelect);
                    }
                }
            } catch (e) {
                console.error("Failed to fetch organizations:", e);
                if (isMounted) {
                    setError(e instanceof Error ? e.message : "Unknown error");
                }
            } finally {
                if (isMounted) {
                    setIsLoading(false);
                }
            }
        };

        fetchData();

        return () => {
            isMounted = false;
        };
    }, []); // Empty dependency array - only run once on mount

    // Refresh function for retry/refresh buttons
    const refreshOrganizations = () => {
        window.location.reload();
    };

    // =========================================================================
    // Organization Selection
    // =========================================================================

    const selectOrganization = async (orgName: string) => {
        try {
            setIsSelecting(true);
            setError(null);

            const response = await apiFetch(`${API_BASE}/organizations/${orgName}/select`, {
                method: "POST"
            });

            if (!response.ok) {
                throw new Error("Failed to select organization");
            }

            const selectedOrg = await response.json();
            setCurrentOrg(selectedOrg);

            // Save to localStorage for persistence across page navigation
            if (typeof window !== 'undefined') {
                localStorage.setItem('selectedOrganization', selectedOrg.name);
            }

            // Notify parent component
            if (onOrganizationChange) {
                onOrganizationChange(selectedOrg);
            }

            // Force full page reload to refresh all data for new org context
            // Using href assignment instead of reload() to ensure cache bypass
            window.location.href = window.location.pathname + "?org=" + selectedOrg.name + "&t=" + Date.now();
        } catch (e) {
            console.error("Failed to select organization:", e);
            setError(e instanceof Error ? e.message : "Unknown error");
        } finally {
            setIsSelecting(false);
        }
    };

    // =========================================================================
    // Render Helpers
    // =========================================================================

    const getScanStatusIcon = (status: string) => {
        switch (status) {
            case "scanning":
                return <Loader2 className="h-3 w-3 animate-spin text-blue-500" />;
            case "error":
                return <AlertCircle className="h-3 w-3 text-red-500" />;
            case "queued":
                return <Loader2 className="h-3 w-3 text-yellow-500" />;
            default:
                return null;
        }
    };

    const getSchemaStatusBadge = (status: string) => {
        switch (status) {
            case "synced":
                return (
                    <Badge variant="outline" className="text-[10px] bg-green-500/10 text-green-600 border-green-500/30">
                        Synced
                    </Badge>
                );
            case "drift":
                return (
                    <Badge variant="outline" className="text-[10px] bg-yellow-500/10 text-yellow-600 border-yellow-500/30">
                        Drift
                    </Badge>
                );
            case "error":
                return (
                    <Badge variant="outline" className="text-[10px] bg-red-500/10 text-red-600 border-red-500/30">
                        Error
                    </Badge>
                );
            default:
                return null;
        }
    };

    // =========================================================================
    // Loading State
    // =========================================================================

    if (isLoading) {
        return (
            <div className={className}>
                <Skeleton className="h-9 w-[200px]" />
            </div>
        );
    }

    // =========================================================================
    // Error State
    // =========================================================================

    if (error && organizations.length === 0) {
        return (
            <div className={className}>
                <TooltipProvider>
                    <Tooltip>
                        <TooltipTrigger asChild>
                            <Button variant="ghost" size="sm" onClick={refreshOrganizations}>
                                <AlertCircle className="h-4 w-4 mr-2 text-red-500" />
                                Retry
                            </Button>
                        </TooltipTrigger>
                        <TooltipContent>
                            <p>{error}</p>
                        </TooltipContent>
                    </Tooltip>
                </TooltipProvider>
            </div>
        );
    }

    // =========================================================================
    // No Organizations
    // =========================================================================

    if (organizations.length === 0) {
        return (
            <div className={className}>
                <Button variant="outline" size="sm" disabled>
                    <Building2 className="h-4 w-4 mr-2" />
                    No Organizations
                </Button>
            </div>
        );
    }

    // =========================================================================
    // Main Render
    // =========================================================================

    return (
        <DropdownMenu>
            <DropdownMenuTrigger asChild>
                <Button
                    variant="outline"
                    role="combobox"
                    disabled={isSelecting}
                    className={`justify-between min-w-[200px] ${className}`}
                >
                    <div className="flex items-center gap-2 truncate">
                        {isSelecting ? (
                            <Loader2 className="h-4 w-4 shrink-0 animate-spin" />
                        ) : (
                            <Building2 className="h-4 w-4 shrink-0 text-muted-foreground" />
                        )}
                        <span className="truncate">
                            {currentOrg?.display_name || currentOrg?.name || "Select Organization"}
                        </span>
                        {/* Scan status indicator removed - not in simplified API */}
                    </div>
                    <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
                </Button>
            </DropdownMenuTrigger>

            <DropdownMenuContent align="start" className="w-[280px]">
                <DropdownMenuLabel className="flex items-center gap-2">
                    <Zap className="h-4 w-4 text-yellow-500" />
                    Organizations
                </DropdownMenuLabel>
                <DropdownMenuSeparator />

                {organizations.map((org) => (
                    <DropdownMenuItem
                        key={org.id}
                        onClick={() => selectOrganization(org.name)}
                        disabled={isSelecting || !org.is_active}
                        className="flex items-center justify-between cursor-pointer py-3"
                    >
                        <div className="flex flex-col gap-1">
                            <div className="flex items-center gap-2">
                                <span className="font-medium">
                                    {org.display_name || org.name}
                                </span>
                                {org.is_default && (
                                    <Badge variant="secondary" className="text-[10px]">
                                        Default
                                    </Badge>
                                )}
                            </div>
                            <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                <span>@{org.github_org}</span>
                                <span>•</span>
                                <span>{org.total_repos} repos</span>
                                <span>•</span>
                                <span>{org.total_findings} findings</span>
                            </div>
                        </div>

                        <div className="flex items-center gap-2">
                            {currentOrg?.id === org.id && (
                                <Check className="h-4 w-4 text-primary" />
                            )}
                        </div>
                    </DropdownMenuItem>
                ))}

                <DropdownMenuSeparator />

                {/* Actions */}
                <DropdownMenuItem
                    onClick={refreshOrganizations}
                    className="cursor-pointer text-muted-foreground"
                >
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Refresh
                </DropdownMenuItem>

                <DropdownMenuItem
                    onClick={() => window.location.href = "/settings/organizations"}
                    className="cursor-pointer text-muted-foreground"
                >
                    <Settings className="h-4 w-4 mr-2" />
                    Manage Organizations
                </DropdownMenuItem>
            </DropdownMenuContent>
        </DropdownMenu>
    );
}

export default OrganizationSelector;
