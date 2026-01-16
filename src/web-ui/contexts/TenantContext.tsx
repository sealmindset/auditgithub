"use client";

import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from "react";
import Cookies from "js-cookie";

// Types
export interface Tenant {
    id: string;
    slug: string;
    name: string;
    github_org: string;
    description: string | null;
    database_name: string;
    is_active: boolean;
    is_provisioned: boolean;
    schema_version: string | null;
    migration_status: string | null;
    created_at: string;
    updated_at: string;
}

interface TenantContextValue {
    // State
    currentTenant: Tenant | null;
    tenants: Tenant[];
    isLoading: boolean;
    error: string | null;
    isMultiTenantEnabled: boolean;

    // Actions
    setTenant: (slug: string) => void;
    refreshTenants: () => Promise<void>;
}

const TenantContext = createContext<TenantContextValue | undefined>(undefined);

// Cookie name for storing selected tenant
const TENANT_COOKIE_NAME = "tenant_slug";
const TENANT_COOKIE_EXPIRY = 365; // days

interface TenantProviderProps {
    children: ReactNode;
    apiBaseUrl?: string;
}

export function TenantProvider({
    children,
    apiBaseUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"
}: TenantProviderProps) {
    const [currentTenant, setCurrentTenant] = useState<Tenant | null>(null);
    const [tenants, setTenants] = useState<Tenant[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [isMultiTenantEnabled, setIsMultiTenantEnabled] = useState(false);

    // Fetch all available tenants
    const refreshTenants = useCallback(async () => {
        try {
            setIsLoading(true);
            setError(null);

            const response = await fetch(`${apiBaseUrl}/tenants`);

            if (!response.ok) {
                throw new Error(`Failed to fetch tenants: ${response.statusText}`);
            }

            const data = await response.json();
            setTenants(data.tenants || []);

            // Check if multi-tenant is enabled (more than 0 tenants registered)
            setIsMultiTenantEnabled(data.total > 0);

            // If we have tenants but no current tenant, try to restore from cookie
            if (data.tenants.length > 0 && !currentTenant) {
                const savedSlug = Cookies.get(TENANT_COOKIE_NAME);
                const savedTenant = data.tenants.find((t: Tenant) => t.slug === savedSlug);

                if (savedTenant) {
                    setCurrentTenant(savedTenant);
                } else {
                    // Default to first tenant
                    setCurrentTenant(data.tenants[0]);
                    Cookies.set(TENANT_COOKIE_NAME, data.tenants[0].slug, { expires: TENANT_COOKIE_EXPIRY });
                }
            }
        } catch (err) {
            console.error("Error fetching tenants:", err);
            setError(err instanceof Error ? err.message : "Failed to fetch tenants");
        } finally {
            setIsLoading(false);
        }
    }, [apiBaseUrl, currentTenant]);

    // Set current tenant
    const setTenant = useCallback((slug: string) => {
        const tenant = tenants.find(t => t.slug === slug);
        if (tenant) {
            setCurrentTenant(tenant);
            Cookies.set(TENANT_COOKIE_NAME, slug, { expires: TENANT_COOKIE_EXPIRY });
        }
    }, [tenants]);

    // Initial load
    useEffect(() => {
        refreshTenants();
    }, []);

    const value: TenantContextValue = {
        currentTenant,
        tenants,
        isLoading,
        error,
        isMultiTenantEnabled,
        setTenant,
        refreshTenants,
    };

    return (
        <TenantContext.Provider value={value}>
            {children}
        </TenantContext.Provider>
    );
}

// Hook for using tenant context
export function useTenant(): TenantContextValue {
    const context = useContext(TenantContext);
    if (context === undefined) {
        throw new Error("useTenant must be used within a TenantProvider");
    }
    return context;
}

// Utility hook for getting the X-Tenant-ID header
export function useTenantHeader(): Record<string, string> {
    const { currentTenant } = useTenant();

    if (currentTenant) {
        return { "X-Tenant-ID": currentTenant.slug };
    }

    return {};
}
