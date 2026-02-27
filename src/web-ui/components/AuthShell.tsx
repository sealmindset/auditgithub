"use client";

import { useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/contexts/AuthContext";
import { TenantProvider } from "@/contexts/TenantContext";
import { AppSidebar } from "@/components/app-sidebar";
import { ModeToggle } from "@/components/mode-toggle";
import { OrganizationSelector } from "@/components/OrganizationSelector";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { Breadcrumbs } from "@/components/Breadcrumbs";
import { QuickSearch } from "@/components/QuickSearch";
import { Loader2 } from "lucide-react";

/** Routes that render without the sidebar / auth gate. */
const PUBLIC_PREFIXES = ["/login", "/invite"];

function isPublicPath(pathname: string): boolean {
  return PUBLIC_PREFIXES.some(
    (p) => pathname === p || pathname.startsWith(p + "/"),
  );
}

export function AuthShell({ children }: { children: React.ReactNode }) {
  const { status } = useAuth();
  const pathname = usePathname();
  const router = useRouter();

  const isPublic = isPublicPath(pathname);

  // Redirect unauthenticated users to /login (protected pages only)
  useEffect(() => {
    if (status === "unauthenticated" && !isPublic) {
      router.replace(`/login?redirect=${encodeURIComponent(pathname)}`);
    }
  }, [status, isPublic, pathname, router]);

  // ── Public pages: render bare (no sidebar) ───────────────────────
  if (isPublic) {
    return <>{children}</>;
  }

  // ── Loading: show spinner while /auth/me resolves ────────────────
  if (status === "loading") {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  // ── Unauthenticated on a protected page: render nothing (redirect in flight)
  if (status === "unauthenticated") {
    return null;
  }

  // ── Authenticated: full sidebar layout ───────────────────────────
  return (
    <TenantProvider>
      <SidebarProvider>
        <div className="flex min-h-screen w-full">
          <AppSidebar />
          <main className="flex-1 overflow-y-auto bg-background">
            <div className="flex h-14 items-center gap-4 border-b bg-muted/40 px-6">
              <SidebarTrigger />
              <OrganizationSelector />
              <Breadcrumbs />
              <div className="flex-1" />
              <QuickSearch />
              <ModeToggle />
            </div>
            {children}
          </main>
        </div>
      </SidebarProvider>
    </TenantProvider>
  );
}
