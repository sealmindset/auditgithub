"use client";

import { useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/contexts/AuthContext";
import { TenantProvider } from "@/contexts/TenantContext";
import { AppSidebar } from "@/components/app-sidebar";
import { ModeToggle } from "@/components/mode-toggle";
import { OrganizationSelector } from "@/components/OrganizationSelector";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { Separator } from "@/components/ui/separator";
import { Breadcrumbs } from "@/components/Breadcrumbs";
import { QuickSearch } from "@/components/QuickSearch";
import { ShieldCheck } from "lucide-react";

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

  // ── Loading: branded hold, not a naked spinner ───────────────────
  if (status === "loading") {
    return <BootScreen />;
  }

  // ── Unauthenticated on a protected page: render nothing (redirect in flight)
  if (status === "unauthenticated") {
    return null;
  }

  // ── Authenticated: full sidebar layout ───────────────────────────
  return (
    <TenantProvider>
      <SidebarProvider>
        <div className="flex min-h-screen w-full bg-background">
          <AppSidebar />
          <div className="flex min-w-0 flex-1 flex-col">
            <header
              data-print-hide
              className="sticky top-0 z-30 flex h-14 shrink-0 items-center gap-2 border-b border-border bg-background/85 px-3 backdrop-blur-md supports-[backdrop-filter]:bg-background/70 sm:px-4"
            >
              <SidebarTrigger className="-ml-1" />
              <Separator
                orientation="vertical"
                className="mr-1 hidden h-5 sm:block"
              />
              <OrganizationSelector />
              <Separator
                orientation="vertical"
                className="mx-1 hidden h-5 lg:block"
              />
              <div className="hidden min-w-0 lg:block">
                <Breadcrumbs />
              </div>
              <div className="flex-1" />
              <QuickSearch />
              <ModeToggle />
            </header>

            <main
              id="main-content"
              className="flex min-w-0 flex-1 flex-col overflow-x-hidden"
            >
              {children}
            </main>
          </div>
        </div>
      </SidebarProvider>
    </TenantProvider>
  );
}

/** Shown while /auth/me resolves. Holds the layout so nothing flashes. */
function BootScreen() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-background">
      <div className="relative flex size-12 items-center justify-center rounded-xl border border-primary-line bg-primary-soft text-primary-text">
        <ShieldCheck className="size-6" aria-hidden="true" />
        <span className="absolute inset-0 animate-ping rounded-xl border border-primary/30" />
      </div>
      <p className="text-sm text-muted-foreground" role="status">
        Verifying your session…
      </p>
    </div>
  );
}
