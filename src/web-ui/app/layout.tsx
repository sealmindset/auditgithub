import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { TenantProvider } from "@/contexts/TenantContext";
import { AppSidebar } from "@/components/app-sidebar";
import { ModeToggle } from "@/components/mode-toggle";
import { OrganizationSelector } from "@/components/OrganizationSelector";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "AuditGitHub - Security Platform",
  description: "Comprehensive security scanning and remediation platform.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={inter.className} suppressHydrationWarning>
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          <TenantProvider>
            <SidebarProvider>
              <div className="flex min-h-screen w-full">
                <AppSidebar />
                <main className="flex-1 overflow-y-auto bg-background">
                  <div className="flex h-14 items-center gap-4 border-b bg-muted/40 px-6">
                    <SidebarTrigger />
                    <OrganizationSelector />
                    <div className="flex-1" />
                    <ModeToggle />
                  </div>
                  {children}
                </main>
              </div>
            </SidebarProvider>
          </TenantProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
