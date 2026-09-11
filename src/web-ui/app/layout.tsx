import type { Metadata, Viewport } from "next";
import localFont from "next/font/local";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { AuthProvider } from "@/contexts/AuthContext";
import { AuthShell } from "@/components/AuthShell";
import { Toaster } from "@/components/ui/toaster";

const inter = localFont({
  src: "./fonts/Inter-Variable.woff2",
  variable: "--font-inter",
  display: "swap",
  // Metric-matched fallback: text does not reflow when the webfont lands.
  fallback: ["system-ui", "-apple-system", "Segoe UI", "sans-serif"],
  adjustFontFallback: "Arial",
});

export const metadata: Metadata = {
  title: {
    default: "AuditGH — Security Platform",
    template: "%s · AuditGH",
  },
  description:
    "Continuous security scanning, triage and remediation for GitHub organizations.",
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  // The browser paints this before any stylesheet loads, so it cannot be a
  // `var()`. These are `--background` from `app/globals.css` converted to sRGB:
  // light `oklch(0.985 0.003 264)`, dark `oklch(0.165 0.012 264)`. If either
  // token moves, re-derive with `scripts/check-contrast.py`'s `oklch_to_srgb`
  // rather than eyeballing a replacement.
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#f9fafc" },
    { media: "(prefers-color-scheme: dark)", color: "#0c0e14" },
  ],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={inter.variable} suppressHydrationWarning>
      <body suppressHydrationWarning>
        {/* First stop on the tab order — keyboard users skip the sidebar. */}
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:rounded-md focus:bg-primary focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-primary-foreground focus:shadow-lg"
        >
          Skip to main content
        </a>
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          <AuthProvider>
            <AuthShell>{children}</AuthShell>
          </AuthProvider>
          <Toaster />
        </ThemeProvider>
      </body>
    </html>
  );
}
