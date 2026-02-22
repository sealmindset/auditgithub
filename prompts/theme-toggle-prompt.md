# LLM Prompt: Create Light/Dark Theme Toggle Switch

## Task Overview

Create a **production-ready light/dark theme toggle switch** for a Next.js 16+ application positioned in the **upper right corner** of the browser screen (header area). The implementation should follow the exact patterns, architecture, and conventions established in the AuditGitHub project.

---

## Tech Stack Requirements

| Technology | Version | Purpose |
|------------|---------|---------|
| **Next.js** | 16.0.6+ | React framework with App Router |
| **React** | 19.2.0+ | UI library |
| **TypeScript** | 5.x | Type safety |
| **next-themes** | 0.2.1+ | Theme management library |
| **Tailwind CSS** | v4 | Utility-first styling (oklch colors) |
| **shadcn/ui** | Latest | Component primitives (Radix UI-based) |
| **lucide-react** | Latest | Icon library (Sun, Moon, Monitor icons) |

---

## Required Dependencies

```bash
npm install next-themes
npx shadcn-ui@latest add button dropdown-menu switch
```

---

## Architecture Overview

### Component Hierarchy

```
RootLayout (layout.tsx)
├── <html> with suppressHydrationWarning
│   └── <body> with suppressHydrationWarning
│       └── ThemeProvider (wraps entire app)
│           └── Header Bar
│               └── ModeToggle (upper right position)
│                   ├── Option A: Dropdown Menu (Light/Dark/System)
│                   ├── Option B: Toggle Switch (Light ↔ Dark)
│                   └── Option C: Animated Icon Button (cycles themes)
```

---

## Core Implementation Files

### 1. `theme-provider.tsx` - Theme Provider Wrapper

```tsx
"use client"

import * as React from "react"
import { ThemeProvider as NextThemesProvider } from "next-themes"

export function ThemeProvider({
    children,
    ...props
}: React.ComponentProps<typeof NextThemesProvider>) {
    return <NextThemesProvider {...props}>{children}</NextThemesProvider>
}
```

**Key Points:**
- Must be a client component (`"use client"`)
- Wraps `NextThemesProvider` from `next-themes`
- Passes through all props for configuration

---

### 2. `layout.tsx` - Root Layout Integration

```tsx
import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { ModeToggle } from "@/components/mode-toggle";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Your App Title",
  description: "Your app description.",
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
          <div className="flex min-h-screen w-full">
            {/* Sidebar if applicable */}
            <main className="flex-1 overflow-y-auto bg-background">
              {/* Header with theme toggle in upper right */}
              <div className="flex h-14 items-center gap-4 border-b bg-muted/40 px-6">
                {/* Left side content */}
                <div className="flex-1" /> {/* Spacer pushes toggle to right */}
                {/* Theme toggle in upper right */}
                <ModeToggle />
              </div>
              {children}
            </main>
          </div>
        </ThemeProvider>
      </body>
    </html>
  );
}
```

**Critical Configuration:**
- `suppressHydrationWarning` on both `<html>` and `<body>` tags (prevents hydration mismatch)
- `attribute="class"` - adds `.dark` class to `<html>` element
- `defaultTheme="system"` - respects OS preference by default
- `enableSystem` - enables system theme detection
- `disableTransitionOnChange` - prevents flash during theme switch

---

### 3. `mode-toggle.tsx` - Theme Toggle Component

#### Option A: Dropdown Menu (Recommended - Supports Light/Dark/System)

```tsx
"use client"

import * as React from "react"
import { Moon, Sun, Monitor } from "lucide-react"
import { useTheme } from "next-themes"

import { Button } from "@/components/ui/button"
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

export function ModeToggle() {
    const { theme, setTheme } = useTheme()
    const [mounted, setMounted] = React.useState(false)

    // Prevent hydration mismatch
    React.useEffect(() => {
        setMounted(true)
    }, [])

    if (!mounted) {
        return (
            <Button variant="outline" size="icon" disabled>
                <Sun className="h-[1.2rem] w-[1.2rem]" />
            </Button>
        )
    }

    return (
        <DropdownMenu>
            <DropdownMenuTrigger asChild>
                <Button variant="outline" size="icon">
                    <Sun className="h-[1.2rem] w-[1.2rem] rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
                    <Moon className="absolute h-[1.2rem] w-[1.2rem] rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
                    <span className="sr-only">Toggle theme</span>
                </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => setTheme("light")}>
                    <Sun className="mr-2 h-4 w-4" />
                    Light
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setTheme("dark")}>
                    <Moon className="mr-2 h-4 w-4" />
                    Dark
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setTheme("system")}>
                    <Monitor className="mr-2 h-4 w-4" />
                    System
                </DropdownMenuItem>
            </DropdownMenuContent>
        </DropdownMenu>
    )
}
```

---

#### Option B: Toggle Switch (Simple Light ↔ Dark)

```tsx
"use client"

import * as React from "react"
import { Moon, Sun } from "lucide-react"
import { useTheme } from "next-themes"
import { Switch } from "@/components/ui/switch"
import { cn } from "@/lib/utils"

export function ModeToggle() {
    const { theme, setTheme, resolvedTheme } = useTheme()
    const [mounted, setMounted] = React.useState(false)

    React.useEffect(() => {
        setMounted(true)
    }, [])

    if (!mounted) {
        return (
            <div className="flex items-center gap-2">
                <Sun className="h-4 w-4 text-muted-foreground" />
                <Switch disabled />
                <Moon className="h-4 w-4 text-muted-foreground" />
            </div>
        )
    }

    const isDark = resolvedTheme === "dark"

    return (
        <div className="flex items-center gap-2">
            <Sun className={cn(
                "h-4 w-4 transition-colors",
                isDark ? "text-muted-foreground" : "text-amber-500"
            )} />
            <Switch
                checked={isDark}
                onCheckedChange={(checked) => setTheme(checked ? "dark" : "light")}
                aria-label="Toggle dark mode"
            />
            <Moon className={cn(
                "h-4 w-4 transition-colors",
                isDark ? "text-blue-400" : "text-muted-foreground"
            )} />
        </div>
    )
}
```

---

#### Option C: Animated Icon Button (Cycles Through Themes)

```tsx
"use client"

import * as React from "react"
import { Moon, Sun, Monitor } from "lucide-react"
import { useTheme } from "next-themes"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

export function ModeToggle() {
    const { theme, setTheme, resolvedTheme } = useTheme()
    const [mounted, setMounted] = React.useState(false)

    React.useEffect(() => {
        setMounted(true)
    }, [])

    const cycleTheme = () => {
        if (theme === "light") setTheme("dark")
        else if (theme === "dark") setTheme("system")
        else setTheme("light")
    }

    if (!mounted) {
        return (
            <Button variant="outline" size="icon" disabled>
                <Sun className="h-[1.2rem] w-[1.2rem]" />
            </Button>
        )
    }

    return (
        <Button
            variant="outline"
            size="icon"
            onClick={cycleTheme}
            className="relative overflow-hidden"
        >
            <Sun className={cn(
                "h-[1.2rem] w-[1.2rem] absolute transition-all duration-300",
                theme === "light"
                    ? "rotate-0 scale-100 opacity-100"
                    : "-rotate-90 scale-0 opacity-0"
            )} />
            <Moon className={cn(
                "h-[1.2rem] w-[1.2rem] absolute transition-all duration-300",
                theme === "dark"
                    ? "rotate-0 scale-100 opacity-100"
                    : "rotate-90 scale-0 opacity-0"
            )} />
            <Monitor className={cn(
                "h-[1.2rem] w-[1.2rem] absolute transition-all duration-300",
                theme === "system"
                    ? "rotate-0 scale-100 opacity-100"
                    : "rotate-90 scale-0 opacity-0"
            )} />
            <span className="sr-only">
                Current theme: {theme}. Click to cycle themes.
            </span>
        </Button>
    )
}
```

---

#### Option D: Fancy Animated Toggle with Label

```tsx
"use client"

import * as React from "react"
import { Moon, Sun } from "lucide-react"
import { useTheme } from "next-themes"
import { cn } from "@/lib/utils"

export function ModeToggle() {
    const { resolvedTheme, setTheme } = useTheme()
    const [mounted, setMounted] = React.useState(false)

    React.useEffect(() => {
        setMounted(true)
    }, [])

    if (!mounted) {
        return <div className="h-9 w-20 rounded-full bg-muted animate-pulse" />
    }

    const isDark = resolvedTheme === "dark"

    return (
        <button
            onClick={() => setTheme(isDark ? "light" : "dark")}
            className={cn(
                "relative inline-flex h-9 w-20 items-center rounded-full p-1 transition-colors duration-300",
                isDark ? "bg-slate-800" : "bg-amber-100"
            )}
            aria-label={`Switch to ${isDark ? "light" : "dark"} mode`}
        >
            {/* Track background decorations */}
            <span className={cn(
                "absolute inset-0 flex items-center justify-between px-2 text-xs font-medium",
                isDark ? "text-slate-400" : "text-amber-600"
            )}>
                <Sun className={cn(
                    "h-4 w-4 transition-opacity",
                    isDark ? "opacity-30" : "opacity-0"
                )} />
                <Moon className={cn(
                    "h-4 w-4 transition-opacity",
                    isDark ? "opacity-0" : "opacity-30"
                )} />
            </span>

            {/* Sliding thumb */}
            <span
                className={cn(
                    "flex h-7 w-7 items-center justify-center rounded-full shadow-md transition-all duration-300",
                    isDark
                        ? "translate-x-11 bg-slate-700"
                        : "translate-x-0 bg-white"
                )}
            >
                {isDark ? (
                    <Moon className="h-4 w-4 text-blue-300" />
                ) : (
                    <Sun className="h-4 w-4 text-amber-500" />
                )}
            </span>
        </button>
    )
}
```

---

### 4. `globals.css` - Theme CSS Variables

```css
@import "tailwindcss";
@plugin "@tailwindcss/typography";

@custom-variant dark (&:is(.dark *));

@theme inline {
  --color-background: var(--background);
  --color-foreground: var(--foreground);
  --color-primary: var(--primary);
  --color-primary-foreground: var(--primary-foreground);
  --color-secondary: var(--secondary);
  --color-secondary-foreground: var(--secondary-foreground);
  --color-muted: var(--muted);
  --color-muted-foreground: var(--muted-foreground);
  --color-accent: var(--accent);
  --color-accent-foreground: var(--accent-foreground);
  --color-destructive: var(--destructive);
  --color-border: var(--border);
  --color-input: var(--input);
  --color-ring: var(--ring);
  --color-card: var(--card);
  --color-card-foreground: var(--card-foreground);
  --color-popover: var(--popover);
  --color-popover-foreground: var(--popover-foreground);
  --radius-sm: calc(var(--radius) - 4px);
  --radius-md: calc(var(--radius) - 2px);
  --radius-lg: var(--radius);
  --radius-xl: calc(var(--radius) + 4px);
}

/* ===== LIGHT THEME (Default) ===== */
:root {
  --radius: 0.625rem;

  /* Core colors */
  --background: oklch(1 0 0);                    /* Pure white */
  --foreground: oklch(0.145 0 0);                /* Near black */

  /* Card/Popover */
  --card: oklch(1 0 0);
  --card-foreground: oklch(0.145 0 0);
  --popover: oklch(1 0 0);
  --popover-foreground: oklch(0.145 0 0);

  /* Primary - Dark for contrast */
  --primary: oklch(0.205 0 0);
  --primary-foreground: oklch(0.985 0 0);

  /* Secondary - Light gray */
  --secondary: oklch(0.97 0 0);
  --secondary-foreground: oklch(0.205 0 0);

  /* Muted - Subtle backgrounds */
  --muted: oklch(0.97 0 0);
  --muted-foreground: oklch(0.556 0 0);

  /* Accent - For hover states */
  --accent: oklch(0.97 0 0);
  --accent-foreground: oklch(0.205 0 0);

  /* Destructive - Red for errors */
  --destructive: oklch(0.577 0.245 27.325);

  /* Borders and inputs */
  --border: oklch(0.922 0 0);
  --input: oklch(0.922 0 0);
  --ring: oklch(0.708 0 0);

  /* Chart colors */
  --chart-1: oklch(0.646 0.222 41.116);
  --chart-2: oklch(0.6 0.118 184.704);
  --chart-3: oklch(0.398 0.07 227.392);
  --chart-4: oklch(0.828 0.189 84.429);
  --chart-5: oklch(0.769 0.188 70.08);

  /* Sidebar specific */
  --sidebar: oklch(0.985 0 0);
  --sidebar-foreground: oklch(0.145 0 0);
  --sidebar-primary: oklch(0.205 0 0);
  --sidebar-primary-foreground: oklch(0.985 0 0);
  --sidebar-accent: oklch(0.97 0 0);
  --sidebar-accent-foreground: oklch(0.205 0 0);
  --sidebar-border: oklch(0.922 0 0);
  --sidebar-ring: oklch(0.708 0 0);
}

/* ===== DARK THEME ===== */
.dark {
  /* Core colors - Inverted */
  --background: oklch(0.145 0 0);                /* Near black */
  --foreground: oklch(0.985 0 0);                /* Near white */

  /* Card/Popover - Slightly lighter than bg */
  --card: oklch(0.205 0 0);
  --card-foreground: oklch(0.985 0 0);
  --popover: oklch(0.205 0 0);
  --popover-foreground: oklch(0.985 0 0);

  /* Primary - Light for contrast */
  --primary: oklch(0.922 0 0);
  --primary-foreground: oklch(0.205 0 0);

  /* Secondary - Dark gray */
  --secondary: oklch(0.269 0 0);
  --secondary-foreground: oklch(0.985 0 0);

  /* Muted - Subtle backgrounds */
  --muted: oklch(0.269 0 0);
  --muted-foreground: oklch(0.708 0 0);

  /* Accent - For hover states */
  --accent: oklch(0.269 0 0);
  --accent-foreground: oklch(0.985 0 0);

  /* Destructive - Lighter red for dark mode */
  --destructive: oklch(0.704 0.191 22.216);

  /* Borders and inputs - Semi-transparent white */
  --border: oklch(1 0 0 / 10%);
  --input: oklch(1 0 0 / 15%);
  --ring: oklch(0.556 0 0);

  /* Chart colors - Adjusted for dark backgrounds */
  --chart-1: oklch(0.488 0.243 264.376);
  --chart-2: oklch(0.696 0.17 162.48);
  --chart-3: oklch(0.769 0.188 70.08);
  --chart-4: oklch(0.627 0.265 303.9);
  --chart-5: oklch(0.645 0.246 16.439);

  /* Sidebar specific */
  --sidebar: oklch(0.205 0 0);
  --sidebar-foreground: oklch(0.985 0 0);
  --sidebar-primary: oklch(0.488 0.243 264.376);
  --sidebar-primary-foreground: oklch(0.985 0 0);
  --sidebar-accent: oklch(0.269 0 0);
  --sidebar-accent-foreground: oklch(0.985 0 0);
  --sidebar-border: oklch(1 0 0 / 10%);
  --sidebar-ring: oklch(0.556 0 0);
}

/* Base layer for global styles */
@layer base {
  * {
    @apply border-border outline-ring/50;
  }
  body {
    @apply bg-background text-foreground;
  }
}
```

---

## Complete File Structure

```
src/
├── app/
│   ├── layout.tsx           # Root layout with ThemeProvider
│   ├── globals.css          # Theme CSS variables (oklch)
│   └── page.tsx             # Home page
├── components/
│   ├── ui/
│   │   ├── button.tsx       # shadcn button
│   │   ├── dropdown-menu.tsx # shadcn dropdown
│   │   └── switch.tsx       # shadcn switch (Radix)
│   ├── theme-provider.tsx   # next-themes wrapper
│   └── mode-toggle.tsx      # Theme toggle component
└── lib/
    └── utils.ts             # cn() utility function
```

---

## Key Implementation Details

### 1. Hydration Mismatch Prevention

The `mounted` state pattern prevents React hydration mismatches:

```tsx
const [mounted, setMounted] = React.useState(false)

React.useEffect(() => {
    setMounted(true)
}, [])

if (!mounted) {
    // Return skeleton/placeholder that matches server render
    return <Button variant="outline" size="icon" disabled>
        <Sun className="h-[1.2rem] w-[1.2rem]" />
    </Button>
}
```

**Why this matters:**
- Server doesn't know user's theme preference
- Client may have different theme than server's default
- Without this pattern, React will warn about hydration mismatch

### 2. Theme vs ResolvedTheme

```tsx
const { theme, resolvedTheme, setTheme } = useTheme()
```

- `theme`: The user's explicit choice ("light", "dark", "system")
- `resolvedTheme`: The actual applied theme ("light" or "dark")
- Use `resolvedTheme` when checking what theme is currently visible
- Use `theme` when checking what the user selected

### 3. Animated Icon Transitions

```tsx
<Sun className="h-[1.2rem] w-[1.2rem] rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
<Moon className="absolute h-[1.2rem] w-[1.2rem] rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
```

**Animation breakdown:**
- Light mode: Sun visible (rotate-0, scale-100), Moon hidden (rotate-90, scale-0)
- Dark mode: Sun hidden (dark:-rotate-90, dark:scale-0), Moon visible (dark:rotate-0, dark:scale-100)
- `transition-all` animates the rotation and scale changes

### 4. Theme Provider Configuration

```tsx
<ThemeProvider
  attribute="class"           // Adds class to <html>
  defaultTheme="system"       // Default to OS preference
  enableSystem                // Enable OS theme detection
  disableTransitionOnChange   // Prevent color transition flash
>
```

**Options explained:**
- `attribute="class"` vs `attribute="data-theme"`: class-based is more compatible with Tailwind
- `enableSystem`: Detects and respects `prefers-color-scheme` media query
- `disableTransitionOnChange`: Prevents momentary flash when theme changes

---

## Accessibility Considerations

1. **Screen Reader Labels:**
   ```tsx
   <span className="sr-only">Toggle theme</span>
   ```

2. **ARIA Labels:**
   ```tsx
   aria-label={`Switch to ${isDark ? "light" : "dark"} mode`}
   ```

3. **Keyboard Navigation:**
   - Dropdown: Arrow keys to navigate, Enter to select
   - Switch: Space/Enter to toggle
   - Button: Enter/Space to activate

4. **Focus Indicators:**
   ```tsx
   focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2
   ```

---

## Testing Checklist

- [ ] Theme toggle appears in upper right corner of header
- [ ] Clicking toggle changes theme immediately
- [ ] Theme persists across page refreshes (localStorage)
- [ ] Theme persists across sessions
- [ ] System preference is detected on first visit
- [ ] No hydration mismatch warnings in console
- [ ] Smooth icon animation during toggle
- [ ] Works with keyboard navigation (Tab, Enter, Space)
- [ ] Screen reader announces theme state
- [ ] All UI components respect theme variables
- [ ] Charts/graphs update colors with theme
- [ ] No flash of wrong theme on page load

---

## Troubleshooting

### Issue: Flash of wrong theme on load

**Solution:** Add this script to `<head>` in layout:
```tsx
<script
  dangerouslySetInnerHTML={{
    __html: `
      try {
        if (localStorage.theme === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
          document.documentElement.classList.add('dark')
        } else {
          document.documentElement.classList.remove('dark')
        }
      } catch (_) {}
    `,
  }}
/>
```

### Issue: Hydration mismatch warning

**Solution:** Use the `mounted` state pattern shown above.

### Issue: Theme not persisting

**Check:**
1. `localStorage` is accessible (not blocked by browser settings)
2. `ThemeProvider` is wrapping the entire app
3. No conflicting theme logic elsewhere

### Issue: CSS variables not applying

**Check:**
1. `.dark` class is being added to `<html>` element
2. CSS variables are defined for both `:root` and `.dark`
3. Components use `bg-background`, `text-foreground`, etc.

---

## Optional Enhancements

### 1. Add Tooltip

```tsx
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"

<Tooltip>
  <TooltipTrigger asChild>
    <Button variant="outline" size="icon" onClick={toggleTheme}>
      {/* Icon */}
    </Button>
  </TooltipTrigger>
  <TooltipContent>
    <p>Current: {theme} theme</p>
  </TooltipContent>
</Tooltip>
```

### 2. Add Sound Effect

```tsx
const toggleTheme = () => {
  const audio = new Audio('/sounds/switch.mp3')
  audio.volume = 0.3
  audio.play()
  setTheme(isDark ? 'light' : 'dark')
}
```

### 3. Add Transition Animation to Page

```css
/* In globals.css */
html.theme-transition,
html.theme-transition *,
html.theme-transition *::before,
html.theme-transition *::after {
  transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease !important;
}
```

```tsx
// In toggle handler
document.documentElement.classList.add('theme-transition')
setTheme(newTheme)
setTimeout(() => {
  document.documentElement.classList.remove('theme-transition')
}, 300)
```

---

## Summary

This prompt provides everything needed to implement a professional light/dark theme toggle:

1. **ThemeProvider** - Wraps app with next-themes
2. **ModeToggle** - Multiple implementation options (dropdown, switch, animated button)
3. **CSS Variables** - Complete oklch-based color system for light and dark
4. **Hydration handling** - Prevents React hydration mismatches
5. **Accessibility** - Screen reader support, keyboard navigation
6. **Position** - Upper right corner of header bar

Choose the toggle style that best fits your UX needs:
- **Dropdown**: Best for apps that want Light/Dark/System options
- **Switch**: Best for simple light ↔ dark toggle
- **Animated Button**: Best for single-click cycling with visual flair
