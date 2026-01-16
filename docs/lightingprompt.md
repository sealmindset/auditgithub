# Theme Switching Implementation Prompt for Next.js Applications

## Prompt

Implement a light/dark/system theme switching feature in my Next.js application. The implementation should use `next-themes` for theme management, Tailwind CSS for styling, and shadcn/ui components for the dropdown menu. The toggle button should be placed in the top-right corner of the header, displaying a Sun icon in light mode and a Moon icon in dark mode with smooth CSS transitions between them. When clicked, a dropdown menu should appear with three options: Light, Dark, and System.

---

## Required Dependencies

Install these packages:

```bash
npm install next-themes lucide-react
npm install @radix-ui/react-dropdown-menu @radix-ui/react-slot
npm install clsx tailwind-merge class-variance-authority
```

Your `package.json` should include:
```json
{
  "dependencies": {
    "next-themes": "^0.2.1",
    "lucide-react": "^0.555.0",
    "@radix-ui/react-dropdown-menu": "^2.1.16",
    "@radix-ui/react-slot": "^1.2.4",
    "class-variance-authority": "^0.7.1",
    "clsx": "^2.1.1",
    "tailwind-merge": "^3.4.0"
  }
}
```

---

## File Structure

Create the following files:

```
├── app/
│   ├── layout.tsx
│   └── globals.css
├── components/
│   ├── theme-provider.tsx
│   ├── mode-toggle.tsx
│   └── ui/
│       ├── button.tsx
│       └── dropdown-menu.tsx
└── lib/
    └── utils.ts
```

---

## Implementation Files

### 1. Utility Function (`lib/utils.ts`)

```typescript
import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
    return twMerge(clsx(inputs))
}
```

### 2. Theme Provider (`components/theme-provider.tsx`)

```typescript
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

### 3. Mode Toggle Button (`components/mode-toggle.tsx`)

This is the theme switcher button with animated Sun/Moon icons and a dropdown menu:

```typescript
"use client"

import * as React from "react"
import { Moon, Sun } from "lucide-react"
import { useTheme } from "next-themes"

import { Button } from "@/components/ui/button"
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

export function ModeToggle() {
    const { setTheme } = useTheme()

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
                    Light
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setTheme("dark")}>
                    Dark
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setTheme("system")}>
                    System
                </DropdownMenuItem>
            </DropdownMenuContent>
        </DropdownMenu>
    )
}
```

**Key Features:**
- **Animated Icons**: Sun rotates out and Moon rotates in when switching to dark mode
- **CSS Transitions**: `transition-all` provides smooth icon animations
- **Accessibility**: `sr-only` span for screen readers
- **Dropdown Alignment**: `align="end"` positions menu to the right

### 4. Button Component (`components/ui/button.tsx`)

```typescript
import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-all disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4 shrink-0 [&_svg]:shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground hover:bg-primary/90",
        destructive:
          "bg-destructive text-white hover:bg-destructive/90 focus-visible:ring-destructive/20 dark:focus-visible:ring-destructive/40 dark:bg-destructive/60",
        outline:
          "border bg-background shadow-xs hover:bg-accent hover:text-accent-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50",
        secondary:
          "bg-secondary text-secondary-foreground hover:bg-secondary/80",
        ghost:
          "hover:bg-accent hover:text-accent-foreground dark:hover:bg-accent/50",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: {
        default: "h-9 px-4 py-2 has-[>svg]:px-3",
        sm: "h-8 rounded-md gap-1.5 px-3 has-[>svg]:px-2.5",
        lg: "h-10 rounded-md px-6 has-[>svg]:px-4",
        icon: "size-9",
        "icon-sm": "size-8",
        "icon-lg": "size-10",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

function Button({
  className,
  variant,
  size,
  asChild = false,
  ...props
}: React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean
  }) {
  const Comp = asChild ? Slot : "button"

  return (
    <Comp
      data-slot="button"
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  )
}

export { Button, buttonVariants }
```

### 5. Dropdown Menu Component (`components/ui/dropdown-menu.tsx`)

```typescript
"use client"

import * as React from "react"
import * as DropdownMenuPrimitive from "@radix-ui/react-dropdown-menu"

import { cn } from "@/lib/utils"

function DropdownMenu({
  ...props
}: React.ComponentProps<typeof DropdownMenuPrimitive.Root>) {
  return <DropdownMenuPrimitive.Root data-slot="dropdown-menu" {...props} />
}

function DropdownMenuTrigger({
  ...props
}: React.ComponentProps<typeof DropdownMenuPrimitive.Trigger>) {
  return (
    <DropdownMenuPrimitive.Trigger
      data-slot="dropdown-menu-trigger"
      {...props}
    />
  )
}

function DropdownMenuContent({
  className,
  sideOffset = 4,
  ...props
}: React.ComponentProps<typeof DropdownMenuPrimitive.Content>) {
  return (
    <DropdownMenuPrimitive.Portal>
      <DropdownMenuPrimitive.Content
        data-slot="dropdown-menu-content"
        sideOffset={sideOffset}
        className={cn(
          "bg-popover text-popover-foreground data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 z-50 max-h-(--radix-dropdown-menu-content-available-height) min-w-[8rem] origin-(--radix-dropdown-menu-content-transform-origin) overflow-x-hidden overflow-y-auto rounded-md border p-1 shadow-md",
          className
        )}
        {...props}
      />
    </DropdownMenuPrimitive.Portal>
  )
}

function DropdownMenuItem({
  className,
  inset,
  variant = "default",
  ...props
}: React.ComponentProps<typeof DropdownMenuPrimitive.Item> & {
  inset?: boolean
  variant?: "default" | "destructive"
}) {
  return (
    <DropdownMenuPrimitive.Item
      data-slot="dropdown-menu-item"
      data-inset={inset}
      data-variant={variant}
      className={cn(
        "focus:bg-accent focus:text-accent-foreground data-[variant=destructive]:text-destructive data-[variant=destructive]:focus:bg-destructive/10 dark:data-[variant=destructive]:focus:bg-destructive/20 data-[variant=destructive]:focus:text-destructive data-[variant=destructive]:*:[svg]:!text-destructive [&_svg:not([class*='text-'])]:text-muted-foreground relative flex cursor-default items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-hidden select-none data-[disabled]:pointer-events-none data-[disabled]:opacity-50 data-[inset]:pl-8 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
        className
      )}
      {...props}
    />
  )
}

export {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
}
```

### 6. Global Styles (`app/globals.css`)

Define CSS custom properties for light and dark themes using OKLCH color space:

```css
@import "tailwindcss";

@custom-variant dark (&:is(.dark *));

@theme inline {
  --color-background: var(--background);
  --color-foreground: var(--foreground);
  --color-card: var(--card);
  --color-card-foreground: var(--card-foreground);
  --color-popover: var(--popover);
  --color-popover-foreground: var(--popover-foreground);
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
}

:root {
  --radius: 0.625rem;
  --background: oklch(1 0 0);
  --foreground: oklch(0.145 0 0);
  --card: oklch(1 0 0);
  --card-foreground: oklch(0.145 0 0);
  --popover: oklch(1 0 0);
  --popover-foreground: oklch(0.145 0 0);
  --primary: oklch(0.205 0 0);
  --primary-foreground: oklch(0.985 0 0);
  --secondary: oklch(0.97 0 0);
  --secondary-foreground: oklch(0.205 0 0);
  --muted: oklch(0.97 0 0);
  --muted-foreground: oklch(0.556 0 0);
  --accent: oklch(0.97 0 0);
  --accent-foreground: oklch(0.205 0 0);
  --destructive: oklch(0.577 0.245 27.325);
  --border: oklch(0.922 0 0);
  --input: oklch(0.922 0 0);
  --ring: oklch(0.708 0 0);
}

.dark {
  --background: oklch(0.145 0 0);
  --foreground: oklch(0.985 0 0);
  --card: oklch(0.205 0 0);
  --card-foreground: oklch(0.985 0 0);
  --popover: oklch(0.205 0 0);
  --popover-foreground: oklch(0.985 0 0);
  --primary: oklch(0.922 0 0);
  --primary-foreground: oklch(0.205 0 0);
  --secondary: oklch(0.269 0 0);
  --secondary-foreground: oklch(0.985 0 0);
  --muted: oklch(0.269 0 0);
  --muted-foreground: oklch(0.708 0 0);
  --accent: oklch(0.269 0 0);
  --accent-foreground: oklch(0.985 0 0);
  --destructive: oklch(0.704 0.191 22.216);
  --border: oklch(1 0 0 / 10%);
  --input: oklch(1 0 0 / 15%);
  --ring: oklch(0.556 0 0);
}

@layer base {
  * {
    @apply border-border outline-ring/50;
  }
  body {
    @apply bg-background text-foreground;
  }
}
```

### 7. Root Layout (`app/layout.tsx`)

Wrap your application with the ThemeProvider and place the ModeToggle in the header:

```typescript
import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { ModeToggle } from "@/components/mode-toggle";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Your App Name",
  description: "Your app description",
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
            <main className="flex-1 overflow-y-auto bg-background">
              <div className="flex h-14 items-center gap-4 border-b bg-muted/40 px-6">
                <div className="font-semibold">Your App</div>
                <div className="flex-1" />
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

---

## Button Placement

The `ModeToggle` button should be placed in the **top-right corner of the header**:

```
┌─────────────────────────────────────────────────────────────┐
│  Logo/Title                                    [☀️/🌙]     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│                      Page Content                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Layout Pattern:**
```tsx
<div className="flex h-14 items-center gap-4 border-b bg-muted/40 px-6">
    <div className="font-semibold">Your App</div>
    <div className="flex-1" />  {/* Spacer pushes toggle to right */}
    <ModeToggle />
</div>
```

---

## Icon Behavior

The button displays animated icons that transition smoothly:

| Theme | Visible Icon | Animation |
|-------|--------------|-----------|
| Light | ☀️ Sun | Rotated 0°, Scale 100% |
| Dark | 🌙 Moon | Rotated 0°, Scale 100% |

**CSS Animation Classes:**
```css
/* Sun icon - visible in light mode */
.rotate-0.scale-100.transition-all.dark:-rotate-90.dark:scale-0

/* Moon icon - visible in dark mode */  
.absolute.rotate-90.scale-0.transition-all.dark:rotate-0.dark:scale-100
```

The `absolute` positioning on Moon overlays it on Sun, and the rotation/scale transitions create a smooth swap effect.

---

## Dropdown Menu Options

When clicked, the button opens a dropdown with three options:

| Option | Action |
|--------|--------|
| **Light** | Forces light theme |
| **Dark** | Forces dark theme |
| **System** | Follows OS preference |

The dropdown is right-aligned (`align="end"`) to stay within viewport bounds.

---

## ThemeProvider Configuration

| Prop | Value | Purpose |
|------|-------|---------|
| `attribute` | `"class"` | Adds `.dark` class to `<html>` |
| `defaultTheme` | `"system"` | Respects OS preference initially |
| `enableSystem` | `true` | Enables system theme detection |
| `disableTransitionOnChange` | `true` | Prevents flash during switch |

---

## Critical Implementation Notes

1. **`suppressHydrationWarning`** - Required on `<html>` and `<body>` tags to prevent Next.js hydration errors

2. **`"use client"`** - Required on `theme-provider.tsx` and `mode-toggle.tsx` since they use React hooks

3. **Theme Persistence** - `next-themes` automatically stores preference in `localStorage`

4. **System Theme Detection** - Listens to `prefers-color-scheme` media query

---

## Testing Checklist

- [ ] Sun icon visible in light mode
- [ ] Moon icon visible in dark mode
- [ ] Smooth rotation animation when switching
- [ ] Dropdown opens on click
- [ ] Dropdown closes when option selected
- [ ] Dropdown closes when clicking outside
- [ ] Theme persists after page refresh
- [ ] System option follows OS preference
- [ ] No hydration errors in console
- [ ] No flash of wrong theme on load

---

## Summary

This implementation provides:
- ✅ Light, Dark, and System theme options
- ✅ Animated Sun/Moon icon transitions
- ✅ Accessible dropdown menu using Radix UI
- ✅ Persistent theme via localStorage
- ✅ System preference detection
- ✅ No hydration mismatches
- ✅ shadcn/ui component patterns
- ✅ Tailwind CSS v4 compatible
