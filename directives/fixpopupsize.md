# Fix Popup Modal Sizes - 75% Browser Screen

## Objective

Standardize all popup modals (dialogs) in the application to be 75% of the browser's current screen size, ensuring consistent user experience across the application.

---

## Problem

The default Radix UI Dialog component has a maximum width constraint (`sm:max-w-lg`) that prevents custom width classes from taking effect. Different dialogs throughout the application have inconsistent sizes, making the UI feel disjointed.

---

## Template Solution

Use the **Analysis Report** dialog in `ZDAReportsView.tsx` as the template for all popup modals.

### Required CSS Classes

```typescript
<DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
```

| Class | Purpose |
|-------|---------|
| `!w-[75vw]` | Width = 75% of viewport width. The `!` prefix adds `!important` to override default constraints. |
| `!h-[75vh]` | Height = 75% of viewport height. The `!` prefix adds `!important`. |
| `!max-w-none` | Removes the default `max-width` constraint from the Dialog component. |
| `flex flex-col` | Enables flex layout for proper content distribution (header, scrollable content, footer). |

### Why `!important` is Required

The Dialog component (`src/web-ui/components/ui/dialog.tsx`) has default styles:

```typescript
className={cn(
  "... w-full max-w-[calc(100%-2rem)] ... sm:max-w-lg",
  className
)}
```

The `sm:max-w-lg` class takes precedence over custom width classes due to Tailwind's specificity. Using `!` (important modifier) ensures our custom sizes override the defaults.

---

## Template Dialog Structure

```typescript
<Dialog open={isOpen} onOpenChange={setIsOpen}>
    <DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
        {/* Header - Fixed at top */}
        <DialogHeader className="flex-shrink-0">
            <div className="flex items-center justify-between">
                <div>
                    <DialogTitle>Modal Title</DialogTitle>
                    <DialogDescription>
                        Optional description text
                    </DialogDescription>
                </div>
                {/* Optional: Action buttons in header */}
                <Button variant="outline" size="sm">
                    Action
                </Button>
            </div>
        </DialogHeader>

        {/* Content - Scrollable */}
        <div className="flex-1 overflow-y-auto space-y-6 pr-2">
            {/* Your content here */}
        </div>

        {/* Optional: Footer - Fixed at bottom */}
        <DialogFooter className="flex-shrink-0">
            <Button variant="outline" onClick={() => setIsOpen(false)}>
                Cancel
            </Button>
            <Button onClick={handleSubmit}>
                Submit
            </Button>
        </DialogFooter>
    </DialogContent>
</Dialog>
```

### Key Layout Principles

1. **DialogContent**: Uses `flex flex-col` for vertical layout
2. **DialogHeader**: Uses `flex-shrink-0` to prevent shrinking
3. **Content Area**: Uses `flex-1 overflow-y-auto` to fill remaining space and scroll
4. **DialogFooter**: Uses `flex-shrink-0` to stay at bottom (if present)

---

## Dialogs to Update

| File | Current Classes | Status |
|------|-----------------|--------|
| `ZDAReportsView.tsx` | `!w-[75vw] !h-[75vh] !max-w-none flex flex-col` | ✅ Template |
| `AskAIDialog.tsx` | `max-w-3xl max-h-[80vh] flex flex-col` | ⚠️ Needs update |
| `AskComponentDialog.tsx` | `max-w-2xl max-h-[85vh]` | ⚠️ Needs update |
| `ContributorsView.tsx` | `max-w-4xl max-h-[90vh] overflow-hidden` | ⚠️ Needs update |
| `ArchitectureView.tsx` | `sm:max-w-[425px]` | ⚠️ Needs update |
| `PromptEditorDialog.tsx` | `sm:max-w-[95vw] h-[85vh] flex flex-col` | ⚠️ Needs update |
| `ai-triage-dialog.tsx` | `sm:max-w-[500px]` | ⚠️ Needs update |

---

## Implementation

### 1. AskAIDialog.tsx

**Location:** `src/web-ui/components/AskAIDialog.tsx`

**Find:**
```typescript
<DialogContent className="max-w-3xl max-h-[80vh] flex flex-col">
```

**Replace with:**
```typescript
<DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
```

---

### 2. AskComponentDialog.tsx

**Location:** `src/web-ui/components/AskComponentDialog.tsx`

**Find:**
```typescript
<DialogContent className="max-w-2xl max-h-[85vh]">
```

**Replace with:**
```typescript
<DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
```

**Note:** Add `flex-1 overflow-y-auto` to the content area if not already present.

---

### 3. ContributorsView.tsx

**Location:** `src/web-ui/components/ContributorsView.tsx`

**Find:**
```typescript
<DialogContent className="max-w-4xl max-h-[90vh] overflow-hidden">
```

**Replace with:**
```typescript
<DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
```

**Note:** Move `overflow-hidden` to content area and add `overflow-y-auto` for scrolling.

---

### 4. ArchitectureView.tsx

**Location:** `src/web-ui/components/ArchitectureView.tsx`

**Find:**
```typescript
<DialogContent className="sm:max-w-[425px]">
```

**Replace with:**
```typescript
<DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
```

---

### 5. PromptEditorDialog.tsx

**Location:** `src/web-ui/components/PromptEditorDialog.tsx`

**Find:**
```typescript
<DialogContent className="sm:max-w-[95vw] h-[85vh] flex flex-col">
```

**Replace with:**
```typescript
<DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
```

---

### 6. ai-triage-dialog.tsx

**Location:** `src/web-ui/components/ai-triage-dialog.tsx`

**Find:**
```typescript
<DialogContent className="sm:max-w-[500px]">
```

**Replace with:**
```typescript
<DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
```

---

## Search Commands

Find all dialogs that need updating:

```bash
grep -rn "DialogContent" src/web-ui/components/ --include="*.tsx" | grep -v "node_modules"
```

Find dialogs NOT using the 75% pattern:

```bash
grep -rn "<DialogContent" src/web-ui/components/ --include="*.tsx" | grep -v "!w-\[75vw\]"
```

---

## Testing Checklist

For each dialog after updating:

- [ ] Dialog opens at 75% of browser width
- [ ] Dialog opens at 75% of browser height
- [ ] Content area is scrollable when content exceeds available space
- [ ] Header stays fixed at top
- [ ] Footer stays fixed at bottom (if applicable)
- [ ] Close button (X) is visible and functional
- [ ] Dialog is centered on screen
- [ ] Dialog works on different screen sizes (responsive)

---

## Alternative Sizes

If 75% is not appropriate for a specific dialog (e.g., confirmation dialogs), use these alternatives:

### Small Dialog (Confirmations)
```typescript
<DialogContent className="!w-[400px] !max-w-none">
```

### Medium Dialog
```typescript
<DialogContent className="!w-[50vw] !h-[50vh] !max-w-none flex flex-col">
```

### Large Dialog (75% - Standard)
```typescript
<DialogContent className="!w-[75vw] !h-[75vh] !max-w-none flex flex-col">
```

### Extra Large Dialog (Near Full Screen)
```typescript
<DialogContent className="!w-[90vw] !h-[90vh] !max-w-none flex flex-col">
```

---

## To Deploy

After making changes:

```bash
docker-compose restart web-ui
```

---

## Reference: Template File

**File:** `src/web-ui/components/ZDAReportsView.tsx`

The Analysis Report dialog in this file serves as the reference implementation for all other dialogs.
