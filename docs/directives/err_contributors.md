# Contributors View Error Report - RESOLVED

## Issues Identified

### Issue 1: Missing DialogTitle for Accessibility (FIXED)

**Error:**
```
`DialogContent` requires a `DialogTitle` for the component to be accessible for screen reader users.
```

**Location:** `components/ContributorsView.tsx` lines 143-151, 317-323

**Root Cause:** The `DialogContent` component was missing `DialogTitle` in loading and error states.

**Fix Applied:** Added `DialogTitle` with `sr-only` class for screen readers in all dialog states:
- Loading state: `<DialogTitle className="sr-only">Loading contributor details</DialogTitle>`
- Not found state: `<DialogTitle className="sr-only">Contributor not found</DialogTitle>`

---

### Issue 2: Missing Contributors (FIXED)

**Problem:** Repository 'ado-work-item-check' should show 2 contributors:
- @mennlo (Lukas Menne)
- @szymonb-ttpsc

But only showing Lukas Menne.

**Root Cause:** The repository is cloned with `--depth 1` (shallow clone), which only retrieves the most recent commit. The `git fetch --unshallow` command was:
1. Failing silently (logged at DEBUG level)
2. No fallback mechanism when unshallow failed

**Location:** `scan_repos.py` line 480 (shallow clone) and lines 1823-1869 (unshallow logic)

**Fix Applied:**
1. Changed unshallow failure logging from DEBUG to WARNING level
2. Added detection for "not a shallow repository" case (which is OK)
3. Added fallback: `git fetch --depth=500` if unshallow fails
4. Better error messages to identify why contributor data is incomplete

---

## Verification Steps

After re-scanning a repository, check:

1. **Console logs should show:**
   ```
   INFO: Unshallowing repository ado-work-item-check for contributor analysis...
   INFO: Successfully unshallowed ado-work-item-check
   ```
   Or if fallback is used:
   ```
   WARNING: Unshallow failed for ado-work-item-check: <reason>
   INFO: Fetching deeper history for ado-work-item-check (depth=500)...
   INFO: Fetched deeper history for ado-work-item-check
   ```

2. **Browser console should NOT show:**
   ```
   DialogContent requires a DialogTitle...
   ```

3. **UI should show all contributors** after re-scanning the repository.

---

## Files Modified

| File | Change |
|------|--------|
| `src/web-ui/components/ContributorsView.tsx` | Added DialogTitle for accessibility in loading and error states |
| `scan_repos.py` | Improved unshallow logic with fallback and better logging |

---

## Notes

- Existing scans before this fix will still show incomplete contributor data
- Re-scan affected repositories to get complete contributor information
- The `--depth 500` fallback should capture most active contributors even if unshallow fails
