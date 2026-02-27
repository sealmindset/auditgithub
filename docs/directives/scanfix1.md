# Scan Override Flag Bug Fix

## Issue Summary

The `--overridescan` command-line flag was being ignored when running the repository scanner. Even when the flag was explicitly passed, repositories were still being skipped with the message "Already completed in previous run".

---

## Symptoms

When running:

```bash
docker-compose run --rm auditgh --repo="CXDevOpsBSG" --rescan-days 360 --overridescan
```

The log output showed contradictory messages:

```
INFO:root:⚡ Override scan enabled - all skip logic disabled, will scan every repository
INFO:root:Processing repository: CXDevOpsBSG
INFO:root:✅ Skipping CXDevOpsBSG: Already completed in previous run
```

The override scan message appeared, but the repository was still skipped.

---

## Root Cause

**File:** `scan_repos.py`

The `resume_state.is_completed()` check was executed **before** the `override_scan` flag was evaluated. This caused the function to return early, never reaching the override scan logic.

### Problematic Code (Before Fix)

```python
logging.info(f"Processing repository: {repo_name}")

# Check if already completed (resume functionality)
if resume_state and resume_state.is_completed(repo_name):
    logging.info(f"✅ Skipping {repo_name}: Already completed in previous run")
    return  # <-- Returns early, never checks override_scan

# Determine if we should skip this repository
should_skip = False
skip_reason = ""

# ... more code ...

# Override scan disables all skip logic
if override_scan:
    logging.info(f"⚡ Scanning {repo_name}: Override scan enabled")
else:
    # ... skip logic checks ...
```

The execution flow was:
1. Check `resume_state.is_completed()` → **Returns early if True**
2. Never reaches the `override_scan` check

---

## Solution

Add `and not override_scan` to the resume_state check condition so it respects the override flag.

### Fixed Code (After Fix)

```python
logging.info(f"Processing repository: {repo_name}")

# Check if already completed (resume functionality) - but respect override_scan
if resume_state and resume_state.is_completed(repo_name) and not override_scan:
    logging.info(f"✅ Skipping {repo_name}: Already completed in previous run")
    return

# Determine if we should skip this repository
should_skip = False
skip_reason = ""

# ... rest of the code ...
```

Now the execution flow is:
1. Check `resume_state.is_completed()` **AND** `not override_scan`
2. Only skip if BOTH conditions are true (completed AND override not enabled)
3. If `override_scan` is True, the check fails and scanning proceeds

---

## File Changes

| File | Line | Change |
|------|------|--------|
| `scan_repos.py` | ~1627 | Added `and not override_scan` to resume_state check |

---

## Implementation

### Locate the Code

Search for the resume state check in `scan_repos.py`:

```bash
grep -n "Already completed in previous run" scan_repos.py
```

Or search for the resume_state check:

```bash
grep -n "resume_state.is_completed" scan_repos.py
```

### Apply the Fix

Change this line:

```python
if resume_state and resume_state.is_completed(repo_name):
```

To:

```python
if resume_state and resume_state.is_completed(repo_name) and not override_scan:
```

---

## Testing

### Test Command

```bash
docker-compose run --rm auditgh --repo="<repo-name>" --overridescan
```

### Expected Behavior (After Fix)

```
INFO:root:⚡ Override scan enabled - all skip logic disabled, will scan every repository
INFO:root:Processing repository: <repo-name>
INFO:root:⚡ Scanning <repo-name>: Override scan enabled
INFO:root:Cloning repository: sleepnumberinc/<repo-name>
...
```

The repository should be cloned and scanned, NOT skipped.

### Test Cases

1. **With --overridescan on previously scanned repo**: Should scan (not skip)
2. **Without --overridescan on previously scanned repo**: Should skip with "Already completed" message
3. **With --overridescan on new repo**: Should scan normally
4. **Resume after interrupt with --overridescan**: Should re-scan all repos

---

## Related Skip Logic

The `scan_repos.py` file has multiple skip conditions. The `override_scan` flag should bypass ALL of them:

| Skip Condition | Purpose | Override Respected? |
|----------------|---------|---------------------|
| `resume_state.is_completed()` | Resume after interrupt | ✅ Fixed |
| `should_skip_problematic_repo()` | Self-annealing for failing repos | ✅ Already handled |
| `was_scanned_within_hours()` | Skip recently scanned repos | ✅ Already handled |
| `was_scanned_within_days()` | Rescan days threshold | ✅ Already handled |

All skip logic is wrapped in:

```python
if override_scan:
    logging.info(f"⚡ Scanning {repo_name}: Override scan enabled")
else:
    # All skip logic checks here
```

The bug was that `resume_state.is_completed()` was checked **outside** this block.

---

## Prevention

When adding new skip logic to `scan_repos.py`, ensure it either:

1. Is placed **inside** the `if override_scan: ... else:` block, OR
2. Explicitly checks `and not override_scan` in the condition

---

## Command-Line Reference

```bash
# Override all skip logic and force scan
docker-compose run --rm auditgh --repo="RepoName" --overridescan

# Override with specific rescan days
docker-compose run --rm auditgh --repo="RepoName" --rescan-days 360 --overridescan

# Override for entire organization
docker-compose run --rm auditgh --overridescan
```
