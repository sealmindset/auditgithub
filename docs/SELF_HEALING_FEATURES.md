# Self-Healing Features

## Overview

The architecture generation system now includes comprehensive self-healing capabilities to automatically handle common failures and edge cases without manual intervention.

## Problem: Why Self-Healing?

When processing 51 repositories, various issues can occur:
1. **Repository doesn't exist** - Taking too long or hanging
2. **Loop stdin consumption** - Processing only 1 repo instead of 51
3. **Network failures** - Temporary connection issues
4. **Rate limits** - Azure AI Foundry and GitHub API limits
5. **Hung processes** - Operations that never complete

Without self-healing, these issues would:
- Require manual monitoring and restart
- Waste time on permanent failures
- Stop entire batch processing
- Lose progress when interrupted

## Solution: Automatic Recovery

### 1. Batch Script Self-Healing ([gen-arch-batch.sh](gen-arch-batch.sh))

#### **Loop Protection**
- **Problem**: `docker-compose exec` was consuming stdin, causing loop to exit after 1 repo
- **Solution**: Redirects stdin to `/dev/null` for each repository
```bash
OUTPUT=$("$SCRIPT_DIR/gen-arch.sh" "${CMD_ARGS[@]}" < /dev/null 2>&1)
```

#### **Timeout Protection**
- **Problem**: Repositories taking forever to process (hanging)
- **Solution**: 10-minute timeout per repository
- Automatically kills hung processes
- Uses native `timeout` command or fallback implementation

#### **Automatic Retry Logic**
- **Problem**: Transient failures breaking batch processing
- **Solution**: Up to 2 automatic retries with exponential backoff
  - First retry: 30 seconds wait
  - Second retry: 60 seconds wait
- Only retries transient errors (network, rate limits)
- Skips permanent errors (repo not found, auth failures)

#### **Smart Error Detection**
The script automatically classifies errors:

**Permanent Errors (no retry):**
- Repository not found
- Does not exist
- No such repository
- Authentication failed
- Permission denied
- 401/403 errors
- Invalid credentials

**Transient Errors (will retry):**
- Rate limit exceeded → 5-minute cooldown
- Network errors
- Connection timeout
- Connection reset/refused
- 502/503/504 errors

**Example Output:**
```bash
Processing: repo-name
Progress: 5/51
========================================
✗ FAILED: repo-name
⟳ Retry attempt 1/2 for: repo-name
Waiting 30s before retry...
✓ SUCCESS: repo-name
```

### 2. CLI Script Self-Healing ([generate_architecture_cli.py](generate_architecture_cli.py))

#### **Repository Validation**
- **Problem**: Attempting to clone non-existent repos wastes time
- **Solution**: Quick validation before cloning (30s timeout)
```python
repo_exists, error = await validate_repo_exists(repo_url, token)
if not repo_exists and is_permanent_error(error):
    return False  # Don't waste time trying to clone
```

#### **Git Operation Timeouts**
- **Problem**: Git operations hanging indefinitely
- **Solution**: All git operations have timeouts
  - Clone: 5 minutes max
  - Push: 2 minutes max
  - Other ops: 10-30 seconds

#### **Graceful Degradation**
- **Problem**: Push failures causing entire operation to fail
- **Solution**: Push failures don't stop architecture generation
  - Files always saved locally
  - Database always updated
  - Push failure logged but process continues
  - Transient push errors flagged for retry by batch script

#### **Transient Error Detection**
The CLI detects and reports transient errors so the batch script can retry:
```python
if is_transient_error(error_message):
    logger.warning("Transient error - may be retried")
    # Batch script will detect this and retry
```

## Configuration

### Batch Script Settings ([gen-arch-batch.sh](gen-arch-batch.sh#L162))
```bash
MAX_RETRIES=2                  # Number of retry attempts
TIMEOUT_SECONDS=600            # 10 minutes per repo
RATE_LIMIT_BACKOFF=300         # 5 minutes wait when rate limited
```

### CLI Script Settings ([generate_architecture_cli.py](generate_architecture_cli.py#L50))
```python
GIT_CLONE_TIMEOUT = 300        # 5 minutes
GIT_PUSH_TIMEOUT = 120         # 2 minutes
MAX_RETRY_ATTEMPTS = 2         # Retry count
RETRY_BACKOFF_BASE = 30        # Exponential backoff base (seconds)
```

## Real-World Scenarios

### Scenario 1: Processing 51 OIC Repositories
**Command:**
```bash
./gen-arch-batch.sh "-oic" --skip-if-exists --delay=60
```

**What Happens:**
1. Script finds 51 matching repos
2. Processes each with stdin protection (no loop consumption)
3. Repos with existing architecture: skipped (10s delay)
4. New repos: full generation (60s delay after)
5. Failed repos: automatic retry (2 attempts)
6. Hung repos: killed after 10 minutes
7. Rate limits: 5-minute cooldown + retry

**Expected Completion:**
- All 51 repositories processed
- ~1-2 hours total (depending on how many are skipped)
- Robust against failures

### Scenario 2: Repository Doesn't Exist
**What Happens:**
1. CLI validates repo exists (30s)
2. Detects "repository not found"
3. Classifies as permanent error
4. Returns immediately (no hanging, no retry)
5. Batch script moves to next repo

### Scenario 3: Rate Limit Hit
**What Happens:**
1. Azure AI Foundry returns rate limit error
2. CLI detects "rate limit" in error message
3. Returns with transient error flag
4. Batch script detects transient error
5. Waits 5 minutes (RATE_LIMIT_BACKOFF)
6. Retries the repository
7. Usually succeeds after cooldown

### Scenario 4: Network Glitch
**What Happens:**
1. Git push fails with "connection reset"
2. CLI detects transient network error
3. Logs warning but saves files locally
4. Batch script detects transient error
5. Waits 30 seconds (first retry backoff)
6. Retries entire process
7. Push likely succeeds on retry

## Monitoring Progress

### Success Indicators
```bash
✓ SUCCESS: repo-name              # Generated successfully
⊘ SKIPPED: repo-name              # Already had architecture
⟳ Retry attempt 1/2 for: repo-name # Automatic retry in progress
```

### Warning Indicators
```bash
⚠ Rate limit detected! Waiting 300s before retry...
Transient error during push: connection reset
Files saved locally, push may be retried
```

### Failure Indicators
```bash
✗ FAILED: repo-name (after 2 retries)        # Exhausted retries
Permanent error detected - repository does not exist
```

## Summary Report

At the end of batch processing, you get a complete summary:

```bash
========================================
Batch Processing Complete
========================================
Total: 51 repositories
Success: 30 (generated architecture)
Skipped: 18 (already had architecture)
Failed: 3

Failed repositories:
  - non-existent-repo (permanent: not found)
  - broken-repo (after 2 retries)
  - auth-issue-repo (permanent: permission denied)
```

## Benefits

1. **Unattended Operation**: Set it and forget it - handles issues automatically
2. **Time Efficient**: No wasted time on permanent failures
3. **Robust**: Handles network glitches, rate limits, hung processes
4. **Transparent**: Clear logging of what's happening and why
5. **Complete**: All recoverable repos get processed, even with interruptions
6. **Smart**: Distinguishes between temporary and permanent failures

## Testing the System

Test the self-healing features:

```bash
# Test with pattern that includes non-existent repos
./gen-arch-batch.sh "test-" --delay=30

# Observe:
# - Non-existent repos: Fail fast (no hanging)
# - Existing repos: Process successfully
# - Network issues: Automatic retry
# - Rate limits: 5-minute cooldown + retry
# - All 51 repos processed (no stdin consumption bug)
```

## Technical Implementation

### Key Functions

**Batch Script:**
- `process_repo_with_healing()` - Main processing with error detection
- Error pattern matching with regex
- Return codes for success/skip/retry/fail states

**CLI Script:**
- `validate_repo_exists()` - Quick repo validation
- `run_git_command_with_timeout()` - Timeout-protected git ops
- `is_transient_error()` - Error classification
- `is_permanent_error()` - Permanent error detection

### Architecture

```
User Command
    ↓
gen-arch-batch.sh (Loop protection, Retry logic, Timeout)
    ↓
gen-arch.sh (Shell wrapper)
    ↓
generate_architecture_cli.py (Validation, Timeouts, Error classification)
    ↓
Git Operations (Clone, Push with timeout protection)
    ↓
Self-Healing Decision (Retry, Skip, or Fail)
```

## Customization

You can adjust self-healing behavior by editing the configuration constants in both scripts:

**More aggressive retries:**
```bash
# In gen-arch-batch.sh
MAX_RETRIES=3                    # 3 attempts instead of 2
RATE_LIMIT_BACKOFF=600           # 10 minutes instead of 5
```

**Longer timeouts:**
```python
# In generate_architecture_cli.py
GIT_CLONE_TIMEOUT = 600          # 10 minutes instead of 5
GIT_PUSH_TIMEOUT = 300           # 5 minutes instead of 2
```

**Shorter delays for testing:**
```bash
./gen-arch-batch.sh "-oic" --skip-if-exists --delay=15
```

## FAQ

**Q: Will it retry forever?**
A: No, maximum 2 retries per repository. Permanent errors are not retried.

**Q: What if I interrupt the batch?**
A: Re-run with `--skip-if-exists` - already processed repos will be skipped.

**Q: How do I know if rate limits were hit?**
A: Look for "Rate limit detected! Waiting 300s before retry..." in output.

**Q: Can it handle 100+ repositories?**
A: Yes, increase delay: `--delay=90` or `--delay=120` for large batches.

**Q: What if a repository takes more than 10 minutes?**
A: Adjust `TIMEOUT_SECONDS` in gen-arch-batch.sh or investigate why it's so slow.

**Q: Will it recover from loop stdin consumption bug?**
A: Yes, stdin is automatically redirected to `/dev/null` to prevent this issue.
