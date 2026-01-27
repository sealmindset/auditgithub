# Batch Processing Guide

## Quick Start

### Docker-Based (Recommended)

The Docker-based version avoids all macOS compatibility issues:

```bash
./gen-arch-batch-docker.sh "-oic" --skip-if-exists --delay=60
```

### Shell-Based (Alternative)

If you prefer the shell script:

```bash
./gen-arch-batch.sh "-oic" --skip-if-exists --delay=60
```

**Note:** The Docker-based version (`gen-arch-batch-docker.sh`) is recommended as it:
- Runs in a consistent environment (no macOS bash 3.2 limitations)
- Has cleaner error handling
- Works identically on all platforms

## Self-Healing Features

The batch processing system includes automatic self-healing capabilities to handle common issues:

### Automatic Retry Logic
- Failed repositories are automatically retried up to 2 times
- Exponential backoff between retries (30s, 60s)
- Smart detection of permanent vs transient errors
- Rate limit detection with automatic 5-minute cooldown

### Timeout Protection
- Maximum 10 minutes per repository (prevents hanging)
- Git clone operations timeout after 5 minutes
- Git push operations timeout after 2 minutes
- Stuck processes are automatically terminated

### Error Classification
**Permanent Errors (no retry):**
- Repository not found
- Authentication/permission failures
- Invalid credentials

**Transient Errors (will retry):**
- Network connection issues
- Rate limit exceeded
- Timeout errors
- Temporary service unavailability

### Loop Protection
- Stdin consumption issue automatically prevented
- Each repository processed independently
- Failed repos don't break the batch

## Why Use These Options?

### `--skip-if-exists`

- Skips repositories that already have architecture documentation
- Checks for existence of all three files in `.architecture/` folder:
  - `architecture_report.md`
  - `architecture_diagram.py`
  - `architecture_diagram.png`
- Useful for:
  - Resuming interrupted batch jobs
  - Running periodic updates without regenerating existing docs
  - Incremental processing of large repository sets

### `--delay=SECONDS`

**Critical for avoiding rate limits!**

The script makes API calls to two services:
1. **Azure AI Foundry** - For generating architecture reports and diagrams
2. **GitHub API** - For pushing commits to repositories

Without delays, you'll hit rate limits quickly with large batches.

**Smart Delay**: When `--skip-if-exists` is enabled, skipped repositories automatically use a shorter 10-second delay instead of the full delay, since no API calls are made for those repos.

#### Recommended Delays:

- **Small batches (1-10 repos)**: `--delay=30`
- **Medium batches (11-25 repos)**: `--delay=45`
- **Large batches (26-50 repos)**: `--delay=60`
- **Very large batches (50+ repos)**: `--delay=90` or higher

**Example**: With `--delay=60 --skip-if-exists`:
- Repos needing generation: 60-second delay
- Repos already having architecture: 10-second delay (automatic)

## Example: Processing 51 OIC Repositories

```bash
./gen-arch-batch.sh "-oic" --skip-if-exists --delay=60
```

**What happens:**
1. Queries database → finds 51 matching repos
2. Shows list and asks for confirmation
3. For each repository:
   - Checks if `.architecture/` files exist (if `--skip-if-exists` enabled)
   - If exists: skips (logs "SKIPPED")
   - If not exists: generates architecture
   - Waits 60 seconds before next repo
4. Shows final summary:
   - Success count (newly generated)
   - Skipped count (already had architecture)
   - Failed count (errors occurred)

**Estimated time:** 51 repos × ~90 seconds/repo (30s generation + 60s delay) = ~76 minutes

## Resuming After Interruption

If the batch processing is interrupted:

```bash
./gen-arch-batch.sh "-oic" --skip-if-exists --delay=60
```

The `--skip-if-exists` flag will skip all repositories that were successfully processed before the interruption.

## Processing Only New Repositories

To process only repositories that don't have architecture yet:

```bash
./gen-arch-batch.sh "EBS-R-" --skip-if-exists --delay=60
```

## Monitoring Progress

The script outputs:
- Real-time progress: `Processing 5/51`
- Status for each repo: `✓ SUCCESS`, `⊘ SKIPPED`, or `✗ FAILED`
- Countdown between repos: `Waiting 60s before next repository...`
- Final summary with counts and lists

## Tips

1. **Start with a smaller subset** to test your pattern:
   ```bash
   # Test with 1 repo first
   ./gen-arch.sh "EBS-E-0007-OIC-Views"

   # Then batch process
   ./gen-arch-batch.sh "-oic" --skip-if-exists --delay=60
   ```

2. **Use screen/tmux for long-running batches**:
   ```bash
   screen -S arch-batch
   ./gen-arch-batch.sh "-oic" --skip-if-exists --delay=60
   # Detach: Ctrl+A, then D
   # Reattach: screen -r arch-batch
   ```

3. **Redirect output to log file**:
   ```bash
   ./gen-arch-batch.sh "-oic" --skip-if-exists --delay=60 2>&1 | tee batch-$(date +%Y%m%d-%H%M%S).log
   ```

4. **Check failed repos and retry**:
   After completion, review failed repos in the summary and process them individually:
   ```bash
   ./gen-arch.sh "EBS-E-3905-SC-OIC-Payroll-File-Positive-And-Negative"
   ```

## Rate Limit Information

### Azure AI Foundry
- Typical limit: ~10-20 requests/minute
- Each repo makes 2 API calls (report + diagram)
- **Recommendation**: Minimum 30-second delay between repos

### GitHub API
- Typical limit: 5000 requests/hour (authenticated)
- Each repo makes 1-2 API calls (push commit)
- Usually not the bottleneck unless pushing to many repos simultaneously

## Troubleshooting

### "Rate limit exceeded"
- Increase delay: `--delay=90` or `--delay=120`
- Process in smaller batches
- Wait 1 hour and resume

### "Repository not found"
- Verify repository name matches exactly (case-insensitive)
- Check repository exists in database

### "Failed to clone repository"
- Check GitHub token is valid
- Verify repository URL is correct
- Ensure network connectivity

### Script interrupted
- Simply re-run with `--skip-if-exists`
- Already processed repos will be skipped
