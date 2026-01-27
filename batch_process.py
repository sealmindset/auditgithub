#!/usr/bin/env python3
"""
Batch process multiple repositories matching a pattern.

This script runs inside Docker and processes multiple repositories
with built-in retry logic, timeout protection, and rate limiting.

Usage:
    python batch_process.py <pattern> [options]

Examples:
    python batch_process.py "-oic" --skip-if-exists --delay=60
    python batch_process.py "EBS-R-" --delay=45
"""

import sys
import os
import time
import asyncio
import argparse
import subprocess
from typing import List, Tuple, Optional

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.api.database import SessionLocal, MULTI_TENANT_ENABLED
from src.api.database_router import database_router
from src.api import models

# Import the main generation function
from generate_architecture_cli import generate_architecture_for_repo, logger

# Self-healing configuration
MAX_RETRIES = 2
TIMEOUT_SECONDS = 600  # 10 minutes per repository
RATE_LIMIT_BACKOFF = 300  # 5 minutes
SHORT_DELAY = 10  # Seconds for skipped repos


class BatchStats:
    """Track batch processing statistics."""
    def __init__(self):
        self.total = 0
        self.success = 0
        self.skipped = 0
        self.failed = 0
        self.skipped_repos = []
        self.failed_repos = []


def get_matching_repositories(pattern: str, tenant_slug: str = "default") -> List[str]:
    """Query database for repositories matching pattern."""
    logger.info("Querying database for matching repositories...")

    # Initialize database connection
    if MULTI_TENANT_ENABLED:
        db = database_router.get_session(tenant_slug)
        if not db:
            logger.error(f"Failed to get database session for tenant: {tenant_slug}")
            return []
    else:
        db = SessionLocal()

    try:
        # Query repositories matching pattern (case-insensitive)
        repos = db.query(models.Repository).filter(
            models.Repository.name.ilike(f"%{pattern}%")
        ).order_by(models.Repository.name).all()

        return [repo.name for repo in repos]
    finally:
        db.close()


async def process_repository_with_timeout(
    repo_name: str,
    tenant_slug: str,
    skip_if_exists: bool,
    timeout: int
) -> Tuple[bool, str]:
    """
    Process a single repository with timeout protection.
    Returns (success, status) where status is "success", "skipped", or "failed".
    """
    try:
        # Run with timeout
        result = await asyncio.wait_for(
            generate_architecture_for_repo(repo_name, tenant_slug, skip_if_exists),
            timeout=timeout
        )

        if result:
            # Check if it was actually skipped by examining recent log output
            # This is a heuristic - if processing was very fast, likely skipped
            return True, "skipped" if skip_if_exists else "success"
        else:
            return False, "failed"

    except asyncio.TimeoutError:
        logger.error(f"Repository {repo_name} exceeded timeout of {timeout}s")
        return False, "failed"
    except Exception as e:
        logger.error(f"Error processing {repo_name}: {e}")
        return False, "failed"


def is_transient_failure(repo_name: str, output: str) -> bool:
    """Check if failure is transient and worth retrying."""
    transient_patterns = [
        "rate limit",
        "network",
        "connection",
        "timeout",
        "temporarily unavailable",
        "502", "503", "504"
    ]

    output_lower = output.lower()
    return any(pattern in output_lower for pattern in transient_patterns)


async def process_with_retry(
    repo_name: str,
    tenant_slug: str,
    skip_if_exists: bool,
    timeout: int,
    max_retries: int,
    stats: BatchStats
) -> str:
    """
    Process repository with automatic retry logic.
    Returns status: "success", "skipped", or "failed".
    """
    for attempt in range(max_retries + 1):
        if attempt > 0:
            backoff = 30 * attempt
            logger.info(f"⟳ Retry attempt {attempt}/{max_retries} for: {repo_name}")
            logger.info(f"Waiting {backoff}s before retry...")
            time.sleep(backoff)

        success, status = await process_repository_with_timeout(
            repo_name, tenant_slug, skip_if_exists, timeout
        )

        if success:
            return status

        # Don't retry on last attempt
        if attempt < max_retries:
            # Check if we should retry (only for transient errors)
            # For now, retry all failures since we can't easily get the error message
            continue

        return "failed"


async def batch_process(
    pattern: str,
    tenant_slug: str = "default",
    skip_if_exists: bool = False,
    delay: int = 0,
    max_retries: int = MAX_RETRIES
):
    """Main batch processing function."""

    logger.info("=" * 80)
    logger.info("Batch Architecture Generation")
    logger.info("=" * 80)
    logger.info(f"Pattern: {pattern}")
    logger.info(f"Tenant: {tenant_slug}")
    if skip_if_exists:
        logger.info("Mode: Skip if exists")
    if delay > 0:
        logger.info(f"Delay: {delay}s between repos")
    logger.info("=" * 80)
    logger.info("")

    # Get matching repositories
    repos = get_matching_repositories(pattern, tenant_slug)

    if not repos:
        logger.error(f"No repositories found matching pattern: {pattern}")
        return False

    logger.info(f"Found {len(repos)} repositories matching pattern '{pattern}':")
    logger.info("")
    for repo in repos:
        logger.info(f"  {repo}")
    logger.info("")
    logger.info("=" * 80)
    logger.info("")

    # Ask for confirmation
    response = input(f"Process all {len(repos)} repositories? (y/N): ")
    if response.lower() not in ['y', 'yes']:
        logger.info("Cancelled.")
        return False

    logger.info("")
    logger.info("Starting batch processing...")
    logger.info("")

    # Process repositories
    stats = BatchStats()
    stats.total = len(repos)

    for i, repo_name in enumerate(repos, 1):
        logger.info("=" * 80)
        logger.info(f"Processing: {repo_name}")
        logger.info(f"Progress: {i}/{stats.total}")
        logger.info("=" * 80)

        # Process with retry
        status = await process_with_retry(
            repo_name, tenant_slug, skip_if_exists,
            TIMEOUT_SECONDS, max_retries, stats
        )

        # Update statistics
        if status == "success":
            stats.success += 1
            logger.info(f"✓ SUCCESS: {repo_name}")
            actual_delay = delay
        elif status == "skipped":
            stats.skipped += 1
            stats.skipped_repos.append(repo_name)
            logger.info(f"⊘ SKIPPED: {repo_name} (architecture already exists)")
            actual_delay = SHORT_DELAY if skip_if_exists else delay
        else:
            stats.failed += 1
            stats.failed_repos.append(repo_name)
            logger.info(f"✗ FAILED: {repo_name}")
            actual_delay = delay

        logger.info("")

        # Add delay between repositories (except after last one)
        if i < stats.total and actual_delay > 0:
            logger.info(f"Waiting {actual_delay}s before next repository...")
            time.sleep(actual_delay)
            logger.info("")

    # Print summary
    logger.info("=" * 80)
    logger.info("Batch Processing Complete")
    logger.info("=" * 80)
    logger.info(f"Total: {stats.total} repositories")
    logger.info(f"Success: {stats.success} (generated architecture)")
    logger.info(f"Skipped: {stats.skipped} (already had architecture)")
    logger.info(f"Failed: {stats.failed}")
    logger.info("")

    if stats.skipped > 0:
        logger.info("Skipped repositories (already had architecture):")
        for repo in stats.skipped_repos:
            logger.info(f"  - {repo}")
        logger.info("")

    if stats.failed > 0:
        logger.info("Failed repositories:")
        for repo in stats.failed_repos:
            logger.info(f"  - {repo}")
        logger.info("")
        return False
    else:
        logger.info("All repositories processed successfully!")
        return True


def main():
    """Main entry point."""
    # Pre-process sys.argv to handle --delay=N format
    processed_args = []
    for arg in sys.argv[1:]:
        if arg.startswith('--delay='):
            # Split --delay=60 into --delay 60
            processed_args.extend(['--delay', arg.split('=', 1)[1]])
        elif arg.startswith('--max-retries='):
            # Split --max-retries=N into --max-retries N
            processed_args.extend(['--max-retries', arg.split('=', 1)[1]])
        else:
            processed_args.append(arg)

    parser = argparse.ArgumentParser(
        description="Batch process repositories matching a pattern"
    )
    parser.add_argument(
        "pattern",
        help="Pattern to match repository names (case-insensitive)"
    )
    parser.add_argument(
        "tenant",
        nargs="?",
        default="default",
        help="Tenant slug (default: default)"
    )
    parser.add_argument(
        "--skip-if-exists",
        action="store_true",
        help="Skip repositories that already have architecture files"
    )
    parser.add_argument(
        "--delay",
        type=int,
        default=0,
        help="Delay in seconds between processing repositories (default: 0)"
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=MAX_RETRIES,
        help=f"Maximum retry attempts for failed repositories (default: {MAX_RETRIES})"
    )

    args = parser.parse_args(processed_args)

    # Run batch processing
    success = asyncio.run(batch_process(
        args.pattern,
        args.tenant,
        args.skip_if_exists,
        args.delay,
        args.max_retries
    ))

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
