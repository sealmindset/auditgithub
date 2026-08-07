#!/usr/bin/env python3
"""
CLI script to generate architecture diagrams and reports for a repository.

Usage:
    python generate_architecture_cli.py <repository_name_or_id>
    python generate_architecture_cli.py "EBS-R-6186-SC-OIC-Stores-With-a-Close-Date-in-HR"
    python generate_architecture_cli.py "d4e5f6g7-8901-2345-6789-012345678901"

This script will:
1. Generate architecture diagram and report for the specified repository
2. Update the database with the results
3. Save copies to ~/Downloads/ with the repository name as filename
"""

import sys
import os
import re
import uuid
import asyncio
import logging
import subprocess
import shutil
import signal
from pathlib import Path
from datetime import datetime
from contextlib import contextmanager
from typing import Optional, Tuple

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from sqlalchemy.orm import Session
from src.api import models
from src.api.database_router import database_router
from src.api.database import SessionLocal, MULTI_TENANT_ENABLED
from src.api.config import settings
from src.api.utils.repo_context import get_repo_context, clone_repo_to_temp, cleanup_repo
from src.api.utils.repo_origin import RepositoryOriginError, resolve_clone_target
from src.api.utils.diagrams_indexer import get_diagrams_index
from src.api.utils.diagram_executor import execute_with_self_annealing
from src.ai_agent.agent import AIAgent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Self-healing configuration
GIT_CLONE_TIMEOUT = 300  # 5 minutes
GIT_PUSH_TIMEOUT = 120   # 2 minutes
MAX_RETRY_ATTEMPTS = 2
RETRY_BACKOFF_BASE = 30  # seconds


class TimeoutError(Exception):
    """Raised when an operation times out."""
    pass


@contextmanager
def timeout_context(seconds: int, operation_name: str = "operation"):
    """Context manager for timing out operations."""
    def timeout_handler(signum, frame):
        raise TimeoutError(f"{operation_name} exceeded timeout of {seconds}s")

    # Set the signal handler
    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)

    try:
        yield
    finally:
        # Restore old handler and cancel alarm
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def run_git_command_with_timeout(
    cmd: list,
    cwd: str,
    timeout: int,
    operation_name: str
) -> Tuple[bool, str]:
    """
    Run a git command with timeout and error handling.
    Returns (success, output/error_message).
    """
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return True, result.stdout
    except subprocess.TimeoutExpired:
        logger.error(f"{operation_name} timed out after {timeout}s")
        return False, f"Timeout: {operation_name} exceeded {timeout}s"
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr if e.stderr else str(e)
        logger.error(f"{operation_name} failed: {error_msg}")
        return False, error_msg
    except Exception as e:
        logger.error(f"{operation_name} unexpected error: {e}")
        return False, str(e)


def is_transient_error(error_message: str) -> bool:
    """Check if an error is transient and worth retrying."""
    transient_patterns = [
        r"network",
        r"connection.*reset",
        r"connection.*refused",
        r"timeout",
        r"timed out",
        r"rate limit",
        r"temporarily unavailable",
        r"502 bad gateway",
        r"503 service unavailable",
        r"504 gateway timeout"
    ]

    error_lower = error_message.lower()
    return any(re.search(pattern, error_lower) for pattern in transient_patterns)


def is_permanent_error(error_message: str) -> bool:
    """Check if an error is permanent and not worth retrying."""
    permanent_patterns = [
        r"repository not found",
        r"does not exist",
        r"no such repository",
        r"authentication failed",
        r"permission denied",
        r"401",
        r"403 forbidden",
        r"invalid credentials"
    ]

    error_lower = error_message.lower()
    return any(re.search(pattern, error_lower) for pattern in permanent_patterns)


async def validate_repo_exists(repo_url: str, token: str) -> Tuple[bool, str]:
    """
    Quick validation that repository exists and is accessible.
    Returns (exists, error_message).

    No longer on the clone path. It validated whatever URL it was handed, and a URL naming
    the wrong organization fails here identically to a deleted repository - so it returned
    `(False, "not found")` and the caller treated that as permanent and gave up. Kept
    because it is a genuine reachability probe; use `resolve_clone_target` to decide *what*
    to probe before probing it.
    """
    try:
        # Use git ls-remote to check if repo exists without cloning
        cmd = ["git", "ls-remote", repo_url]

        # Add authentication if token provided
        if token and "github.com" in repo_url:
            auth_url = repo_url.replace("https://", f"https://x-access-token:{token}@")
            cmd = ["git", "ls-remote", auth_url]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30  # Quick check
        )

        if result.returncode == 0:
            return True, ""
        else:
            error = result.stderr or "Repository validation failed"
            return False, error
    except subprocess.TimeoutExpired:
        return False, "Repository validation timed out"
    except Exception as e:
        return False, f"Repository validation error: {str(e)}"


def get_output_folder() -> Path:
    """Get the output folder path for generated architectures."""
    # Check if we're running in Docker
    if os.path.exists('/.dockerenv'):
        # In Docker, save to project directory which is mounted
        output_dir = Path('/app/generated_architectures')
    else:
        # Outside Docker, check for project directory first
        script_dir = Path(__file__).parent
        output_dir = script_dir / 'generated_architectures'

        # If that doesn't work, fall back to Downloads
        if not script_dir.exists() or not os.access(script_dir, os.W_OK):
            home = Path.home()
            output_dir = home / "Downloads" / "generated_architectures"

    if not output_dir.exists():
        output_dir.mkdir(parents=True, exist_ok=True)

    return output_dir


def sanitize_filename(name: str) -> str:
    """Sanitize a string to be used as a filename."""
    # Replace invalid filename characters with underscores
    name = re.sub(r'[<>:"/\\|?*]', '_', name)
    # Remove leading/trailing spaces and dots
    name = name.strip('. ')
    # Limit length
    if len(name) > 200:
        name = name[:200]
    return name


async def get_github_token_for_repo(db: Session, project: models.Repository) -> str:
    """
    Get the GitHub token for a repository's organization.
    Falls back to the default GITHUB_TOKEN if no org-specific token is found.
    """
    # If repo has an organization_id, try to get the org's token
    if project.organization_id:
        try:
            org = db.query(models.Organization).filter(
                models.Organization.id == project.organization_id
            ).first()

            if org:
                # Try to get token from secrets manager
                try:
                    import sys
                    sys.path.insert(0, '/app/execution')
                    from secrets_manager import get_org_credentials
                    creds = await get_org_credentials(org.name)
                    if creds and creds.get('github_token'):
                        logger.info(f"Using org-specific token for {org.name}")
                        return creds['github_token']
                except Exception as e:
                    logger.warning(f"Could not get org credentials from secrets manager: {e}")

                # Try environment variable pattern ORG_{NAME}_TOKEN
                env_token = os.environ.get(f"ORG_{org.name}_TOKEN")
                if env_token:
                    logger.info(f"Using env token for org {org.name}")
                    return env_token
        except Exception as e:
            logger.warning(f"Error getting org token: {e}")

    # Fall back to default token
    return settings.GITHUB_TOKEN


async def generate_architecture_for_repo(repo_identifier: str, tenant_slug: str = "default", skip_if_exists: bool = False):
    """Generate architecture diagram and report for a repository."""

    # Initialize database connection
    if MULTI_TENANT_ENABLED:
        logger.info(f"Multi-tenant mode enabled, using tenant: {tenant_slug}")
        db = database_router.get_session(tenant_slug)
        if not db:
            logger.error(f"Failed to get database session for tenant: {tenant_slug}")
            return False
    else:
        logger.info("Single-tenant mode, using master database")
        db = SessionLocal()

    try:
        # Find the repository by name or ID
        project = None
        try:
            # Try as UUID first
            repo_uuid = uuid.UUID(repo_identifier)
            project = db.query(models.Repository).filter(
                models.Repository.id == repo_uuid
            ).first()
        except (ValueError, AttributeError):
            # Try as name
            project = db.query(models.Repository).filter(
                models.Repository.name == repo_identifier
            ).first()

        if not project:
            logger.error(f"Repository not found: {repo_identifier}")
            return False

        logger.info(f"Found repository: {project.name} (ID: {project.id})")

        if not project.url:
            logger.error(f"Repository {project.name} has no URL configured")
            return False

        # Initialize AI agent
        logger.info("Initializing AI agent...")

        # Determine model and url based on provider (matching ai.py router logic)
        provider = settings.AI_PROVIDER
        model = settings.AI_MODEL
        ollama_url = settings.OLLAMA_BASE_URL

        if provider == "openai" and settings.OPENAI_MODEL:
            model = settings.OPENAI_MODEL
        elif provider in ["claude", "anthropic_foundry"] and settings.ANTHROPIC_MODEL:
            model = settings.ANTHROPIC_MODEL
        elif (provider == "gemini" or provider == "google") and settings.GEMINI_MODEL:
            model = settings.GEMINI_MODEL
        elif provider == "docker":
            ollama_url = settings.DOCKER_BASE_URL
            model = settings.DOCKER_MODEL or "ai/llama3.2:latest"

        logger.info(f"Using AI provider: {provider}, model: {model}")

        ai_agent = AIAgent(
            openai_api_key=settings.OPENAI_API_KEY,
            anthropic_api_key=settings.ANTHROPIC_API_KEY,
            provider=provider,
            model=model,
            ollama_base_url=ollama_url,
            azure_foundry_endpoint=settings.AZURE_AI_FOUNDRY_ENDPOINT,
            azure_foundry_api_key=settings.AZURE_AI_FOUNDRY_API_KEY,
            gemini_api_key=settings.GEMINI_API_KEY
        )

        # Get diagrams index
        logger.info("Loading diagrams index...")
        diagrams_index = get_diagrams_index()
        logger.info(f"Loaded {len(diagrams_index)} diagram node types")

        # Resolve which organization actually owns this repository, and get that org's
        # token in the same step. `validate_repo_exists(project.url, ...)` used to stand
        # here, and on a 404 it declared a permanent error and returned False - so a row
        # whose `url` names the wrong organization was written off as a deleted repository.
        # 483 of 2,540 rows name an organization that disagrees with their own foreign key,
        # and every sampled one of them is present under the other name.
        logger.info(f"Resolving repository origin for {project.name}...")
        try:
            target = await resolve_clone_target(db, project)
        except RepositoryOriginError as e:
            # Now a real absence: every known organization was asked and none answered.
            logger.error(f"Repository origin unresolved: {e}")
            return False

        if target.corrected:
            logger.warning(f"Stored URL was wrong; corrected to {target.url}")
        logger.info(f"Cloning {target.url} (token: {target.token_source})...")
        try:
            # Use timeout-protected clone
            repo_path = clone_repo_to_temp(target.url, target.token)
            logger.info(f"Repository cloned successfully to: {repo_path}")
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Failed to clone repository: {error_msg}")
            if is_permanent_error(error_msg):
                logger.error("Permanent error - cannot proceed")
                return False
            raise  # Re-raise for retry logic

        try:
            # Check if architecture files already exist in the repository
            if skip_if_exists:
                arch_dir = os.path.join(repo_path, '.architecture')
                required_files = [
                    os.path.join(arch_dir, 'architecture_report.md'),
                    os.path.join(arch_dir, 'architecture_diagram.py'),
                    os.path.join(arch_dir, 'architecture_diagram.png')
                ]

                if all(os.path.exists(f) for f in required_files):
                    logger.info("=" * 80)
                    logger.info("SKIPPED! Architecture files already exist in repository.")
                    logger.info(f"Repository: {project.name}")
                    logger.info(f"Location: {project.url}/.architecture/")
                    logger.info("Use --force to regenerate architecture files.")
                    logger.info("=" * 80)
                    return True  # Return success since files exist

            # Get repository context
            logger.info("Analyzing repository structure...")
            structure, configs = get_repo_context(repo_path)
            logger.info(f"Found {len(configs)} configuration files")

            # Generate architecture overview
            logger.info("Generating architecture report and diagram code...")
            full_response = await ai_agent.generate_architecture_overview(
                repo_name=project.name,
                file_structure=structure,
                config_files=configs
            )

            # Parse Python code from response
            diagram_code = None
            report = full_response
            image_b64 = None

            code_match = re.search(r"```python\n(.*?)```", full_response, re.DOTALL)
            if code_match:
                diagram_code = code_match.group(1).strip()
                # Remove the code block from the report
                report = full_response.replace(code_match.group(0), "").strip()
                logger.info("Extracted diagram code from response")

                # Generate diagram image
                logger.info("Executing diagram code to generate image...")
                try:
                    image_b64, final_code, fix_log = execute_with_self_annealing(
                        code=diagram_code,
                        diagrams_index=diagrams_index,
                        ai_fix_callback=None,
                        max_retries=3,
                        report_context=report
                    )
                    if fix_log:
                        logger.info(f"Self-annealing applied: {', '.join(fix_log)}")
                    if image_b64:
                        logger.info("Diagram image generated successfully")
                        diagram_code = final_code  # Use the fixed code
                    else:
                        raise Exception("Failed to generate diagram image")
                except Exception as e:
                    logger.warning(f"Diagram execution failed: {e}")
                    logger.info("Attempting AI-powered fix...")
                    try:
                        if hasattr(ai_agent.provider, 'fix_and_enhance_diagram_code'):
                            fixed_code = await ai_agent.provider.fix_and_enhance_diagram_code(
                                diagram_code, str(e), diagrams_index, report_context=report
                            )

                            # Clean up code block if present
                            code_match_fix = re.search(r"```python\n(.*?)```", fixed_code, re.DOTALL)
                            if code_match_fix:
                                fixed_code = code_match_fix.group(1).strip()
                            else:
                                fixed_code = fixed_code.replace("```python", "").replace("```", "").strip()

                            diagram_code = fixed_code
                            # Try again with self-annealing on the AI-fixed code
                            image_b64, final_code, fix_log = execute_with_self_annealing(
                                code=diagram_code,
                                diagrams_index=diagrams_index,
                                ai_fix_callback=None,
                                max_retries=3,
                                report_context=report
                            )
                            if image_b64:
                                diagram_code = final_code
                                logger.info("AI-powered fix successful")
                            else:
                                raise Exception("AI fix failed to generate image")
                    except Exception as fix_error:
                        logger.error(f"AI-powered fix failed: {fix_error}")
            else:
                logger.warning("No diagram code found in response")

            # Update database
            logger.info("Updating database...")
            project.architecture_report = report
            project.architecture_diagram = diagram_code
            db.commit()
            logger.info("Database updated successfully")

            # Save to output folder
            output_folder = get_output_folder()
            base_filename = sanitize_filename(project.name)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            # Save report
            report_filename = f"{base_filename}_report_{timestamp}.md"
            report_path = output_folder / report_filename
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report)
            logger.info(f"Report saved to: {report_path}")

            # Save diagram code
            if diagram_code:
                code_filename = f"{base_filename}_diagram_{timestamp}.py"
                code_path = output_folder / code_filename
                with open(code_path, 'w', encoding='utf-8') as f:
                    f.write(diagram_code)
                logger.info(f"Diagram code saved to: {code_path}")

            # Save diagram image
            if image_b64:
                import base64
                image_filename = f"{base_filename}_diagram_{timestamp}.png"
                image_path = output_folder / image_filename
                image_data = base64.b64decode(image_b64)
                with open(image_path, 'wb') as f:
                    f.write(image_data)
                logger.info(f"Diagram image saved to: {image_path}")

            # Upload files to GitHub repository (with self-healing)
            logger.info("Uploading files to GitHub repository...")
            push_success = False
            push_error_msg = ""

            try:
                # Create .architecture directory in the repo
                arch_dir = os.path.join(repo_path, '.architecture')
                os.makedirs(arch_dir, exist_ok=True)

                # Copy files to the repository
                shutil.copy(report_path, os.path.join(arch_dir, f"architecture_report.md"))
                logger.info(f"Copied report to .architecture/architecture_report.md")

                if diagram_code:
                    shutil.copy(code_path, os.path.join(arch_dir, f"architecture_diagram.py"))
                    logger.info(f"Copied diagram code to .architecture/architecture_diagram.py")

                if image_b64:
                    shutil.copy(image_path, os.path.join(arch_dir, f"architecture_diagram.png"))
                    logger.info(f"Copied diagram image to .architecture/architecture_diagram.png")

                # Configure git user for commit (quick, no timeout needed)
                subprocess.run(
                    ["git", "config", "user.email", "auditgithub@sleepnumber.com"],
                    cwd=repo_path,
                    check=True,
                    capture_output=True,
                    timeout=10
                )
                subprocess.run(
                    ["git", "config", "user.name", "AuditGitHub Bot"],
                    cwd=repo_path,
                    check=True,
                    capture_output=True,
                    timeout=10
                )

                # Add files to git
                success, output = run_git_command_with_timeout(
                    ["git", "add", ".architecture/"],
                    repo_path,
                    timeout=30,
                    operation_name="Git add"
                )
                if not success:
                    raise Exception(f"Failed to add files to git: {output}")
                logger.info("Added files to git staging")

                # Check if there are changes to commit
                success, output = run_git_command_with_timeout(
                    ["git", "status", "--porcelain"],
                    repo_path,
                    timeout=30,
                    operation_name="Git status"
                )
                if not success:
                    raise Exception(f"Failed to check git status: {output}")

                if output.strip():
                    # Create commit
                    commit_message = f"Add architecture documentation\n\nGenerated by AuditGitHub on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n- Architecture report\n- Architecture diagram code\n- Architecture diagram image"

                    success, output = run_git_command_with_timeout(
                        ["git", "commit", "-m", commit_message],
                        repo_path,
                        timeout=30,
                        operation_name="Git commit"
                    )
                    if not success:
                        raise Exception(f"Failed to create commit: {output}")
                    logger.info("Created git commit")

                    # Get the current branch name
                    success, branch_name = run_git_command_with_timeout(
                        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                        repo_path,
                        timeout=10,
                        operation_name="Get branch name"
                    )
                    if not success:
                        raise Exception(f"Failed to get branch name: {branch_name}")

                    branch_name = branch_name.strip()
                    logger.info(f"Pushing to branch: {branch_name}")

                    # Construct authenticated URL for push
                    if token and "github.com" in project.url:
                        push_url = project.url.replace("https://", f"https://x-access-token:{token}@")
                    else:
                        push_url = project.url

                    # Push to remote with timeout protection
                    success, output = run_git_command_with_timeout(
                        ["git", "push", push_url, f"HEAD:{branch_name}"],
                        repo_path,
                        timeout=GIT_PUSH_TIMEOUT,
                        operation_name="Git push"
                    )

                    if success:
                        logger.info(f"Successfully pushed files to GitHub repository")
                        push_success = True
                    else:
                        push_error_msg = output
                        # Check if error is transient
                        if is_transient_error(output):
                            logger.warning(f"Transient error during push: {output}")
                            logger.warning("Files saved locally, push may be retried")
                        else:
                            logger.error(f"Failed to push to GitHub: {output}")
                else:
                    logger.info("No changes to commit (files already up to date in repository)")
                    push_success = True

            except subprocess.TimeoutExpired as e:
                push_error_msg = f"Git operation timed out: {e}"
                logger.error(push_error_msg)
                logger.warning("Files saved locally but not uploaded to GitHub")
                if is_transient_error(push_error_msg):
                    # Mark for potential retry by batch script
                    pass
            except subprocess.CalledProcessError as e:
                push_error_msg = e.stderr.decode() if e.stderr else str(e)
                logger.error(f"Failed to upload files to GitHub: {push_error_msg}")
                logger.warning("Files saved locally but not uploaded to GitHub")
            except Exception as e:
                push_error_msg = str(e)
                logger.error(f"Error uploading to GitHub: {push_error_msg}")
                logger.warning("Files saved locally but not uploaded to GitHub")

            logger.info("=" * 80)
            logger.info("SUCCESS! Architecture generation completed.")
            logger.info(f"Repository: {project.name}")
            logger.info(f"Files saved locally to: {output_folder}")
            logger.info(f"  - Report: {report_filename}")
            if diagram_code:
                logger.info(f"  - Code: {code_filename}")
            if image_b64:
                logger.info(f"  - Image: {image_filename}")
            logger.info(f"Files uploaded to GitHub: {project.url}/.architecture/")
            logger.info("=" * 80)

            return True

        finally:
            # Cleanup cloned repository
            cleanup_repo(repo_path)

    except Exception as e:
        logger.error(f"Error generating architecture: {e}", exc_info=True)
        return False
    finally:
        db.close()


def main():
    """Main entry point for the CLI script."""
    if len(sys.argv) < 2:
        print("Usage: python generate_architecture_cli.py <repository_name_or_id> [tenant_slug] [--skip-if-exists]")
        print()
        print("Examples:")
        print('  python generate_architecture_cli.py "My Repository Name"')
        print('  python generate_architecture_cli.py "d4e5f6g7-8901-2345-6789-012345678901"')
        print('  python generate_architecture_cli.py "My Repo" "tenant-slug"')
        print('  python generate_architecture_cli.py "My Repo" --skip-if-exists')
        print()
        print("Options:")
        print("  --skip-if-exists    Skip repositories that already have architecture files in .architecture/ folder")
        sys.exit(1)

    # Parse arguments
    repo_identifier = sys.argv[1]
    tenant_slug = "default"
    skip_if_exists = False

    # Check for flags and tenant slug
    for arg in sys.argv[2:]:
        if arg == "--skip-if-exists":
            skip_if_exists = True
        elif not arg.startswith("--"):
            tenant_slug = arg

    logger.info("=" * 80)
    logger.info("Architecture Generation CLI")
    logger.info("=" * 80)
    logger.info(f"Repository: {repo_identifier}")
    logger.info(f"Tenant: {tenant_slug}")
    if skip_if_exists:
        logger.info("Mode: Skip if exists")
    logger.info("=" * 80)

    # Run the async function
    success = asyncio.run(generate_architecture_for_repo(repo_identifier, tenant_slug, skip_if_exists))

    if success:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
