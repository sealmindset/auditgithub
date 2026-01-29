"""
GitHub Actions Integration Service

Fetches workflow runs, deployments, and CI/CD data from GitHub API.
"""
import logging
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from .. import models

logger = logging.getLogger(__name__)


class GitHubActionsService:
    """Service for integrating with GitHub Actions API."""

    def __init__(self, github_token: str):
        """
        Initialize GitHub Actions service.

        Args:
            github_token: GitHub Personal Access Token with workflow permissions
        """
        self.github_token = github_token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Make authenticated request to GitHub API.

        Args:
            endpoint: API endpoint path
            params: Query parameters

        Returns:
            JSON response data
        """
        url = f"{self.base_url}{endpoint}"
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub API request failed: {e}")
            raise

    def fetch_workflow_runs(
        self,
        owner: str,
        repo: str,
        days_back: int = 30,
        status: Optional[str] = None,
        branch: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch workflow runs for a repository.

        Args:
            owner: GitHub organization/user
            repo: Repository name
            days_back: How many days of history to fetch
            status: Filter by status (completed, in_progress, queued)
            branch: Filter by branch

        Returns:
            List of workflow run dictionaries
        """
        endpoint = f"/repos/{owner}/{repo}/actions/runs"

        # Calculate date threshold
        created_after = (datetime.utcnow() - timedelta(days=days_back)).isoformat()

        params = {
            "per_page": 100,
            "created": f">={created_after}"
        }

        if status:
            params["status"] = status
        if branch:
            params["branch"] = branch

        try:
            data = self._make_request(endpoint, params)
            return data.get("workflow_runs", [])
        except Exception as e:
            logger.error(f"Failed to fetch workflow runs for {owner}/{repo}: {e}")
            return []

    def fetch_deployments(
        self,
        owner: str,
        repo: str,
        environment: Optional[str] = None,
        days_back: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Fetch deployment history for a repository.

        Args:
            owner: GitHub organization/user
            repo: Repository name
            environment: Filter by environment name
            days_back: How many days of history to fetch

        Returns:
            List of deployment dictionaries
        """
        endpoint = f"/repos/{owner}/{repo}/deployments"

        params = {
            "per_page": 100
        }

        if environment:
            params["environment"] = environment

        try:
            deployments = self._make_request(endpoint, params)

            # Filter by date
            cutoff = datetime.utcnow() - timedelta(days=days_back)
            filtered = []

            for deployment in deployments:
                created_at = datetime.fromisoformat(deployment["created_at"].replace("Z", "+00:00"))
                if created_at >= cutoff:
                    # Fetch deployment status
                    status_data = self._fetch_deployment_status(owner, repo, deployment["id"])
                    deployment["status_info"] = status_data
                    filtered.append(deployment)

            return filtered
        except Exception as e:
            logger.error(f"Failed to fetch deployments for {owner}/{repo}: {e}")
            return []

    def _fetch_deployment_status(self, owner: str, repo: str, deployment_id: int) -> Dict[str, Any]:
        """Fetch the latest status for a deployment."""
        endpoint = f"/repos/{owner}/{repo}/deployments/{deployment_id}/statuses"

        try:
            statuses = self._make_request(endpoint)
            if statuses:
                return statuses[0]  # Most recent status
            return {}
        except Exception as e:
            logger.error(f"Failed to fetch deployment status: {e}")
            return {}

    def fetch_workflow_file(self, owner: str, repo: str, path: str, ref: str = "main") -> Optional[str]:
        """
        Fetch workflow file content.

        Args:
            owner: GitHub organization/user
            repo: Repository name
            path: Path to workflow file (e.g., .github/workflows/deploy.yml)
            ref: Branch or ref

        Returns:
            Workflow file content as string, or None if not found
        """
        endpoint = f"/repos/{owner}/{repo}/contents/{path}"
        params = {"ref": ref}

        try:
            data = self._make_request(endpoint, params)
            # Content is base64 encoded
            import base64
            content = base64.b64decode(data["content"]).decode("utf-8")
            return content
        except Exception as e:
            logger.error(f"Failed to fetch workflow file {path}: {e}")
            return None

    def sync_repository_workflows(
        self,
        db: Session,
        repository: models.Repository,
        owner: str,
        repo: str,
        days_back: int = 30
    ) -> Dict[str, int]:
        """
        Sync workflow runs and deployments for a repository.

        Args:
            db: Database session
            repository: Repository model instance
            owner: GitHub organization/user
            repo: Repository name
            days_back: How many days of history to sync

        Returns:
            Dictionary with counts of synced items
        """
        stats = {
            "workflows_synced": 0,
            "runs_synced": 0,
            "deployments_synced": 0
        }

        try:
            # 1. Fetch and sync workflow runs
            workflow_runs = self.fetch_workflow_runs(owner, repo, days_back=days_back)

            for run_data in workflow_runs:
                # Check if pipeline exists, create if not
                pipeline = db.query(models.CICDPipeline).filter(
                    models.CICDPipeline.repository_id == repository.id,
                    models.CICDPipeline.platform == "github_actions",
                    models.CICDPipeline.name == run_data["name"]
                ).first()

                if not pipeline:
                    pipeline = models.CICDPipeline(
                        repository_id=repository.id,
                        platform="github_actions",
                        name=run_data["name"],
                        file_path=run_data.get("path"),
                        branch=run_data.get("head_branch"),
                        is_active=True
                    )
                    db.add(pipeline)
                    db.flush()
                    stats["workflows_synced"] += 1

                # Check if workflow run already exists
                existing_run = db.query(models.WorkflowRun).filter(
                    models.WorkflowRun.pipeline_id == pipeline.id,
                    models.WorkflowRun.run_id == run_data["id"]
                ).first()

                if not existing_run:
                    workflow_run = models.WorkflowRun(
                        pipeline_id=pipeline.id,
                        repository_id=repository.id,
                        run_id=run_data["id"],
                        run_number=run_data["run_number"],
                        workflow_name=run_data["name"],
                        event=run_data["event"],
                        status=run_data["status"],
                        conclusion=run_data.get("conclusion"),
                        branch=run_data.get("head_branch"),
                        commit_sha=run_data["head_sha"],
                        commit_message=run_data.get("head_commit", {}).get("message"),
                        actor=run_data.get("actor", {}).get("login"),
                        html_url=run_data.get("html_url"),
                        started_at=self._parse_github_datetime(run_data.get("run_started_at")),
                        completed_at=self._parse_github_datetime(run_data.get("updated_at")),
                        extra_data=run_data
                    )

                    # Calculate duration if both times exist
                    if workflow_run.started_at and workflow_run.completed_at:
                        duration = (workflow_run.completed_at - workflow_run.started_at).total_seconds()
                        workflow_run.duration_seconds = int(duration)

                    db.add(workflow_run)
                    stats["runs_synced"] += 1

            # 2. Fetch and sync deployments
            deployments = self.fetch_deployments(owner, repo, days_back=days_back)

            for deploy_data in deployments:
                # Check if deployment already exists
                existing_deployment = db.query(models.Deployment).filter(
                    models.Deployment.repository_id == repository.id,
                    models.Deployment.deployment_id == deploy_data["id"]
                ).first()

                if not existing_deployment:
                    status_info = deploy_data.get("status_info", {})

                    deployment = models.Deployment(
                        repository_id=repository.id,
                        deployment_id=deploy_data["id"],
                        environment=deploy_data.get("environment", "unknown"),
                        status=status_info.get("state", "unknown"),
                        commit_sha=deploy_data["sha"],
                        ref=deploy_data.get("ref"),
                        deployer=deploy_data.get("creator", {}).get("login"),
                        deployment_url=status_info.get("environment_url"),
                        log_url=status_info.get("log_url"),
                        started_at=self._parse_github_datetime(deploy_data.get("created_at")),
                        completed_at=self._parse_github_datetime(status_info.get("updated_at")),
                        extra_data=deploy_data
                    )

                    # Calculate duration if both times exist
                    if deployment.started_at and deployment.completed_at:
                        duration = (deployment.completed_at - deployment.started_at).total_seconds()
                        deployment.duration_seconds = int(duration)

                    db.add(deployment)
                    stats["deployments_synced"] += 1

            db.commit()
            logger.info(f"Synced CI/CD data for {owner}/{repo}: {stats}")
            return stats

        except Exception as e:
            db.rollback()
            logger.error(f"Failed to sync repository workflows: {e}")
            raise

    def _parse_github_datetime(self, dt_string: Optional[str]) -> Optional[datetime]:
        """Parse GitHub API datetime string to Python datetime."""
        if not dt_string:
            return None
        try:
            return datetime.fromisoformat(dt_string.replace("Z", "+00:00"))
        except Exception:
            return None


def sync_all_repositories_cicd(
    db: Session,
    organization_id: str,
    github_token: str,
    days_back: int = 30
) -> Dict[str, Any]:
    """
    Sync CI/CD data for all repositories in an organization.

    Args:
        db: Database session
        organization_id: Organization UUID
        github_token: GitHub token for API access
        days_back: How many days of history to sync

    Returns:
        Dictionary with sync statistics
    """
    service = GitHubActionsService(github_token)

    # Get organization
    org = db.query(models.Organization).filter(models.Organization.id == organization_id).first()
    if not org:
        raise ValueError(f"Organization {organization_id} not found")

    # Get all active repositories
    repositories = db.query(models.Repository).filter(
        models.Repository.organization_id == organization_id,
        models.Repository.url.isnot(None)
    ).all()

    total_stats = {
        "repositories_processed": 0,
        "repositories_failed": 0,
        "total_workflows_synced": 0,
        "total_runs_synced": 0,
        "total_deployments_synced": 0,
        "errors": []
    }

    for repo in repositories:
        try:
            # Parse owner/repo from GitHub URL
            # Example: https://github.com/owner/repo.git
            url_parts = repo.url.rstrip('.git').split('/')
            owner = url_parts[-2]
            repo_name = url_parts[-1]

            stats = service.sync_repository_workflows(db, repo, owner, repo_name, days_back)

            total_stats["repositories_processed"] += 1
            total_stats["total_workflows_synced"] += stats["workflows_synced"]
            total_stats["total_runs_synced"] += stats["runs_synced"]
            total_stats["total_deployments_synced"] += stats["deployments_synced"]

        except Exception as e:
            error_msg = f"Failed to sync {repo.name}: {str(e)}"
            logger.error(error_msg)
            total_stats["repositories_failed"] += 1
            total_stats["errors"].append(error_msg)

    logger.info(f"Completed CI/CD sync for organization {org.name}: {total_stats}")
    return total_stats
