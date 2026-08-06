"""
Deployment Observation Service (phase P2: GitHub Deployments API).

P1 answers "this repository's CD contract is *wired* to push to this
environment". P2 answers the different question "a deploy to this environment
actually happened, when, and who triggered it". Both write into
``repo_deployment_map``; P2 uses ``method = 'github_deployment'`` so an observed
deploy sits alongside the static inference instead of overwriting it, and the
two can be compared (wired-but-never-used vs used-but-not-wired).

Access used - all read-only, all covered by the existing PAT's `repo` scope:
    GET /repos/{o}/{r}/deployments                      deployment records
    GET /repos/{o}/{r}/deployments/{id}/statuses         latest state per deploy

Writes:
    deployments         one row per observed GitHub deployment record
    deployment_targets  one row per (organization, environment name)
    repo_deployment_map one row per (repository, environment) actually deployed

SECURITY: a deployment's ``payload`` is arbitrary JSON supplied by whoever
created the deployment and can contain configuration or credential material.
Only its **key names** are stored (``evidence.payload_keys``); values are
dropped at ingest and never reach the database.

COVERAGE: a repository probed with no deployment records gets an explicit
``is_resolved = false`` row with ``unresolved_reason =
'no_deployments_observed'``. That is "we looked and GitHub knows of no deploy",
which is different from "this repository deploys nowhere" - many repositories in
this estate deploy through workflows that never create a Deployment object.
"""
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text as sa_text
from sqlalchemy.orm import Session

from . import github_budget
from .github_reader import RATE_LIMITED, GitHubReader
from .reusable_workflow_parser import (
    UNRESOLVED_ENVIRONMENT,
    classify_environment_kind,
    infer_region,
)

logger = logging.getLogger(__name__)

METHOD = "github_deployment"
OBSERVER_VERSION = "p2.0"

# A deployment record proves the pipeline targeted the environment. A successful
# status proves it landed. Confidence separates those two claims.
_STATE_CONFIDENCE: Dict[str, float] = {
    "success": 0.95,
    "inactive": 0.95,   # succeeded, then superseded by a later deploy
    "in_progress": 0.85,
    "queued": 0.85,
    "pending": 0.85,
    "waiting": 0.85,
    "failure": 0.85,    # environment was targeted; delivery did not land
    "error": 0.85,
}
# Status not fetched (statuses budget spent): outcome unknown, targeting known.
CONFIDENCE_STATUS_UNKNOWN = 0.90
# Nothing deployed inside the observation window.
CONFIDENCE_STALE_PENALTY = 0.05

# GitHub returns deployments newest-first, 100 per page.
_PER_PAGE = 100

# API cost of probing one repository: the deployments list plus one statuses
# call per environment sampled. Used for budget admission, so it must not
# understate - see github_budget.
def per_repo_cost(max_pages: int, statuses_per_repo: int) -> int:
    return max_pages + statuses_per_repo


class DeploymentObservationService(GitHubReader):
    """Turns GitHub Deployment records into observed deployment-map rows."""

    # -- Collection -------------------------------------------------------

    def list_deployments(
        self, owner: str, repo: str, max_pages: int = 1
    ) -> Tuple[List[Dict[str, Any]], int, int]:
        """List a repository's deployment records, newest first.

        Returns:
            (deployments, status, pages_fetched). An empty list with status 200
            means GitHub has no deployment records for the repository - a real
            observation, not a failure.
        """
        collected: List[Dict[str, Any]] = []
        pages = 0
        for page in range(1, max_pages + 1):
            payload, status = self._get(
                f"/repos/{owner}/{repo}/deployments",
                params={"per_page": _PER_PAGE, "page": page},
            )
            if status != 200:
                return collected, status, pages
            pages += 1
            batch = payload if isinstance(payload, list) else []
            collected.extend(batch)
            if len(batch) < _PER_PAGE:
                break
        return collected, 200, pages

    def latest_status(
        self, owner: str, repo: str, deployment_id: int
    ) -> Tuple[Optional[Dict[str, Any]], int]:
        """Fetch the most recent status of one deployment.

        GitHub returns statuses newest-first, so one page of size 1 is enough
        and keeps the per-repository cost bounded.
        """
        payload, status = self._get(
            f"/repos/{owner}/{repo}/deployments/{deployment_id}/statuses",
            params={"per_page": 1},
        )
        if status != 200 or not isinstance(payload, list) or not payload:
            return None, status
        return payload[0], status

    def probe_repository(
        self,
        owner: str,
        repo: str,
        max_pages: int = 1,
        statuses_per_repo: int = 4,
        active_days: int = 365,
    ) -> Dict[str, Any]:
        """Collect one repository's deployment observations.

        Returns a dict with `rows` (map rows), `deployments` (raw records worth
        persisting), `status_by_id`, and either `ok`, `forbidden`,
        `rate_limited` or `error`.
        """
        deployments, status, pages = self.list_deployments(owner, repo, max_pages)

        if status == RATE_LIMITED:
            return {"outcome": "rate_limited"}
        if status == 403:
            self._record_gap(
                "repo_deployments_forbidden",
                f"GET /repos/{owner}/{repo}/deployments",
                403,
                "Deployment history unreadable for this repository; observed "
                "deployments cannot be collected and the repository stays at "
                "P1 capability-only evidence.",
            )
            return {"outcome": "forbidden", "http_status": 403}
        if status == 404:
            # Repository renamed or deleted since the inventory snapshot.
            return {"outcome": "not_found", "http_status": 404}
        if status != 200:
            return {"outcome": "error", "http_status": status}

        latest_per_env = _latest_per_environment(deployments)

        # Statuses are the expensive part: one call per environment. Spend them
        # on the newest deployment of each environment, most recent first, and
        # record which environments went unqueried rather than guessing.
        status_by_id: Dict[int, Dict[str, Any]] = {}
        ordered_envs = sorted(
            latest_per_env.items(),
            key=lambda kv: kv[1]["latest"].get("created_at") or "",
            reverse=True,
        )
        for _env, info in ordered_envs[:statuses_per_repo]:
            dep_id = info["latest"].get("id")
            if not isinstance(dep_id, int):
                continue
            state, st_code = self.latest_status(owner, repo, dep_id)
            if st_code == RATE_LIMITED:
                # Drop this repository entirely rather than writing rows whose
                # statuses were half-collected; the next run re-probes it.
                return {"outcome": "rate_limited"}
            if state:
                status_by_id[dep_id] = state

        rows = build_environment_rows(
            owner, repo, latest_per_env, status_by_id, active_days, pages
        )
        return {
            "outcome": "ok",
            "rows": rows,
            "deployments": deployments,
            "status_by_id": status_by_id,
            "environments_observed": len(latest_per_env),
            "deployment_records": len(deployments),
            "pages_fetched": pages,
        }

    # -- Persistence ------------------------------------------------------

    def upsert_deployment_target(
        self, db: Session, organization_id: str, environment: str, kind: str
    ) -> Optional[str]:
        """Upsert the org-scoped deployment target for an environment name."""
        row = db.execute(
            sa_text(
                """
                INSERT INTO deployment_targets (organization_id, name, type, cloud_provider)
                VALUES (CAST(:org_id AS uuid), :name, :type, NULL)
                ON CONFLICT (organization_id, name) DO UPDATE
                    SET type = EXCLUDED.type, updated_at = NOW()
                RETURNING id::text
                """
            ),
            {"org_id": organization_id, "name": environment[:255], "type": kind[:50]},
        ).fetchone()
        return row[0] if row else None

    def upsert_deployments(
        self,
        db: Session,
        organization_id: str,
        repository_id: str,
        deployments: List[Dict[str, Any]],
        status_by_id: Dict[int, Dict[str, Any]],
    ) -> int:
        """Persist raw deployment records into the `deployments` table.

        Only key names of the deployment payload are stored - a payload is
        attacker-or-tooling-supplied JSON and may contain secret material.
        """
        target_cache: Dict[str, Optional[str]] = {}
        written = 0
        for dep in deployments:
            environment = (dep.get("environment") or UNRESOLVED_ENVIRONMENT)[:255]
            kind = _environment_kind(environment, dep)
            if environment not in target_cache:
                target_cache[environment] = self.upsert_deployment_target(
                    db, organization_id, environment, kind
                )
            state = status_by_id.get(dep.get("id")) or {}
            started_at = _parse_ts(dep.get("created_at"))
            completed_at = _parse_ts(state.get("created_at")) if state else None
            duration = (
                int((completed_at - started_at).total_seconds())
                if started_at and completed_at and completed_at >= started_at
                else None
            )
            db.execute(
                sa_text(
                    """
                    INSERT INTO deployments (
                        repository_id, target_id, deployment_id, environment, status,
                        commit_sha, commit_message, ref, deployer, deployment_url,
                        log_url, started_at, completed_at, duration_seconds, extra_data
                    ) VALUES (
                        CAST(:repo_id AS uuid), CAST(:target_id AS uuid), :deployment_id,
                        :environment, :status, :commit_sha, :commit_message, :ref,
                        :deployer, :deployment_url, :log_url, :started_at, :completed_at,
                        :duration_seconds, CAST(:extra_data AS jsonb)
                    )
                    ON CONFLICT (repository_id, deployment_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        target_id = EXCLUDED.target_id,
                        deployment_url = EXCLUDED.deployment_url,
                        log_url = EXCLUDED.log_url,
                        completed_at = EXCLUDED.completed_at,
                        duration_seconds = EXCLUDED.duration_seconds,
                        extra_data = EXCLUDED.extra_data,
                        updated_at = NOW()
                    """
                ),
                {
                    "repo_id": repository_id,
                    "target_id": target_cache.get(environment),
                    "deployment_id": dep.get("id"),
                    "environment": environment,
                    # 'unknown' means the statuses call was not spent on this
                    # record, not that GitHub reported no state.
                    "status": (state.get("state") or "unknown")[:50],
                    "commit_sha": (dep.get("sha") or "")[:40],
                    "commit_message": _truncate(dep.get("description"), 2000),
                    "ref": _truncate(dep.get("ref"), 255),
                    "deployer": _truncate((dep.get("creator") or {}).get("login"), 255),
                    "deployment_url": _truncate(state.get("environment_url"), 512),
                    "log_url": _truncate(state.get("log_url"), 512),
                    "started_at": started_at,
                    "completed_at": completed_at,
                    "duration_seconds": duration,
                    "extra_data": _json(
                        {
                            "task": dep.get("task"),
                            "production_environment": dep.get("production_environment"),
                            "transient_environment": dep.get("transient_environment"),
                            "original_environment": dep.get("original_environment"),
                            "creator_type": (dep.get("creator") or {}).get("type"),
                            "payload_keys": _payload_keys(dep.get("payload")),
                            "status_source": "statuses_api" if state else "not_fetched",
                            "observer_version": OBSERVER_VERSION,
                        }
                    ),
                },
            )
            written += 1
        return written

    def upsert_map_rows(
        self, db: Session, organization_id: str, repository_id: str,
        rows: List[Dict[str, Any]],
    ) -> int:
        """Upsert observed deployment rows, one per (repository, environment)."""
        written = 0
        for row in rows:
            db.execute(
                sa_text(
                    """
                    INSERT INTO repo_deployment_map (
                        organization_id, repository_id, environment, environment_kind,
                        cloud_provider, resource_type, resource_identifier,
                        subscription_or_account, region, runner_labels, deploy_identity,
                        tf_backend, method, confidence, source_workflow_id, is_resolved,
                        unresolved_reason, evidence, first_observed_at, last_observed_at
                    ) VALUES (
                        CAST(:org_id AS uuid), CAST(:repo_id AS uuid), :environment,
                        :environment_kind, NULL, :resource_type, :resource_identifier,
                        NULL, :region, NULL, NULL, NULL, :method, :confidence, NULL,
                        :is_resolved, :unresolved_reason, CAST(:evidence AS jsonb),
                        NOW(), NOW()
                    )
                    ON CONFLICT (repository_id, environment, method,
                                 COALESCE(resource_identifier, ''),
                                 COALESCE(resource_type, ''))
                    DO UPDATE SET
                        environment_kind = EXCLUDED.environment_kind,
                        region = EXCLUDED.region,
                        confidence = EXCLUDED.confidence,
                        is_resolved = EXCLUDED.is_resolved,
                        unresolved_reason = EXCLUDED.unresolved_reason,
                        evidence = EXCLUDED.evidence,
                        last_observed_at = NOW(),
                        is_current = true,
                        updated_at = NOW()
                    """
                ),
                {
                    "org_id": organization_id,
                    "repo_id": repository_id,
                    "environment": row["environment"],
                    "environment_kind": row["environment_kind"],
                    "resource_type": row["resource_type"],
                    "resource_identifier": row["resource_identifier"],
                    "region": row["region"],
                    "method": METHOD,
                    "confidence": row["confidence"],
                    "is_resolved": row["is_resolved"],
                    "unresolved_reason": row["unresolved_reason"],
                    "evidence": _json(row["evidence"]),
                },
            )
            written += 1
        return written

    # -- Candidate selection ---------------------------------------------

    def select_candidates(
        self,
        db: Session,
        organization_id: str,
        only_mapped: bool = True,
        include_archived: bool = False,
        refresh_days: int = 7,
        limit: Optional[int] = None,
    ) -> List[Tuple[str, str]]:
        """Pick which repositories to probe, oldest observation first.

        This ordering *is* the resume mechanism: a run stopped by the rate limit
        has already committed the repositories it finished, and those are then
        skipped for `refresh_days`, so the next run continues rather than
        restarting.

        Args:
            only_mapped: Restrict to repositories that already carry a
                deployment-map row from another method (P1's 374). These are the
                ones where observation adds the most - it confirms or refutes a
                capability claim.
            include_archived: Probe archived repositories too.
            refresh_days: Skip repositories observed more recently than this.
            limit: Cap the number of repositories returned.
        """
        sql = """
            SELECT r.id::text, r.name
            FROM repositories r
            LEFT JOIN repo_deployment_map o
                   ON o.repository_id = r.id AND o.method = :method
            WHERE r.organization_id = CAST(:org_id AS uuid)
              AND (:include_archived OR NOT COALESCE(r.is_archived, false))
              AND (
                  NOT :only_mapped
                  OR EXISTS (
                      SELECT 1 FROM repo_deployment_map p
                      WHERE p.repository_id = r.id AND p.method <> :method
                  )
              )
            GROUP BY r.id, r.name
            HAVING MAX(o.last_observed_at) IS NULL
                OR MAX(o.last_observed_at) < NOW() - CAST(:refresh AS interval)
            ORDER BY MAX(o.last_observed_at) ASC NULLS FIRST, r.name ASC
        """
        if limit:
            sql += " LIMIT :limit"
        params: Dict[str, Any] = {
            "org_id": organization_id,
            "method": METHOD,
            "only_mapped": only_mapped,
            "include_archived": include_archived,
            "refresh": f"{max(0, refresh_days)} days",
        }
        if limit:
            params["limit"] = limit
        return [(row[0], row[1]) for row in db.execute(sa_text(sql), params).fetchall()]

    # -- Orchestration ----------------------------------------------------

    def sync(
        self,
        db: Session,
        organization_id: str,
        org_login: str,
        only_mapped: bool = True,
        include_archived: bool = False,
        refresh_days: int = 7,
        repo_limit: Optional[int] = None,
        max_pages: int = 1,
        statuses_per_repo: int = 4,
        active_days: int = 365,
        commit_every: int = 25,
        respect_budget: bool = True,
    ) -> Dict[str, Any]:
        """Run phase P2 end to end.

        Holds an `on_demand` budget lease for the whole run so scheduled scans
        stand down, and stops cleanly at the on-demand floor instead of running
        into 403s - a run that stops with a reported remainder is honest, a run
        that dies mid-repository leaves partial data that looks complete.
        """
        started = datetime.utcnow()
        stats: Dict[str, Any] = {
            "candidates": 0,
            "repositories_probed": 0,
            "repositories_with_deployments": 0,
            "repositories_without_deployments": 0,
            "repositories_forbidden": 0,
            "repositories_not_found": 0,
            "repositories_errored": 0,
            "deployment_records_written": 0,
            "map_rows_written": 0,
            "environments_observed": 0,
            "production_environments_observed": 0,
            "rate_limited": False,
            "rights_gaps": {},
        }
        lease = github_budget.begin(
            github_budget.TIER_ON_DEMAND, "deployment_observation_sync"
        )
        try:
            return self._sync_inner(
                db, organization_id, org_login, only_mapped, include_archived,
                refresh_days, repo_limit, max_pages, statuses_per_repo, active_days,
                commit_every, respect_budget, stats, started,
            )
        finally:
            github_budget.end(github_budget.TIER_ON_DEMAND, lease)

    def _sync_inner(
        self, db, organization_id, org_login, only_mapped, include_archived,
        refresh_days, repo_limit, max_pages, statuses_per_repo, active_days,
        commit_every, respect_budget, stats, started,
    ) -> Dict[str, Any]:
        stats["rate_limit_at_start"] = self.rate_limit_status()

        candidates = self.select_candidates(
            db, organization_id, only_mapped=only_mapped,
            include_archived=include_archived, refresh_days=refresh_days,
            limit=repo_limit,
        )
        stats["candidates"] = len(candidates)
        cost = per_repo_cost(max_pages, statuses_per_repo)
        seen_envs: set = set()
        prod_envs: set = set()

        for index, (repo_id, repo_name) in enumerate(candidates):
            if respect_budget:
                allowed, reason, _snap = github_budget.can_run(
                    github_budget.TIER_ON_DEMAND, need=cost
                )
                if not allowed:
                    db.commit()
                    stats["stopped_early"] = (
                        f"Stopped at the shared-budget floor after "
                        f"{stats['repositories_probed']} repositories: {reason}. "
                        f"{len(candidates) - index} candidates remain; re-run to "
                        "continue - completed repositories are already committed. "
                        "This is throttling arbitration, not a permissions problem."
                    )
                    stats["candidates_remaining"] = len(candidates) - index
                    break

            result = self.probe_repository(
                org_login, repo_name, max_pages=max_pages,
                statuses_per_repo=statuses_per_repo, active_days=active_days,
            )
            outcome = result["outcome"]

            if outcome == "rate_limited":
                db.commit()
                stats["rate_limited"] = True
                stats["aborted"] = (
                    f"GitHub rate limit reached while reading {repo_name}; stopped so "
                    "partial results are not mistaken for complete coverage. Re-run "
                    f"after {self._reset_utc()} - completed repositories are already "
                    "committed."
                )
                stats["candidates_remaining"] = len(candidates) - index
                break
            if outcome == "forbidden":
                stats["repositories_forbidden"] += 1
                continue
            if outcome == "not_found":
                stats["repositories_not_found"] += 1
                continue
            if outcome != "ok":
                stats["repositories_errored"] += 1
                logger.warning(
                    "Deployment probe of %s failed with HTTP %s",
                    repo_name, result.get("http_status"),
                )
                continue

            stats["repositories_probed"] += 1
            if result["deployment_records"]:
                stats["repositories_with_deployments"] += 1
                stats["deployment_records_written"] += self.upsert_deployments(
                    db, organization_id, repo_id, result["deployments"],
                    result["status_by_id"],
                )
            else:
                stats["repositories_without_deployments"] += 1

            stats["map_rows_written"] += self.upsert_map_rows(
                db, organization_id, repo_id, result["rows"]
            )
            for row in result["rows"]:
                if not row["is_resolved"]:
                    continue
                seen_envs.add(row["environment"])
                if row["environment_kind"] == "production":
                    prod_envs.add((repo_id, row["environment"]))

            if (index + 1) % commit_every == 0:
                db.commit()

        db.commit()
        stats["environments_observed"] = len(seen_envs)
        stats["production_environments_observed"] = len(prod_envs)
        stats["rights_gaps"] = self.rights_gaps
        stats["api_requests"] = self.request_count
        stats["duration_seconds"] = round(
            (datetime.utcnow() - started).total_seconds(), 1
        )
        return stats


# ---------------------------------------------------------------------------
# Row building (pure functions - no network, directly testable)
# ---------------------------------------------------------------------------

def _latest_per_environment(
    deployments: List[Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    """Group deployment records by environment, keeping the newest per env.

    GitHub returns newest-first, but the ordering is not relied on: records are
    compared by `created_at` so a reordered or merged page set still yields the
    real latest deploy.
    """
    grouped: Dict[str, Dict[str, Any]] = {}
    for dep in deployments:
        env = dep.get("environment") or UNRESOLVED_ENVIRONMENT
        created = dep.get("created_at") or ""
        entry = grouped.get(env)
        if entry is None:
            grouped[env] = {
                "latest": dep,
                "count": 1,
                "deployers": [],
                "oldest_created_at": created,
            }
            entry = grouped[env]
        else:
            entry["count"] += 1
            if created > (entry["latest"].get("created_at") or ""):
                entry["latest"] = dep
            if created and created < (entry["oldest_created_at"] or ""):
                entry["oldest_created_at"] = created
        login = (dep.get("creator") or {}).get("login")
        if login and login not in entry["deployers"]:
            entry["deployers"].append(login)
    return grouped


def build_environment_rows(
    owner: str,
    repo: str,
    latest_per_env: Dict[str, Dict[str, Any]],
    status_by_id: Dict[int, Dict[str, Any]],
    active_days: int,
    pages_fetched: int,
) -> List[Dict[str, Any]]:
    """Build `repo_deployment_map` rows from one repository's observations.

    A repository with no deployment records yields a single explicit unresolved
    row: GitHub knows of no deploy. That is a bounded negative observation, not
    a claim that the repository deploys nowhere - workflows that push without
    creating a Deployment object are invisible here by construction.
    """
    endpoint = f"GET /repos/{owner}/{repo}/deployments"
    if not latest_per_env:
        return [{
            "environment": UNRESOLVED_ENVIRONMENT,
            "environment_kind": "unknown",
            "resource_type": None,
            "resource_identifier": None,
            "region": None,
            "confidence": 0.90,
            "is_resolved": False,
            "unresolved_reason": "no_deployments_observed",
            "evidence": {
                "claim": "no_deployment_records_exist",
                "endpoint": endpoint,
                "pages_fetched": pages_fetched,
                "observer_version": OBSERVER_VERSION,
                "note": (
                    "GitHub has no Deployment records for this repository. Workflows "
                    "that deploy without creating a Deployment object are not visible "
                    "to this method; see the reusable_workflow rows for capability."
                ),
            },
        }]

    now = datetime.utcnow()
    rows: List[Dict[str, Any]] = []
    for environment, info in latest_per_env.items():
        latest = info["latest"]
        kind = _environment_kind(environment, latest)
        state = status_by_id.get(latest.get("id")) or {}
        last_at = _parse_ts(latest.get("created_at"))
        days_since = int((now - last_at).total_seconds() // 86400) if last_at else None
        stale = days_since is not None and days_since > active_days

        if state.get("state"):
            confidence = _STATE_CONFIDENCE.get(state["state"], CONFIDENCE_STATUS_UNKNOWN)
        else:
            confidence = CONFIDENCE_STATUS_UNKNOWN
        if stale:
            confidence -= CONFIDENCE_STALE_PENALTY
        confidence = round(max(0.10, min(0.95, confidence)), 2)

        rows.append({
            "environment": environment[:255],
            "environment_kind": kind,
            # The Deployments API says which environment was deployed to, never
            # which cloud resource. Cloud detail comes from joining the P1 rows
            # for the same repository and environment.
            "resource_type": None,
            "resource_identifier": _truncate(state.get("environment_url"), 512),
            "region": infer_region(environment),
            "confidence": confidence,
            "is_resolved": True,
            "unresolved_reason": None,
            "evidence": {
                "claim": "deployment_observed",
                "endpoint": endpoint,
                "deployment_id": latest.get("id"),
                "sha": latest.get("sha"),
                "ref": latest.get("ref"),
                "task": latest.get("task"),
                "deployer": (latest.get("creator") or {}).get("login"),
                "deployer_type": (latest.get("creator") or {}).get("type"),
                "production_environment": latest.get("production_environment"),
                "transient_environment": latest.get("transient_environment"),
                "original_environment": (
                    latest.get("original_environment")
                    if latest.get("original_environment") != environment else None
                ),
                "environment_kind_source": _kind_source(environment, latest),
                "latest_status": (
                    {
                        "state": state.get("state"),
                        "created_at": state.get("created_at"),
                        "log_url": state.get("log_url"),
                        "environment_url": state.get("environment_url"),
                        "creator": (state.get("creator") or {}).get("login"),
                    }
                    if state else None
                ),
                "status_source": "statuses_api" if state else "not_fetched_budget_cap",
                "last_deployment_at": latest.get("created_at"),
                "days_since_last_deployment": days_since,
                "stale": stale,
                "active_days_window": active_days,
                "deployment_records_in_window": info["count"],
                "distinct_deployers": info["deployers"][:10],
                "oldest_record_in_window": info.get("oldest_created_at") or None,
                "pages_fetched": pages_fetched,
                # Key names only: a deployment payload is caller-supplied JSON
                # and can carry configuration or credential material.
                "payload_keys": _payload_keys(latest.get("payload")),
                "observer_version": OBSERVER_VERSION,
            },
        })
    return rows


def _environment_kind(environment: str, deployment: Dict[str, Any]) -> str:
    """Classify an environment, using GitHub's own flags to break ties.

    Name-based classification misses environments named things like `live` or
    `blue`; GitHub's `production_environment` flag is authoritative for those.
    """
    kind = classify_environment_kind(environment)
    if kind != "unknown":
        return kind
    if deployment.get("production_environment"):
        return "production"
    if deployment.get("transient_environment"):
        return "ephemeral"
    return "unknown"


def _kind_source(environment: str, deployment: Dict[str, Any]) -> str:
    if classify_environment_kind(environment) != "unknown":
        return "environment_name"
    if deployment.get("production_environment"):
        return "github_production_environment_flag"
    if deployment.get("transient_environment"):
        return "github_transient_environment_flag"
    return "unclassified"


def _payload_keys(payload: Any) -> Optional[List[str]]:
    """Key names of a deployment payload. Values are dropped, never stored."""
    if isinstance(payload, dict):
        return sorted(str(k)[:64] for k in payload.keys())[:25]
    if isinstance(payload, str) and payload.strip():
        return ["__opaque_string_payload__"]
    return None


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _truncate(value: Any, length: int) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    return text[:length] if text else None


def _json(value: Any) -> Optional[str]:
    import json

    if value is None:
        return None
    return json.dumps(value, default=str)
