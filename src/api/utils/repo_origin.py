"""Resolve which GitHub organization a repository actually lives in, before cloning it.

Written after "generate System Architecture" failed on `web-webadmin` with:

    remote: Repository not found.
    fatal: repository 'https://github.com/SleepNumberInc/web-webadmin/' not found

Nothing about that message is a lie and nothing in it is useful. Three separate things
had to be established before the cause was visible:

1. **git redacts credentials.** A clone through
   ``https://x-access-token:<token>@github.com/...`` prints the bare URL on failure, and
   appends a trailing slash. So the absence of a token in the error text is not evidence
   that no token was sent - reading it that way sends you looking for the wrong bug.
2. **"Repository not found" means the token authenticated and then could not see the
   repository.** A token that failed to authenticate says ``Invalid username or token``
   instead. The two are worth telling apart: one is a credential problem, the other is a
   visibility or naming problem.
3. **The row was internally inconsistent.** ``Repository.url`` said
   ``github.com/SleepNumberInc/web-webadmin``; ``Repository.organization_id`` pointed at
   ``sleepnumberlabs``. The caller resolved the token from the foreign key and the URL from
   the string column, so it presented a sleepnumberlabs credential to a SleepNumberInc
   path. Those two can never both be right, and the clone can only ever fail.

The repository is really ``sleepnumberlabs/web-webadmin``, private and not archived.

**Neither column is authoritative.** 483 of 2,540 rows disagree with themselves, in both
directions - 445 with ``url=SleepNumberInc, fk=sleepnumberlabs`` and 38 the other way
around. Sampled in both directions, every one of them resolved to *sleepnumberlabs*. So a
rule of "trust the foreign key" is wrong for 38 rows and a rule of "trust the URL" is wrong
for 445, and there is no third column to break the tie. The only correct answer is to ask
GitHub, which costs one request and replaces a bare git 404 with a statement of what was
tried.

The answer is then written back, so a row is repaired the first time anything touches it
rather than by a sweep of 483 repositories against a shared 5000/hr budget.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


@dataclass
class OriginProbe:
    """One (organization, HTTP status) pair, kept so a failure can name what it tried."""

    org: str
    status: int
    token_source: str


@dataclass
class CloneTarget:
    """Where to clone from, and the credential that has been shown to reach it."""

    org: str
    name: str
    url: str
    token: str
    token_source: str
    corrected: bool = False
    probes: List[OriginProbe] = field(default_factory=list)


class RepositoryOriginError(Exception):
    """No candidate organization answered for this repository.

    Carries the probes so the caller reports which organizations were asked and what each
    said. Doctrine §0.6: a failure that cannot be acted on is not a finding, and
    "not found" on its own does not say whether the repository moved, was deleted, or is
    invisible to the credential we hold.
    """

    def __init__(self, name: str, probes: List[OriginProbe]) -> None:
        self.name = name
        self.probes = probes
        tried = "; ".join(f"{p.org} -> HTTP {p.status} (token: {p.token_source})"
                          for p in probes) or "no candidate organizations"
        super().__init__(
            f"Repository '{name}' was not found in any known organization. Tried: {tried}. "
            f"A 404 here means the credential authenticated and the repository was not "
            f"visible to it, which is either a rename or transfer on GitHub's side or a "
            f"repository the token's organization does not include. To distinguish them, "
            f"a token with `repo` scope on the owning organization is required; with one, "
            f"a 404 is proof of absence rather than of blindness.")


async def get_token_for_org(db: Session, org_name: Optional[str]) -> Tuple[Optional[str], str]:
    """Return ``(token, provenance)`` for an organization.

    Provenance is returned rather than logged because which credential was used is the
    first thing you need when a clone 404s, and it is the one thing the git error will
    never tell you.
    """
    from ..config import settings

    if org_name:
        try:
            import sys
            if "/app/execution" not in sys.path:
                sys.path.insert(0, "/app/execution")
            from secrets_manager import get_org_credentials  # type: ignore

            creds = await get_org_credentials(org_name)
            if creds and creds.get("github_token"):
                return creds["github_token"], f"secrets store ({org_name})"
        except Exception as exc:
            # Not fatal, and not silent either: the fallback below reaches a *different*
            # organization's credential, which is exactly how this bug presented.
            logger.warning("Org credentials unavailable for %s: %s", org_name, exc)

        env_token = os.environ.get(f"ORG_{org_name}_TOKEN")
        if env_token:
            return env_token, f"ORG_{org_name}_TOKEN"

    if settings.GITHUB_TOKEN:
        return settings.GITHUB_TOKEN, "settings.GITHUB_TOKEN"
    return None, "none"


class OrgDirectory:
    """The three questions this module asks about organizations, behind one seam.

    A seam rather than inline queries because the resolution rule is the thing worth
    testing and a real `Session` cannot be stood up here - these models declare Postgres
    ``ARRAY`` and ``JSONB`` columns that SQLite refuses to compile, which is why the
    tenant-isolation suites error on this database. Testing against a fake Session instead
    would have tested SQLAlchemy's expression objects.
    """

    def __init__(self, db: Session):
        self._db = db

    def _all(self):
        from .. import models
        return self._db.query(models.Organization).all()

    def names(self) -> List[str]:
        return [o.name for o in self._all() if o.name]

    def name_for_id(self, organization_id) -> Optional[str]:
        for org in self._all():
            if org.id == organization_id:
                return org.name
        return None

    def id_for_name(self, org_name: str):
        for org in self._all():
            if org.name and org.name.lower() == org_name.lower():
                return org.id
        return None


def candidate_orgs(repo, directory: OrgDirectory) -> List[str]:
    """Candidate organizations, in the order most likely to answer.

    The URL's organization goes first only because it is the string a human last looked
    at. The foreign key follows. Every other known organization follows those, because
    with three organizations in the estate an exhaustive answer costs at most two extra
    requests, and a wrong answer costs a report.
    """
    candidates: List[str] = []

    def add(value: Optional[str]) -> None:
        if value and value.lower() not in {c.lower() for c in candidates}:
            candidates.append(value)

    if repo.url and "github.com/" in repo.url:
        segments = repo.url.split("github.com/", 1)[1].strip("/").split("/")
        if len(segments) >= 2:
            add(segments[0])

    if repo.organization_id:
        add(directory.name_for_id(repo.organization_id))

    for name in directory.names():
        add(name)

    return candidates


async def resolve_clone_target(db: Session, repo, persist: bool = True,
                               directory: Optional[OrgDirectory] = None) -> CloneTarget:
    """Ask GitHub which organization owns ``repo``, and return a matched URL and token.

    One request in the common case: the first candidate answers. On a mismatched row the
    second answers. The row is then corrected in place so the request is not spent again.
    """
    from .github_reader import GitHubReader

    directory = directory or OrgDirectory(db)
    name = (repo.name or "").strip()
    if not name:
        raise RepositoryOriginError(repo.name or "<unnamed>", [])

    probes: List[OriginProbe] = []
    for org in candidate_orgs(repo, directory):
        token, source = await get_token_for_org(db, org)
        if not token:
            probes.append(OriginProbe(org=org, status=0, token_source="none"))
            continue

        payload, status = GitHubReader(token)._get(f"/repos/{org}/{name}")
        probes.append(OriginProbe(org=org, status=status, token_source=source))
        if status != 200:
            continue

        # GitHub's own spelling of the owner and name wins over both of ours. A repository
        # renamed on GitHub still answers under its old name via a redirect, and taking the
        # response's `full_name` is what keeps the correction we persist from re-staling.
        full_name = (payload or {}).get("full_name") or f"{org}/{name}"
        real_org, _, real_name = full_name.partition("/")
        url = f"https://github.com/{full_name}"
        linked = directory.name_for_id(repo.organization_id) if repo.organization_id else None
        corrected = (url != (repo.url or "")) or bool(
            linked and linked.lower() != real_org.lower())

        if persist and corrected:
            repo.url = url
            owning_id = directory.id_for_name(real_org)
            if owning_id is not None:
                repo.organization_id = owning_id
            try:
                db.commit()
                logger.info("Corrected origin for %s -> %s", name, url)
            except Exception as exc:
                db.rollback()
                # The clone can still proceed on the resolved values; only the repair is
                # lost, and losing it costs one request next time rather than a failure.
                logger.warning("Could not persist corrected origin for %s: %s", name, exc)

        return CloneTarget(org=real_org, name=real_name or name, url=url, token=token,
                           token_source=source, corrected=corrected, probes=probes)

    raise RepositoryOriginError(name, probes)
