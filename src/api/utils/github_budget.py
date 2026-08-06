"""
Shared GitHub API budget governor.

Every GitHub caller in this deployment shares one PAT, therefore one 5000/hr
primary rate limit, and nothing arbitrated between them. Observed failure: an
org import exhausted the window (X-RateLimit-Used: 5019), after which the
deployment-topology sync got 403 "API rate limit exceeded" and wrote nothing.
The same collision was latent in the scheduler, which registered ~2500 repo
scan cron jobs all landing in one time window on the same token.

Two mechanisms:

1. **Observed budget, not asserted budget.** ``GET /rate_limit`` has been seen
   reporting 4990 remaining while the very next real request returned 403 with
   ``X-RateLimit-Used: 5019``. So the authoritative number is whatever the last
   real response header said. Callers push those headers here; everyone reads
   the same snapshot.

2. **Tiered floors + idle gate.** Background work (scheduled scans) is only
   allowed to spend down to a reserved floor, and only when no interactive or
   on-demand work is in flight. Interactive work is never blocked by this
   module - it is the thing being protected.

Redis holds the state so the API process, CLI scripts and scan subprocesses see
one view. Without Redis the module degrades to per-process state and says so in
``snapshot()["backend"]`` - degraded means "cannot coordinate", so background
work is refused rather than allowed blind.
"""

import logging
import os
import time
import uuid
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Tiers, most protected first.
TIER_INTERACTIVE = "interactive"   # a human is waiting: UI request, manual sync
TIER_ON_DEMAND = "on_demand"       # operator-triggered batch: topology sync, one repo scan
TIER_BACKGROUND = "background"     # cron: scheduled scans, annealing

# Calls a tier must leave behind for the tiers above it.
_DEFAULT_FLOORS = {
    TIER_INTERACTIVE: 0,
    TIER_ON_DEMAND: 400,
    TIER_BACKGROUND: 2000,
}

# Namespaced so tests cannot flush the live budget state of a running estate.
_KEY_NS = os.environ.get("GITHUB_BUDGET_KEY_PREFIX", "gh")
_KEY_BUDGET = f"{_KEY_NS}:budget:core"
_KEY_LEASE_PREFIX = f"{_KEY_NS}:lease"
_KEY_ACTIVITY = f"{_KEY_NS}:activity"

# A background scan is refused unless this many calls are available above the
# floor - a scan that starts and dies half way through is worse than one that
# never started, because it leaves partial data that looks complete.
DEFAULT_SCAN_COST = int(os.environ.get("GITHUB_SCAN_COST_ESTIMATE", "150"))

# How long after the last interactive/on-demand activity the estate counts as
# idle enough for background work.
IDLE_SECONDS = int(os.environ.get("GITHUB_IDLE_SECONDS", "300"))

_LEASE_TTL = int(os.environ.get("GITHUB_LEASE_TTL_SECONDS", "7200"))


def _floor(tier: str) -> int:
    env = f"GITHUB_BUDGET_FLOOR_{tier.upper()}"
    raw = os.environ.get(env)
    if raw:
        try:
            return int(raw)
        except ValueError:
            logger.warning("Ignoring non-integer %s=%r", env, raw)
    return _DEFAULT_FLOORS.get(tier, 0)


def _redis():
    try:
        from src.rbac.cache import redis_client
        return redis_client
    except Exception:  # pragma: no cover - import-time environment issue
        return None


# Fallback state when Redis is unavailable. Deliberately process-local.
_local: Dict[str, Any] = {"remaining": None, "reset_epoch": None, "used": None,
                          "observed_at": None, "leases": {}, "activity": {}}


# ---------------------------------------------------------------------------
# Observation
# ---------------------------------------------------------------------------

def observe_headers(headers: Any) -> Optional[int]:
    """Record the rate-limit headers of any real GitHub response.

    Returns the observed remaining count, or None when the response carried no
    rate-limit headers (some error paths do not).
    """
    def _int(name: str) -> Optional[int]:
        try:
            value = headers.get(name) if headers else None
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    remaining = _int("X-RateLimit-Remaining")
    if remaining is None:
        return None
    reset_epoch = _int("X-RateLimit-Reset")
    used = _int("X-RateLimit-Used")
    now = int(time.time())

    client = _redis()
    if client is not None:
        try:
            client.hset(_KEY_BUDGET, mapping={
                "remaining": remaining,
                "reset_epoch": reset_epoch or 0,
                "used": used or 0,
                "observed_at": now,
            })
            # Expire a little past the window so a stale window is never trusted.
            client.expire(_KEY_BUDGET, max(60, (reset_epoch or now + 3600) - now + 120))
            return remaining
        except Exception as exc:
            logger.debug("GitHub budget observe failed: %s", exc)

    _local.update({"remaining": remaining, "reset_epoch": reset_epoch,
                   "used": used, "observed_at": now})
    return remaining


def snapshot() -> Dict[str, Any]:
    """Current shared view of the budget."""
    client = _redis()
    data: Dict[str, Any] = {}
    backend = "redis"
    if client is not None:
        try:
            data = client.hgetall(_KEY_BUDGET) or {}
        except Exception as exc:
            logger.debug("GitHub budget read failed: %s", exc)
            backend = "degraded"
    else:
        backend = "degraded"

    if backend != "redis" or not data:
        data = {k: _local.get(k) for k in ("remaining", "reset_epoch", "used", "observed_at")}
        if backend == "redis":
            backend = "redis_empty"

    def _num(key: str) -> Optional[int]:
        raw = data.get(key)
        if raw in (None, ""):
            return None
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return None
        # 0 is a real value for `remaining` (budget exhausted) but a placeholder
        # for the epoch fields, which are written as 0 when GitHub omits them.
        if value == 0 and key in ("reset_epoch", "observed_at"):
            return None
        return value

    remaining = _num("remaining")
    reset_epoch = _num("reset_epoch")
    observed_at = _num("observed_at")
    now = int(time.time())

    # A window that has already reset means the budget is full again, but say so
    # as an inference rather than pretending it was observed.
    window_expired = bool(reset_epoch and reset_epoch <= now)

    return {
        "backend": backend,
        "remaining": remaining,
        "used": _num("used"),
        "reset_epoch": reset_epoch,
        "reset_utc": (
            datetime.utcfromtimestamp(reset_epoch).isoformat() + "Z" if reset_epoch else None
        ),
        "observed_at": observed_at,
        "observation_age_seconds": (now - observed_at) if observed_at else None,
        "window_expired": window_expired,
        "floors": {t: _floor(t) for t in (TIER_INTERACTIVE, TIER_ON_DEMAND, TIER_BACKGROUND)},
    }


# ---------------------------------------------------------------------------
# Activity leases
# ---------------------------------------------------------------------------

def begin(tier: str, name: str, ttl: int = _LEASE_TTL) -> str:
    """Announce that work of `tier` is in flight. Returns a lease id."""
    lease_id = uuid.uuid4().hex[:12]
    key = f"{_KEY_LEASE_PREFIX}:{tier}:{lease_id}"
    client = _redis()
    if client is not None:
        try:
            client.set(key, name, ex=ttl)
            client.set(f"{_KEY_ACTIVITY}:{tier}", str(int(time.time())), ex=max(ttl, IDLE_SECONDS))
            return lease_id
        except Exception as exc:
            logger.debug("GitHub budget lease failed: %s", exc)
    _local["leases"][key] = (name, time.time() + ttl)
    _local["activity"][tier] = time.time()
    return lease_id


def end(tier: str, lease_id: str) -> None:
    """Release a lease and stamp the tier's last-activity time."""
    key = f"{_KEY_LEASE_PREFIX}:{tier}:{lease_id}"
    client = _redis()
    if client is not None:
        try:
            client.delete(key)
            client.set(f"{_KEY_ACTIVITY}:{tier}", str(int(time.time())), ex=IDLE_SECONDS * 2)
            return
        except Exception as exc:
            logger.debug("GitHub budget lease release failed: %s", exc)
    _local["leases"].pop(key, None)
    _local["activity"][tier] = time.time()


def touch(tier: str = TIER_INTERACTIVE) -> None:
    """Record activity without holding a lease (used by request middleware)."""
    client = _redis()
    if client is not None:
        try:
            client.set(f"{_KEY_ACTIVITY}:{tier}", str(int(time.time())), ex=IDLE_SECONDS * 2)
            return
        except Exception:
            pass
    _local["activity"][tier] = time.time()


def active_leases(tier: str) -> int:
    client = _redis()
    if client is not None:
        try:
            return len(list(client.scan_iter(match=f"{_KEY_LEASE_PREFIX}:{tier}:*", count=100)))
        except Exception as exc:
            logger.debug("GitHub budget lease scan failed: %s", exc)
            return 0
    now = time.time()
    prefix = f"{_KEY_LEASE_PREFIX}:{tier}:"
    return sum(1 for k, (_n, exp) in _local["leases"].items() if k.startswith(prefix) and exp > now)


def seconds_since_activity(tier: str) -> Optional[int]:
    client = _redis()
    if client is not None:
        try:
            raw = client.get(f"{_KEY_ACTIVITY}:{tier}")
            return int(time.time()) - int(raw) if raw else None
        except Exception:
            return None
    ts = _local["activity"].get(tier)
    return int(time.time() - ts) if ts else None


# ---------------------------------------------------------------------------
# Admission control
# ---------------------------------------------------------------------------

def can_run(tier: str, need: int = 1) -> Tuple[bool, str, Dict[str, Any]]:
    """Decide whether `tier` may spend `need` calls now.

    Returns (allowed, reason, snapshot). `reason` is always populated so a
    refusal can be logged and surfaced verbatim - a deferred scan must be
    visibly deferred, never silently skipped.
    """
    snap = snapshot()

    if tier == TIER_INTERACTIVE:
        return True, "interactive tier is never gated", snap

    remaining = snap["remaining"]
    floor = _floor(tier)

    if tier == TIER_BACKGROUND:
        if snap["backend"] == "degraded":
            return False, (
                "budget state unavailable (no Redis): cannot coordinate with "
                "interactive work, so background scans are refused"
            ), snap
        blocking = {
            t: active_leases(t) for t in (TIER_INTERACTIVE, TIER_ON_DEMAND)
        }
        busy = {t: n for t, n in blocking.items() if n}
        if busy:
            return False, f"higher-priority work in flight: {busy}", snap
        for t in (TIER_INTERACTIVE, TIER_ON_DEMAND):
            age = seconds_since_activity(t)
            if age is not None and age < IDLE_SECONDS:
                return False, (
                    f"{t} activity {age}s ago, idle threshold is {IDLE_SECONDS}s"
                ), snap

    if remaining is None:
        if snap["window_expired"]:
            return True, "no observation this window; window already reset", snap
        return (
            tier != TIER_BACKGROUND,
            "no rate-limit observation yet this window",
            snap,
        )

    if snap["window_expired"]:
        return True, "observed window has reset; full budget assumed", snap

    if remaining - need < floor:
        return False, (
            f"{remaining} calls remain; {tier} needs {need} and must leave "
            f"{floor} for higher-priority work (resets {snap['reset_utc']})"
        ), snap

    return True, f"{remaining} remain, above the {floor} floor for {tier}", snap
