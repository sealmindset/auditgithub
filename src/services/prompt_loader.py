"""
Prompt Loader — Runtime prompt resolution with 3-tier fallback.

Tier 1: Redis cache (fast, TTL-based)
Tier 2: Database lookup (authoritative — always attempted)
Tier 3: Seed-derived fallback (emergency only, logged as ERROR)

IMPORTANT DESIGN DECISIONS:
- The DATABASE is the single source of truth for prompts.
- Hardcoded prompts in provider code are REMOVED. They do not exist.
- Tier 3 fallbacks are loaded from the seed definitions, not scattered
  across provider files. They exist ONLY for cold-start / DB-down scenarios.
- When Tier 3 is used, it logs an ERROR so ops knows the DB path failed.
- Providers call get_prompt() / render_prompt() and trust the result.

Usage:
    from src.services.prompt_loader import get_prompt, render_prompt

    # Get raw prompt content by slug
    content = get_prompt("finding-triage")

    # Get and render with variables
    rendered = render_prompt("finding-triage", variables={
        "title": "SQL Injection in login.py",
        "description": "...",
        "severity": "high",
        "scanner": "semgrep"
    })
"""

import logging
import json
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy-loaded module-level database session factory
# ---------------------------------------------------------------------------
_SessionLocal = None
_session_init_attempted = False


def _get_db() -> Optional[Session]:
    """
    Get a database session. Works from any context (API, execution agents,
    CLI scripts) as long as DATABASE_URL is configured.
    """
    global _SessionLocal, _session_init_attempted
    if not _session_init_attempted:
        _session_init_attempted = True
        try:
            from src.api.database import SessionLocal
            _SessionLocal = SessionLocal
        except Exception as e:
            logger.warning(f"prompt_loader: Could not import SessionLocal: {e}")
            _SessionLocal = None

    if _SessionLocal:
        try:
            return _SessionLocal()
        except Exception as e:
            logger.error(f"prompt_loader: Failed to create DB session: {e}")
    return None


# ---------------------------------------------------------------------------
# Redis cache (Tier 1)
# ---------------------------------------------------------------------------
_redis = None


def _get_redis():
    global _redis
    if _redis is None:
        try:
            from src.auth.tokens import redis_client
            redis_client.ping()
            _redis = redis_client
        except Exception:
            _redis = False  # Mark as unavailable
    return _redis if _redis is not False else None


CACHE_PREFIX = "prompt:"
CACHE_TTL = 300  # 5 minutes


def _cache_key(slug: str) -> str:
    return f"{CACHE_PREFIX}{slug}"


def _get_from_cache(slug: str) -> Optional[Dict[str, Any]]:
    """Tier 1: Try Redis cache."""
    redis = _get_redis()
    if not redis:
        return None
    try:
        cached = redis.get(_cache_key(slug))
        if cached:
            return json.loads(cached)
    except Exception as e:
        logger.debug(f"Redis cache miss for prompt '{slug}': {e}")
    return None


def _set_cache(slug: str, data: Dict[str, Any]):
    """Cache prompt data in Redis."""
    redis = _get_redis()
    if not redis:
        return
    try:
        redis.setex(_cache_key(slug), CACHE_TTL, json.dumps(data))
    except Exception as e:
        logger.debug(f"Failed to cache prompt '{slug}': {e}")


def invalidate_cache(slug: str):
    """Remove a prompt from cache (called on update)."""
    redis = _get_redis()
    if not redis:
        return
    try:
        redis.delete(_cache_key(slug))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Database lookup (Tier 2 — authoritative)
# ---------------------------------------------------------------------------

def _get_from_db(slug: str, db: Session, version: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """Tier 2: Database lookup for active prompt and its current version content."""
    try:
        from src.api.prompt_models import Prompt, PromptVersion

        prompt = db.query(Prompt).filter(
            Prompt.slug == slug,
            Prompt.is_active == True
        ).first()

        if not prompt:
            return None

        target_version = version or prompt.current_version
        pv = db.query(PromptVersion).filter(
            PromptVersion.prompt_id == prompt.id,
            PromptVersion.version == target_version
        ).first()

        if not pv:
            return None

        data = {
            "slug": prompt.slug,
            "content": pv.content,
            "system_message": pv.system_message,
            "parameters": pv.parameters or {},
            "model": pv.model or prompt.model,
            "provider": prompt.provider,
            "input_schema": pv.input_schema,
            "output_schema": pv.output_schema,
            "version": pv.version,
            "category": prompt.category,
        }

        # Cache for next time
        _set_cache(slug, data)
        return data

    except Exception as e:
        logger.error(f"Database lookup failed for prompt '{slug}': {e}")
        return None


# ---------------------------------------------------------------------------
# Tier 3: Seed-derived fallbacks (loaded lazily from seed_prompts.py)
# ---------------------------------------------------------------------------
_FALLBACKS: Optional[Dict[str, Dict[str, Any]]] = None


def _load_fallbacks() -> Dict[str, Dict[str, Any]]:
    """
    Build fallback dict from the seed definitions in seed_prompts.py.
    This is the SAME data that gets inserted into the database on first setup.
    Single source of truth — no duplication.
    """
    global _FALLBACKS
    if _FALLBACKS is not None:
        return _FALLBACKS

    _FALLBACKS = {}
    try:
        from scripts.seed_prompts import PROMPT_SEEDS
        for seed in PROMPT_SEEDS:
            _FALLBACKS[seed["slug"]] = {
                "content": seed["content"],
                "system_message": seed.get("system_message"),
                "parameters": seed.get("parameters", {}),
                "model": seed.get("model"),
                "provider": seed.get("provider"),
            }
    except Exception as e:
        logger.warning(f"prompt_loader: Could not load seed fallbacks: {e}")

    return _FALLBACKS


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_prompt(
    slug: str,
    db: Optional[Session] = None,
    version: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """
    Resolve a prompt by slug using 3-tier fallback.

    The caller does NOT need to provide a db session — the loader creates
    its own if none is given. This ensures the database is ALWAYS consulted.

    Returns dict with: content, system_message, parameters, model, provider, etc.
    Returns None only if prompt not found in any tier.
    """
    # Tier 1: Redis (skip if requesting a specific version)
    if version is None:
        cached = _get_from_cache(slug)
        if cached:
            return cached

    # Tier 2: Database (always attempt — create our own session if needed)
    own_session = False
    if db is None:
        db = _get_db()
        own_session = True

    try:
        if db:
            result = _get_from_db(slug, db, version)
            if result:
                return result
    finally:
        if own_session and db:
            try:
                db.close()
            except Exception:
                pass

    # Tier 3: Seed-derived fallback (emergency only)
    fallbacks = _load_fallbacks()
    fallback = fallbacks.get(slug)
    if fallback:
        logger.error(
            f"PROMPT FALLBACK: Using seed-derived fallback for '{slug}'. "
            "Database is unreachable or prompt not seeded. "
            "Run `python scripts/seed_prompts.py` to populate the database."
        )
        return {
            "slug": slug,
            "content": fallback["content"],
            "system_message": fallback.get("system_message"),
            "parameters": fallback.get("parameters", {}),
            "model": fallback.get("model"),
            "provider": fallback.get("provider"),
            "version": 0,
            "category": "fallback",
        }

    logger.error(f"Prompt '{slug}' not found in any tier (cache/db/seed fallbacks)")
    return None


def render_prompt(
    slug: str,
    db: Optional[Session] = None,
    variables: Optional[Dict[str, Any]] = None,
    version: Optional[int] = None,
) -> Optional[str]:
    """
    Resolve and render a prompt template with variables.

    Uses Python str.format_map() for {variable} substitution.
    Returns the rendered content string, or None if prompt not found.
    """
    prompt_data = get_prompt(slug, db=db, version=version)
    if not prompt_data:
        return None

    content = prompt_data["content"]
    if variables:
        try:
            content = content.format_map(variables)
        except KeyError as e:
            logger.warning(f"Missing variable {e} in prompt '{slug}', leaving placeholder")

    return content


def get_prompt_with_system(
    slug: str,
    db: Optional[Session] = None,
    variables: Optional[Dict[str, Any]] = None,
    version: Optional[int] = None,
) -> Tuple[Optional[str], Optional[str], Dict[str, Any]]:
    """
    Resolve prompt and return (content, system_message, parameters) tuple.

    Convenience method for LLM provider calls that need all three.
    """
    prompt_data = get_prompt(slug, db=db, version=version)
    if not prompt_data:
        return None, None, {}

    content = prompt_data["content"]
    if variables:
        try:
            content = content.format_map(variables)
        except KeyError as e:
            logger.warning(f"Missing variable {e} in prompt '{slug}'")

    return content, prompt_data.get("system_message"), prompt_data.get("parameters", {})
