"""
Prompt Management System - Core Service

Handles CRUD operations, version management, usage tracking, search,
audit logging, and import/export for AI prompts.
"""

import logging
import difflib
from typing import List, Dict, Any, Optional, Tuple
from uuid import UUID
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_, or_, Integer

from src.api.prompt_models import (
    Prompt, PromptVersion, PromptUsage, PromptTag,
    PromptTestCase, PromptAuditLog
)

logger = logging.getLogger(__name__)


class PromptService:
    """Core service for prompt CRUD, versioning, and search."""

    def __init__(self, db: Session):
        self.db = db

    # =========================================================================
    # Prompt CRUD
    # =========================================================================

    def list_prompts(
        self,
        skip: int = 0,
        limit: int = 50,
        category: Optional[str] = None,
        agent_id: Optional[str] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        tag: Optional[str] = None,
        is_active: Optional[bool] = None,
        search: Optional[str] = None,
        sort_by: str = "updated_at",
        sort_dir: str = "desc",
    ) -> Tuple[List[Prompt], int]:
        """List prompts with filtering, search, and pagination."""
        query = self.db.query(Prompt)

        # Filters
        if category:
            query = query.filter(Prompt.category == category)
        if agent_id:
            query = query.filter(Prompt.agent_id == agent_id)
        if provider:
            query = query.filter(Prompt.provider == provider)
        if model:
            query = query.filter(Prompt.model == model)
        if is_active is not None:
            query = query.filter(Prompt.is_active == is_active)
        if tag:
            query = query.join(PromptTag).filter(PromptTag.tag == tag)
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                or_(
                    Prompt.name.ilike(search_pattern),
                    Prompt.slug.ilike(search_pattern),
                    Prompt.description.ilike(search_pattern),
                    Prompt.agent_id.ilike(search_pattern),
                )
            )

        total = query.count()

        # Sorting
        sort_column = getattr(Prompt, sort_by, Prompt.updated_at)
        if sort_dir == "asc":
            query = query.order_by(sort_column.asc())
        else:
            query = query.order_by(sort_column.desc())

        prompts = query.offset(skip).limit(limit).all()
        return prompts, total

    def get_prompt(self, slug: str) -> Optional[Prompt]:
        """Get a prompt by slug."""
        return self.db.query(Prompt).filter(Prompt.slug == slug).first()

    def get_prompt_by_id(self, prompt_id: UUID) -> Optional[Prompt]:
        """Get a prompt by UUID."""
        return self.db.query(Prompt).filter(Prompt.id == prompt_id).first()

    def create_prompt(self, data: Dict[str, Any], user_sub: str, user_email: str = None) -> Prompt:
        """Create a new prompt with initial version."""
        tags = data.pop("tags", [])
        content = data.pop("content")
        system_message = data.pop("system_message", None)
        parameters = data.pop("parameters", {})
        input_schema = data.pop("input_schema", None)
        output_schema = data.pop("output_schema", None)
        change_summary = data.pop("change_summary", "Initial version")

        # Create prompt record
        prompt = Prompt(
            slug=data["slug"],
            name=data["name"],
            description=data.get("description"),
            category=data["category"],
            subcategory=data.get("subcategory"),
            agent_id=data.get("agent_id"),
            provider=data.get("provider"),
            model=data.get("model"),
            current_version=1,
            is_active=True,
            created_by=user_sub,
            updated_by=user_sub,
        )
        self.db.add(prompt)
        self.db.flush()  # Get the ID

        # Create version 1
        version = PromptVersion(
            prompt_id=prompt.id,
            version=1,
            content=content,
            system_message=system_message,
            parameters=parameters,
            model=data.get("model"),
            input_schema=input_schema,
            output_schema=output_schema,
            change_summary=change_summary,
            created_by=user_sub,
        )
        self.db.add(version)

        # Create tags
        for tag_name in tags:
            self.db.add(PromptTag(prompt_id=prompt.id, tag=tag_name.lower().strip()))

        # Audit log
        self._audit(
            action="created",
            prompt=prompt,
            version=1,
            user_id=user_sub,
            user_email=user_email,
            new_value={"content": content, "system_message": system_message, "parameters": parameters},
        )

        self.db.commit()
        self.db.refresh(prompt)
        return prompt

    def update_prompt(self, slug: str, data: Dict[str, Any], user_sub: str, user_email: str = None) -> Prompt:
        """Update a prompt — creates a new version. Never overwrites existing versions."""
        prompt = self.get_prompt(slug)
        if not prompt:
            raise ValueError(f"Prompt not found: {slug}")
        if prompt.is_locked:
            raise PermissionError(f"Prompt is locked by {prompt.locked_by}: {prompt.locked_reason}")

        # Extract version-specific data
        content = data.pop("content")
        system_message = data.pop("system_message", None)
        parameters = data.pop("parameters", None)
        input_schema = data.pop("input_schema", None)
        output_schema = data.pop("output_schema", None)
        change_summary = data.pop("change_summary", "Updated")
        tags = data.pop("tags", None)

        # Get previous version for diff
        prev_version = self.get_version(prompt.id, prompt.current_version)
        old_content = prev_version.content if prev_version else ""

        # Increment version
        new_version_num = prompt.current_version + 1
        prompt.current_version = new_version_num
        prompt.updated_by = user_sub

        # Update prompt-level fields if provided
        for field in ("name", "description", "category", "subcategory", "agent_id", "provider", "model"):
            if field in data and data[field] is not None:
                setattr(prompt, field, data[field])

        # Create new immutable version
        version = PromptVersion(
            prompt_id=prompt.id,
            version=new_version_num,
            content=content,
            system_message=system_message,
            parameters=parameters if parameters is not None else (prev_version.parameters if prev_version else {}),
            model=data.get("model") or (prev_version.model if prev_version else None),
            input_schema=input_schema if input_schema is not None else (prev_version.input_schema if prev_version else None),
            output_schema=output_schema if output_schema is not None else (prev_version.output_schema if prev_version else None),
            change_summary=change_summary,
            created_by=user_sub,
        )
        self.db.add(version)

        # Update tags if provided
        if tags is not None:
            self.db.query(PromptTag).filter(PromptTag.prompt_id == prompt.id).delete()
            for tag_name in tags:
                self.db.add(PromptTag(prompt_id=prompt.id, tag=tag_name.lower().strip()))

        # Audit log
        self._audit(
            action="updated",
            prompt=prompt,
            version=new_version_num,
            user_id=user_sub,
            user_email=user_email,
            old_value={"content": old_content, "version": new_version_num - 1},
            new_value={"content": content, "version": new_version_num, "change_summary": change_summary},
        )

        self.db.commit()
        self.db.refresh(prompt)
        return prompt

    def delete_prompt(self, slug: str, user_sub: str, user_email: str = None) -> bool:
        """Soft-delete a prompt (set is_active=False)."""
        prompt = self.get_prompt(slug)
        if not prompt:
            return False

        prompt.is_active = False
        prompt.updated_by = user_sub

        self._audit(
            action="deactivated",
            prompt=prompt,
            user_id=user_sub,
            user_email=user_email,
        )

        self.db.commit()
        return True

    def activate_prompt(self, slug: str, user_sub: str, user_email: str = None) -> Optional[Prompt]:
        """Reactivate a soft-deleted prompt."""
        prompt = self.get_prompt(slug)
        if not prompt:
            return None

        prompt.is_active = True
        prompt.updated_by = user_sub

        self._audit(action="activated", prompt=prompt, user_id=user_sub, user_email=user_email)

        self.db.commit()
        self.db.refresh(prompt)
        return prompt

    def lock_prompt(self, slug: str, reason: str, user_sub: str, user_email: str = None) -> Optional[Prompt]:
        """Lock a prompt to prevent edits."""
        prompt = self.get_prompt(slug)
        if not prompt:
            return None

        prompt.is_locked = True
        prompt.locked_by = user_sub
        prompt.locked_reason = reason

        self._audit(
            action="locked",
            prompt=prompt,
            user_id=user_sub,
            user_email=user_email,
            new_value={"reason": reason},
        )

        self.db.commit()
        self.db.refresh(prompt)
        return prompt

    def unlock_prompt(self, slug: str, user_sub: str, user_email: str = None) -> Optional[Prompt]:
        """Unlock a prompt."""
        prompt = self.get_prompt(slug)
        if not prompt:
            return None

        prompt.is_locked = False
        prompt.locked_by = None
        prompt.locked_reason = None

        self._audit(action="unlocked", prompt=prompt, user_id=user_sub, user_email=user_email)

        self.db.commit()
        self.db.refresh(prompt)
        return prompt

    # =========================================================================
    # Version Management
    # =========================================================================

    def list_versions(self, prompt_id: UUID) -> List[PromptVersion]:
        """List all versions of a prompt, newest first."""
        return (
            self.db.query(PromptVersion)
            .filter(PromptVersion.prompt_id == prompt_id)
            .order_by(PromptVersion.version.desc())
            .all()
        )

    def get_version(self, prompt_id: UUID, version: int) -> Optional[PromptVersion]:
        """Get a specific version of a prompt."""
        return (
            self.db.query(PromptVersion)
            .filter(
                PromptVersion.prompt_id == prompt_id,
                PromptVersion.version == version,
            )
            .first()
        )

    def restore_version(
        self, slug: str, target_version: int, user_sub: str,
        user_email: str = None, change_summary: str = None
    ) -> Optional[Prompt]:
        """Restore a prompt to a previous version (creates a new version with old content)."""
        prompt = self.get_prompt(slug)
        if not prompt:
            return None

        old_version = self.get_version(prompt.id, target_version)
        if not old_version:
            raise ValueError(f"Version {target_version} not found for prompt {slug}")

        # Create a new version with the old content
        new_version_num = prompt.current_version + 1
        prompt.current_version = new_version_num
        prompt.updated_by = user_sub

        summary = change_summary or f"Restored from version {target_version}"
        version = PromptVersion(
            prompt_id=prompt.id,
            version=new_version_num,
            content=old_version.content,
            system_message=old_version.system_message,
            parameters=old_version.parameters,
            model=old_version.model,
            input_schema=old_version.input_schema,
            output_schema=old_version.output_schema,
            change_summary=summary,
            created_by=user_sub,
        )
        self.db.add(version)

        self._audit(
            action="restored",
            prompt=prompt,
            version=new_version_num,
            user_id=user_sub,
            user_email=user_email,
            old_value={"restored_from": target_version},
            new_value={"version": new_version_num, "change_summary": summary},
        )

        self.db.commit()
        self.db.refresh(prompt)
        return prompt

    def diff_versions(self, prompt_id: UUID, v1: int, v2: int) -> Dict[str, Any]:
        """Generate a unified diff between two versions."""
        version1 = self.get_version(prompt_id, v1)
        version2 = self.get_version(prompt_id, v2)

        if not version1 or not version2:
            raise ValueError(f"One or both versions not found: v{v1}, v{v2}")

        content_diff = "\n".join(
            difflib.unified_diff(
                (version1.content or "").splitlines(),
                (version2.content or "").splitlines(),
                fromfile=f"v{v1}",
                tofile=f"v{v2}",
                lineterm="",
            )
        )

        system_diff = "\n".join(
            difflib.unified_diff(
                (version1.system_message or "").splitlines(),
                (version2.system_message or "").splitlines(),
                fromfile=f"v{v1}",
                tofile=f"v{v2}",
                lineterm="",
            )
        )

        params_diff = None
        if version1.parameters != version2.parameters:
            params_diff = {"from": version1.parameters, "to": version2.parameters}

        model_changed = None
        if version1.model != version2.model:
            model_changed = {"old": version1.model, "new": version2.model}

        return {
            "content_diff": content_diff or None,
            "system_message_diff": system_diff or None,
            "parameters_diff": params_diff,
            "model_changed": model_changed,
        }

    # =========================================================================
    # Tags
    # =========================================================================

    def list_tags(self) -> List[Dict[str, Any]]:
        """List all tags with usage counts."""
        results = (
            self.db.query(PromptTag.tag, func.count(PromptTag.id).label("count"))
            .group_by(PromptTag.tag)
            .order_by(desc("count"))
            .all()
        )
        return [{"tag": r.tag, "count": r.count} for r in results]

    def get_tags_for_prompt(self, prompt_id: UUID) -> List[str]:
        """Get all tags for a prompt."""
        tags = self.db.query(PromptTag.tag).filter(PromptTag.prompt_id == prompt_id).all()
        return [t.tag for t in tags]

    def add_tag(self, prompt_id: UUID, tag: str) -> bool:
        """Add a tag to a prompt."""
        existing = (
            self.db.query(PromptTag)
            .filter(PromptTag.prompt_id == prompt_id, PromptTag.tag == tag)
            .first()
        )
        if existing:
            return False
        self.db.add(PromptTag(prompt_id=prompt_id, tag=tag.lower().strip()))
        self.db.commit()
        return True

    def remove_tag(self, prompt_id: UUID, tag: str) -> bool:
        """Remove a tag from a prompt."""
        deleted = (
            self.db.query(PromptTag)
            .filter(PromptTag.prompt_id == prompt_id, PromptTag.tag == tag)
            .delete()
        )
        self.db.commit()
        return deleted > 0

    # =========================================================================
    # Usage Tracking
    # =========================================================================

    def list_usages(self, prompt_id: UUID) -> List[PromptUsage]:
        """List all usage entries for a prompt."""
        return (
            self.db.query(PromptUsage)
            .filter(PromptUsage.prompt_id == prompt_id)
            .order_by(PromptUsage.is_primary.desc(), PromptUsage.call_count.desc())
            .all()
        )

    def register_usage(self, prompt_id: UUID, data: Dict[str, Any]) -> PromptUsage:
        """Register a new usage location for a prompt."""
        usage = PromptUsage(prompt_id=prompt_id, **data)
        self.db.add(usage)
        self.db.commit()
        self.db.refresh(usage)
        return usage

    def record_call(
        self,
        prompt_slug: str,
        provider: str,
        model: str,
        location: str,
        latency_ms: int,
        tokens_in: int,
        tokens_out: int,
        error: bool = False,
    ) -> None:
        """Record a runtime invocation of a prompt. Called by the usage tracking middleware."""
        prompt = self.get_prompt(prompt_slug)
        if not prompt:
            return

        # Find or create usage entry for this location
        usage = (
            self.db.query(PromptUsage)
            .filter(
                PromptUsage.prompt_id == prompt.id,
                PromptUsage.location == location,
                PromptUsage.usage_type == "runtime_call",
            )
            .first()
        )

        if not usage:
            usage = PromptUsage(
                prompt_id=prompt.id,
                usage_type="runtime_call",
                location=location,
                call_count=0,
                total_tokens=0,
                error_count=0,
            )
            self.db.add(usage)

        # Update metrics (running averages)
        old_count = usage.call_count or 0
        new_count = old_count + 1
        usage.call_count = new_count
        usage.last_called_at = datetime.now(timezone.utc)
        usage.total_tokens = (usage.total_tokens or 0) + tokens_in + tokens_out
        usage.last_model_used = model
        usage.last_provider_used = provider

        if old_count > 0 and usage.avg_latency_ms:
            usage.avg_latency_ms = int((usage.avg_latency_ms * old_count + latency_ms) / new_count)
            usage.avg_tokens_in = int(((usage.avg_tokens_in or 0) * old_count + tokens_in) / new_count)
            usage.avg_tokens_out = int(((usage.avg_tokens_out or 0) * old_count + tokens_out) / new_count)
        else:
            usage.avg_latency_ms = latency_ms
            usage.avg_tokens_in = tokens_in
            usage.avg_tokens_out = tokens_out

        if error:
            usage.error_count = (usage.error_count or 0) + 1

        self.db.commit()

    # =========================================================================
    # Test Cases
    # =========================================================================

    def list_test_cases(self, prompt_id: UUID) -> List[PromptTestCase]:
        """List saved test cases for a prompt."""
        return (
            self.db.query(PromptTestCase)
            .filter(PromptTestCase.prompt_id == prompt_id)
            .order_by(PromptTestCase.created_at.desc())
            .all()
        )

    def create_test_case(self, prompt_id: UUID, data: Dict[str, Any], user_sub: str) -> PromptTestCase:
        """Save a test case."""
        tc = PromptTestCase(prompt_id=prompt_id, created_by=user_sub, **data)
        self.db.add(tc)
        self.db.commit()
        self.db.refresh(tc)
        return tc

    # =========================================================================
    # Audit Log
    # =========================================================================

    def list_audit_log(
        self,
        prompt_id: Optional[UUID] = None,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[PromptAuditLog], int]:
        """List audit log entries with filters."""
        query = self.db.query(PromptAuditLog)

        if prompt_id:
            query = query.filter(PromptAuditLog.prompt_id == prompt_id)
        if user_id:
            query = query.filter(PromptAuditLog.user_id == user_id)
        if action:
            query = query.filter(PromptAuditLog.action == action)

        total = query.count()
        entries = query.order_by(PromptAuditLog.created_at.desc()).offset(skip).limit(limit).all()
        return entries, total

    def _audit(
        self,
        action: str,
        prompt: Prompt,
        version: int = None,
        user_id: str = None,
        user_email: str = None,
        old_value: Dict = None,
        new_value: Dict = None,
        ip_address: str = None,
        user_agent: str = None,
    ) -> None:
        """Append an entry to the immutable audit log."""
        entry = PromptAuditLog(
            action=action,
            prompt_id=prompt.id,
            prompt_slug=prompt.slug,
            version=version or prompt.current_version,
            user_id=user_id,
            user_email=user_email,
            old_value=old_value,
            new_value=new_value,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self.db.add(entry)

    # =========================================================================
    # Analytics
    # =========================================================================

    def get_analytics_overview(self) -> Dict[str, Any]:
        """Get system-wide prompt analytics."""
        total = self.db.query(func.count(Prompt.id)).scalar()
        active = self.db.query(func.count(Prompt.id)).filter(Prompt.is_active == True).scalar()
        total_versions = self.db.query(func.count(PromptVersion.id)).scalar()
        total_agents = (
            self.db.query(func.count(func.distinct(Prompt.agent_id)))
            .filter(Prompt.agent_id.isnot(None))
            .scalar()
        )

        # Usage stats
        usage_stats = self.db.query(
            func.coalesce(func.sum(PromptUsage.call_count), 0),
            func.coalesce(func.sum(PromptUsage.total_tokens), 0),
            func.coalesce(func.sum(PromptUsage.error_count), 0),
        ).first()
        total_calls = usage_stats[0]
        total_tokens = usage_stats[1]
        total_errors = usage_stats[2]
        error_rate = round((total_errors / total_calls * 100) if total_calls > 0 else 0, 2)

        # Versions today
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        versions_today = (
            self.db.query(func.count(PromptVersion.id))
            .filter(PromptVersion.created_at >= today_start)
            .scalar()
        )

        # Category breakdown
        categories = (
            self.db.query(Prompt.category, func.count(Prompt.id))
            .group_by(Prompt.category)
            .all()
        )
        category_breakdown = {r[0]: r[1] for r in categories}

        # Provider breakdown
        providers = (
            self.db.query(Prompt.provider, func.count(Prompt.id))
            .filter(Prompt.provider.isnot(None))
            .group_by(Prompt.provider)
            .all()
        )
        provider_breakdown = {r[0]: r[1] for r in providers}

        # Model breakdown
        models = (
            self.db.query(Prompt.model, func.count(Prompt.id))
            .filter(Prompt.model.isnot(None))
            .group_by(Prompt.model)
            .all()
        )
        model_breakdown = {r[0]: r[1] for r in models}

        return {
            "total_prompts": total,
            "active_prompts": active,
            "total_versions": total_versions,
            "total_agents": total_agents,
            "total_calls": total_calls,
            "total_tokens": total_tokens,
            "versions_today": versions_today,
            "error_rate": error_rate,
            "category_breakdown": category_breakdown,
            "provider_breakdown": provider_breakdown,
            "model_breakdown": model_breakdown,
        }

    def get_agent_summary(self, agent_id: str) -> Dict[str, Any]:
        """Get summary for a specific agent."""
        prompts = (
            self.db.query(Prompt)
            .filter(Prompt.agent_id == agent_id)
            .all()
        )
        active_count = sum(1 for p in prompts if p.is_active)

        prompt_ids = [p.id for p in prompts]
        total_calls = 0
        if prompt_ids:
            total_calls = (
                self.db.query(func.coalesce(func.sum(PromptUsage.call_count), 0))
                .filter(PromptUsage.prompt_id.in_(prompt_ids))
                .scalar()
            )

        return {
            "agent_id": agent_id,
            "prompt_count": len(prompts),
            "active_count": active_count,
            "total_calls": total_calls,
            "prompts": prompts,
        }

    def list_agents(self) -> List[Dict[str, Any]]:
        """List all agents with prompt counts."""
        results = (
            self.db.query(
                Prompt.agent_id,
                func.count(Prompt.id).label("prompt_count"),
                func.sum(func.cast(Prompt.is_active, Integer)).label("active_count"),
            )
            .filter(Prompt.agent_id.isnot(None))
            .group_by(Prompt.agent_id)
            .all()
        )

        agents = []
        for r in results:
            prompts = (
                self.db.query(Prompt)
                .filter(Prompt.agent_id == r.agent_id)
                .all()
            )
            ids = [p.id for p in prompts]
            total_calls = 0
            if ids:
                total_calls = (
                    self.db.query(func.coalesce(func.sum(PromptUsage.call_count), 0))
                    .filter(PromptUsage.prompt_id.in_(ids))
                    .scalar()
                )
            agents.append({
                "agent_id": r.agent_id,
                "prompt_count": r.prompt_count,
                "active_count": r.active_count or 0,
                "total_calls": total_calls,
                "_prompt_objs": prompts,
            })

        return agents

    # =========================================================================
    # Import/Export
    # =========================================================================

    def export_prompts(self, slugs: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Export prompts (all or by slug list) in portable format."""
        query = self.db.query(Prompt)
        if slugs:
            query = query.filter(Prompt.slug.in_(slugs))

        prompts = query.all()
        result = []
        for p in prompts:
            current = self.get_version(p.id, p.current_version)
            tags = self.get_tags_for_prompt(p.id)
            result.append({
                "slug": p.slug,
                "name": p.name,
                "description": p.description,
                "category": p.category,
                "subcategory": p.subcategory,
                "agent_id": p.agent_id,
                "provider": p.provider,
                "model": p.model,
                "content": current.content if current else "",
                "system_message": current.system_message if current else None,
                "parameters": current.parameters if current else {},
                "input_schema": current.input_schema if current else None,
                "output_schema": current.output_schema if current else None,
                "tags": tags,
            })
        return result

    def import_prompts(
        self, items: List[Dict[str, Any]], overwrite: bool, user_sub: str, user_email: str = None
    ) -> Dict[str, Any]:
        """Bulk import prompts."""
        created = 0
        updated = 0
        skipped = 0
        errors = []

        for item in items:
            try:
                existing = self.get_prompt(item["slug"])
                if existing:
                    if overwrite:
                        self.update_prompt(
                            slug=item["slug"],
                            data={
                                "content": item["content"],
                                "system_message": item.get("system_message"),
                                "parameters": item.get("parameters"),
                                "input_schema": item.get("input_schema"),
                                "output_schema": item.get("output_schema"),
                                "tags": item.get("tags"),
                                "change_summary": "Imported (overwrite)",
                                "name": item.get("name"),
                                "description": item.get("description"),
                                "category": item.get("category"),
                                "subcategory": item.get("subcategory"),
                                "agent_id": item.get("agent_id"),
                                "provider": item.get("provider"),
                                "model": item.get("model"),
                            },
                            user_sub=user_sub,
                            user_email=user_email,
                        )
                        updated += 1
                    else:
                        skipped += 1
                else:
                    self.create_prompt(data=item, user_sub=user_sub, user_email=user_email)
                    created += 1
            except Exception as e:
                errors.append(f"{item.get('slug', '?')}: {str(e)}")
                logger.error(f"Import error for {item.get('slug')}: {e}")

        return {"created": created, "updated": updated, "skipped": skipped, "errors": errors}

    # =========================================================================
    # Runtime Prompt Loading (for AI providers)
    # =========================================================================

    def get_active_prompt_content(self, slug: str) -> Optional[Dict[str, Any]]:
        """
        Load a prompt's current content for runtime use by AI providers.
        Returns None if prompt not found or inactive.
        """
        prompt = self.get_prompt(slug)
        if not prompt or not prompt.is_active:
            return None

        version = self.get_version(prompt.id, prompt.current_version)
        if not version:
            return None

        return {
            "slug": prompt.slug,
            "content": version.content,
            "system_message": version.system_message,
            "parameters": version.parameters or {},
            "model": version.model or prompt.model,
            "provider": prompt.provider,
            "input_schema": version.input_schema,
            "output_schema": version.output_schema,
        }
