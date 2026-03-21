#!/usr/bin/env python3
import argparse
import asyncio
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import shlex
import signal
import sys
import datetime
import fnmatch
import json
import logging
import logging.handlers
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import atexit
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any, DefaultDict, Set
from collections import defaultdict
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv
import toml
from functools import lru_cache

# Database imports (optional - for adding skipped repos)
try:
    from src.api.database import SessionLocal
    from src.api import models
    from src.knowledge_base import KnowledgeBase
    from sqlalchemy import func
    DATABASE_AVAILABLE = True
except ImportError as e:
    DATABASE_AVAILABLE = False
    logging.debug(f"Database not available: {e}")
    # Define KnowledgeBase as None if not available
    KnowledgeBase = None

# =============================================================================
# DOE Self-Annealing: AI Model Configuration
# =============================================================================
# Detects and corrects AI model misconfigurations at runtime

class AIModelSelfAnnealing:
    """
    DOE Self-Annealing for AI Model Configuration.
    
    Detects provider/model mismatches and auto-corrects them:
    - Claude provider with non-Claude model (e.g., llama3) -> corrects to claude-sonnet-4-20250514
    - OpenAI provider with non-OpenAI model -> corrects to gpt-4o
    - Ollama provider validation
    
    Logs all corrections for audit trail.
    """
    
    # Known model patterns per provider
    CLAUDE_MODELS = ["claude-3", "claude-sonnet", "claude-opus", "claude-haiku", "claude-instant"]
    OPENAI_MODELS = ["gpt-4", "gpt-3.5", "o1", "o3"]
    OLLAMA_MODELS = ["llama", "mistral", "codellama", "phi", "gemma", "qwen"]
    
    # Default models per provider
    DEFAULTS = {
        "claude": "claude-sonnet-4-20250514",
        "anthropic": "claude-sonnet-4-20250514",
        "anthropic_foundry": "claude-sonnet-4-20250514",
        "openai": "gpt-4o",
        "ollama": "llama3",
        "docker": "llama3"
    }
    
    def __init__(self):
        self.corrections_made = []
        self.logger = logging.getLogger("DOE.SelfAnnealing.AIModel")
    
    def detect_mismatch(self, provider: str, model: str) -> bool:
        """Detect if the model is incompatible with the provider."""
        provider_lower = provider.lower()
        model_lower = model.lower() if model else ""
        
        # Claude provider with non-Claude model
        if provider_lower in ["claude", "anthropic", "anthropic_foundry"]:
            if not any(cm in model_lower for cm in self.CLAUDE_MODELS):
                return True
        
        # OpenAI provider with non-OpenAI model
        elif provider_lower == "openai":
            if not any(om in model_lower for om in self.OPENAI_MODELS):
                return True
        
        # Ollama provider - more permissive, but check for obvious mismatches
        elif provider_lower in ["ollama", "docker"]:
            # Claude/OpenAI models won't work with Ollama
            if any(cm in model_lower for cm in self.CLAUDE_MODELS):
                return True
            if any(om in model_lower for om in self.OPENAI_MODELS):
                return True
        
        return False
    
    def correct_model(self, provider: str, model: str) -> str:
        """Auto-correct the model based on provider."""
        provider_lower = provider.lower()
        original_model = model
        
        # Get the correct default model for this provider
        corrected_model = self.DEFAULTS.get(provider_lower, model)
        
        # Log the correction
        correction = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "provider": provider,
            "original_model": original_model,
            "corrected_model": corrected_model,
            "reason": f"Model '{original_model}' incompatible with provider '{provider}'"
        }
        self.corrections_made.append(correction)
        
        self.logger.warning(
            f"DOE Self-Annealing: Corrected AI model mismatch - "
            f"Provider '{provider}' had model '{original_model}', "
            f"corrected to '{corrected_model}'"
        )
        
        return corrected_model
    
    def validate_and_correct(self, provider: str, model: str) -> str:
        """
        Validate provider/model combination and correct if needed.
        
        Returns the validated (possibly corrected) model name.
        """
        if self.detect_mismatch(provider, model):
            return self.correct_model(provider, model)
        return model
    
    def detect_from_error(self, error_message: str, provider: str, model: str) -> tuple:
        """
        Detect misconfiguration from API error response and suggest correction.
        
        Returns (should_retry, corrected_model)
        """
        error_lower = error_message.lower()
        
        # Claude API returning "model: llama3" error
        if "model:" in error_lower and provider.lower() in ["claude", "anthropic", "anthropic_foundry"]:
            # Extract the bad model from error
            if "llama" in error_lower or "gpt" in error_lower or "mistral" in error_lower:
                corrected = self.correct_model(provider, model)
                self.logger.info(f"DOE Self-Annealing: Detected API error, will retry with model '{corrected}'")
                return (True, corrected)
        
        # OpenAI API model not found
        if "model_not_found" in error_lower or "does not exist" in error_lower:
            if provider.lower() == "openai":
                corrected = self.correct_model(provider, model)
                return (True, corrected)
        
        return (False, model)
    
    def get_correction_report(self) -> list:
        """Return all corrections made during this session."""
        return self.corrections_made


# Global self-annealing instance
ai_model_annealing = AIModelSelfAnnealing()


# =============================================================================
# DOE Self-Annealing: Organization Filtering
# =============================================================================
# Detects and corrects organization context issues during scanning

class OrgFilteringSelfAnnealing:
    """
    DOE Self-Annealing for Organization Filtering in Scans.
    
    Detects and corrects organization context issues:
    - Repos being scanned without proper org context
    - Findings potentially going to wrong organization
    - Org/repo URL mismatches
    - Missing organization_id in scan operations
    
    Logs all corrections and anomalies for audit trail.
    """
    
    def __init__(self):
        self.corrections = []
        self.anomalies = []
        self.org_cache = {}  # Cache org lookups: repo_url -> org_id
        self.logger = logging.getLogger("DOE.SelfAnnealing.OrgFiltering")
        self._db_available = DATABASE_AVAILABLE
    
    def detect_org_mismatch(self, repo_url: str, expected_org: str) -> bool:
        """
        Detect if a repository URL belongs to a different organization than expected.
        
        Args:
            repo_url: Full GitHub repository URL
            expected_org: The organization name we expect the repo to belong to
            
        Returns:
            True if mismatch detected, False if OK
        """
        if not repo_url or not expected_org:
            return False
        
        # Extract org from URL: https://github.com/{org}/{repo}
        try:
            parts = repo_url.rstrip('/').split('/')
            if 'github.com' in repo_url and len(parts) >= 4:
                url_org = parts[-2]  # org is second to last
                if url_org.lower() != expected_org.lower():
                    self.logger.warning(
                        f"DOE Self-Annealing: Org mismatch detected - "
                        f"URL org '{url_org}' != expected org '{expected_org}'"
                    )
                    return True
        except Exception as e:
            self.logger.debug(f"Error parsing repo URL: {e}")
        
        return False
    
    def detect_missing_org_context(self, org_id: Optional[str], org_name: Optional[str]) -> bool:
        """
        Detect if organization context is missing when it should be set.
        
        Returns True if org context is missing/invalid.
        """
        if not org_id and not org_name:
            return True
        return False
    
    def resolve_org_from_repo(self, repo_url: str, repo_name: str = None) -> Optional[Dict[str, str]]:
        """
        Resolve organization context from repository URL or name.
        
        Returns dict with org_id, org_name, github_org or None if not found.
        """
        if not self._db_available:
            return None
        
        # Check cache first
        cache_key = repo_url or repo_name
        if cache_key in self.org_cache:
            return self.org_cache[cache_key]
        
        try:
            db = SessionLocal()
            
            # Try to find repo in database
            repo = None
            if repo_url:
                repo = db.query(models.Repository).filter(
                    models.Repository.url == repo_url
                ).first()
            
            if not repo and repo_name:
                repo = db.query(models.Repository).filter(
                    models.Repository.name == repo_name
                ).first()
            
            if repo and repo.organization_id:
                # Get org details
                org = db.query(models.Organization).filter(
                    models.Organization.id == repo.organization_id
                ).first()
                
                if org:
                    result = {
                        "org_id": str(org.id),
                        "org_name": org.name,
                        "github_org": org.github_org
                    }
                    self.org_cache[cache_key] = result
                    db.close()
                    return result
            
            # Try to extract org from URL and look up
            if repo_url and 'github.com' in repo_url:
                parts = repo_url.rstrip('/').split('/')
                if len(parts) >= 4:
                    github_org = parts[-2]
                    org = db.query(models.Organization).filter(
                        models.Organization.github_org == github_org
                    ).first()
                    
                    if org:
                        result = {
                            "org_id": str(org.id),
                            "org_name": org.name,
                            "github_org": org.github_org
                        }
                        self.org_cache[cache_key] = result
                        db.close()
                        return result
            
            db.close()
        except Exception as e:
            self.logger.debug(f"Error resolving org from repo: {e}")
        
        return None
    
    def correct_org_context(
        self, 
        current_org_id: Optional[str], 
        current_org_name: Optional[str],
        repo_url: str = None,
        repo_name: str = None
    ) -> Dict[str, Optional[str]]:
        """
        Auto-correct organization context based on repository information.
        
        Returns corrected org_id and org_name.
        """
        # If we have valid context, verify it
        if current_org_id and current_org_name:
            # Check for mismatch with repo URL
            if repo_url and self.detect_org_mismatch(repo_url, current_org_name):
                # Try to resolve correct org
                resolved = self.resolve_org_from_repo(repo_url, repo_name)
                if resolved:
                    correction = {
                        "timestamp": datetime.datetime.utcnow().isoformat(),
                        "type": "org_mismatch",
                        "repo_url": repo_url,
                        "original_org": current_org_name,
                        "corrected_org": resolved["org_name"],
                        "reason": f"Repo URL indicates org '{resolved['github_org']}', not '{current_org_name}'"
                    }
                    self.corrections.append(correction)
                    self.logger.warning(
                        f"DOE Self-Annealing: Corrected org context from '{current_org_name}' "
                        f"to '{resolved['org_name']}' based on repo URL"
                    )
                    return {"org_id": resolved["org_id"], "org_name": resolved["org_name"]}
            
            # Context looks valid
            return {"org_id": current_org_id, "org_name": current_org_name}
        
        # Missing context - try to resolve from repo
        resolved = self.resolve_org_from_repo(repo_url, repo_name)
        if resolved:
            correction = {
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "type": "missing_org_context",
                "repo_url": repo_url,
                "repo_name": repo_name,
                "resolved_org": resolved["org_name"],
                "reason": "Organization context was missing, resolved from repository"
            }
            self.corrections.append(correction)
            self.logger.warning(
                f"DOE Self-Annealing: Resolved missing org context to '{resolved['org_name']}' "
                f"from repo '{repo_name or repo_url}'"
            )
            return {"org_id": resolved["org_id"], "org_name": resolved["org_name"]}
        
        # Could not resolve - log anomaly
        anomaly = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "type": "unresolved_org",
            "repo_url": repo_url,
            "repo_name": repo_name,
            "reason": "Could not resolve organization context"
        }
        self.anomalies.append(anomaly)
        self.logger.warning(
            f"DOE Self-Annealing: Could not resolve org context for '{repo_name or repo_url}'"
        )
        
        return {"org_id": None, "org_name": None}
    
    def validate_finding_org(
        self,
        finding_data: Dict[str, Any],
        expected_org_id: str,
        repo_url: str = None
    ) -> Dict[str, Any]:
        """
        Validate and correct organization_id for a finding before database insert.
        
        Returns finding_data with corrected organization_id if needed.
        """
        current_org_id = finding_data.get("organization_id")
        
        # If finding has no org_id, set it
        if not current_org_id and expected_org_id:
            finding_data["organization_id"] = expected_org_id
            self.logger.debug(f"DOE Self-Annealing: Set missing org_id on finding")
            return finding_data
        
        # If finding has different org_id than expected, investigate
        if current_org_id and expected_org_id and str(current_org_id) != str(expected_org_id):
            # This could be a cross-org finding - verify via repo
            if repo_url:
                resolved = self.resolve_org_from_repo(repo_url)
                if resolved:
                    correct_org_id = resolved["org_id"]
                    if str(correct_org_id) != str(current_org_id):
                        correction = {
                            "timestamp": datetime.datetime.utcnow().isoformat(),
                            "type": "finding_org_mismatch",
                            "finding_title": finding_data.get("title", "Unknown")[:50],
                            "original_org_id": current_org_id,
                            "corrected_org_id": correct_org_id,
                            "reason": "Finding org_id didn't match repo's organization"
                        }
                        self.corrections.append(correction)
                        finding_data["organization_id"] = correct_org_id
                        self.logger.warning(
                            f"DOE Self-Annealing: Corrected finding org_id from "
                            f"'{current_org_id}' to '{correct_org_id}'"
                        )
        
        return finding_data
    
    def validate_scan_context(
        self,
        target_org: str,
        github_org: str,
        org_id: str = None
    ) -> Dict[str, Any]:
        """
        Validate scan context before starting a scan.
        
        Ensures target org, GitHub org, and org_id are consistent.
        Returns validated context with any corrections.
        """
        result = {
            "target_org": target_org,
            "github_org": github_org,
            "org_id": org_id,
            "valid": True,
            "corrections": []
        }
        
        # Check if target and github_org match
        if target_org and github_org and target_org.lower() != github_org.lower():
            self.logger.warning(
                f"DOE Self-Annealing: Target org '{target_org}' differs from "
                f"GitHub org '{github_org}' - using target_org"
            )
            result["corrections"].append({
                "field": "github_org",
                "original": github_org,
                "corrected": target_org,
                "reason": "Target org takes precedence"
            })
            result["github_org"] = target_org
        
        # Try to resolve org_id if missing
        if not org_id and self._db_available:
            try:
                db = SessionLocal()
                org = db.query(models.Organization).filter(
                    models.Organization.github_org == (target_org or github_org)
                ).first()
                
                if org:
                    result["org_id"] = str(org.id)
                    result["corrections"].append({
                        "field": "org_id",
                        "original": None,
                        "corrected": str(org.id),
                        "reason": "Resolved org_id from database"
                    })
                    self.logger.info(
                        f"DOE Self-Annealing: Resolved org_id '{org.id}' for '{target_org or github_org}'"
                    )
                db.close()
            except Exception as e:
                self.logger.debug(f"Error resolving org_id: {e}")
        
        # Verify org_id matches the target org
        if org_id and target_org and self._db_available:
            try:
                db = SessionLocal()
                org = db.query(models.Organization).filter(
                    models.Organization.id == org_id
                ).first()
                
                if org and org.github_org.lower() != target_org.lower():
                    # Mismatch - find correct org
                    correct_org = db.query(models.Organization).filter(
                        models.Organization.github_org == target_org
                    ).first()
                    
                    if correct_org:
                        result["org_id"] = str(correct_org.id)
                        result["corrections"].append({
                            "field": "org_id",
                            "original": org_id,
                            "corrected": str(correct_org.id),
                            "reason": f"org_id was for '{org.github_org}', corrected to '{target_org}'"
                        })
                        self.logger.warning(
                            f"DOE Self-Annealing: Corrected org_id from '{org_id}' "
                            f"('{org.github_org}') to '{correct_org.id}' ('{target_org}')"
                        )
                db.close()
            except Exception as e:
                self.logger.debug(f"Error verifying org_id: {e}")
        
        if result["corrections"]:
            self.corrections.extend(result["corrections"])
        
        return result
    
    def get_correction_report(self) -> Dict[str, Any]:
        """Return all corrections and anomalies from this session."""
        return {
            "corrections": self.corrections,
            "anomalies": self.anomalies,
            "total_corrections": len(self.corrections),
            "total_anomalies": len(self.anomalies)
        }
    
    def log_summary(self):
        """Log a summary of all corrections made."""
        if self.corrections or self.anomalies:
            self.logger.info(
                f"DOE Self-Annealing Summary: {len(self.corrections)} corrections, "
                f"{len(self.anomalies)} anomalies"
            )
            for c in self.corrections:
                self.logger.info(f"  Correction: {c.get('type', 'unknown')} - {c.get('reason', '')}")
            for a in self.anomalies:
                self.logger.warning(f"  Anomaly: {a.get('type', 'unknown')} - {a.get('reason', '')}")


# Global self-annealing instance for org filtering
org_filtering_annealing = OrgFilteringSelfAnnealing()


# =============================================================================
# DOE Self-Annealing: Scanner Health (Safety + general scanner resilience)
# =============================================================================

class ScannerSelfAnnealing:
    """
    DOE Self-Annealing for scanner execution.

    Tracks scanner failures per-repo and per-scanner, detects common failure
    modes (timeouts, auth errors, network issues, missing binaries), and
    auto-corrects by:
      - Adjusting timeouts based on observed execution times
      - Falling back to alternative commands when the primary fails
      - Skipping persistently broken scanners for a cooldown period
      - Logging all corrections for audit trail
    """

    # Known failure signatures and their remediation strategies
    FAILURE_SIGNATURES = {
        "timeout": {
            "patterns": ["timed out", "timeout", "deadline exceeded", "killed"],
            "action": "increase_timeout",
        },
        "auth": {
            "patterns": ["401", "403", "authentication", "unauthorized", "api key", "invalid key"],
            "action": "skip_scanner",
        },
        "network": {
            "patterns": ["connection refused", "connection reset", "dns", "network unreachable", "ssl"],
            "action": "retry_with_backoff",
        },
        "not_found": {
            "patterns": ["not found", "no such file", "command not found", "not recognized"],
            "action": "skip_scanner",
        },
        "rate_limit": {
            "patterns": ["rate limit", "429", "too many requests", "quota exceeded"],
            "action": "retry_with_backoff",
        },
    }

    # Safety-specific fallback commands
    SAFETY_FALLBACKS = [
        # Primary: safety scan (v3 CLI)
        {
            "cmd": ["safety", "scan", "--file", "{requirements}", "--output", "json",
                     "--ignore-unpinned-requirements", "--continue-on-error", "--disable-optional-output"],
            "label": "safety scan (v3)",
        },
        # Fallback 1: safety check (v2 CLI)
        {
            "cmd": ["safety", "check", "--file", "{requirements}", "--json"],
            "label": "safety check (v2)",
        },
        # Fallback 2: pip-audit as substitute
        {
            "cmd": ["pip-audit", "-r", "{requirements}", "--format", "json"],
            "label": "pip-audit (fallback)",
        },
    ]

    DEFAULT_TIMEOUT = 120  # seconds — hard cap, no escalation
    MAX_TIMEOUT = 120      # same as default: fail fast after 2 minutes
    MIN_TIMEOUT = 30
    COOLDOWN_MINUTES = 60  # Skip broken scanners for this long
    MAX_TIMEOUT_RETRIES = 1  # Only retry a timeout once before moving to fallback

    def __init__(self):
        self.logger = logging.getLogger("DOE.SelfAnnealing.Scanner")
        self.corrections = []
        # scanner_name -> {failures: int, last_failure: datetime, timeout: int, skip_until: datetime, fallback_idx: int}
        self.scanner_state = {}

    def _get_state(self, scanner_name: str) -> dict:
        if scanner_name not in self.scanner_state:
            self.scanner_state[scanner_name] = {
                "failures": 0,
                "last_failure": None,
                "timeout": self.DEFAULT_TIMEOUT,
                "skip_until": None,
                "fallback_idx": 0,
                "total_runs": 0,
                "total_successes": 0,
            }
        return self.scanner_state[scanner_name]

    def classify_failure(self, stderr: str, returncode: int) -> str:
        """Classify a scanner failure by matching error output against known signatures."""
        stderr_lower = (stderr or "").lower()

        if returncode == -9 or returncode == 137:  # SIGKILL (timeout)
            return "timeout"

        for failure_type, info in self.FAILURE_SIGNATURES.items():
            if any(p in stderr_lower for p in info["patterns"]):
                return failure_type

        return "unknown"

    def record_success(self, scanner_name: str):
        """Record a successful scanner execution."""
        state = self._get_state(scanner_name)
        state["failures"] = 0
        state["total_runs"] += 1
        state["total_successes"] += 1
        state["fallback_idx"] = 0  # Reset to primary command on success

    def record_failure(self, scanner_name: str, stderr: str, returncode: int, repo_name: str = "") -> dict:
        """
        Record a scanner failure and determine the corrective action.

        Returns dict with keys: action, detail, should_retry
        """
        state = self._get_state(scanner_name)
        state["failures"] += 1
        state["total_runs"] += 1
        state["last_failure"] = datetime.datetime.utcnow()

        failure_type = self.classify_failure(stderr, returncode)
        action = self.FAILURE_SIGNATURES.get(failure_type, {}).get("action", "log_only")

        correction = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "scanner": scanner_name,
            "repo": repo_name,
            "failure_type": failure_type,
            "returncode": returncode,
            "action": action,
            "consecutive_failures": state["failures"],
        }

        result = {"action": action, "detail": "", "should_retry": False}

        if action == "increase_timeout":
            timeout_failures = sum(1 for c in self.corrections if c.get("scanner") == scanner_name and c.get("failure_type") == "timeout")
            if timeout_failures <= self.MAX_TIMEOUT_RETRIES:
                old_timeout = state["timeout"]
                state["timeout"] = min(int(old_timeout * 1.5), self.MAX_TIMEOUT)
                correction["old_timeout"] = old_timeout
                correction["new_timeout"] = state["timeout"]
                result["detail"] = f"Timeout {old_timeout}s -> {state['timeout']}s (retry {timeout_failures}/{self.MAX_TIMEOUT_RETRIES})"
                result["should_retry"] = True
                print(f"[auditgh]   ⟳ {scanner_name}: {result['detail']}", flush=True)
            else:
                result["detail"] = f"Timed out {timeout_failures} times, marking incomplete"
                result["should_retry"] = False
                print(f"[auditgh]   ✗ {scanner_name}: {result['detail']}", flush=True)

        elif action == "retry_with_backoff":
            if state["failures"] <= 3:
                backoff = 2 ** state["failures"]
                result["detail"] = f"Retrying in {backoff}s (attempt {state['failures']}/3)"
                result["should_retry"] = True
                print(f"[auditgh]   ⟳ {scanner_name}: {result['detail']}", flush=True)
            else:
                state["skip_until"] = datetime.datetime.utcnow() + datetime.timedelta(minutes=self.COOLDOWN_MINUTES)
                result["detail"] = f"Too many failures, cooling down for {self.COOLDOWN_MINUTES}m"
                print(f"[auditgh]   ✗ {scanner_name}: {result['detail']}", flush=True)

        elif action == "skip_scanner":
            state["skip_until"] = datetime.datetime.utcnow() + datetime.timedelta(minutes=self.COOLDOWN_MINUTES)
            result["detail"] = f"Scanner disabled for {self.COOLDOWN_MINUTES}m ({failure_type})"
            print(f"[auditgh]   ✗ {scanner_name}: {result['detail']}", flush=True)

        else:
            if state["failures"] >= 3:
                state["skip_until"] = datetime.datetime.utcnow() + datetime.timedelta(minutes=self.COOLDOWN_MINUTES)
                result["detail"] = f"Unknown failure x{state['failures']}, cooling down"
                print(f"[auditgh]   ✗ {scanner_name}: {result['detail']}", flush=True)

        correction["result"] = result["detail"]
        self.corrections.append(correction)
        self.logger.warning(f"DOE Self-Annealing [{scanner_name}]: {failure_type} -> {result['detail']}")

        return result

    def should_skip(self, scanner_name: str) -> tuple:
        """Check if a scanner should be skipped due to cooldown."""
        state = self._get_state(scanner_name)
        if state["skip_until"]:
            now = datetime.datetime.utcnow()
            if now < state["skip_until"]:
                remaining = (state["skip_until"] - now).total_seconds() / 60
                return True, f"Cooling down ({remaining:.0f}m remaining, {state['failures']} failures)"
            else:
                # Cooldown expired, reset
                state["skip_until"] = None
                state["failures"] = 0
                self.logger.info(f"DOE Self-Annealing [{scanner_name}]: Cooldown expired, re-enabling")
        return False, ""

    def get_timeout(self, scanner_name: str) -> int:
        """Get the current (possibly adjusted) timeout for a scanner."""
        return self._get_state(scanner_name)["timeout"]

    def get_safety_fallback(self) -> dict:
        """Get the current Safety command to try (primary or fallback)."""
        state = self._get_state("safety")
        idx = min(state["fallback_idx"], len(self.SAFETY_FALLBACKS) - 1)
        return self.SAFETY_FALLBACKS[idx]

    def advance_safety_fallback(self) -> bool:
        """Move to the next Safety fallback command. Returns False if exhausted."""
        state = self._get_state("safety")
        state["fallback_idx"] += 1
        if state["fallback_idx"] >= len(self.SAFETY_FALLBACKS):
            return False
        fb = self.SAFETY_FALLBACKS[state["fallback_idx"]]
        print(f"[auditgh]   ⟳ safety: Falling back to {fb['label']}", flush=True)
        self.logger.info(f"DOE Self-Annealing [safety]: Falling back to {fb['label']}")
        return True

    def get_health_report(self) -> dict:
        """Return health summary for all tracked scanners."""
        report = {}
        for name, state in self.scanner_state.items():
            total = state["total_runs"]
            success_rate = (state["total_successes"] / total * 100) if total > 0 else 0
            report[name] = {
                "total_runs": total,
                "success_rate": f"{success_rate:.0f}%",
                "current_timeout": state["timeout"],
                "consecutive_failures": state["failures"],
                "status": "cooling_down" if state["skip_until"] and datetime.datetime.utcnow() < state["skip_until"] else "active",
            }
        return report


# Global scanner self-annealing instance
scanner_annealing = ScannerSelfAnnealing()


# AI Agent imports (optional - only loaded if enabled)
try:
    from src.ai_agent.providers import OpenAIProvider, ClaudeProvider
    from src.ai_agent.diagnostics import DiagnosticCollector
    from src.ai_agent.reasoning import ReasoningEngine
    from src.ai_agent.remediation import RemediationEngine
    from src.ai_agent.learning import LearningSystem
    AI_AGENT_AVAILABLE = True
except ImportError as e:
    AI_AGENT_AVAILABLE = False
    logging.debug(f"AI agent not available: {e}")

# API Audit Scanner (optional)
try:
    from execution.scan_api import run_api_audit
    API_AUDIT_AVAILABLE = True
except ImportError as e:
    API_AUDIT_AVAILABLE = False
    logging.debug(f"API audit scanner not available: {e}")

# Progress monitoring (optional - requires psutil)
try:
    from src.progress_monitor import ProgressMonitor
    from src.progress_helpers import register_process, unregister_process, get_process_info
    from src.progress_wrapper import run_with_progress_monitoring
    from src.repo_intel import analyze_repo  # Import Repo Intelligence
    from src.knowledge_base import KnowledgeBase # Import Knowledge Base
    import psutil
    PROGRESS_MONITOR_AVAILABLE = True
except ImportError as e:
    PROGRESS_MONITOR_AVAILABLE = False
    logging.debug(f"Progress monitoring not available: {e}")

# Safe repo name and subprocess handling
try:
    from src.repo_name_handler import RepoNameHandler, NameRisk
    from src.safe_subprocess import run_safe, run_with_timeout, SubprocessTimeout
    SAFE_SUBPROCESS_AVAILABLE = True
except ImportError as e:
    SAFE_SUBPROCESS_AVAILABLE = False
    logging.debug(f"Safe subprocess module not available: {e}")

# Load environment variables from .env file
load_dotenv()

# Global shutdown event for graceful termination
shutdown_event = threading.Event()
shutdown_requested = False

# Global tracking for stuck repositories
stuck_repos_log = []

# Global AI agent components (initialized in main if enabled)
ai_provider = None
reasoning_engine = None
remediation_engine = None
learning_system = None


class Config:
    """Global configuration for the script."""
    def __init__(self):
        self.GITHUB_API = os.getenv("GITHUB_API", "https://api.github.com")
        self.ORG_NAME = os.getenv("GITHUB_ORG", "sleepnumberinc")
        self.GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        self.REPORT_DIR = os.getenv("REPORT_DIR", "vulnerability_reports")
        self.CLONE_DIR = None
        self.HEADERS = {}
        # Optional Docker image target for SBOMs (Syft)
        self.DOCKER_IMAGE = None
        # Syft optional integration
        self.SYFT_FORMAT = os.getenv("SYFT_FORMAT", "cyclonedx-json")
        # Grype VEX support (list of files)
        self.VEX_FILES: List[str] = []
        # Optional Semgrep taint-mode config path (ruleset)
        self.SEMGREP_TAINT_CONFIG: Optional[str] = None
        # Optional policy file for gating
        self.POLICY_PATH: Optional[str] = None
        
        # Multi-tenant: Organization ID for database scoping
        self.ORGANIZATION_ID: Optional[str] = None  # UUID string of selected organization
        self.ORGANIZATION_NAME: Optional[str] = None  # Name of selected organization
        
        # AI Agent Configuration
        self.ENABLE_AI = os.getenv("ENABLE_AI", "false").lower() == "true"
        self.OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
        self.ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
        self.AI_PROVIDER = os.getenv("AI_PROVIDER", "openai")
        
        # Select model based on provider to avoid using wrong model (e.g., llama3 with Claude)
        provider = self.AI_PROVIDER.lower()
        if provider in ["claude", "anthropic", "anthropic_foundry"]:
            raw_model = os.getenv("ANTHROPIC_MODEL") or os.getenv("AI_MODEL") or "claude-sonnet-4-20250514"
        elif provider == "openai":
            raw_model = os.getenv("OPENAI_MODEL") or os.getenv("AI_MODEL") or "gpt-4o"
        elif provider in ["ollama", "docker"]:
            raw_model = os.getenv("AI_MODEL") or "llama3"
        else:
            raw_model = os.getenv("AI_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-4o"
        
        # DOE Self-Annealing: Validate and correct model configuration at startup
        self.AI_MODEL = ai_model_annealing.validate_and_correct(self.AI_PROVIDER, raw_model)
        
        # AI Failover Configuration
        self.AI_FAILOVER_ENABLED = os.getenv("AI_FAILOVER_ENABLED", "false").lower() == "true"
        self.AI_FAILOVER_MODEL = os.getenv("AI_FAILOVER_MODEL", "ai/qwen3")

        
        # Cleanup configuration
        self.KEEP_CLONES = os.getenv("KEEP_CLONES", "false").lower() == "true"
        
        # Set up headers if token is available
        if self.GITHUB_TOKEN:
            self.HEADERS = {
                "Authorization": f"Bearer {self.GITHUB_TOKEN}",
                "Accept": "application/vnd.github.v3+json"
            }

# Create a global config instance
config = Config()

def setup_temp_dir() -> str:
    """
    Create and return a temporary directory for repository cloning.
    
    Returns:
        str: Path to the created temporary directory
    """
    try:
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp(prefix="repo_scan_")
        
        # Ensure the directory exists
        os.makedirs(temp_dir, exist_ok=True)
        
        # Set permissions to ensure the directory is accessible
        os.chmod(temp_dir, 0o755)
        
        # Update the global config with the new temp directory
        config.CLONE_DIR = temp_dir
        
        return temp_dir
        
    except Exception as e:
        error_msg = f"Failed to create temporary directory: {e}"
        logging.error(error_msg)
        # Set CLONE_DIR to None to prevent further operations on invalid directory
        config.CLONE_DIR = None
        raise RuntimeError(error_msg)
        raise

def configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )

def make_session():
    """Create and configure a requests session with retry logic and GitHub authentication."""
    session = requests.Session()
    
    # Configure retry strategy
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    
    # Add headers from config
    if hasattr(config, 'HEADERS') and config.HEADERS:
        session.headers.update(config.HEADERS)
    
    return session


def validate_github_token(token: str) -> tuple[bool, str, list[str]]:
    """
    Validate a GitHub token by making a test API call.
    
    Returns:
        tuple: (is_valid, username_or_error, scopes)
            - is_valid: True if token is valid
            - username_or_error: GitHub username if valid, error message if not
            - scopes: List of OAuth scopes the token has
    """
    try:
        response = requests.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"
            },
            timeout=10
        )
        
        if response.status_code == 200:
            user_data = response.json()
            username = user_data.get("login", "unknown")
            scopes = response.headers.get("X-OAuth-Scopes", "").split(", ")
            scopes = [s.strip() for s in scopes if s.strip()]
            return True, username, scopes
        elif response.status_code == 401:
            return False, "Bad credentials - token is invalid or expired", []
        elif response.status_code == 403:
            # Check for rate limiting vs permission issues
            if "rate limit" in response.text.lower():
                return False, "Rate limit exceeded", []
            return False, "Access forbidden - token may lack required permissions", []
        else:
            return False, f"Unexpected response: {response.status_code}", []
    except requests.exceptions.Timeout:
        return False, "Connection timeout while validating token", []
    except requests.exceptions.RequestException as e:
        return False, f"Network error: {str(e)}", []


# -------------------- Helper Functions --------------------

def get_rate_limit_headers(response: requests.Response) -> dict:
    """Extract rate limit headers from response."""
    return {
        'limit': int(response.headers.get('X-RateLimit-Limit', 0)),
        'remaining': int(response.headers.get('X-RateLimit-Remaining', 0)),
        'reset': int(response.headers.get('X-RateLimit-Reset', 0)),
    }

def get_all_repos(session: requests.Session, include_forks: bool = False, include_archived: bool = False, timeout: int = 30) -> list:
    """
    Fetch all repositories from the organization with pagination and rate limit handling.
    
    Args:
        session: The requests session to use for API calls
        include_forks: Whether to include forked repositories
        include_archived: Whether to include archived repositories
        timeout: Request timeout in seconds
        
    Returns:
        List of repository objects
    """
    if not all([config.GITHUB_API, config.ORG_NAME, config.HEADERS]):
        logging.error("Missing required configuration for get_all_repos")
        return []
    
    logging.info(f"Fetching repositories for organization: {config.ORG_NAME}")
    
    repos = []
    page = 1
    per_page = 100  # Maximum allowed by GitHub API
    max_retries = 3
    retry_delay = 5  # seconds
    # Default to organization endpoint, but fall back to user endpoint on 404
    api_path = f"/orgs/{config.ORG_NAME}/repos"
    tried_user_fallback = False
    
    while True:
        retry_count = 0
        while retry_count < max_retries:
            try:
                # Build the API URL with parameters
                url = f"{config.GITHUB_API}{api_path}"
                params = {
                    'per_page': per_page,
                    'page': page,
                    'type': 'all',  # Get all repository types
                    'sort': 'full_name',
                    'direction': 'asc'
                }
                
                logging.debug(f"Fetching repos page {page}...")
                response = session.get(
                    url,
                    headers=config.HEADERS,
                    params=params,
                    timeout=timeout
                )
                
                # Check rate limits
                check_rate_limits(response)
                
                # Handle rate limiting (HTTP 403)
                if response.status_code == 403:
                    handle_rate_limit(response)
                    continue  # Retry the same request after rate limit resets
                
                # Handle 404 for orgs by falling back to user endpoint once
                if response.status_code == 404 and not tried_user_fallback and api_path.startswith("/orgs/"):
                    logging.info(f"Organization '{config.ORG_NAME}' not found or inaccessible. Retrying as a user account...")
                    api_path = f"/users/{config.ORG_NAME}/repos"
                    tried_user_fallback = True
                    # Reset retries and keep page at 1 for user listing
                    retry_count = 0
                    page = 1
                    time.sleep(1)
                    continue
                
                # Handle other HTTP errors
                response.raise_for_status()
                
                # Process the successful response
                page_repos = response.json()
                if not page_repos:
                    logging.debug("No more repositories found")
                    return repos
                
                # Process repositories from this page
                process_repositories(page_repos, repos, include_forks, include_archived)
                
                # Check if we've reached the last page
                if len(page_repos) < per_page:
                    logging.debug("Reached the last page of repositories")
                    return repos
                
                # Move to the next page
                page += 1
                break  # Success, exit retry loop
                
            except requests.exceptions.HTTPError as http_err:
                # If we already tried user fallback and still got 404, stop early
                if http_err.response is not None and http_err.response.status_code == 404 and tried_user_fallback:
                    logging.error(f"Account '{config.ORG_NAME}' not found as organization or user at {url}")
                    return repos
                retry_count += 1
                if retry_count >= max_retries:
                    logging.error(f"Failed to fetch repositories after {max_retries} attempts: {str(http_err)}")
                    if hasattr(http_err, 'response') and http_err.response is not None:
                        logging.error(f"Response: {http_err.response.status_code} - {http_err.response.text}")
                    return repos
                wait_time = retry_delay * (2 ** (retry_count - 1))
                logging.warning(f"Request failed (attempt {retry_count}/{max_retries}). Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            except requests.exceptions.RequestException as e:
                retry_count += 1
                if retry_count >= max_retries:
                    logging.error(f"Failed to fetch repositories after {max_retries} attempts: {str(e)}")
                    if hasattr(e, 'response') and e.response is not None:
                        logging.error(f"Response: {e.response.status_code} - {e.response.text}")
                    return repos
                
                wait_time = retry_delay * (2 ** (retry_count - 1))  # Exponential backoff
                logging.warning(f"Request failed (attempt {retry_count}/{max_retries}). Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
    
    return repos

def get_single_repo(session: requests.Session, repo_identifier: str, timeout: int = 30) -> Optional[dict]:
    """Fetch a single repository by name or owner/name.
    
    repo_identifier can be one of:
    - "repo" (resolved against config.ORG_NAME as owner)
    - "owner/repo" (explicit owner)
    """
    try:
        if "/" in repo_identifier:
            owner, name = repo_identifier.split("/", 1)
        else:
            owner, name = config.ORG_NAME, repo_identifier
        url = f"{config.GITHUB_API}/repos/{owner}/{name}"
        logging.info(f"Fetching repository: {owner}/{name}")
        resp = session.get(url, headers=config.HEADERS, timeout=timeout)
        if resp.status_code == 404:
            logging.error(f"Repository not found or inaccessible: {owner}/{name}")
            return None
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch repository {repo_identifier}: {e}")
        return None

def check_rate_limits(response: requests.Response) -> None:
    """Check and log rate limit information from response headers."""
    if 'X-RateLimit-Remaining' in response.headers:
        remaining = int(response.headers['X-RateLimit-Remaining'])
        limit = int(response.headers.get('X-RateLimit-Limit', 0))
        
        if remaining < 10:  # Warn when running low on API requests
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
            reset_dt = datetime.datetime.fromtimestamp(reset_time)
            logging.warning(
                f"API rate limit: {remaining}/{limit} requests remaining. "
                f"Resets at {reset_dt.strftime('%Y-%m-%d %H:%M:%S')}"
            )

def handle_rate_limit(response: requests.Response) -> None:
    """Handle GitHub API rate limiting by waiting until the rate limit resets."""
    if 'X-RateLimit-Reset' in response.headers:
        reset_time = int(response.headers['X-RateLimit-Reset'])
        wait_time = max(0, reset_time - int(time.time())) + 5  # Add buffer
        logging.warning(f"Rate limit reached. Waiting {wait_time} seconds until reset...")
        time.sleep(wait_time)
    else:
        # If we don't have reset info, use a default wait time
        logging.warning("Rate limited but no reset time provided. Waiting 60 seconds...")
        time.sleep(60)

def process_repositories(page_repos: list, repos: list, include_forks: bool, include_archived: bool) -> None:
    """Process a page of repositories and add them to the results if they match the criteria."""
    for repo in page_repos:
        repo_name = repo.get('name', 'unnamed')
        is_fork = repo.get('fork', False)
        is_archived = repo.get('archived', False)
        
        # Skip based on filters
        if (not include_forks and is_fork) or (not include_archived and is_archived):
            logging.debug(
                f"Skipping repository: {repo_name} "
                f"(fork={is_fork}, archived={is_archived})"
            )
            continue
        
        # Add repository to results
        repos.append(repo)
        logging.debug(f"Added repository: {repo_name} (fork={is_fork}, archived={is_archived})")
    
    logging.info(f"Processed {len(page_repos)} repositories. Total so far: {len(repos)}")

def clone_repo(repo: dict) -> bool:
    """
    Clone a repository from GitHub.
    
    Args:
        repo: Repository information dictionary from GitHub API
        
    Returns:
        bool: True if clone was successful, False otherwise
    """
    if not config.CLONE_DIR:
        logging.error("CLONE_DIR is not configured")
        return False
        
    repo_name = repo.get("name") or (repo.get("full_name", "").split("/")[-1] if repo.get("full_name") else "repo")
    if not repo_name:
        logging.error("Could not determine repository name")
        return False
        
    dest_path = os.path.join(config.CLONE_DIR, repo_name)
    
    # Get the clone URL
    clone_url = repo.get("clone_url")
    if not clone_url and repo.get("full_name"):
        clone_url = f"https://github.com/{repo['full_name']}.git"
    
    if not clone_url:
        logging.error(f"No clone URL found for repository: {repo_name}")
        return False
    
    # Insert token into the URL for authentication
    if config.GITHUB_TOKEN and "@github.com" not in clone_url and clone_url.startswith("https://"):
        # Parse the URL to handle special characters in the token
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(clone_url)
        if parsed.scheme == 'https':
            # Rebuild the URL with the token
            netloc = f"x-access-token:{config.GITHUB_TOKEN}@{parsed.netloc}"
            clone_url = urlunparse((
                parsed.scheme,
                netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
            
            # Configure git to use the token for this URL
            try:
                # Store the credential in git's credential helper
                subprocess.run(
                    ["git", "config", "--global", "credential.helper", "store"],
                    capture_output=True,
                    text=True
                )
                
                # Add the credential to the URL
                subprocess.run(
                    ["git", "config", "--global", 
                     f"url.https://x-access-token:{config.GITHUB_TOKEN}@{parsed.netloc}/.insteadOf", 
                     f"https://{parsed.netloc}/"],
                    capture_output=True,
                    text=True
                )
            except Exception as e:
                logging.warning(f"Failed to configure git credentials: {e}")
    
    try:
        # Create parent directory if it doesn't exist
        os.makedirs(config.CLONE_DIR, exist_ok=True)
        
        # Remove existing directory if it exists
        if os.path.exists(dest_path):
            logging.debug(f"Removing existing directory: {dest_path}")
            shutil.rmtree(dest_path, ignore_errors=True)
        
        # Clone the repository with a timeout
        logging.info(f"Cloning {repo_name} from {clone_url} to {dest_path}...")
        
        # Use subprocess.Popen for better control over the process
        process = subprocess.Popen(
            ["git", "clone", "--depth", "1", clone_url, dest_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        try:
            # Wait for the process to complete with a timeout
            stdout, stderr = process.communicate(timeout=300)  # 5 minute timeout
            
            if process.returncode != 0:
                error_msg = stderr or "Unknown error"
                logging.error(f"Failed to clone {repo_name}: {error_msg}")
                # Clean up partial clone if it exists
                if os.path.exists(dest_path):
                    shutil.rmtree(dest_path, ignore_errors=True)
                return False
                
        except subprocess.TimeoutExpired:
            # Terminate the process if it times out
            process.kill()
            stdout, stderr = process.communicate()
            logging.error(f"Clone operation timed out for {repo_name}")
            if os.path.exists(dest_path):
                shutil.rmtree(dest_path, ignore_errors=True)
            return False
        
        # Verify the repository was cloned successfully
        if not os.path.isdir(dest_path):
            logging.error(f"Repository directory not found after clone: {dest_path}")
            return False
            
        logging.info(f"Successfully cloned {repo_name} to {dest_path}")
        return True
        
    except Exception as e:
        logging.error(f"Error cloning {repo_name}: {str(e)}", exc_info=True)
        # Clean up on error
        if os.path.exists(dest_path):
            shutil.rmtree(dest_path, ignore_errors=True)
        return False

def extract_requirements(repo_path):
    """
    Extract Python dependencies from various dependency files.
    Returns a tuple of (requirements_path, is_temporary, source_file).
    """
    # Check for requirements.txt first
    req_file = os.path.join(repo_path, "requirements.txt")
    if os.path.exists(req_file):
        return req_file, False, "requirements.txt"
        
    # Check for pyproject.toml
    pyproject = os.path.join(repo_path, "pyproject.toml")
    if os.path.exists(pyproject):
        try:
            data = toml.load(pyproject)
            deps = []
            
            # Check for modern PEP 621 format
            if "project" in data and "dependencies" in data["project"]:
                deps.extend(data["project"]["dependencies"])
                
            # Check for optional dependencies
            if "project" in data and "optional-dependencies" in data["project"]:
                for optional_deps in data["project"]["optional-dependencies"].values():
                    deps.extend(optional_deps)
            
            if deps:
                temp_req = os.path.join(CLONE_DIR, "temp_requirements.txt")
                with open(temp_req, "w") as f:
                    for dep in deps:
                        # Skip environment markers for now
                        if ";" in dep:
                            dep = dep.split(";")[0].strip()
                        f.write(f"{dep}\n")
                return temp_req, True, "pyproject.toml"
                
        except Exception as e:
            logging.warning(f"Error parsing pyproject.toml: {e}")
    
    # Check for setup.py as a last resort
    setup_py = os.path.join(repo_path, "setup.py")
    if os.path.exists(setup_py):
        try:
            # Use pipreqs to generate requirements.txt from imports
            temp_req = os.path.join(CLONE_DIR, "temp_requirements.txt")
            result = subprocess.run(
                ["pipreqs", "--print", repo_path],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                with open(temp_req, "w") as f:
                    f.write(result.stdout)
                return temp_req, True, "setup.py (generated)"
        except Exception as e:
            logging.warning(f"Error generating requirements from setup.py: {e}")
    
    return None, False, None

def log_stuck_repo(repo_name: str, duration: float, phase: str, details: str = "") -> None:
    """
    Log information about a stuck repository for post-mortem analysis.
    
    Args:
        repo_name: Name of the repository
        duration: How long it was running before timeout (seconds)
        phase: What phase it was in (cloning, scanning, etc.)
        details: Additional details about what was happening
    """
    stuck_info = {
        'repo_name': repo_name,
        'duration_minutes': round(duration / 60, 2),
        'phase': phase,
        'details': details,
        'timestamp': datetime.datetime.now().isoformat()
    }
    stuck_repos_log.append(stuck_info)
    
    # Also write to a log file immediately
    log_file = os.path.join(config.REPORT_DIR, "stuck_repos.log")
    try:
        os.makedirs(config.REPORT_DIR, exist_ok=True)
        with open(log_file, 'a') as f:
            f.write(f"{stuck_info['timestamp']} | {repo_name} | {stuck_info['duration_minutes']}min | {phase} | {details}\n")
    except Exception as e:
        logging.warning(f"Failed to write to stuck_repos.log: {e}")

def detect_languages(repo_path: str) -> Set[str]:
    """
    Detect programming languages used in the repository.
    Returns a set of normalized language names (e.g., 'python', 'javascript', 'go', 'java').
    """
    languages = set()
    
    # Extensions mapping
    ext_map = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'javascript',
        '.tsx': 'javascript',
        '.go': 'go',
        '.java': 'java',
        '.rb': 'ruby',
        '.php': 'php',
        '.cs': 'csharp',
        '.cpp': 'cpp',
        '.c': 'cpp',
        '.h': 'cpp',
    }
    
    # Walk the directory
    for root, _, files in os.walk(repo_path):
        if '.git' in root: continue
        
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in ext_map:
                languages.add(ext_map[ext])
                
    return languages

def detect_iac(repo_path: str) -> bool:
    """
    Detect if the repository contains Infrastructure as Code (IaC).
    Checks for Terraform, CloudFormation, Kubernetes, Dockerfiles, etc.
    """
    iac_extensions = {'.tf', '.tfvars', '.yaml', '.yml', '.json'} # YAML/JSON for K8s/CFN
    iac_filenames = {'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'}
    
    for root, _, files in os.walk(repo_path):
        if '.git' in root: continue
        
        for file in files:
            if file in iac_filenames:
                return True
            
            ext = os.path.splitext(file)[1].lower()
            if ext == '.tf':
                return True
            
            # For YAML/JSON, we might want to be smarter, but for now, 
            # if we see them, we assume potential IaC/Config.
            # Checkov is fast enough that false positives here are okay.
            if ext in {'.yaml', '.yml'} and ('k8s' in root or 'kubernetes' in root or 'chart' in root):
                return True
                
    return False

def generate_partial_report(repo_name: str, repo_url: str, report_dir: str, completed_scans: List[str], error_msg: str, ai_analysis=None) -> None:
    """
    Generate a partial report for a repository that timed out or failed.
    
    Args:
        repo_name: Repository name
        repo_url: Repository URL
        report_dir: Directory to save the report
        completed_scans: List of scans that completed before timeout
        error_msg: Error message explaining what happened
        ai_analysis: Optional AI analysis results
    """
    try:
        os.makedirs(report_dir, exist_ok=True)
        summary_path = os.path.join(report_dir, f"{repo_name}_summary.md")
        
        with open(summary_path, 'w') as f:
            f.write(f"# Security Scan Summary: {repo_name} (INCOMPLETE)\n\n")
            f.write(f"**Repository:** [{repo_name}]({repo_url})\n\n")
            f.write(f"**Status:** ⚠️ TIMEOUT/ERROR\n\n")
            f.write(f"**Error:** {error_msg}\n\n")
            f.write(f"**Timestamp:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if completed_scans:
                f.write("## Completed Scans\n\n")
                for scan in completed_scans:
                    f.write(f"- ✓ {scan}\n")
                f.write("\n")
            
            # AI Analysis Section (if available)
            if ai_analysis:
                f.write("## 🤖 AI Analysis\n\n")
                f.write(f"**Root Cause:** {ai_analysis.root_cause}\n\n")
                f.write(f"**Severity:** {ai_analysis.severity.value.upper()}\n\n")
                f.write(f"**Confidence:** {ai_analysis.confidence:.0%}\n\n")
                f.write(f"**Explanation:** {ai_analysis.explanation}\n\n")
                
                if ai_analysis.remediation_suggestions:
                    f.write("### Suggested Fixes\n\n")
                    for i, sug in enumerate(ai_analysis.remediation_suggestions, 1):
                        f.write(f"{i}. **{sug.action.value.replace('_', ' ').title()}**\n")
                        f.write(f"   - **Rationale:** {sug.rationale}\n")
                        f.write(f"   - **Expected Impact:** {sug.estimated_impact}\n")
                        f.write(f"   - **Confidence:** {sug.confidence:.0%}\n")
                        f.write(f"   - **Safety Level:** {sug.safety_level}\n")
                        if sug.params:
                            f.write(f"   - **Parameters:** {sug.params}\n")
                        f.write("\n")
                
                f.write(f"**AI Cost:** ${ai_analysis.estimated_cost:.4f}\n\n")
            
            f.write("## Note\n\n")
            f.write("This repository scan did not complete successfully. ")
            f.write("The scan was terminated due to timeout or error. ")
            f.write("Partial results may be available in this directory.\n")
        logging.info(f"Generated partial report for {repo_name} at {summary_path}")
    except Exception as e:
        logging.error(f"Failed to generate partial report for {repo_name}: {e}")

def process_repo_with_timeout(
    repo: Dict[str, Any],
    report_dir: str,
    timeout_minutes: int = 30,
    progress_check_interval: int = 30,
    max_idle_time: int = 180,
    min_cpu_threshold: float = 5.0,
    force_rescan: bool = False,
    rescan_days: int = 30,
    skip_scan: bool = False,
    override_scan: bool = False,
    resume_state: Optional['ResumeState'] = None,
    tenant_slug: str = None
) -> Dict[str, Any]:
    """
    Wrapper around process_repo with intelligent progress monitoring.

    Instead of a hard timeout, monitors scan progress and only times out
    if no progress is detected for max_idle_time seconds.

    Args:
        repo: Repository information from GitHub API
        report_dir: Directory to save reports
        timeout_minutes: Initial timeout in minutes (extends if making progress)
        progress_check_interval: Seconds between progress checks
        max_idle_time: Seconds of no progress before timeout
        min_cpu_threshold: Minimum CPU % to consider active
        force_rescan: If True, force rescan regardless of existing reports
        rescan_days: Days threshold for rescanning repos with recent activity
        skip_scan: If True, skip repos scanned within last 48 hours
        override_scan: If True, override all skip logic and scan every repo
        resume_state: Optional resume state manager for tracking progress

    Returns:
        Dict with status information about the scan
    """
    repo_name = repo.get('name', 'unknown')
    repo_url = repo.get('html_url', '')

    # Use RepoNameHandler for safe name handling if available
    if SAFE_SUBPROCESS_AVAILABLE:
        name_info = RepoNameHandler.analyze(repo_name)
        safe_repo_name = name_info.safe_filesystem
        if name_info.warnings:
            for warning in name_info.warnings:
                logging.warning(f"⚠️  {repo_name}: {warning}")
        if name_info.risk_level in (NameRisk.NEEDS_ESCAPING, NameRisk.DANGEROUS):
            logging.info(f"📋 Using safe handling for {repo_name} (risk: {name_info.risk_level.value})")
    else:
        # Fallback: Sanitize repo name for filesystem paths
        safe_repo_name = "".join(c if c.isalnum() or c in '._-' else '_' for c in repo_name)

    start_time = time.time()

    # Check if shutdown was requested
    if shutdown_event.is_set():
        logging.info(f"Skipping {repo_name} due to shutdown request")
        return {'repo': repo_name, 'status': 'skipped', 'reason': 'shutdown'}

    logging.info(
        f"Starting scan of {repo_name} "
        f"(initial timeout: {timeout_minutes}m, progress monitoring enabled)"
    )

    # Create a future for the process_repo function
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(process_repo, repo, report_dir, force_rescan, rescan_days, skip_scan, override_scan, resume_state, tenant_slug)
        
        # Progress monitoring loop
        initial_timeout = timeout_minutes * 60
        last_progress_check = start_time
        progress_extensions = 0
        
        try:
            while True:
                elapsed = time.time() - start_time
                
                # Check if future completed
                try:
                    result = future.result(timeout=progress_check_interval)
                    # Scan completed successfully
                    duration = time.time() - start_time
                    logging.info(f"Completed scan of {repo_name} in {duration/60:.2f} minutes")
                    return {'repo': repo_name, 'status': 'success', 'duration': duration}
                except concurrent.futures.TimeoutError:
                    # Future still running, check progress
                    pass
                
                # Check if we've exceeded initial timeout
                if elapsed > initial_timeout:
                    # Check for progress (if progress monitoring available)
                    if PROGRESS_MONITOR_AVAILABLE:
                        process_info = get_process_info(repo_name)
                        if process_info and "progress_monitor" in process_info:
                            monitor = process_info["progress_monitor"]
                            metrics = monitor.check_progress()
                            
                            if metrics.is_progressing:
                                # Scan is making progress, extend timeout
                                progress_extensions += 1
                                logging.info(
                                    f"✓ Progress detected for {repo_name}: {metrics.progress_reason} "
                                    f"(CPU={metrics.cpu_percent:.1f}%, Output={metrics.total_output_lines} lines) "
                                    f"- extending timeout (extension #{progress_extensions})"
                                )
                                # Extend by another timeout period
                                initial_timeout = elapsed + (timeout_minutes * 60)
                                continue
                            elif monitor.is_stuck():
                                # No progress for max_idle_time - trigger timeout
                                idle_time = monitor.get_idle_time()
                                logging.warning(
                                    f"⚠️  TIMEOUT: {repo_name} - no progress for {idle_time:.0f}s "
                                    f"(threshold: {max_idle_time}s)"
                                )
                                raise concurrent.futures.TimeoutError(
                                    f"No progress detected for {idle_time:.0f}s"
                                )
                    else:
                        # Progress monitoring not available, use simple timeout
                        logging.warning(
                            f"⚠️  TIMEOUT: {repo_name} exceeded {timeout_minutes} minute limit "
                            f"(progress monitoring unavailable)"
                        )
                        raise concurrent.futures.TimeoutError(
                            f"Exceeded {timeout_minutes} minute timeout"
                        )
                
                last_progress_check = time.time()
            
        except concurrent.futures.TimeoutError as timeout_err:
            # Repository scan timed out - this is the self-annealing part
            duration = time.time() - start_time
            error_msg = str(timeout_err) if str(timeout_err) else f"Repository scan exceeded timeout of {timeout_minutes} minutes"
            
            logging.warning(f"⚠️  TIMEOUT: {repo_name} exceeded {timeout_minutes} minute limit")
            logging.warning(f"   Duration: {duration/60:.2f} minutes")
            logging.warning(f"   Progress extensions: {progress_extensions}")
            logging.warning(f"   Applying self-annealing recovery: skipping to next repository")
            
            # Collect progress metrics for AI analysis
            progress_summary = None
            if PROGRESS_MONITOR_AVAILABLE:
                process_info = get_process_info(repo_name)
                if process_info and "progress_monitor" in process_info:
                    progress_summary = process_info["progress_monitor"].get_summary()
            
            # AI-Enhanced Analysis (if enabled)
            ai_analysis = None
            if AI_AGENT_AVAILABLE and reasoning_engine:
                try:
                    logging.info(f"🤖 Running AI analysis for {repo_name}...")
                    
                    # Collect repository metadata
                    repo_metadata = {
                        "size_mb": 0,  # Could be enhanced with actual size
                        "file_count": 0,
                        "primary_language": repo.get("language", "unknown"),
                        "loc": 0
                    }
                    
                    # Run AI analysis asynchronously with progress data
                    ai_analysis = asyncio.run(reasoning_engine.analyze_stuck_scan(
                        repo_name=repo_name,
                        scanner="unknown",  # Could track which scanner was running
                        phase="scanning",
                        timeout_duration=int(duration),
                        repo_metadata=repo_metadata,
                        scanner_progress=progress_summary  # Include progress metrics
                    ))
                    
                    # Log AI insights
                    logging.info(f"   Suggestions: {len(ai_analysis.remediation_suggestions)}")
                    logging.info(f"   Cost: ${ai_analysis.estimated_cost:.4f}")
                    

                    
                    # Apply remediation if enabled
                    if remediation_engine and ai_analysis.remediation_suggestions:
                        logging.info(f"🔧 Applying remediation suggestions...")
                        results = remediation_engine.apply_suggestions(
                            suggestions=ai_analysis.remediation_suggestions,
                            repo_name=repo_name,
                            scanner="unknown"
                        )
                        
                        for result in results:
                            status = result.get("status", "unknown")
                            action = result.get("action", "unknown")
                            if status == "applied":
                                logging.info(f"   ✓ Applied: {action}")
                            elif status == "skipped":
                                logging.info(f"   ⊘ Skipped: {action} ({result.get('reason', 'unknown')})")
                            elif status == "dry_run":
                                logging.info(f"   🔍 Dry-run: {action}")
                    
                    # Record in learning system
                    if learning_system:
                        learning_system.record_analysis(
                            repo_name=repo_name,
                            scanner="unknown",
                            root_cause=ai_analysis.root_cause,
                            confidence=ai_analysis.confidence,
                            suggestions_count=len(ai_analysis.remediation_suggestions)
                        )
                        
                        # Record each suggestion
                        for sug in ai_analysis.remediation_suggestions:
                            learning_system.record_suggestion(
                                repo_name=repo_name,
                                scanner="unknown",
                                suggestion_action=sug.action.value,
                                applied=False,  # Will be updated if remediation is applied
                                outcome=None,
                                notes=sug.rationale
                            )
                
                except Exception as ai_error:
                    logging.error(f"AI analysis failed for {repo_name}: {ai_error}")
                    # Continue with normal timeout handling
            
            # Log to stuck repos tracking
            log_stuck_repo(
                repo_name=repo_name,
                duration=duration,
                phase="scanning",
                details=f"Exceeded {timeout_minutes} minute timeout (extensions: {progress_extensions})"
            )
            
            # Generate partial report (with AI insights if available)
            repo_report_dir = os.path.join(report_dir, safe_repo_name)
            generate_partial_report(
                repo_name=repo_name,
                repo_url=repo_url,
                report_dir=repo_report_dir,
                completed_scans=[],  # We don't know what completed
                error_msg=error_msg,
                ai_analysis=ai_analysis  # Pass AI analysis to report generator
            )

            # Attempt to ingest partial results
            try:
                logging.info(f"Attempting to ingest partial results for {repo_name}...")
                ingest_script = os.path.join(os.path.dirname(__file__), "execution", "ingest_results.py")
                # Use named arguments to safely handle repo names that start with '-'
                cmd = [sys.executable, ingest_script, "--repo-name", repo_name, "--repo-dir", repo_report_dir]

                # Use safe subprocess with timeout to prevent hangs
                if SAFE_SUBPROCESS_AVAILABLE:
                    try:
                        result = run_with_timeout(cmd, timeout=300, check=True)
                        logging.info(f"Partial results ingestion completed for {repo_name}")
                    except SubprocessTimeout:
                        logging.error(f"Ingest script timed out for {repo_name}")
                else:
                    subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
                    logging.info(f"Partial results ingestion completed for {repo_name}")
            except subprocess.TimeoutExpired:
                logging.error(f"Ingest script timed out for {repo_name}")
            except Exception as e:
                logging.error(f"Failed to ingest partial results for {repo_name}: {e}")
            
            # Self-annealing: Record timeout failure
            record_repo_failure(repo_name, f"timeout after {duration/60:.1f}m")

            # Cancel the future (won't stop it immediately but marks it as cancelled)
            future.cancel()

            return {
                'repo': repo_name,
                'status': 'timeout',
                'duration': duration,
                'timeout_limit': timeout_minutes,
                'progress_extensions': progress_extensions,
                'ai_analysis': ai_analysis is not None,
                'progress_summary': progress_summary
            }

        except Exception as e:
            # Other error occurred
            duration = time.time() - start_time
            error_msg = f"Error during scan: {str(e)}"

            logging.error(f"❌ ERROR: {repo_name} failed after {duration/60:.2f} minutes: {e}")

            # Self-annealing: Record error failure
            record_repo_failure(repo_name, f"error: {str(e)[:100]}")

            # Log to stuck repos tracking
            log_stuck_repo(
                repo_name=repo_name,
                duration=duration,
                phase="scanning",
                details=f"Error: {str(e)[:200]}"
            )

            # Generate partial report
            repo_report_dir = os.path.join(report_dir, safe_repo_name)
            generate_partial_report(
                repo_name=repo_name,
                repo_url=repo_url,
                report_dir=repo_report_dir,
                completed_scans=[],
                error_msg=error_msg
            )

            return {
                'repo': repo_name,
                'status': 'error',
                'duration': duration,
                'error': str(e)
            }


def _parse_github_datetime(date_str: Optional[str]) -> Optional[datetime.datetime]:
    """Parse GitHub API datetime string to Python datetime."""
    if not date_str:
        return None
    try:
        # GitHub returns ISO 8601 format: 2024-01-15T10:30:00Z
        return datetime.datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        return None


def _persist_scan_findings(db_session, repository_id: str, findings: List[Dict[str, Any]], scanner_name: str):
    """
    Persist generic findings to the database.
    
    Args:
        db_session: SQLAlchemy session
        repository_id: UUID of the repository
        findings: List of finding dictionaries (normalized)
        scanner_name: Name of the scanner (semgrep, gitleaks, etc.)
    """
    if not db_session or not repository_id:
        return

    try:
        # Get organization_id from repository
        repo = db_session.query(models.Repository).filter(models.Repository.id == repository_id).first()
        if not repo:
            logging.error(f"Could not find repository {repository_id} for persistence")
            return
            
        organization_id = repo.organization_id

        # Determine finding type based on scanner
        finding_type = "sast"
        if scanner_name in ["gitleaks", "trufflehog", "whispers"]:
            finding_type = "secret"
        elif scanner_name in ["dependency-check", "safety", "pip-audit", "npm-audit"]:
            finding_type = "sca"
        elif scanner_name in ["checkov", "terrascan", "kics"]:
            finding_type = "iac"

        # Count new findings
        count = 0
        
        for f in findings:
            # Check deduplication (optional optimization: hash based dedupe)
            # For now, we trust the scanner's unique output or simple duplication is acceptable for MVP
            
            finding = models.Finding(
                repository_id=repository_id,
                organization_id=organization_id,
                scanner_name=scanner_name,
                finding_type=finding_type,
                title=f.get('title', 'Unknown Issue'),
                description=f.get('description', ''),
                severity=f.get('severity', 'MEDIUM').upper(),
                file_path=f.get('file_path'),
                line_start=f.get('line_start'),
                line_end=f.get('line_end'),
                code_snippet=f.get('code_snippet', '')[:1000] if f.get('code_snippet') else None,
                cve_id=f.get('cve_id'),
                cwe_id=f.get('cwe_id'),
                package_name=f.get('package_name'),
                package_version=f.get('package_version'),
                fixed_version=f.get('fixed_version'),
                status='open'
            )
            db_session.add(finding)
            count += 1
            
        db_session.commit()
        logging.info(f"Persisted {count} {scanner_name} findings to database")

    except Exception as e:
        logging.error(f"Failed to persist {scanner_name} findings: {e}")
        db_session.rollback()



def ensure_repo_in_database(repo: dict) -> Optional[str]:
    """
    Ensure a repository exists in the database with full GitHub metadata.
    Creates new repos or updates existing ones with the latest API data.
    
    Multi-tenant: Uses config.ORGANIZATION_ID to scope repositories to the correct organization.

    Args:
        repo: Repository data from GitHub API
    """
    if not DATABASE_AVAILABLE:
        logging.debug("Database not available, skipping repo database entry")
        return

    try:
        db = SessionLocal()
        try:
            repo_name = repo.get('name')
            if not repo_name:
                logging.warning("Repository name missing, cannot add to database")
                return

            # Get organization ID for multi-tenant scoping
            org_id = config.ORGANIZATION_ID
            if not org_id:
                # Try to get default organization from database
                from sqlalchemy import text
                result = db.execute(text("SELECT id FROM organizations WHERE is_default = true LIMIT 1"))
                row = result.fetchone()
                if row:
                    org_id = str(row[0])
                    logging.debug(f"Using default organization ID: {org_id}")

            # Extract GitHub metadata from API response
            github_metadata = {
                'description': repo.get('description') or '',
                'url': repo.get('html_url', ''),
                'full_name': repo.get('full_name'),
                'default_branch': repo.get('default_branch', 'main'),
                'language': repo.get('language'),
                'pushed_at': _parse_github_datetime(repo.get('pushed_at')),
                'github_created_at': _parse_github_datetime(repo.get('created_at')),
                'github_updated_at': _parse_github_datetime(repo.get('updated_at')),
                'stargazers_count': repo.get('stargazers_count', 0),
                'watchers_count': repo.get('watchers_count', 0),
                'forks_count': repo.get('forks_count', 0),
                'open_issues_count': repo.get('open_issues_count', 0),
                'size_kb': repo.get('size', 0),
                'is_fork': repo.get('fork', False),
                'is_archived': repo.get('archived', False),
                'is_disabled': repo.get('disabled', False),
                'is_private': repo.get('private', True),
                'visibility': repo.get('visibility'),
                'topics': repo.get('topics', []),
                'has_wiki': repo.get('has_wiki', False),
                'has_pages': repo.get('has_pages', False),
                'has_discussions': repo.get('has_discussions', False),
            }
            
            # Extract license name if present
            license_info = repo.get('license')
            if license_info and isinstance(license_info, dict):
                github_metadata['license_name'] = license_info.get('spdx_id') or license_info.get('name')
            
            # Extract owner info if present
            owner_info = repo.get('owner')
            if owner_info and isinstance(owner_info, dict):
                github_metadata['owner_type'] = owner_info.get('type')
                github_metadata['owner_id'] = str(owner_info.get('id', ''))

            # Multi-tenant: Check if repository already exists for THIS organization
            query = db.query(models.Repository).filter(models.Repository.name == repo_name)
            if org_id:
                query = query.filter(models.Repository.organization_id == org_id)
            existing_repo = query.first()

            if existing_repo:
                # Update existing repo with latest GitHub metadata
                for key, value in github_metadata.items():
                    if value is not None:  # Only update non-None values
                        setattr(existing_repo, key, value)
                # Ensure organization_id is set (for migration of old data)
                if org_id and not existing_repo.organization_id:
                    existing_repo.organization_id = org_id
                db.commit()
                logging.debug(f"✓ Updated {repo_name} GitHub metadata in database (org: {config.ORGANIZATION_NAME or 'default'})")
                return str(existing_repo.id)

            # Create new repository entry with full metadata and organization scope
            new_repo = models.Repository(
                name=repo_name,
                organization_id=org_id,
                **github_metadata
            )

            db.add(new_repo)
            db.commit()
            logging.info(f"✓ Added {repo_name} to database with GitHub metadata (org: {config.ORGANIZATION_NAME or 'default'})")
            return str(new_repo.id)

        finally:
            db.close()

    except Exception as e:
        logging.error(f"Failed to add/update repository in database: {e}")
        return None


def was_scanned_within_hours(repo_name: str, hours: int = 48) -> tuple[bool, str]:
    """
    Check if a repository was scanned within the specified number of hours.

    Args:
        repo_name: Name of the repository
        hours: Number of hours to check (default: 48)

    Returns:
        Tuple of (was_scanned_recently, message)
    """
    if not DATABASE_AVAILABLE:
        logging.debug("Database not available, cannot check scan time")
        return False, "Database not available"

    try:
        db = SessionLocal()
        try:
            # Query the repository from database
            repo_record = db.query(models.Repository).filter(
                models.Repository.name == repo_name
            ).first()

            if not repo_record:
                return False, f"Repository not found in database"

            if not repo_record.last_scanned_at:
                return False, "Repository has never been scanned"

            # Calculate time since last scan
            now = datetime.datetime.now(datetime.timezone.utc)
            last_scan = repo_record.last_scanned_at

            # Ensure last_scan is timezone-aware
            if last_scan.tzinfo is None:
                last_scan = last_scan.replace(tzinfo=datetime.timezone.utc)

            hours_since_scan = (now - last_scan).total_seconds() / 3600

            if hours_since_scan < hours:
                return True, f"Scanned {hours_since_scan:.1f} hours ago (within {hours} hour threshold)"
            else:
                return False, f"Last scanned {hours_since_scan:.1f} hours ago (outside {hours} hour threshold)"

        finally:
            db.close()

    except Exception as e:
        logging.error(f"Error checking scan time for {repo_name}: {e}")
        return False, f"Error checking scan time: {e}"


def should_skip_inactive_repo(repo_name: str, inactive_days: int = 180) -> tuple[bool, str]:
    """
    Check if a repository should be skipped because it exists in the database
    and has a last commit older than the specified number of days.

    Args:
        repo_name: Name of the repository
        inactive_days: Number of days since last commit to consider inactive (default: 180)

    Returns:
        Tuple of (should_skip, message)
    """
    if not DATABASE_AVAILABLE:
        return False, "Database not available"

    try:
        db = SessionLocal()
        try:
            # Query the repository from database
            repo_record = db.query(models.Repository).filter(
                models.Repository.name == repo_name
            ).first()

            if not repo_record:
                return False, "Repository not in database yet"

            # Get the most recent commit date from contributors
            last_commit = db.query(func.max(models.Contributor.last_commit_at)).filter(
                models.Contributor.repository_id == repo_record.id
            ).scalar()

            if not last_commit:
                return False, "No commit data in database"

            # Calculate days since last commit
            now = datetime.datetime.now(datetime.timezone.utc)

            # Ensure last_commit is timezone-aware
            if last_commit.tzinfo is None:
                last_commit = last_commit.replace(tzinfo=datetime.timezone.utc)

            days_since_commit = (now - last_commit).total_seconds() / (60 * 60 * 24)

            if days_since_commit > inactive_days:
                return True, f"Repository is inactive ({days_since_commit:.0f} days since last commit, threshold: {inactive_days} days)"
            else:
                return False, f"Repository is active ({days_since_commit:.0f} days since last commit)"

        finally:
            db.close()

    except Exception as e:
        logging.error(f"Error checking repo activity for {repo_name}: {e}")
        return False, f"Error checking activity: {e}"


def should_skip_problematic_repo(repo_name: str, failure_threshold: int = 3, retry_days: int = 7) -> tuple[bool, str]:
    """
    Self-annealing: Check if a repository should be skipped due to repeated failures.

    Repos with failure_count >= failure_threshold are skipped, but only if they failed
    recently (within retry_days). This allows automatic retry after some time.

    Args:
        repo_name: Name of the repository
        failure_threshold: Number of consecutive failures before auto-skip (default: 3)
        retry_days: Days to wait before retrying a failed repo (default: 7)

    Returns:
        Tuple of (should_skip, message)
    """
    if not DATABASE_AVAILABLE:
        return False, "Database not available"

    try:
        db = SessionLocal()
        try:
            repo_record = db.query(models.Repository).filter(
                models.Repository.name == repo_name
            ).first()

            if not repo_record:
                return False, "Repository not in database yet"

            failure_count = repo_record.failure_count or 0

            if failure_count >= failure_threshold:
                # Check if we should retry (last failure was a while ago)
                if repo_record.last_failure_at:
                    now = datetime.datetime.now(datetime.timezone.utc)
                    last_failure = repo_record.last_failure_at

                    if last_failure.tzinfo is None:
                        last_failure = last_failure.replace(tzinfo=datetime.timezone.utc)

                    days_since_failure = (now - last_failure).total_seconds() / (60 * 60 * 24)

                    if days_since_failure < retry_days:
                        reason = repo_record.last_failure_reason or "unknown"
                        return True, f"Repository has failed {failure_count} times (last: {reason}, {days_since_failure:.1f}d ago). Will retry after {retry_days} days."
                    else:
                        # Enough time has passed, let's retry
                        logging.info(f"Retrying {repo_name} after {days_since_failure:.1f} days since last failure")
                        return False, f"Retrying after {days_since_failure:.1f} days"
                else:
                    # Has failures but no timestamp? Skip it
                    return True, f"Repository has failed {failure_count} times. Will retry later."

            return False, f"Repository failure count: {failure_count}"

        finally:
            db.close()

    except Exception as e:
        logging.error(f"Error checking failure status for {repo_name}: {e}")
        return False, f"Error checking failures: {e}"


def has_problematic_name(repo_name: str) -> tuple[bool, str]:
    """
    Check if a repository name has characters that need special handling.

    Problematic names include:
    - Names starting with hyphen (interpreted as flags by CLI tools)
    - Names starting with period (hidden files, can cause path issues)
    - Names with special characters that break shell commands

    Returns:
        Tuple of (needs_special_handling, reason)
    """
    if not repo_name:
        return True, "Empty repository name"

    if repo_name.startswith('-'):
        return True, "Repository name starts with hyphen (needs quoting for CLI)"

    if repo_name.startswith('.'):
        return True, "Repository name starts with period (hidden file)"

    # Check for characters that need escaping in shell commands
    problematic_chars = ['`', '$', '(', ')', '{', '}', '|', '&', ';', '<', '>', '!', '*', '?', ' ', '"', "'"]
    for char in problematic_chars:
        if char in repo_name:
            return True, f"Repository name contains special character '{char}' (needs escaping)"

    return False, "Name OK"


def safe_repo_path(repo_name: str, base_path: str = "") -> str:
    """
    Create a safe file path for a repository, handling problematic names.

    For repos starting with '-', prefix with './' to prevent CLI flag interpretation.
    """
    # Sanitize for filesystem
    safe_name = "".join(c if c.isalnum() or c in '._-' else '_' for c in repo_name)

    if base_path:
        return os.path.join(base_path, safe_name)
    return safe_name


def quote_repo_name(repo_name: str) -> str:
    """
    Properly quote a repository name for use in shell commands.

    Handles repos starting with '-' by using '--' separator or './' prefix.
    """
    import shlex
    # Always use shlex.quote for safe shell escaping
    return shlex.quote(repo_name)


def record_repo_failure(repo_name: str, reason: str):
    """
    Record a repository scan failure in the database (self-annealing).
    Increments failure_count and updates last_failure_at/reason.
    """
    if not DATABASE_AVAILABLE:
        return

    try:
        db = SessionLocal()
        try:
            repo_record = db.query(models.Repository).filter(
                models.Repository.name == repo_name
            ).first()

            if repo_record:
                repo_record.failure_count = (repo_record.failure_count or 0) + 1
                repo_record.last_failure_at = datetime.datetime.now(datetime.timezone.utc)
                repo_record.last_failure_reason = reason[:255]  # Truncate to fit column
                db.commit()
                logging.info(f"📊 Recorded failure for {repo_name}: {reason} (count: {repo_record.failure_count})")
            else:
                logging.warning(f"Cannot record failure for {repo_name}: not in database")

        finally:
            db.close()

    except Exception as e:
        logging.error(f"Error recording failure for {repo_name}: {e}")


def reset_repo_failures(repo_name: str):
    """
    Reset failure count for a repository after successful scan (self-annealing).
    """
    if not DATABASE_AVAILABLE:
        return

    try:
        db = SessionLocal()
        try:
            repo_record = db.query(models.Repository).filter(
                models.Repository.name == repo_name
            ).first()

            if repo_record and repo_record.failure_count and repo_record.failure_count > 0:
                old_count = repo_record.failure_count
                repo_record.failure_count = 0
                repo_record.last_failure_at = None
                repo_record.last_failure_reason = None
                db.commit()
                logging.info(f"✅ Reset failure count for {repo_name} (was: {old_count})")

        finally:
            db.close()

    except Exception as e:
        logging.error(f"Error resetting failures for {repo_name}: {e}")


class ResumeState:
    """
    Manages resume state for interrupted scans.
    Tracks which repositories have been successfully completed.
    """

    def __init__(self, state_file: str = ".scan_resume_state.pkl"):
        """
        Initialize resume state manager.

        Args:
            state_file: Path to the state file for persistence
        """
        self.state_file = state_file
        self.completed_repos: Set[str] = set()
        self.scan_start_time: Optional[datetime.datetime] = None
        self.total_repos: int = 0
        self._lock = threading.RLock()  # RLock allows reentrant locking (same thread can acquire multiple times)

    def load(self) -> bool:
        """
        Load resume state from file.

        Returns:
            True if state was loaded successfully, False otherwise
        """
        if not os.path.exists(self.state_file):
            return False

        try:
            with open(self.state_file, 'r') as f:
                state_data = json.load(f)
                self.completed_repos = set(state_data.get('completed_repos', []))
                self.scan_start_time = state_data.get('scan_start_time')
                self.total_repos = state_data.get('total_repos', 0)
                return True
        except Exception as e:
            logging.warning(f"Could not load resume state: {e}")
            return False

    def save(self) -> None:
        """Save current state to file."""
        with self._lock:
            try:
                state_data = {
                    'completed_repos': list(self.completed_repos),
                    'scan_start_time': self.scan_start_time,
                    'total_repos': self.total_repos
                }
                with open(self.state_file, 'w') as f:
                    json.dump(state_data, f)
            except Exception as e:
                logging.error(f"Could not save resume state: {e}")

    def mark_completed(self, repo_name: str) -> None:
        """
        Mark a repository as completed.

        Args:
            repo_name: Name of the repository
        """
        with self._lock:
            self.completed_repos.add(repo_name)
            self.save()

    def is_completed(self, repo_name: str) -> bool:
        """
        Check if a repository has been completed.

        Args:
            repo_name: Name of the repository

        Returns:
            True if already completed, False otherwise
        """
        return repo_name in self.completed_repos

    def clear(self) -> None:
        """Clear all resume state."""
        with self._lock:
            self.completed_repos.clear()
            self.scan_start_time = None
            self.total_repos = 0
            if os.path.exists(self.state_file):
                os.remove(self.state_file)

    def initialize_scan(self, total_repos: int) -> None:
        """
        Initialize a new scan.

        Args:
            total_repos: Total number of repositories to scan
        """
        self.scan_start_time = datetime.datetime.now()
        self.total_repos = total_repos
        self.save()

    def get_progress(self) -> Dict[str, Any]:
        """
        Get current progress information.

        Returns:
            Dictionary with progress information
        """
        completed = len(self.completed_repos)
        remaining = max(0, self.total_repos - completed)

        # Safety check: if completed > total, something is wrong (corrupted state)
        # Cap completed at total to prevent absurd percentages
        if completed > self.total_repos and self.total_repos > 0:
            logging.warning(f"Resume state corrupted: completed ({completed}) > total ({self.total_repos}). Capping to total.")
            completed = self.total_repos
            remaining = 0

        progress = {
            'completed': completed,
            'remaining': remaining,
            'total': self.total_repos,
            'percentage': (completed / self.total_repos * 100) if self.total_repos > 0 else 0,
            'scan_start_time': self.scan_start_time
        }

        if self.scan_start_time and completed > 0:
            elapsed = (datetime.datetime.now() - self.scan_start_time).total_seconds()
            avg_time_per_repo = elapsed / completed
            estimated_remaining_time = avg_time_per_repo * remaining
            progress['elapsed_seconds'] = elapsed
            progress['estimated_remaining_seconds'] = estimated_remaining_time

        return progress


def should_rescan_repository(repo_name: str, report_dir: str, days_threshold: int = 30, force_rescan: bool = False) -> tuple[bool, str]:
    """
    Check if a repository should be rescanned based on existing reports and last activity.

    Args:
        repo_name: Name of the repository
        report_dir: Base directory where reports are stored
        days_threshold: Number of days to consider as "recent activity" (default: 30)
        force_rescan: If True, always rescan regardless of existing reports (default: False)

    Returns:
        tuple: (should_scan: bool, reason: str)
    """
    # If force rescan is enabled, always scan
    if force_rescan:
        return True, "Force rescan enabled"

    safe_repo_name = "".join(c if c.isalnum() or c in '._-' else '_' for c in repo_name)
    repo_report_dir = os.path.join(report_dir, safe_repo_name)

    # If report directory doesn't exist, we should scan
    if not os.path.exists(repo_report_dir):
        return True, "No existing scan reports found"

    # Check for intel report which contains contributor info
    intel_json_path = os.path.join(repo_report_dir, f"{safe_repo_name}_intel.json")

    if not os.path.exists(intel_json_path):
        return True, "No repo intelligence report found"

    try:
        with open(intel_json_path, 'r') as f:
            intel_data = json.load(f)

        # Check last commit date from contributors
        contributors = intel_data.get('contributors', {})
        top_contributors = contributors.get('top_contributors', [])

        if not top_contributors:
            return True, "No contributor data found in intel report"

        # Find the most recent commit across all contributors
        latest_commit_ts = None
        for contributor in top_contributors:
            last_commit_str = contributor.get('last_commit_at', '')
            if last_commit_str:
                try:
                    # Parse ISO format timestamp
                    commit_dt = datetime.datetime.fromisoformat(last_commit_str)
                    if latest_commit_ts is None or commit_dt > latest_commit_ts:
                        latest_commit_ts = commit_dt
                except ValueError:
                    continue

        if latest_commit_ts is None:
            return True, "Could not parse last commit date"

        # Calculate days since last commit
        days_since_commit = (datetime.datetime.now() - latest_commit_ts).days

        if days_since_commit <= days_threshold:
            return True, f"Repository has recent activity ({days_since_commit} days ago)"
        else:
            return False, f"Repository is inactive ({days_since_commit} days since last commit, threshold: {days_threshold} days)"

    except json.JSONDecodeError:
        logging.warning(f"Could not parse intel report for {repo_name}, will rescan")
        return True, "Intel report is corrupted"
    except Exception as e:
        logging.warning(f"Error checking scan status for {repo_name}: {e}, will rescan")
        return True, f"Error reading intel report: {e}"

def process_repo(repo: Dict[str, Any], report_dir: str, force_rescan: bool = False, rescan_days: int = 30, skip_scan: bool = False, override_scan: bool = False, resume_state: Optional['ResumeState'] = None, tenant_slug: str = None) -> None:
    """
    Process a single repository: clone, scan for vulnerabilities, and generate a report.

    Args:
        repo: Repository information from GitHub API
        report_dir: Directory to save the report
        force_rescan: If True, force rescan regardless of existing reports
        rescan_days: Days threshold for rescanning repos with recent activity
        skip_scan: If True, skip repos scanned within last 48 hours
        override_scan: If True, override all skip logic and scan every repo
        resume_state: Optional resume state manager for tracking progress
    """
    # Validate configuration
    if not config.CLONE_DIR:
        config.CLONE_DIR = setup_temp_dir()
        if not config.CLONE_DIR:
            logging.error("Failed to set up temporary directory for cloning")
            return

    # Get repository information
    repo_name = repo.get('name', '').strip()
    repo_url = repo.get('html_url', '')
    repo_full_name = repo.get('full_name', repo_name)
    repo_path = None

    if not repo_name:
        logging.error("Repository name is missing")
        return

    # Analyze repository name for potential issues
    if SAFE_SUBPROCESS_AVAILABLE:
        name_info = RepoNameHandler.analyze(repo_name)
        safe_repo_name = name_info.safe_filesystem

        # Log warnings about problematic names
        if name_info.warnings:
            for warning in name_info.warnings:
                logging.warning(f"Repository '{repo_name}': {warning}")
    else:
        # Fallback: Warn about potentially problematic repository names
        if repo_name.startswith('-'):
            logging.warning(f"Repository name '{repo_name}' starts with hyphen. This may cause issues with GitHub API.")
        if repo_name.startswith('.'):
            logging.warning(f"Repository name '{repo_name}' starts with period. This may cause issues.")

        # Sanitize the repository name for use in file paths
        safe_repo_name = "".join(c if c.isalnum() or c in '._-' else '_' for c in repo_name)

    print(f"[auditgh] Processing repository: {repo_full_name}")
    logging.info(f"Processing repository: {repo_name}")
    
    # Always ensure repository metadata is up-to-date in database
    # This saves all GitHub API metadata (pushed_at, stars, forks, archived, etc.)
    # Always ensure repository metadata is up-to-date in database
    # This saves all GitHub API metadata (pushed_at, stars, forks, archived, etc.)
    repo_id = ensure_repo_in_database(repo)

    # Check if already completed (resume functionality) - but respect override_scan
    if resume_state and resume_state.is_completed(repo_name) and not override_scan:
        logging.info(f"✅ Skipping {repo_name}: Already completed in previous run")
        return

    # Determine if we should skip this repository
    should_skip = False
    skip_reason = ""

    # Check for problematic repo names - warn but continue processing
    # These names need special handling (quoting/escaping) but should still follow skip logic
    if SAFE_SUBPROCESS_AVAILABLE:
        is_special_name, name_note = RepoNameHandler.is_problematic(repo_name)
    else:
        is_special_name, name_note = has_problematic_name(repo_name)

    if is_special_name:
        logging.warning(f"⚠️  {repo_name}: {name_note} - will process with safe argument handling")

    # Override scan disables all skip logic
    if override_scan:
        logging.info(f"⚡ Scanning {repo_name}: Override scan enabled")
    else:
        # Self-annealing: Check if repo has failed repeatedly
        if not should_skip:
            is_problematic, failure_msg = should_skip_problematic_repo(repo_name, failure_threshold=3, retry_days=7)
            if is_problematic:
                should_skip = True
                skip_reason = failure_msg

        # Check if repo was scanned within 48 hours (if skip_scan is enabled)
        if skip_scan and not should_skip:
            was_recent, scan_msg = was_scanned_within_hours(repo_name, 48)
            if was_recent:
                should_skip = True
                skip_reason = scan_msg

        # Check if repo is in database and inactive (last commit > 180 days)
        if not should_skip:
            is_inactive, activity_msg = should_skip_inactive_repo(repo_name, 180)
            if is_inactive:
                should_skip = True
                skip_reason = activity_msg

        # If not skipped by database checks, apply existing rescan logic (intel report check)
        if not should_skip:
            should_scan, reason = should_rescan_repository(repo_name, report_dir, rescan_days, force_rescan)
            if not should_scan:
                should_skip = True
                skip_reason = reason
            else:
                logging.info(f"🔄 Scanning {repo_name}: {reason}")

    # If we determined we should skip, skip it
    if should_skip:
        print(f"[auditgh] Skipping {repo_name}: {skip_reason}")
        logging.info(f"⏭️  Skipping {repo_name}: {skip_reason}")
        # Still mark as completed for resume state even if skipped
        if resume_state:
            resume_state.mark_completed(repo_name)
        return

    # Create a directory for this repository's report
    repo_report_dir = os.path.join(report_dir, safe_repo_name)
    os.makedirs(repo_report_dir, exist_ok=True)
    logging.debug(f"Created report directory: {repo_report_dir}")
    
    # Initialize error log file
    error_log_path = os.path.join(repo_report_dir, f"{safe_repo_name}_error.log")
    
    def log_error(message: str) -> None:
        """Helper function to log errors to both console and error log"""
        logging.error(message)
        with open(error_log_path, 'a') as f:
            f.write(f"{datetime.datetime.now().isoformat()} - {message}\n")
    
    # Clone the repository
    print(f"[auditgh] Cloning {repo_name}...")
    logging.info(f"Cloning repository: {repo_name}")
    if not clone_repo(repo):
        error_msg = f"Failed to clone repository: {repo_name}"
        log_error(error_msg)
        return
    
    # Verify the repository was cloned successfully
    repo_path = os.path.join(config.CLONE_DIR, repo_name)
    if not os.path.isdir(repo_path):
        error_msg = f"Repository directory not found after clone: {repo_path}"
        log_error(error_msg)
        return
        
    logging.info(f"Successfully cloned repository to: {repo_path}")
    
    try:
        # Run various security scans
        print(f"[auditgh] Running security scans for {repo_name}...")
        logging.info(f"Running security scans for {repo_name}...")
        
        # Parse scanners list
        enabled_scanners = set(s.strip().lower() for s in config.SCANNERS.split(','))
        run_all = 'all' in enabled_scanners

        def is_scanner_enabled(name):
            enabled = run_all or name.lower() in enabled_scanners
            if enabled:
                print(f"[auditgh]   ▸ {name}...", flush=True)
            return enabled

        # Extract requirements for Python projects
        requirements_path, is_temp, source_file = extract_requirements(repo_path)
        if requirements_path:
            logging.info(f"Found requirements file: {source_file} at {requirements_path}")
            
            # Run safety scan
            if is_scanner_enabled('safety'):
                safety_result = run_safety_scan(requirements_path, repo_name, repo_report_dir)
            else:
                safety_result = None
            
            # Run pip-audit scan
            if is_scanner_enabled('pip-audit'):
                pip_audit_result = run_pip_audit_scan(requirements_path, repo_name, repo_report_dir)
            else:
                pip_audit_result = None
            
            # Clean up temporary requirements file if created
            if is_temp and os.path.exists(requirements_path):
                os.remove(requirements_path)
        else:
            logging.info("No Python requirements file found")
            safety_result = None
            pip_audit_result = None

        semgrep_result = None
        syft_repo_result = None
        syft_image_result = None
        grype_repo_result = None
        grype_image_result = None
        checkov_result = None
        gitleaks_result = None
        semgrep_taint_result = None
        bandit_result = None
        trivy_fs_result = None
        npm_audit_result = None
        retire_js_result = None
        govulncheck_result = None
        bundle_audit_result = None
        dependency_check_result = None
        trufflehog_result = None
        nuclei_result = None
        ossgadget_result = None
        cloc_result = None
        api_audit_result = None
        # New Phase 1 scanners (December 2024)
        horusec_result = None
        whispers_result = None
        bearer_result = None
        dockle_result = None
        terrascan_result = None
        
        # Run npm audit for Node.js projects (supports npm, yarn, pnpm)
        if is_scanner_enabled('npm-audit'):
            npm_audit_result = run_npm_audit(repo_path, repo_name, repo_report_dir)
        
        # Run Retire.js for client-side libraries
        if is_scanner_enabled('retirejs'):
            retire_js_result = run_retire_js(repo_path, repo_name, repo_report_dir)
        
        # Run govulncheck for Go projects
        if is_scanner_enabled('govulncheck'):
            govulncheck_result = run_govulncheck(repo_path, repo_name, repo_report_dir)
        
        # Run bundle audit for Ruby projects
        if is_scanner_enabled('bundle-audit'):
            bundle_audit_result = run_bundle_audit(repo_path, repo_name, repo_report_dir)
        
        # Run OWASP Dependency-Check for Java projects
        if is_scanner_enabled('dependency-check'):
            dependency_check_result = run_dependency_check(repo_path, repo_name, repo_report_dir)
        
        # Run API Audit Scanner
        if is_scanner_enabled('api-audit') and API_AUDIT_AVAILABLE:
            try:
                api_audit_result = run_api_audit(
                    repo_path=repo_path,
                    repo_name=repo_name,
                    output_dir=repo_report_dir,
                    db_session=SessionLocal() if DATABASE_AVAILABLE else None,
                    repository_id=repo_id
                )
            except Exception as e:
                logging.error(f"API audit failed for {repo_name}: {e}")
                api_audit_result = None
        
        # Detect languages and IaC
        detected_languages = detect_languages(repo_path)
        has_iac = detect_iac(repo_path)
        logging.info(f"Detected languages for {repo_name}: {detected_languages}")
        logging.info(f"Detected IaC for {repo_name}: {has_iac}")

        # Run TruffleHog (Verified Secrets)
        if is_scanner_enabled('trufflehog'):
            trufflehog_result = run_trufflehog(
                repo_path=repo_path, 
                repo_name=repo_name, 
                report_dir=repo_report_dir,
                db_session=SessionLocal() if DATABASE_AVAILABLE else None,
                repository_id=repo_id
            )
        
        # Run Nuclei (Vulnerability Scanning)
        if is_scanner_enabled('nuclei'):
            nuclei_result = run_nuclei(repo_path, repo_name, repo_report_dir)
        
        # Run OSSGadget (Malware/Backdoor)
        if is_scanner_enabled('ossgadget'):
            ossgadget_result = run_ossgadget(repo_path, repo_name, repo_report_dir)
        
        # Run Repo Intelligence (OSINT)
        if PROGRESS_MONITOR_AVAILABLE:
            # Unshallow the repository to get full git history for contributor analysis
            unshallow_success = False
            try:
                logging.info(f"Unshallowing repository {repo_name} for contributor analysis...")
                unshallow_result = subprocess.run(
                    ["git", "fetch", "--unshallow"],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                if unshallow_result.returncode == 0:
                    logging.info(f"Successfully unshallowed {repo_name}")
                    unshallow_success = True
                else:
                    # Check if it's already complete (not a shallow repo) - that's OK
                    if "not a shallow repository" in unshallow_result.stderr.lower():
                        logging.info(f"Repository {repo_name} is already complete (not shallow)")
                        unshallow_success = True
                    else:
                        logging.warning(f"Unshallow failed for {repo_name}: {unshallow_result.stderr.strip()}")
            except subprocess.TimeoutExpired:
                logging.warning(f"Unshallow timeout for {repo_name}")
            except Exception as e:
                logging.warning(f"Could not unshallow {repo_name}: {e}")

            # Fallback: fetch more history if unshallow failed
            if not unshallow_success:
                try:
                    logging.info(f"Fetching deeper history for {repo_name} (depth=500)...")
                    fetch_result = subprocess.run(
                        ["git", "fetch", "--depth=500"],
                        cwd=repo_path,
                        capture_output=True,
                        text=True,
                        timeout=120
                    )
                    if fetch_result.returncode == 0:
                        logging.info(f"Fetched deeper history for {repo_name}")
                    else:
                        logging.warning(f"Could not fetch deeper history for {repo_name}: {fetch_result.stderr.strip()}")
                except Exception as e:
                    logging.warning(f"Fallback fetch failed for {repo_name}: {e}, contributor data may be incomplete")

            repo_intel_result = analyze_repo(repo_path, repo_name, repo_report_dir)
            
        # Run cloc for LOC stats
        if is_scanner_enabled('cloc'):
            cloc_result = run_cloc(repo_path, repo_name, repo_report_dir)

        # Generate Architecture Overview (AI)
        architecture_overview = ""
        if config.ENABLE_AI and ai_agent:
            logging.info(f"Generating architecture overview for {repo_name}...")
            architecture_overview = generate_repo_architecture(repo_path, repo_name, ai_agent)
            logging.info(f"Architecture overview generated. Length: {len(architecture_overview)}")
        else:
            logging.info("AI Agent disabled or not initialized. Skipping architecture overview.")
        
        # Run Semgrep scan for the repository
        if is_scanner_enabled('semgrep'):
            semgrep_result = run_semgrep_scan(
                repo_path=repo_path, 
                repo_name=repo_name, 
                report_dir=repo_report_dir,
                db_session=SessionLocal() if DATABASE_AVAILABLE else None,
                repository_id=repo_id
            )
            # Optional Semgrep taint-mode scan
            if config.SEMGREP_TAINT_CONFIG:
                semgrep_taint_result = run_semgrep_taint(repo_path, repo_name, repo_report_dir, config.SEMGREP_TAINT_CONFIG)
        
        # Run Syft to generate SBOM for the repo directory
        if is_scanner_enabled('syft'):
            syft_repo_result = run_syft(repo_path, repo_name, repo_report_dir, target_type="repo", sbom_format=config.SYFT_FORMAT)
            
            # If Docker image provided, also run Syft on the image
            if config.DOCKER_IMAGE:
                syft_image_result = run_syft(config.DOCKER_IMAGE, repo_name, repo_report_dir, target_type="image", sbom_format=config.SYFT_FORMAT)
        
        # Run Grype vulnerability scan on the repo directory
        if is_scanner_enabled('grype'):
            grype_repo_result = run_grype(repo_path, repo_name, repo_report_dir, target_type="repo", vex_files=config.VEX_FILES)
            # If Docker image provided, run Grype on the image
            if config.DOCKER_IMAGE:
                grype_image_result = run_grype(config.DOCKER_IMAGE, repo_name, repo_report_dir, target_type="image", vex_files=config.VEX_FILES)

        # Run Checkov for Terraform if applicable
        if is_scanner_enabled('checkov'):
            if has_iac:
                checkov_result = run_checkov(repo_path, repo_name, repo_report_dir)
            else:
                logging.info(f"Skipping Checkov for {repo_name} (no IaC detected)")
                checkov_result = None
        
        # Trivy filesystem scan (optional if installed)
        if is_scanner_enabled('trivy'):
            trivy_fs_result = run_trivy_fs(repo_path, repo_name, repo_report_dir)

        # =====================================================================
        # NEW PHASE 1 SCANNERS (December 2024)
        # =====================================================================
        
        # Run Horusec multi-tool SAST scanner
        if is_scanner_enabled('horusec'):
            horusec_result = run_horusec(repo_path, repo_name, repo_report_dir)
        
        # Run Whispers for additional secret patterns in config files
        if is_scanner_enabled('whispers'):
            whispers_result = run_whispers(repo_path, repo_name, repo_report_dir)
        
        # Run Bearer for sensitive data flow analysis (PII/PHI detection)
        if is_scanner_enabled('bearer'):
            bearer_result = run_bearer(repo_path, repo_name, repo_report_dir)
        
        # Run Dockle for Dockerfile best practices (if Dockerfiles present)
        if is_scanner_enabled('dockle'):
            dockle_result = run_dockle(repo_path, repo_name, repo_report_dir)
        
        # Run Terrascan for additional IaC coverage (if IaC files present)
        if is_scanner_enabled('terrascan'):
            if has_iac:
                terrascan_result = run_terrascan(repo_path, repo_name, repo_report_dir)
            else:
                logging.info(f"Skipping Terrascan for {repo_name} (no IaC detected)")

        # =====================================================================
        # PHASE 3 SCANNERS: Go Security & Mobile Security
        # =====================================================================
        
        gosec_result = None
        golangci_result = None
        mobsf_result = None
        
        # Run gosec for Go security analysis
        if is_scanner_enabled('gosec'):
            gosec_result = run_gosec(repo_path, repo_name, repo_report_dir)
        
        # Run GolangCI-Lint with security linters (complements gosec)
        if is_scanner_enabled('golangci-lint'):
            golangci_result = run_golangci_lint(repo_path, repo_name, repo_report_dir)
        
        # Run MobSF for mobile app security (Android/iOS)
        if is_scanner_enabled('mobsf'):
            mobsf_result = run_mobsf_static(repo_path, repo_name, repo_report_dir)

        # Generate AI Remediation Plans (using Knowledge Base)
        if PROGRESS_MONITOR_AVAILABLE and config.ENABLE_AI:
            # We need to pass the global 'kb' object.
            # Since process_repo runs in a thread/process, we might need to re-init KB or pass it.
            # For now, let's assume we can instantiate it or use a global if it's thread-safe.
            # Actually, process_repo is called by ThreadPoolExecutor in main.
            # But 'kb' is local to main. We need to pass it to process_repo.
            # For simplicity, let's re-instantiate KB inside process_repo if needed, or pass it.
            # Let's try to instantiate it here if it's lightweight.
            try:
                from src.knowledge_base import KnowledgeBase
                local_kb = KnowledgeBase()
                generate_ai_remediations(repo_name, repo_report_dir, local_kb)
            except Exception as e:
                logging.warning(f"Could not generate AI remediations: {e}")

        # Generate summary report
        generate_summary_report(
            repo_name=repo_name,
            repo_url=repo_url,
            requirements_path=requirements_path if requirements_path else "",
            safety_result=safety_result,
            pip_audit_result=pip_audit_result,
            npm_audit_result=npm_audit_result,
            govulncheck_result=govulncheck_result,
            bundle_audit_result=bundle_audit_result,
            dependency_check_result=dependency_check_result,
            semgrep_result=semgrep_result,
            semgrep_taint_result=semgrep_taint_result,
            checkov_result=checkov_result,
            gitleaks_result=gitleaks_result,
            bandit_result=bandit_result,
            trivy_fs_result=trivy_fs_result,
            repo_local_path=repo_path,
            report_dir=repo_report_dir,
            repo_full_name=repo_full_name,
            detected_languages=detected_languages,
            cloc_result=cloc_result,
            architecture_overview=architecture_overview
        )
        
        logging.info(f"Completed processing repository: {repo_name}")

        # Self-annealing: Reset failure count on successful scan
        reset_repo_failures(repo_name)

        # Mark repository as completed for resume functionality
        if resume_state:
            resume_state.mark_completed(repo_name)
            progress = resume_state.get_progress()
            logging.info(f"📊 Progress: {progress['completed']}/{progress['total']} repos ({progress['percentage']:.1f}%)")

        # Also print to console so users see an immediate pointer to the report location
        try:
            summary_path = os.path.join(repo_report_dir, f"{repo_name}_summary.md")
            if os.path.exists(summary_path):
                print(f"[auditgh] {repo_name}: summary -> {summary_path}")
            else:
                print(f"[auditgh] {repo_name}: reports -> {repo_report_dir}")
        except Exception:
            pass

    except Exception as e:
        error_msg = f"Error processing repository {repo_name}: {str(e)}"
        log_error(error_msg)
        logging.exception("Unexpected error:")
        
    finally:
        # Clean up temporary files
        if 'requirements_path' in locals() and is_temp and requirements_path and os.path.exists(requirements_path):
            try:
                os.remove(requirements_path)
                logging.debug(f"Cleaned up temporary file: {requirements_path}")
            except Exception as e:
                logging.warning(f"Failed to remove temporary file {requirements_path}: {e}")

        # Clean up the cloned repository if it exists
        if repo_path and os.path.exists(repo_path):
            try:
                shutil.rmtree(repo_path, ignore_errors=True)
                logging.debug(f"Cleaned up repository directory: {repo_path}")
            except Exception as e:
                logging.warning(f"Failed to clean up repository directory {repo_path}: {e}")


    
    # 7. Ingest Results into Database
    # -------------------------------------------------------------------------
    try:
        logging.info(f"Ingesting results for {repo_name}...")
        ingest_script = os.path.join(os.path.dirname(__file__), "..", "maintenance", "ingest_scans.py")
        # Use ORIGINAL repo_name for database (matches GitHub API) and safe path for --repo-dir
        # Named arguments safely handle repo names starting with '-'
        cmd = [sys.executable, ingest_script, "--repo-name", repo_name, "--repo-dir", repo_report_dir]
        
        # Add tenant argument if specified
        if tenant_slug:
            cmd.extend(["--tenant", tenant_slug])
            
        # Pass explicit organization ID if available
        if config.ORGANIZATION_ID:
            cmd.extend(["--organization-id", str(config.ORGANIZATION_ID)])

        # Use safe subprocess with timeout to prevent hangs
        if SAFE_SUBPROCESS_AVAILABLE:
            try:
                result = run_with_timeout(cmd, timeout=300)  # 5 minute timeout
                logging.info(f"Results ingestion completed for {repo_name}")
            except SubprocessTimeout:
                logging.error(f"Ingest script timed out for {repo_name} (5 minute limit)")
        else:
            # Fallback with timeout
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            logging.info(f"Results ingestion completed for {repo_name}")
    except subprocess.TimeoutExpired:
        logging.error(f"Ingest script timed out for {repo_name}")
    except Exception as e:
        logging.error(f"Failed to ingest results for {repo_name}: {e}")
    
    # 8. Cleanup
    # -------------------------------------------------------------------------
    if not config.KEEP_CLONES:
        try:
            shutil.rmtree(repo_path, ignore_errors=True)
            logging.info(f"Cleaned up {repo_path}")
        except Exception as e:
            logging.warning(f"Failed to cleanup {repo_path}: {e}")

def run_safety_scan(requirements_path, repo_name, report_dir):
    """Run safety scan on requirements file with DOE self-annealing.

    Self-healing behaviours:
    - Checks cooldown before running (skips if scanner recently failed repeatedly)
    - Adjusts timeout dynamically based on observed failures
    - Falls back through alternative commands: safety scan v3 -> safety check v2 -> pip-audit
    - Retries with back-off on transient network / rate-limit errors
    - Records all corrections for audit trail
    """
    output_path = os.path.join(report_dir, f"{repo_name}_safety.txt")

    # Self-annealing: check cooldown
    skip, reason = scanner_annealing.should_skip("safety")
    if skip:
        print(f"[auditgh]   ⏸ safety: skipped ({reason})", flush=True)
        logging.info(f"Safety scan skipped for {repo_name}: {reason}")
        with open(output_path, "w") as f:
            f.write(f"Safety scan skipped (self-annealing): {reason}\n")
        return subprocess.CompletedProcess(
            args=["safety"], returncode=0,
            stdout='{"scanned": [], "affected_packages": {}, "vulnerabilities": []}',
            stderr=""
        )

    logging.info(f"Running Safety scan for {repo_name}...")

    # Try each fallback command until one succeeds
    while True:
        fallback = scanner_annealing.get_safety_fallback()
        # Build command, substituting the requirements path placeholder
        cmd = [arg.replace("{requirements}", requirements_path) for arg in fallback["cmd"]]
        timeout = scanner_annealing.get_timeout("safety")

        try:
            logging.debug(f"Running command ({fallback['label']}, timeout={timeout}s): {' '.join(cmd)}")

            if PROGRESS_MONITOR_AVAILABLE:
                result = run_with_progress_monitoring(
                    cmd=cmd,
                    repo_name=repo_name,
                    scanner_name="safety",
                    cwd=None,
                    timeout=timeout,
                )
            else:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout
                )

            # Success path
            if result.returncode == 0:
                scanner_annealing.record_success("safety")

                if not result.stdout.strip():
                    logging.debug("No vulnerabilities found in safety scan")
                    return subprocess.CompletedProcess(
                        args=cmd, returncode=0,
                        stdout='{"scanned": [], "affected_packages": {}, "vulnerabilities": []}',
                        stderr=result.stderr,
                    )

                with open(output_path, "w") as f:
                    f.write(result.stdout or "")
                return result

            # Non-zero exit — let self-annealing decide what to do
            correction = scanner_annealing.record_failure(
                "safety", result.stderr, result.returncode, repo_name
            )

            if correction["should_retry"] and correction["action"] == "retry_with_backoff":
                backoff = 2 ** scanner_annealing._get_state("safety")["failures"]
                time.sleep(min(backoff, 30))
                continue  # retry same command

            if correction["action"] == "increase_timeout":
                continue  # retry same command with bigger timeout

            # Try next fallback command
            if scanner_annealing.advance_safety_fallback():
                continue

            # All fallbacks exhausted — write what we have and return
            with open(output_path, "w") as f:
                f.write(result.stdout or "")
                if result.stderr:
                    f.write(f"\n[ERROR] stderr output:\n{result.stderr}")
                f.write(f"\n[WARNING] Safety scan completed with non-zero exit code ({result.returncode})")
                f.write(f"\n[SELF-ANNEALING] All fallback commands exhausted")
            logging.warning(f"Safety scan: all fallbacks exhausted for {repo_name}")
            return result

        except subprocess.TimeoutExpired:
            print(f"[auditgh]   ⏱ safety: timed out after {timeout}s ({fallback['label']})", flush=True)
            correction = scanner_annealing.record_failure(
                "safety", "timed out", -9, repo_name
            )
            if correction["should_retry"]:
                continue
            # Timeout exhausted for this command — try next fallback
            if scanner_annealing.advance_safety_fallback():
                continue
            # All fallbacks exhausted — mark incomplete and move on
            print(f"[auditgh]   ✗ safety: INCOMPLETE — not accessible (timed out)", flush=True)
            with open(output_path, "w") as f:
                f.write(f"[INCOMPLETE] Safety scan not accessible — timed out after {timeout}s\n")
                f.write(f"All fallback commands exhausted. Scanner may be unavailable.\n")
            return subprocess.CompletedProcess(
                args=cmd, returncode=1, stdout="", stderr=f"INCOMPLETE: timed out after {timeout}s"
            )

        except Exception as e:
            error_msg = f"Error running safety scan ({fallback['label']}): {e}"
            logging.error(error_msg)
            scanner_annealing.record_failure("safety", str(e), 1, repo_name)
            if scanner_annealing.advance_safety_fallback():
                continue
            with open(output_path, "w") as f:
                f.write(error_msg)
            return subprocess.CompletedProcess(
                args=cmd, returncode=1, stdout="", stderr=error_msg
            )

def run_semgrep_taint(repo_path: str, repo_name: str, report_dir: str, config_path: str) -> subprocess.CompletedProcess:
    """Run Semgrep taint-mode scan using a provided ruleset/config.

    Writes JSON and Markdown summaries to <repo>_semgrep_taint.*
    """
    output_json = os.path.join(report_dir, f"{repo_name}_semgrep_taint.json")
    output_md = os.path.join(report_dir, f"{repo_name}_semgrep_taint.md")
    os.makedirs(report_dir, exist_ok=True)
    cmd = ["semgrep", "--config", config_path, "--json", "--quiet", repo_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    with open(output_json, 'w') as f:
        f.write(result.stdout or "")
    try:
        data = json.loads(result.stdout or '{}')
    except Exception:
        data = {}
    # Minimal exploitable flows summary
    with open(output_md, 'w') as f:
        f.write("# Semgrep Taint-Mode (Exploitable Flows)\n\n")
        flows = data.get('results', []) if isinstance(data, dict) else []
        if not flows:
            f.write("No exploitable flows found or ruleset produced no results.\n")
        else:
            # show up to 10 flows with source->sink
            count = 0
            for r in flows:
                if count >= 10: break
                path = r.get('path','')
                m = r.get('extra',{}).get('message','')
                start = r.get('start',{}).get('line')
                end = r.get('end',{}).get('line')
                f.write(f"- {path}:{start}-{end} — {m}\n")
                count += 1
    return result

def run_pip_audit_scan(requirements_path, repo_name, report_dir):
    """Run pip-audit scan on requirements file and return the output."""
    output_path = os.path.join(report_dir, f"{repo_name}_pip_audit.md")
    logging.info(f"Running pip-audit scan for {repo_name}...")
    
    base_cmd = ["pip-audit", "-r", requirements_path]
    
    try:
        # First try with markdown output
        cmd = base_cmd + ["--output", "markdown"]
        # Use progress monitoring if available
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="pip-audit",
                cwd=None,
                timeout=3600
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
        
        # If markdown output fails, try with JSON and convert
        if result.returncode != 0 or not result.stdout.strip():
            logging.debug("Markdown output failed, trying JSON output")
            cmd = base_cmd + ["--format", "json"]
            json_result = subprocess.run(cmd, capture_output=True, text=True)
            
            if json_result.returncode == 0 and json_result.stdout.strip():
                try:
                    # Convert JSON to markdown
                    data = json.loads(json_result.stdout)
                    markdown = "# pip-audit Report\n\n"
                    
                    if "vulnerabilities" in data and data["vulnerabilities"]:
                        markdown += "## Vulnerabilities\n\n"
                        for vuln in data["vulnerabilities"]:
                            pkg = vuln.get("package", {})
                            markdown += f"### {pkg.get('name', 'Unknown')} {pkg.get('version', '')}\n"
                            markdown += f"- **ID:** {vuln.get('id', 'Unknown')}\n"
                            if "fix_versions" in vuln and vuln["fix_versions"]:
                                markdown += f"- **Fixed in:** {', '.join(vuln['fix_versions'])}\n"
                            if "details" in vuln:
                                markdown += f"\n{vuln['details']}\n"
                            markdown += "\n---\n\n"
                        else:
                            markdown += "No vulnerabilities found.\n"
                    
                    result = subprocess.CompletedProcess(
                        args=cmd,
                        returncode=0,
                        stdout=markdown,
                        stderr=json_result.stderr
                    )
                except json.JSONDecodeError:
                    result = json_result
        
        # Write the output to file
        with open(output_path, "w") as f:
            f.write(result.stdout or "")
            if result.stderr:
                f.write("\n[ERROR] stderr output:\n")
                f.write(result.stderr)
            
            if result.returncode != 0:
                f.write("\n[WARNING] pip-audit completed with non-zero exit code")
        
        if result.returncode != 0:
            logging.warning(f"pip-audit exited with code {result.returncode} for {repo_name}")
        
        return result

    except Exception as e:
        error_msg = f"Error running pip-audit: {e}"
        logging.error(error_msg)
        with open(output_path, "w") as f:
            f.write(error_msg)
        return subprocess.CompletedProcess(
            args=cmd, returncode=1,
            stdout="", stderr=error_msg
        )


def run_npm_audit(repo_path, repo_name, report_dir):
    """Run npm audit for Node.js projects."""
    output_path = os.path.join(report_dir, f"{repo_name}_npm_audit.json")
    logging.info(f"Running npm audit for {repo_name}...")
    
    if not os.path.exists(os.path.join(repo_path, "package.json")):
        return None
        
    try:
        cmd = ["npm", "audit", "--json"]
        # Use progress monitoring if available
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="npm",
                cwd=repo_path,
                timeout=3600
            )
        else:
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True
            )
        
        with open(output_path, "w") as f:
            f.write(result.stdout)
            
        # Convert to markdown (handle both legacy 'advisories' and modern 'vulnerabilities' schemas)
        md_output = os.path.join(report_dir, f"{repo_name}_npm_audit.md")
        try:
            data = json.loads(result.stdout)
            with open(md_output, "w") as f:
                f.write(f"# npm Audit Report\n\n")
                f.write(f"**Repository:** {repo_name}\n\n")

                # Summary from metadata if available
                metadata = data.get('metadata') or {}
                vulns_summary = metadata.get('vulnerabilities') or {}
                if vulns_summary:
                    f.write("## Summary\n\n")
                    for sev, count in vulns_summary.items():
                        f.write(f"- {sev.title()}: {count}\n")
                    total = sum(vulns_summary.values())
                    f.write(f"- Total: {total}\n\n")

                # Legacy schema: 'advisories'
                if isinstance(data.get('advisories'), dict) and data['advisories']:
                    f.write("## Vulnerabilities\n\n")
                    for adv in data['advisories'].values():
                        f.write(f"### {adv.get('module_name','unknown')} ({adv.get('vulnerable_versions','unknown')})\n")
                        f.write(f"**Severity:** {adv.get('severity','unknown').title()}\n")
                        f.write(f"**Vulnerable Versions:** {adv.get('vulnerable_versions','unknown')}\n")
                        f.write(f"**Fixed In:** {adv.get('patched_versions','None')}\n")
                        f.write(f"**Title:** {adv.get('title','No title')}\n")
                        overview = adv.get('overview') or adv.get('recommendation') or 'No overview'
                        f.write(f"**Overview:** {overview}\n")
                        if adv.get('url'):
                            f.write(f"**More Info:** {adv['url']}\n")
                        f.write("\n---\n\n")

                # Modern schema: 'vulnerabilities' is a dict keyed by package
                elif isinstance(data.get('vulnerabilities'), dict) and data['vulnerabilities']:
                    f.write("## Vulnerabilities\n\n")
                    for pkg, vuln in data['vulnerabilities'].items():
                        severity = (vuln.get('severity') or 'unknown').title()
                        rng = vuln.get('range') or vuln.get('vulnerable_versions') or 'unknown'
                        fix = vuln.get('fixAvailable')
                        if isinstance(fix, dict):
                            fixed_in = f"{fix.get('name', pkg)}@{fix.get('version','unknown')}"
                        elif fix is True:
                            fixed_in = 'Update to latest'
                        else:
                            fixed_in = 'No fix available'

                        title = ' | '.join(sorted({(i.get('title') if isinstance(i, dict) else str(i)) for i in (vuln.get('via') or []) if i})) or 'No title'
                        nodes = vuln.get('nodes') or []
                        sample_paths = '\n'.join(f"  - `{n}`" for n in nodes[:5]) if nodes else '  - (paths not provided)'

                        f.write(f"### {pkg}\n")
                        f.write(f"**Severity:** {severity}\n")
                        f.write(f"**Vulnerable Range:** {rng}\n")
                        f.write(f"**Fixed In:** {fixed_in}\n")
                        f.write(f"**Title(s):** {title}\n")
                        f.write(f"**Sample Paths:**\n{sample_paths}\n")
                        f.write("\n---\n\n")
                else:
                    f.write("## No vulnerabilities found\n")

        except json.JSONDecodeError:
            with open(md_output, "w") as f:
                f.write("Error parsing npm audit output\n")
                f.write(result.stderr or "No error details available")
                
        return result
        
    except Exception as e:
        logging.error(f"Error running npm audit: {e}")
        with open(output_path, "w") as f:
            f.write(f"Error running npm audit: {e}")
        return None

def run_govulncheck(repo_path, repo_name, report_dir):
    """Run govulncheck for Go projects."""
    output_path = os.path.join(report_dir, f"{repo_name}_govulncheck.json")
    logging.info(f"Running govulncheck for {repo_name}...")
    
    if not os.path.exists(os.path.join(repo_path, "go.mod")):
        return None
        
    try:
        cmd = ["govulncheck", "-json", "./..."]
        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True
        )
        
        with open(output_path, "w") as f:
            f.write(result.stdout)
            
        # Convert to markdown
        md_output = os.path.join(report_dir, f"{repo_name}_govulncheck.md")
        with open(md_output, "w") as f:
            f.write(f"# Go Vulnerability Check Report\n\n")
            f.write(f"**Repository:** {repo_name}\n\n")
            
            if result.stdout.strip():
                try:
                    for line in result.stdout.splitlines():
                        if line.strip():
                            vuln = json.loads(line)
                            if vuln.get("Type") == "vuln":
                                f.write(f"## {vuln.get('OSV', 'Unknown')}\n")
                                f.write(f"**Module:** {vuln.get('PkgPath', 'Unknown')}\n")
                                f.write(f"**Version:** {vuln.get('FoundIn', 'Unknown')}\n")
                                f.write(f"**Fixed In:** {vuln.get('FixedIn', 'Not fixed')}\n")
                                f.write(f"**Details:** {vuln.get('Details', 'No details')}\n")
                                f.write("\n---\n\n")
                except json.JSONDecodeError:
                    f.write("Error parsing govulncheck output\n")
                    f.write(result.stderr or "No error details available")
            else:
                f.write("## No vulnerabilities found\n")
                
        return result
        
    except Exception as e:
        logging.error(f"Error running govulncheck: {e}")
        with open(output_path, "w") as f:
            f.write(f"Error running govulncheck: {e}")
        return None
    finally:
        # Clean up the temporary directory if the clone failed
        if temp_dir and os.path.exists(temp_dir) and not os.path.isdir(os.path.join(temp_dir, repo_name)):
            logging.debug(f"Cleaning up temporary directory: {temp_dir}")
            shutil.rmtree(temp_dir, ignore_errors=True)

def run_bundle_audit(repo_path, repo_name, report_dir):
    """Run bundle audit for Ruby projects."""
    output_path = os.path.join(report_dir, f"{repo_name}_bundle_audit.txt")
    logging.info(f"Running bundle audit for {repo_name}...")
    
    if not os.path.exists(os.path.join(repo_path, "Gemfile.lock")):
        return None
        
    try:
        cmd = ["bundle", "audit", "--update"]
        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True
        )
        
        with open(output_path, "w") as f:
            f.write(result.stdout)
            if result.stderr:
                f.write("\n=== STDERR ===\n")
                f.write(result.stderr)
                
        return result
        
    except Exception as e:
        logging.error(f"Error running bundle audit: {e}")
        with open(output_path, "w") as f:
            f.write(f"Error running bundle audit: {e}")
        return None

def run_dependency_check(repo_path, repo_name, report_dir):
    """
    Run OWASP Dependency-Check for Java projects.
    
    Args:
        repo_path: Path to the repository
        repo_name: Name of the repository
        report_dir: Directory to save the report
        
    Returns:
        str: Path to the generated report or None if not applicable
    """
    output_dir = os.path.join(report_dir, f"{repo_name}_dependency_check")
    output_path = os.path.join(output_dir, "dependency-check-report.json")
    logging.info(f"Running OWASP Dependency-Check for {repo_name}...")
    
    # Check for Maven projects only - Gradle is handled by Trivy/Grype (much faster)
    # Old check included: ["pom.xml", "build.gradle", "build.gradle.kts"]
    java_project = os.path.exists(os.path.join(repo_path, "pom.xml"))
    if not java_project:
        return None
        
    try:
        # Skip if dependency-check is not installed
        # Prefer Python wrapper 'dependency-check' (dependency-check-py), fallback to shell script if present
        dc_bin = shutil.which("dependency-check") or shutil.which("dependency-check.sh")
        if not dc_bin:
            logging.info("OWASP Dependency-Check not found on PATH; skipping for this repository")
            return None
        os.makedirs(output_dir, exist_ok=True)
        # Common excludes to reduce noise and speed up
        excludes = [
            ".git/**", ".venv/**", "**/__pycache__/**", ".tox/**", "node_modules/**", "build/**", "dist/**"
        ]
        cmd = [dc_bin,
               "--project", repo_name,
               "--scan", repo_path,
               "--out", output_dir,
               "--format", "JSON",
               "--format", "JSON",
               # Enable all analyzers for deep scanning
               "--enableExperimental",
               ]
        # Add excludes
        for pattern in excludes:
            cmd += ["--exclude", pattern]
        # Prefer not to fail the whole scan due to minor issues
        # Enable Assembly analyzer
        # cmd += ["--disableAssembly"]
        
        # Ensure a cache/data directory for NVD to avoid repeated downloads
        env = os.environ.copy()
        data_dir = env.get("DC_DATA_DIR") or os.path.join(os.path.expanduser("~"), ".cache", "dependency-check")
        os.makedirs(data_dir, exist_ok=True)
        env["DC_DATA_DIR"] = data_dir
        
        logging.debug(f"Running Dependency-Check: {' '.join(cmd)}")
        
        # Run with progress monitoring
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env
        )
        
        # Register process for progress monitoring (if available)
        progress_monitor = None
        if PROGRESS_MONITOR_AVAILABLE:
            try:
                ps_process = psutil.Process(process.pid)
                progress_monitor = ProgressMonitor(
                    process=ps_process,
                    scanner_name="dependency-check",
                    min_cpu_threshold=1.0,
                    check_interval=30,
                    max_idle_time=180
                )
                register_process(repo_name, {
                    "pid": process.pid,
                    "progress_monitor": progress_monitor,
                    "scanner": "dependency-check"
                })
                logging.debug(f"Registered Dependency-Check process {process.pid} for progress monitoring")
            except Exception as monitor_err:
                logging.debug(f"Could not register progress monitor: {monitor_err}")
        
        try:
            # Read output with timeout (1 hour adaptive)
            stdout, stderr = process.communicate(timeout=3600)
            
            # Feed output to progress monitor
            if progress_monitor:
                for line in (stdout + stderr).splitlines():
                    progress_monitor.add_output(line)
            
            # Create CompletedProcess object
            result = subprocess.CompletedProcess(
                args=cmd,
                returncode=process.returncode,
                stdout=stdout if stdout else "",
                stderr=stderr if stderr else ""
            )
            
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            raise
        finally:
            # Unregister process
            if PROGRESS_MONITOR_AVAILABLE:
                unregister_process(repo_name)
        
        # Convert to markdown if the report was generated
        if os.path.exists(output_path):
            md_output = os.path.join(report_dir, f"{repo_name}_dependency_check.md")
            try:
                with open(output_path, 'r') as f:
                    data = json.load(f)
                    
                with open(md_output, 'w') as f:
                    f.write(f"# OWASP Dependency-Check Report\n\n")
                    f.write(f"**Repository:** {repo_name}\n")
                    f.write(f"**Generated:** {data.get('projectInfo', {}).get('reportDate', 'Unknown')}\n\n")
                    
                    if 'dependencies' in data:
                        vuln_count = sum(1 for dep in data['dependencies'] 
                                      if 'vulnerabilities' in dep and dep['vulnerabilities'])
                        f.write(f"## Summary\n")
                        f.write(f"- **Total Dependencies:** {len(data['dependencies'])}\n")
                        f.write(f"- **Vulnerable Dependencies:** {vuln_count}\n\n")
                        
                        if vuln_count > 0:
                            f.write("## Vulnerable Dependencies\n\n")
                            for dep in data['dependencies']:
                                if 'vulnerabilities' in dep and dep['vulnerabilities']:
                                    f.write(f"### {dep.get('fileName', 'Unknown')}\n")
                                    f.write(f"**Version:** {dep.get('version', 'Unknown')}\n")
                                    f.write(f"**Vulnerabilities:** {len(dep['vulnerabilities'])}\n\n")
                                    
                                    for vuln in dep['vulnerabilities']:
                                        f.write(f"#### {vuln.get('name', 'Unknown')}\n")
                                        f.write(f"**Severity:** {vuln.get('severity', 'Unknown').title()}\n")
                                        f.write(f"**CVSS Score:** {vuln.get('cvssv3', {}).get('baseScore', 'N/A')}\n")
                                        f.write(f"**Description:** {vuln.get('description', 'No description')}\n")
                                        f.write(f"**Solution:** {vuln.get('solution', 'No solution provided')}\n")
                                        f.write("\n---\n\n")
                    else:
                        f.write("## No vulnerabilities found\n")
                        
            except Exception as e:
                logging.error(f"Error processing dependency-check report: {e}")
                with open(md_output, 'w') as f:
                    f.write(f"Error processing dependency-check report: {e}")
        
        return result
        
    except Exception as e:
        logging.error(f"Error running OWASP Dependency-Check: {e}")
        with open(os.path.join(report_dir, f"{repo_name}_dependency_check_error.txt"), 'w') as f:
            f.write(f"Error running OWASP Dependency-Check: {e}")
        return None

def write_code_snippet(f, finding):
    """Helper function to write code snippet with line numbers."""
    extra = finding.get('extra', {})
    if not ('lines' in extra and extra['lines']):
        return
    
    try:
        if 'lines' in extra and extra['lines']:
            first_line = extra['lines'][0]
            if isinstance(first_line, dict):
                lang = first_line.get('language', '')
            else:
                lang = '' # Handle case where lines might not be a dict
    except Exception:
        lang = ''
    if isinstance(extra['lines'][0], dict):
        content = extra['lines'][0].get('content', '')
    else:
        content = ''
    start = int(finding.get('start', {}).get('line', 1)) - 1
    code_lines = [f"{i + start + 1}: {line}" for i, line in enumerate(content.split('\n'))]
    f.write(f"```{lang}\n")
    f.write("\n".join(code_lines))
    f.write("\n```\n\n")

def run_semgrep_scan(repo_path: str, repo_name: str, report_dir: str, db_session=None, repository_id: str=None) -> Optional[subprocess.CompletedProcess]:
    """Run semgrep scan on the repository and save results.
    
    Args:
        repo_path: Path to the repository
        repo_name: Name of the repository
        report_dir: Directory to save the report
        
    Returns:
        CompletedProcess or None if scan couldn't be run
    """
    if not os.path.isdir(repo_path):
        logging.error(f"Repository directory not found: {repo_path}")
        return None
        
    output_path = os.path.join(report_dir, f"{repo_name}_semgrep.json")
    md_output = os.path.join(report_dir, f"{repo_name}_semgrep.md")
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    logging.info(f"Running Semgrep scan for {repo_name}...")
    
    # Initialize with failure state
    result = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="Semgrep scan failed to initialize"
    )
    
    # Initialize cmd variable at function scope
    cmd = None
    
    # Ensure the report directory exists
    os.makedirs(report_dir, exist_ok=True)
    
    # Initialize result with failure state in case of early return
    result = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr=f"Repository directory not found or not accessible: {repo_path}"
    )
    
    # Check if repository directory exists and is accessible
    if not os.path.isdir(repo_path):
        error_msg = f"Repository directory not found or not accessible: {repo_path}"
        logging.error(error_msg)
        with open(md_output, 'w') as f:
            f.write(f"# Semgrep Scan Failed\n\n{error_msg}\n")
        return result
        
    # Create a clean environment for subprocess
    env = os.environ.copy()
    # Ensure HOME is set to a valid directory
    if 'HOME' not in env or not os.path.isdir(env.get('HOME', '')):
        env['HOME'] = os.path.expanduser('~')
    # Set a minimal PATH if not set
    if 'PATH' not in env:
        env['PATH'] = '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'
    
    try:
        # First, check if semgrep is installed
        semgrep_cmd = "semgrep"
        if not shutil.which(semgrep_cmd):
            # Try with python -m semgrep as fallback
            semgrep_cmd = f"{sys.executable} -m semgrep"
            if not shutil.which(sys.executable):
                raise RuntimeError("semgrep is not installed. Please install it with 'pip install semgrep'")
        
        # Build base command
        cmd = [
            "semgrep", "scan",
            "--config", "p/security-audit",
            "--config", "p/ci",
            "--config", "p/owasp-top-ten",
            "--config", "p/security-audit",
            "--config", "p/ci",
            "--config", "p/owasp-top-ten",
            "--config", "p/secrets",
            "--config", "p/command-injection",
            "--config", "p/sql-injection",
            "--config", "p/xss",
            "--config", "p/jwt",
            "--config", "p/docker",
            "--config", "p/golang",
            "--config", "p/python",
            "--metrics", "off",  # Disable metrics to avoid network calls
            "--timeout", "300",  # 5 minute timeout per file
            "--timeout-threshold", "3",  # Max number of timeouts before failing
            "--max-memory", "2000",  # 2GB memory limit to prevent OOM (was 6000)
            "--jobs", "1",  # Force single-threaded to reduce memory pressure
            "--max-target-bytes", "5000000",  # 5MB file size limit
            "--verbose"
        ]
        # Auto-include local custom rules in semgrep-rules/
        try:
            project_root = os.path.dirname(os.path.abspath(__file__))
            rules_dir = os.path.join(project_root, "semgrep-rules")
            if os.path.isdir(rules_dir):
                for fname in os.listdir(rules_dir):
                    if fname.endswith((".yml", ".yaml")):
                        cmd += ["--config", os.path.join(rules_dir, fname)]
        except Exception as _semgrep_rules_err:
            logging.debug(f"Skipping custom semgrep rules due to error: {_semgrep_rules_err}")
        # Output and execution options
        # Output and execution options
        cmd += [
            "--json",
            "--output", output_path
        ]
        
        # Log environment and version info for diagnostics
        try:
            env_info = {
                'python': sys.version,
                'platform': sys.platform,
                'pwd': os.getcwd(),
                'path': os.environ.get('PATH', '')
            }
            logging.debug(f"Environment info: {json.dumps(env_info, indent=2)}")
            
            # Get semgrep version
            if shutil.which("semgrep"):
                ver_cmd = ["semgrep", "--version"]
            else:
                ver_cmd = [sys.executable, "-m", "semgrep", "--version"]
            
            try:
                ver_result = subprocess.run(
                    ver_cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False
                )
                if ver_result.returncode == 0:
                    logging.debug(f"Semgrep version: {ver_result.stdout.strip() or ver_result.stderr.strip()}")
                else:
                    logging.debug(f"Semgrep version check returned non-zero: {ver_result.stderr.strip()}")
            except (subprocess.SubprocessError, FileNotFoundError) as ve:
                logging.debug(f"Could not get semgrep version: {str(ve)}")
        except Exception as e:
            logging.debug(f"Could not gather version info: {str(e)}")
        # Prepare environment
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'  # Ensure output is unbuffered
        
        # Set a reasonable PATH if not set
        if 'PATH' not in env:
            env['PATH'] = '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'
            
        # Set HOME if not set
        if 'HOME' not in env:
            env['HOME'] = os.path.expanduser('~')
        
        # Log the command being run
        safe_cmd = ' '.join(shlex.quote(arg) for arg in cmd)
        logging.debug(f"Running command: {safe_cmd} in directory: {repo_path}")
        
        try:
            # Double check directory exists before running
            if not os.path.isdir(repo_path):
                raise FileNotFoundError(f"Repository directory not found: {repo_path}")

            # Run semgrep with progress monitoring
            process = subprocess.Popen(
                cmd,
                cwd=repo_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env
            )
            
            # Register process for progress monitoring (if available)
            progress_monitor = None
            if PROGRESS_MONITOR_AVAILABLE:
                try:
                    ps_process = psutil.Process(process.pid)
                    progress_monitor = ProgressMonitor(
                        process=ps_process,
                        scanner_name="semgrep",
                        min_cpu_threshold=1.0,
                        check_interval=30,
                        max_idle_time=180
                    )
                    register_process(repo_name, {
                        "pid": process.pid,
                        "progress_monitor": progress_monitor,
                        "scanner": "semgrep"
                    })
                    logging.debug(f"Registered Semgrep process {process.pid} for progress monitoring")
                except Exception as monitor_err:
                    logging.debug(f"Could not register progress monitor: {monitor_err}")
            
            # Collect output while monitoring progress
            stdout_lines = []
            stderr_lines = []
            
            try:
                # Read output with timeout
                stdout, stderr = process.communicate(timeout=3600)  # 1 hour timeout (adaptive)
                stdout_lines = stdout.splitlines() if stdout else []
                stderr_lines = stderr.splitlines() if stderr else []
                
                # Feed output to progress monitor
                if progress_monitor:
                    for line in stdout_lines + stderr_lines:
                        progress_monitor.add_output(line)
                
                returncode = process.returncode
                
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                raise
            finally:
                # Unregister process
                if PROGRESS_MONITOR_AVAILABLE:
                    unregister_process(repo_name)
            
            # Create CompletedProcess object
            result = subprocess.CompletedProcess(
                args=cmd,
                returncode=returncode,
                stdout=stdout if stdout else "",
                stderr=stderr if stderr else ""
            )
            
            # Log stderr if there was any output
            if result.stderr.strip():
                logging.debug(f"Semgrep stderr: {result.stderr.strip()}")
                
        except subprocess.TimeoutExpired:
            error_msg = "Semgrep scan timed out after 10 minutes"
            logging.error(error_msg)
            with open(md_output, 'w') as f:
                f.write(f"# Semgrep Scan Failed\n\n{error_msg}\n")
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=1,
                stdout="",
                stderr=error_msg
            )
            
        except Exception as e:
            error_msg = f"Error running semgrep: {str(e)}"
            logging.error(error_msg, exc_info=True)
            with open(md_output, 'w') as f:
                f.write(f"# Semgrep Scan Failed\n\n{error_msg}\n")
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=1,
                stdout="",
                stderr=error_msg
            )
        
        # Handle output file - Semgrep sometimes writes to stdout/stderr instead of the file
        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            # Try to parse JSON from stdout or stderr
            json_source = None
            if result.stdout and result.stdout.strip():
                json_source = result.stdout
                source_name = "stdout"
            elif result.stderr and result.stderr.strip():
                json_source = result.stderr
                source_name = "stderr"
            
            if json_source:
                try:
                    # Semgrep may output JSON to stdout or stderr
                    output_json = json.loads(json_source)
                    with open(output_path, 'w') as f:
                        json.dump(output_json, f, indent=2)
                    logging.info(f"Parsed Semgrep JSON from {source_name} for {repo_name}")
                except json.JSONDecodeError as json_err:
                    logging.debug(f"Failed to parse JSON from {source_name}: {json_err}")
                    # Not JSON, create fallback based on return code
                    if result.returncode in (0, 1, 2):
                        # Successful scan but no JSON output
                        with open(output_path, 'w') as f:
                            json.dump({"results": []}, f)
                    else:
                        # Error case
                        with open(output_path, 'w') as f:
                            json.dump({
                                "errors": [{
                                    "code": result.returncode,
                                    "message": result.stderr or result.stdout or "Unknown error during semgrep scan"
                                }],
                                "results": []
                            }, f)
            else:
                # No stdout, create fallback
                if result.returncode in (0, 1, 2):
                    with open(output_path, 'w') as f:
                        json.dump({"results": []}, f)
                else:
                    with open(output_path, 'w') as f:
                        json.dump({
                            "errors": [{
                                "code": result.returncode,
                                "message": result.stderr or "Unknown error during semgrep scan"
                            }],
                            "results": []
                        }, f)
        
        # Ensure output file is valid JSON
        try:
            with open(output_path, 'r') as f:
                json.load(f)  # Will raise JSONDecodeError if invalid
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in Semgrep output file: {str(e)}")
            # Create a valid error result
            with open(output_path, 'w') as f:
                json.dump({
                    "errors": [{
                        "code": -1,
                        "message": f"Invalid scan output: {str(e)}"
                    }],
                    "results": []
                }, f)
        
        # Generate markdown report
        # Semgrep exit codes: 0=no findings, 1=findings, 2=blocking findings
        # All three are successful scans, not errors
        with open(md_output, 'w') as f:
            f.write(f"# Semgrep Scan Results\n\n")
            f.write(f"**Repository:** {repo_name}\n")
            f.write(f"**Scan Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if result.returncode in (0, 1, 2):
                if os.path.exists(output_path):
                    try:
                        with open(output_path, 'r') as json_file:
                            semgrep_results = json.load(json_file)
                        
                        if 'results' in semgrep_results and semgrep_results['results']:
                            # Persist to database
                            if db_session and repository_id:
                                try:
                                    normalized_findings = []
                                    for item in semgrep_results['results']:
                                        normalized_findings.append({
                                            "title": item.get('extra', {}).get('message', 'Semgrep Issue').splitlines()[0],
                                            "description": item.get('extra', {}).get('message', ''),
                                            "severity": item.get('extra', {}).get('severity', 'WARNING'),
                                            "file_path": item.get('path'),
                                            "line_start": item.get('start', {}).get('line'),
                                            "line_end": item.get('end', {}).get('line'),
                                            "code_snippet": item.get('extra', {}).get('lines', ''),
                                            "rule_id": item.get('check_id'),
                                            "cwe_id": item.get('extra', {}).get('metadata', {}).get('cwe', [None])[0] if isinstance(item.get('extra', {}).get('metadata', {}).get('cwe'), list) else None
                                        })
                                    _persist_scan_findings(db_session, repository_id, normalized_findings, "semgrep")
                                except Exception as e:
                                    logging.error(f"Failed to process Semgrep findings for DB: {e}")

                            f.write("## Findings Summary\n\n")
                            f.write(f"Found {len(semgrep_results['results'])} potential issues.\n\n")
                            
                            # Group by severity
                            by_severity = {}
                            for finding in semgrep_results['results']:
                                severity = finding.get('extra', {}).get('severity', 'WARNING')
                                by_severity[severity] = by_severity.get(severity, 0) + 1
                            
                            if by_severity:
                                f.write("### Issues by Severity\n\n")
                                for severity, count in sorted(by_severity.items()):
                                    f.write(f"- **{severity.capitalize()}**: {count} issues\n")
                                f.write("\n")
                            
                            # Show top 5 findings
                            f.write("## Top 5 Findings\n\n")
                            for i, finding in enumerate(semgrep_results['results'][:5], 1):
                                path = finding.get('path', 'unknown')
                                line = finding.get('start', {}).get('line', '?')
                                message = finding.get('extra', {}).get('message', 'No message')
                                severity = finding.get('extra', {}).get('severity', 'WARNING')
                                
                                f.write(f"### {i}. {severity.upper()}: {message.splitlines()[0]}\n")
                                f.write(f"**File:** `{path}:{line}`  \n")
                                f.write(f"**Rule ID:** `{finding.get('check_id', 'unknown')}`  \n")
                                f.write(f"**Severity:** {severity.capitalize()}  \n\n")
                                
                                # Show code snippet if available
                                write_code_snippet(f, finding)
                                f.write("---\n\n")
                            
                            if len(semgrep_results['results']) > 5:
                                f.write(f"*And {len(semgrep_results['results']) - 5} more findings...*\n\n")
                        else:
                            f.write("## No issues found! ✅\n")
                    
                    except json.JSONDecodeError as e:
                        f.write("Error: Could not parse semgrep JSON output\n")
                        f.write("```\n")
                        f.write(str(e))
                        f.write("\n```\n")
                        return result
                else:
                    f.write("## No issues found! ✅\n")
            else:
                f.write("## Scan Failed\n\n")
                f.write("Semgrep encountered an error during the scan.\n\n")
                f.write("### Error Details\n")
                f.write("```\n")
                # Include both stderr and stdout for better diagnostics
                if result.stderr:
                    f.write(result.stderr)
                    f.write("\n")
                if result.stdout:
                    f.write(result.stdout)
                if not (result.stderr or result.stdout):
                    f.write("No error details available")
                f.write("\n```\n")
        
        logging.info(f"Semgrep scan for {repo_name} finished with return code: {result.returncode}")
        return result
            
    except Exception as e:
        error_msg = f"Error running semgrep: {str(e)}"
        logging.error(f"{error_msg}\n{traceback.format_exc()}")
        with open(md_output, 'w') as f:
            f.write(f"# Semgrep Scan Failed\n\n{error_msg}\n\n**Error Details:**\n```\n{traceback.format_exc()}\n```")
        return subprocess.CompletedProcess(
            args=cmd if cmd is not None else [],
            returncode=1,
            stdout="",
            stderr=error_msg
        )

def get_repo_contributors(session: requests.Session, repo_full_name: str) -> List[Dict[str, Any]]:
    """
    Get top 5 contributors for a repository with detailed information.
    
    Args:
        session: The requests session to use for the API call
        repo_full_name: Full name of the repository (e.g., 'owner/repo')
        
    Returns:
        List of contributor dictionaries with detailed information
    """
    try:
        logging.info(f"Fetching contributors for {repo_full_name}")

        # Get basic contributor information
        url = f"{config.GITHUB_API}/repos/{repo_full_name}/contributors?per_page=5&anon=false"
        response = session.get(url, headers=config.HEADERS)

        # Log response status and headers for debugging
        logging.debug(f"Response status: {response.status_code}")
        logging.debug(f"Response headers: {dict(response.headers)}")

        # Check for error status codes BEFORE parsing
        if response.status_code == 409:
            logging.warning(f"Repository conflict (409) for {repo_full_name}. Repository may be empty or have issues. Skipping contributors.")
            return []
        elif response.status_code == 404:
            logging.warning(f"Repository not found (404): {repo_full_name}. Skipping contributors.")
            return []
        elif response.status_code >= 400:
            logging.error(f"HTTP {response.status_code} error for {repo_full_name}: {response.text[:200]}")
            return []

        # Check for empty response body before parsing
        if not response.text or response.text.strip() == '':
            logging.warning(f"Empty response body for {repo_full_name} (status {response.status_code}). Skipping contributors.")
            return []

        # Handle rate limiting before raising HTTP errors
        rate_limit = get_rate_limit_headers(response)
        remaining = int(rate_limit.get('remaining', 0))

        if remaining < 10:
            reset_time = int(rate_limit.get('reset', 0))
            wait_time = max(0, reset_time - int(time.time())) + 5  # Add 5 second buffer
            if wait_time > 0:
                logging.warning(f"Approaching rate limit. Remaining: {remaining}. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                # Retry the request after waiting
                response = session.get(url, headers=config.HEADERS)
                # Check retry response status
                if response.status_code == 409:
                    logging.warning(f"Repository conflict (409) after retry for {repo_full_name}. Skipping contributors.")
                    return []
                elif response.status_code >= 400:
                    logging.error(f"HTTP {response.status_code} error after retry for {repo_full_name}")
                    return []
                # Check for empty response on retry
                if not response.text or response.text.strip() == '':
                    logging.warning(f"Empty response body after retry for {repo_full_name}. Skipping contributors.")
                    return []

        # Log response content for debugging
        response_text = response.text
        logging.debug(f"Response content (first 500 chars): {response_text[:500]}")

        try:
            contributors = response.json()
        except json.JSONDecodeError as json_err:
            logging.warning(f"Failed to parse JSON response for {repo_full_name}: {json_err} (status: {response.status_code})")
            return []
            
        if not isinstance(contributors, list):
            logging.error(f"Unexpected response format for contributors. Expected list, got: {type(contributors)}")
            logging.error(f"Response content: {contributors}")
            return []
            
        # Get additional user details for each contributor
        detailed_contributors = []
        for contributor in contributors[:5]:  # Limit to top 5
            try:
                if 'login' in contributor:  # Skip anonymous contributors
                    user_url = f"{config.GITHUB_API}/users/{contributor['login']}"
                    user_response = session.get(user_url, headers=config.HEADERS)
                    user_response.raise_for_status()
                    user_data = user_response.json()
                    
                    # Combine basic contributor info with detailed user data
                    detailed_contributor = {
                        'login': contributor.get('login'),
                        'id': contributor.get('id'),
                        'contributions': contributor.get('contributions', 0),
                        'avatar_url': contributor.get('avatar_url', ''),
                        'html_url': contributor.get('html_url', ''),
                        'name': user_data.get('name', ''),
                        'company': user_data.get('company', ''),
                        'location': user_data.get('location', ''),
                        'public_repos': user_data.get('public_repos', 0),
                        'followers': user_data.get('followers', 0),
                        'created_at': user_data.get('created_at', ''),
                        'updated_at': user_data.get('updated_at', '')
                    }
                    detailed_contributors.append(detailed_contributor)
                    
                    # Be nice to the API
                    time.sleep(0.5)
                    
            except Exception as user_error:
                logging.warning(f"Error getting details for user {contributor.get('login')}: {user_error}")
                # Fall back to basic info if detailed fetch fails
                detailed_contributors.append(contributor)
        
        return detailed_contributors

    except Exception as e:
        logging.error(f"Unexpected error getting contributors for {repo_full_name}: {e}", exc_info=True)
        return []

def get_repo_languages(session: requests.Session, repo_full_name: str) -> List[Tuple[str, int]]:
    """Get programming languages used in the repository, sorted by bytes of code."""
    try:
        url = f"{config.GITHUB_API}/repos/{repo_full_name}/languages"
        response = session.get(url, headers=config.HEADERS)
        response.raise_for_status()
        languages = response.json()
        return sorted(languages.items(), key=lambda x: x[1], reverse=True)[:5]
    except Exception as e:
        logging.error(f"Error getting languages for {repo_full_name}: {e}")
        return []

def analyze_commit_messages(session: requests.Session, repo_full_name: str) -> Dict[str, Any]:
    """Analyze commit messages to get last update date and top 5 commit reasons."""
    try:
        # Get the latest commit
        commits_url = f"{config.GITHUB_API}/repos/{repo_full_name}/commits?per_page=1"
        commits_response = session.get(commits_url, headers=config.HEADERS)

        # Check for error status codes BEFORE parsing
        if commits_response.status_code == 409:
            logging.warning(f"Repository conflict (409) for {repo_full_name}. Repository may be empty or have no commits.")
            return {
                'last_update': 'Unknown',
                'top_commit_reasons': []
            }
        elif commits_response.status_code == 404:
            logging.warning(f"Repository not found (404): {repo_full_name}")
            return {
                'last_update': 'Unknown',
                'top_commit_reasons': []
            }
        elif commits_response.status_code >= 400:
            logging.error(f"HTTP {commits_response.status_code} error for {repo_full_name}: {commits_response.text[:200]}")
            return {
                'last_update': 'Unknown',
                'top_commit_reasons': []
            }

        try:
            commits_data = commits_response.json()
            last_commit = commits_data[0] if commits_data and isinstance(commits_data, list) else None
        except (json.JSONDecodeError, IndexError, TypeError) as e:
            logging.warning(f"Failed to parse commits response for {repo_full_name}: {e}")
            return {
                'last_update': 'Unknown',
                'top_commit_reasons': []
            }

        last_update = last_commit['commit']['committer']['date'] if last_commit else "Unknown"

        # Get recent commits for analysis (last 100)
        all_commits_url = f"{config.GITHUB_API}/repos/{repo_full_name}/commits?per_page=100"
        all_commits_response = session.get(all_commits_url, headers=config.HEADERS)

        # Check status before parsing
        if all_commits_response.status_code >= 400:
            logging.warning(f"Could not fetch commit history for {repo_full_name}: HTTP {all_commits_response.status_code}")
            return {
                'last_update': last_update,
                'top_commit_reasons': []
            }

        # Simple commit message analysis
        try:
            all_commits_data = all_commits_response.json()
            if not isinstance(all_commits_data, list):
                logging.warning(f"Unexpected commit history format for {repo_full_name}")
                return {
                    'last_update': last_update,
                    'top_commit_reasons': []
                }
            commit_messages = [commit['commit']['message'] for commit in all_commits_data]
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logging.warning(f"Failed to parse commit history for {repo_full_name}: {e}")
            return {
                'last_update': last_update,
                'top_commit_reasons': []
            }

        common_prefixes = defaultdict(int)

        for msg in commit_messages:
            # Extract first few words as a prefix
            words = msg.strip().split()
            if words:
                prefix = ' '.join(words[:3]).lower()
                common_prefixes[prefix] += 1

        top_commit_reasons = sorted(common_prefixes.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            'last_update': last_update,
            'top_commit_reasons': top_commit_reasons
        }
    except Exception as e:
        logging.error(f"Unexpected error analyzing commits for {repo_full_name}: {e}")
        return {
            'last_update': 'Unknown',
            'top_commit_reasons': []
        }

def get_top_vulnerabilities(scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract top 5 vulnerabilities from scan results (Safety, npm audit, and Grype)."""
    vulnerabilities: List[Dict[str, Any]] = []

    # Process Safety results
    try:
        res = scan_results.get('safety')
        if res and res.stdout:
            safety_data = json.loads(res.stdout)
            for vuln in safety_data.get('vulnerabilities', [])[:10]:
                vulnerabilities.append({
                    'type': 'Python',
                    'name': vuln.get('package_name', 'Unknown'),
                    'severity': (vuln.get('severity') or 'unknown'),
                    'affected_versions': vuln.get('affected_versions', 'Unknown'),
                    'fixed_in': vuln.get('patched_versions', 'None'),
                    'remediation': f"Update to version {vuln.get('patched_versions', 'latest')}"
                })
    except Exception as e:
        logging.error(f"Error processing safety results: {e}")

    # Process npm audit results (legacy format; modern npm uses audit levels differently)
    try:
        res = scan_results.get('npm_audit')
        if res and res.stdout:
            npm_data = json.loads(res.stdout)
            advisories = (npm_data.get('advisories') or {}) if isinstance(npm_data, dict) else {}
            for adv in list(advisories.values())[:10]:
                vulnerabilities.append({
                    'type': 'Node',
                    'name': adv.get('module_name', 'Unknown'),
                    'severity': (adv.get('severity') or 'unknown'),
                    'affected_versions': adv.get('vulnerable_versions', 'Unknown'),
                    'fixed_in': ', '.join(adv.get('patched_versions', [])) if isinstance(adv.get('patched_versions'), list) else adv.get('patched_versions', 'None'),
                    'remediation': f"Update {adv.get('module_name','package')} to a fixed version"
                })
    except Exception as e:
        logging.error(f"Error processing npm audit results: {e}")

    # Process Trivy filesystem results (augment Top 5 with FS scan vulns)
    try:
        trivy = scan_results.get('trivy_fs') or {}
        results = trivy.get('Results', []) if isinstance(trivy, dict) else []
        kev_map = load_kev()
        epss_map = load_epss()
        for res in results:
            for v in res.get('Vulnerabilities', []) or []:
                vid = v.get('VulnerabilityID') or ''
                name = v.get('PkgName') or 'unknown'
                sev = (v.get('Severity') or 'unknown').lower()
                affected = v.get('InstalledVersion') or ''
                fixed_in = v.get('FixedVersion') or ''
                vulnerabilities.append({
                    'type': 'Trivy',
                    'name': name,
                    'severity': sev,
                    'affected_versions': affected,
                    'fixed_in': fixed_in,
                    'kev': bool(kev_map.get(vid)) if vid.startswith('CVE-') else False,
                    'epss': float(epss_map.get(vid, 0.0)) if vid.startswith('CVE-') else 0.0,
                    'remediation': f"Update {name} to a fixed version"
                })
    except Exception as e:
        logging.error(f"Error processing trivy fs results: {e}")

    # Process Grype repo results (JSON already loaded/enriched by caller if present)
    try:
        grype_data = scan_results.get('grype') or {}
        matches = grype_data.get('matches', []) if isinstance(grype_data, dict) else []
        for m in matches:
            v = m.get('vulnerability', {})
            vuln = m.get('vulnerability', {})
            art = m.get('artifact', {})
            sev = (vuln.get('severity') or 'Unknown').lower()
            pkg = art.get('name') or 'Unknown'
            ver = art.get('version') or 'Unknown'
            fix = vuln.get('fix', {}) or {}
            fix_versions = fix.get('versions') or []
            fixed_in = ', '.join(fix_versions) if isinstance(fix_versions, list) and fix_versions else fix.get('state', 'None')
            # Threat intel
            cve = vuln.get('id') or ''
            kev = False
            epss = None
            try:
                ti = m.get('_threat', {})
                kev = bool(ti.get('kev'))
                epss = ti.get('epss')
            except Exception:
                pass
            vulnerabilities.append({
                'type': 'Dependency',
                'name': pkg,
                'severity': sev,
                'affected_versions': ver,
                'fixed_in': fixed_in,
                'remediation': f"Update {pkg} to a fixed version" if fixed_in and fixed_in != 'None' else "Monitor vendor guidance",
                'cve': cve,
                'kev': kev,
                'epss': epss
            })
    except Exception as e:
        logging.error(f"Error processing grype results: {e}")

    # Deduplicate entries across sources
    seen = set()
    unique_vulns: List[Dict[str, Any]] = []
    for v in vulnerabilities:
        key = (
            (v.get('type') or '').lower(),
            (v.get('name') or '').lower(),
            (v.get('affected_versions') or '').lower(),
            (v.get('severity') or '').lower(),
            (v.get('fixed_in') or '').lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        unique_vulns.append(v)

    # Sort by KEV, EPSS, then severity (critical, high, moderate/medium, low, unknown)
    severity_order = {'critical': 0, 'high': 1, 'moderate': 2, 'medium': 2, 'low': 3, 'unknown': 4}
    def _rank(v: Dict[str, Any]):
        kev = 0 if not v.get('kev') else -1  # kev=True gets higher priority
        epss_rank = -float(v.get('epss') or 0.0)
        sev_rank = severity_order.get((v.get('severity') or 'unknown').lower(), 5)
        return (kev, epss_rank, sev_rank)
    unique_vulns.sort(key=_rank)

    return unique_vulns[:5]

# -------------------- Threat Intel (KEV / EPSS) --------------------

def _cache_dir() -> str:
    d = os.path.join('.cache')
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass
    return d

@lru_cache(maxsize=1)
def load_kev() -> Dict[str, bool]:
    kev_map: Dict[str, bool] = {}
    url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    try:
        r = requests.get(url, timeout=10)
        if r.ok:
            data = r.json()
            for item in data.get('vulnerabilities', []):
                cve = item.get('cveID')
                if cve:
                    kev_map[cve] = True
            # cache file
            with open(os.path.join(_cache_dir(), 'kev.json'), 'w') as f:
                json.dump(list(kev_map.keys()), f)
    except Exception:
        # try cache
        try:
            with open(os.path.join(_cache_dir(), 'kev.json'), 'r') as f:
                ids = json.load(f)
                kev_map = {cve: True for cve in ids}
        except Exception:
            pass
    return kev_map

@lru_cache(maxsize=1)
def load_epss() -> Dict[str, float]:
    epss_map: Dict[str, float] = {}
    url = 'https://epss.cyentia.com/epss_scores-current.csv.gz'
    try:
        r = requests.get(url, timeout=10)
        if r.ok:
            import gzip
            import io
            buf = io.BytesIO(r.content)
            with gzip.open(buf, 'rt') as gz:
                for line in gz:
                    if line.startswith('cve,epss,percentile'):
                        continue
                    parts = line.strip().split(',')
                    if len(parts) >= 2:
                        cve, epss = parts[0], float(parts[1] or 0.0)
                        epss_map[cve] = epss
            with open(os.path.join(_cache_dir(), 'epss.json'), 'w') as f:
                json.dump(epss_map, f)
    except Exception:
        # try cache
        try:
            with open(os.path.join(_cache_dir(), 'epss.json'), 'r') as f:
                epss_map = json.load(f)
        except Exception:
            pass
    return epss_map

def enrich_grype_with_threat_intel(grype_data: Dict[str, Any]) -> Dict[str, Any]:
    kev = load_kev()
    epss = load_epss()
    try:
        for m in grype_data.get('matches', []) or []:
            v = m.get('vulnerability', {})
            cve = v.get('id') or ''
            if not cve:
                continue
            m['_threat'] = {
                'kev': bool(kev.get(cve)),
                'epss': float(epss.get(cve, 0.0))
            }
    except Exception:
        pass
    return grype_data

# -------------------- Policy Loading and Evaluation --------------------

def _read_json(path: str) -> Any:
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return None

def load_policy() -> Dict[str, Any]:
    path = config.POLICY_PATH or 'policy.yaml'
    if not os.path.exists(path):
        return {}
    try:
        import yaml  # type: ignore
        with open(path, 'r') as f:
            return yaml.safe_load(f) or {}
    except Exception:
        # Very small fallback: attempt to parse limited subset is not safe; return empty
        return {}

def evaluate_policy(report_dir: str, repo_name: str) -> Tuple[bool, List[str]]:
    policy = load_policy()
    if not policy:
        # default: evaluate current Checkov gate only (High+ = fail)
        violations: List[str] = []
        chk_json = os.path.join(report_dir, f"{repo_name}_checkov.json")
        
        # Check if the file exists first
        if not os.path.exists(chk_json):
            return (True, violations)  # No checkov results, so no violations
            
        data = _read_json(chk_json) or {}
        
        # Safely handle different JSON structures
        if isinstance(data, dict):
            results = data.get('results', {}) or {}
            if isinstance(results, dict):
                failed = results.get('failed_checks', [])
            else:
                failed = []
        else:
            failed = []
            
        # Check if failed is a list before iterating
        if isinstance(failed, list):
            if any(isinstance(i, dict) and (i.get('severity') or '').upper() in ('CRITICAL', 'HIGH') for i in failed):
                violations.append("checkov: contains High or Critical failed checks")
                
        return (len(violations) == 0, violations)

    gates = (policy.get('gates') or {})
    violations: List[str] = []

    # Grype gates
    gcfg = gates.get('grype') or {}
    if gcfg:
        grype_json = os.path.join(report_dir, f"{repo_name}_grype_repo.json")
        gd = _read_json(grype_json) or {}
        # If enriched not present, enrich on the fly
        try:
            if gd:
                gd = enrich_grype_with_threat_intel(gd)
        except Exception:
            pass
        matches = gd.get('matches', []) if isinstance(gd, dict) else []
        if gcfg.get('require_no_kev', False):
            if any(bool(m.get('_threat',{}).get('kev')) for m in matches):
                violations.append("grype: KEV vulnerability present")
        max_epss = gcfg.get('max_epss')
        if isinstance(max_epss, (int,float)):
            if any(float(m.get('_threat',{}).get('epss') or 0.0) >= float(max_epss) for m in matches):
                violations.append(f"grype: EPSS >= {max_epss}")
        max_sev = (gcfg.get('max_severity') or '').lower()
        sev_rank = {'critical':4,'high':3,'medium':2,'low':1,'negligible':0}
        if max_sev in sev_rank:
            for m in matches:
                s = (m.get('vulnerability',{}).get('severity') or 'unknown').lower()
                if sev_rank.get(s, -1) >= sev_rank[max_sev]:
                    violations.append(f"grype: severity {s} >= {max_sev}")
                    break

    # Checkov gates
    ccfg = gates.get('checkov') or {}
    if ccfg:
        chk_json = os.path.join(report_dir, f"{repo_name}_checkov.json")
        data = _read_json(chk_json) or {}
        failed = (data.get('results', {}) or {}).get('failed_checks', [])
        counts = {'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0,'UNKNOWN':0}
        for i in failed or []:
            sev = (i.get('severity') or 'UNKNOWN').upper()
            if sev not in counts: sev = 'UNKNOWN'
            counts[sev]+=1
        max_sev = (ccfg.get('max_severity') or '').upper()
        order = {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1,'UNKNOWN':0}
        if max_sev in order:
            for sev, n in counts.items():
                if order[sev] >= order[max_sev] and n>0 and (sev in ('CRITICAL','HIGH','MEDIUM','LOW')):
                    violations.append(f"checkov: contains {sev} findings >= {max_sev}")
                    break
        mcounts = ccfg.get('max_counts') or {}
        for sev, limit in mcounts.items():
            s = sev.upper()
            try:
                lim = int(limit)
                if counts.get(s,0) > lim:
                    violations.append(f"checkov: {s} count {counts.get(s,0)} exceeds {lim}")
            except Exception:
                continue

    # Secrets gates
    scfg = gates.get('secrets') or {}
    if scfg:
        gl_json = os.path.join(report_dir, f"{repo_name}_gitleaks.json")
        secrets = _read_json(gl_json)
        total = len(secrets) if isinstance(secrets, list) else 0
        max_findings = scfg.get('max_findings')
        if isinstance(max_findings, int) and total > max_findings:
            violations.append(f"secrets: {total} findings > {max_findings}")

    # Semgrep gates
    sgcfg = gates.get('semgrep') or {}
    if sgcfg:
        sg_json = os.path.join(report_dir, f"{repo_name}_semgrep.json")
        data = _read_json(sg_json) or {}
        results = data.get('results', []) if isinstance(data, dict) else []
        # Map severities
        map_sev = {'ERROR':'high','WARNING':'medium','INFO':'low'}
        counts = {'high':0,'medium':0,'low':0}
        for r in results:
            sev = map_sev.get((r.get('extra',{}).get('severity') or '').upper())
            if sev: counts[sev]+=1
        max_sev = (sgcfg.get('max_severity') or '').lower()
        rank = {'critical':3,'high':2,'medium':1,'low':0}
        if max_sev in rank and counts:
            for sev, n in counts.items():
                if rank.get(sev, -1) >= rank[max_sev] and n>0:
                    violations.append(f"semgrep: contains {sev} findings >= {max_sev}")
                    break
        mcounts = sgcfg.get('max_counts') or {}
        for sev, limit in mcounts.items():
            try:
                if counts.get(sev.lower(),0) > int(limit):
                    violations.append(f"semgrep: {sev} count {counts.get(sev.lower(),0)} exceeds {limit}")
            except Exception:
                continue

    # Semgrep taint gates
    tcfg = gates.get('semgrep_taint') or {}
    if tcfg:
        st_json = os.path.join(report_dir, f"{repo_name}_semgrep_taint.json")
        data = _read_json(st_json) or {}
        flows = data.get('results', []) if isinstance(data, dict) else []
        max_flows = tcfg.get('max_flows')
        if isinstance(max_flows, int) and len(flows) > max_flows:
            violations.append(f"semgrep_taint: flows {len(flows)} exceeds {max_flows}")

    # Bandit gates (if present)
    bcfg = gates.get('bandit') or {}
    if bcfg:
        bj = os.path.join(report_dir, f"{repo_name}_bandit.json")
        bd = _read_json(bj) or {}
        results = bd.get('results', []) if isinstance(bd, dict) else []
        counts = {'HIGH':0,'MEDIUM':0,'LOW':0}
        for r in results:
            sev = (r.get('issue_severity') or '').upper()
            if sev in counts: counts[sev]+=1
        max_sev = (bcfg.get('max_severity') or '').upper()
        order = {'CRITICAL':3,'HIGH':2,'MEDIUM':1,'LOW':0}
        if max_sev in order:
            for sev, n in counts.items():
                if order.get(sev, -1) >= order[max_sev] and n>0:
                    violations.append(f"bandit: contains {sev} findings >= {max_sev}")
                    break
        mcounts = bcfg.get('max_counts') or {}
        for sev, limit in mcounts.items():
            try:
                if counts.get(sev.upper(),0) > int(limit):
                    violations.append(f"bandit: {sev} count {counts.get(sev.upper(),0)} exceeds {limit}")
            except Exception:
                continue

    # Trivy FS gates (if present)
    tvcfg = gates.get('trivy_fs') or {}
    if tvcfg:
        tj = os.path.join(report_dir, f"{repo_name}_trivy_fs.json")
        td = _read_json(tj) or {}
        results = td.get('Results', []) if isinstance(td, dict) else []
        counts = {'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0,'UNKNOWN':0}
        for res in results:
            for v in res.get('Vulnerabilities', []) or []:
                sev = (v.get('Severity') or 'UNKNOWN').upper()
                if sev not in counts: sev='UNKNOWN'
                counts[sev]+=1
        max_sev = (tvcfg.get('max_severity') or '').upper()
        order = {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1,'UNKNOWN':0}
        if max_sev in order:
            for sev, n in counts.items():
                if order[sev] >= order[max_sev] and n>0 and sev in order:
                    violations.append(f"trivy_fs: contains {sev} findings >= {max_sev}")
                    break
        mcounts = tvcfg.get('max_counts') or {}
        for sev, limit in mcounts.items():
            try:
                if counts.get(sev.upper(),0) > int(limit):
                    violations.append(f"trivy_fs: {sev} count {counts.get(sev.upper(),0)} exceeds {limit}")
            except Exception:
                continue

    return (len(violations) == 0, violations)

# -------------------- Contributor Attribution Helpers --------------------

def load_semgrep_results(path: str) -> List[dict]:
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        return data.get('results', []) if isinstance(data, dict) else []
    except Exception:
        return []

def load_grype_results(path: str) -> Dict[str, Any]:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return {}

@lru_cache(maxsize=2048)
def _blame_cache_key(repo_path: str, rel_path: str, line: int) -> str:
    return f"{rel_path}:{line}"

def blame_line(repo_local_path: str, rel_path: str, line: int) -> Dict[str, str]:
    try:
        cmd = ["git", "blame", "-L", f"{line},{line}", "--line-porcelain", rel_path]
        result = subprocess.run(cmd, cwd=repo_local_path, capture_output=True, text=True)
        if result.returncode != 0:
            return {"name": "unknown", "email": "", "raw": result.stderr.strip()}
        name, email = "unknown", ""
        for ln in result.stdout.splitlines():
            if ln.startswith("author "):
                name = ln[len("author ") :].strip()
            elif ln.startswith("author-mail "):
                email = ln[len("author-mail ") :].strip(" <>")
        return {"name": name or "unknown", "email": email, "raw": ""}
    except Exception as e:
        return {"name": "unknown", "email": "", "raw": str(e)}

def map_author_to_contributor(author_name: str, author_email: str, contributors: List[Dict[str, Any]]) -> str:
    name_l = (author_name or "").strip().lower()
    email_l = (author_email or "").strip().lower()
    for c in (contributors or [])[:10]:
        login = (c.get('login') or '').strip()
        if login and login.lower() in (name_l, email_l):
            return login
        if c.get('name') and c['name'].strip().lower() == name_l:
            return login or c['name']
    return author_name or "unknown"

MANIFEST_GLOBS = [
    "requirements.txt", "requirements.in", "Pipfile", "pyproject.toml",
    "package.json", "pom.xml", "build.gradle", "build.gradle.kts",
    "go.mod", "Gemfile", "Gemfile.lock"
]

def _iter_manifest_files(repo_local_path: str) -> List[str]:
    found = []
    for root, _dirs, files in os.walk(repo_local_path):
        for fn in files:
            if fn in MANIFEST_GLOBS or fn.endswith((".lock",)):
                found.append(os.path.relpath(os.path.join(root, fn), repo_local_path))
    return found

def find_manifest_references(repo_local_path: str, package: str, version: Optional[str]) -> List[Tuple[str, int, str]]:
    refs: List[Tuple[str, int, str]] = []
    pk_re = re.compile(re.escape(package), re.IGNORECASE)
    ver_re = re.compile(re.escape(version)) if version else None
    for rel in _iter_manifest_files(repo_local_path):
        try:
            with open(os.path.join(repo_local_path, rel), 'r', errors='ignore') as f:
                for idx, line in enumerate(f, start=1):
                    if pk_re.search(line) and (ver_re.search(line) if ver_re else True):
                        disp = f"[dep] {rel}:{idx} {package}{('@'+version) if version else ''}"
                        refs.append((rel, idx, disp))
                        if len(refs) >= 3:
                            return refs
        except Exception:
            continue
    return refs

def get_last_commit_per_contributor(session: requests.Session, repo_full_name: str, contributors: List[Dict[str, Any]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for c in (contributors or [])[:5]:
        login = c.get('login')
        if not login:
            continue
        try:
            url = f"{config.GITHUB_API}/repos/{repo_full_name}/commits?author={login}&per_page=1"
            r = session.get(url, headers=config.HEADERS)
            if r.status_code == 200 and r.json():
                out[login] = r.json()[0]['commit']['author']['date']
        except Exception:
            continue
    return out

def aggregate_vulns_by_contributor(repo_local_path: str,
                                   semgrep_results: List[dict],
                                   grype_data: Dict[str, Any],
                                   contributors: List[Dict[str, Any]],
                                   blame_cap_semgrep: int = 200,
                                   blame_cap_grype: int = 100) -> Dict[str, Dict[str, Any]]:
    contrib_map: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"count": 0, "locations": [], "details": []})

    # Semgrep mapping
    seen = set()
    blamed = 0
    for res in semgrep_results:
        path = res.get('path')
        start = res.get('start', {}).get('line') or res.get('start', {}).get('lineNumber') or 0
        rule_id = (res.get('check_id') or res.get('extra', {}).get('id') or 'rule')
        if not (path and start):
            continue
        key = (path, int(start), str(rule_id))
        if key in seen:
            continue
        seen.add(key)
        if blamed >= blame_cap_semgrep:
            break
        blamed += 1
        author = blame_line(repo_local_path, path, int(start))
        who = map_author_to_contributor(author.get('name', ''), author.get('email', ''), contributors)
        contrib_map[who]["count"] += 1
        loc = f"{path}:{start}"
        if len(contrib_map[who]["locations"]) < 3 and loc not in contrib_map[who]["locations"]:
            contrib_map[who]["locations"].append(loc)
        # Details
        rule_name = res.get('extra', {}).get('message', '') or str(rule_id)
        contrib_map[who]["details"].append(f"- Semgrep: {loc} ({rule_name})")

    # Grype mapping
    matches = (grype_data.get('matches') or []) if isinstance(grype_data, dict) else []
    blamed_g = 0
    for m in matches:
        if blamed_g >= blame_cap_grype:
            break
        vuln = m.get('vulnerability', {})
        art = m.get('artifact', {})
        pkg = art.get('name') or art.get('pkg', {}).get('name') or ''
        ver = art.get('version') or ''
        if not pkg:
            continue
        refs = find_manifest_references(repo_local_path, pkg, ver)
        for (rel, line_no, disp) in refs:
            if blamed_g >= blame_cap_grype:
                break
            blamed_g += 1
            author = blame_line(repo_local_path, rel, int(line_no))
            who = map_author_to_contributor(author.get('name', ''), author.get('email', ''), contributors)
            contrib_map[who]["count"] += 1
            if len(contrib_map[who]["locations"]) < 3 and disp not in contrib_map[who]["locations"]:
                contrib_map[who]["locations"].append(disp)
            vid = vuln.get('id') or vuln.get('cve') or ''
            sev = vuln.get('severity') or ''
            contrib_map[who]["details"].append(f"- Grype: {disp} {pkg}{('@'+ver) if ver else ''} {vid} {('Severity: '+sev) if sev else ''}")

    return contrib_map

def build_contributor_vuln_table(session: requests.Session,
                                 repo_full_name: str,
                                 repo_local_path: str,
                                 report_dir: str,
                                 repo_name: str) -> Tuple[List[List[str]], Dict[str, str]]:
    # Load contributors
    contributors = get_repo_contributors(session, repo_full_name)
    # Load Semgrep/Grype outputs
    semgrep_json = os.path.join(report_dir, f"{repo_name}_semgrep.json")
    grype_json = os.path.join(report_dir, f"{repo_name}_grype_repo.json")
    semgrep_results = load_semgrep_results(semgrep_json)
    grype_results = load_grype_results(grype_json)
    # Aggregate
    contrib_map = aggregate_vulns_by_contributor(repo_local_path, semgrep_results, grype_results, contributors)
    # Last commit per contributor
    last_commits = get_last_commit_per_contributor(session, repo_full_name, contributors)
    # Build rows for the top 5 contributors by contributions
    rows: List[List[str]] = []
    details_md: Dict[str, str] = {}
    top5 = (contributors or [])[:5]
    for c in top5:
        login = c.get('login') or (c.get('name') or 'unknown')
        total_commits = str(c.get('contributions', '0'))
        last_commit = last_commits.get(login, 'Unknown')
        stats = contrib_map.get(login) or contrib_map.get(c.get('name') or '') or {"count": 0, "locations": [], "details": []}
        count = str(stats["count"]) if isinstance(stats.get("count"), int) else str(stats.get("count", 0))
        locs = "; ".join(stats["locations"]) if stats.get("locations") else "—"
        rows.append([login, total_commits, last_commit, count, locs])
        # Details md
        if stats.get("details"):
            details_md[login] = "\n".join(stats["details"][:50])
        else:
            details_md[login] = "(No mapped findings)"
    return rows, details_md

# -------------------- Terraform Pre-Deploy Section --------------------

def load_checkov_json(file_path: str) -> dict:
    """Safely load Checkov JSON file with validation."""
    if not os.path.exists(file_path):
        logging.debug(f"Checkov JSON not found: {file_path}")
        return {}
    
    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()
            if not content:
                logging.warning(f"Empty Checkov JSON file: {file_path}")
                return {}
            return json.loads(content)
    except json.JSONDecodeError as je:
        logging.error(f"Invalid JSON in {file_path}: {str(je)}")
        return {}
    except Exception as e:
        logging.error(f"Error reading {file_path}: {str(e)}")
        return {}

def build_tf_predeploy_section(report_dir: str, repo_name: str) -> str:
    """Build a Terraform Pre-Deploy section using Checkov JSON results.

    Returns a markdown string or empty string if no Checkov JSON is available.
    """
    checkov_json = os.path.join(report_dir, f"{repo_name}_checkov.json")
    data = load_checkov_json(checkov_json)
    if not data:
        return ""
    
    # Handle different possible structures of Checkov JSON output
    if isinstance(data, list):
        # If the root is a list, it might contain multiple results
        failed = []
        for item in data:
            if isinstance(item, dict):
                results = item.get('results', {}) if isinstance(item.get('results'), dict) else {}
                failed.extend(results.get('failed_checks', []) or [])
    elif isinstance(data, dict):
        # Standard case where root is an object with 'results'
        results = data.get('results', {}) if isinstance(data.get('results'), dict) else {}
        failed = results.get('failed_checks', []) or []
    else:
        logging.warning(f"Unexpected Checkov JSON structure: {type(data)}")
        failed = []
    
    # Ensure failed is a list
    if not isinstance(failed, list):
        logging.warning(f"Expected failed_checks to be a list, got {type(failed)}")
        failed = []
    # Severity counts
    sev_counts = {"CRITICAL":0, "HIGH":0, "MEDIUM":0, "LOW":0, "UNKNOWN":0}
    for item in failed:
        sev = (item.get('severity') or 'UNKNOWN').upper()
        if sev not in sev_counts:
            sev = 'UNKNOWN'
        sev_counts[sev] += 1
    gate_fail = (sev_counts['CRITICAL'] > 0) or (sev_counts['HIGH'] > 0)
    gate = "FAIL" if gate_fail else "PASS"

    # Deduplicate and sort top items
    def _sev_rank(s: str) -> int:
        s = (s or 'UNKNOWN').upper()
        order = {"CRITICAL":0, "HIGH":1, "MEDIUM":2, "LOW":3, "UNKNOWN":4}
        return order.get(s, 5)
    seen = set()
    unique_failed = []
    for it in failed:
        key = (
            (it.get('check_id') or '').lower(),
            (it.get('resource') or '').lower(),
            (it.get('file_path') or '').lower(),
            str(it.get('file_line_range') or '')
        )
        if key in seen:
            continue
        seen.add(key)
        unique_failed.append(it)
    unique_failed.sort(key=lambda x: (_sev_rank(x.get('severity')), (x.get('file_path') or '')))

    # Build Top table (up to 10)
    md = []
    md.append("## Terraform Pre-Deploy\n")
    md.append(f"**Gate:** {gate} (Critical: {sev_counts['CRITICAL']}, High: {sev_counts['HIGH']}, Medium: {sev_counts['MEDIUM']}, Low: {sev_counts['LOW']})\n\n")
    md.append("### Summary of Failed Checks (Top 10)\n\n")
    md.append("| Severity | Check ID | Resource | File:Line |\n")
    md.append("|---|---|---|---|\n")
    for it in unique_failed[:10]:
        sev = (it.get('severity') or 'UNKNOWN').upper()
        chk = it.get('check_id', 'UNKNOWN')
        res = it.get('resource', 'resource')
        file_path = it.get('file_path', 'unknown')
        lines = it.get('file_line_range') or []
        line_disp = f"{file_path}{(':' + '-'.join(map(str, lines))) if lines else ''}"
        guide = it.get('guideline') or ''
        chk_disp = f"[{chk}]({guide})" if guide else chk
        md.append(f"| {sev} | {chk_disp} | {res} | {line_disp} |\n")
    md.append("\n")

    # Grouped remediation tasks
    md.append("### Required Remediation Tasks (Grouped)\n\n")
    groups = {
        'Security': [],
        'Network': [],
        'IAM': [],
        'Logging/Monitoring': [],
        'Data Protection': [],
        'Compliance/Tagging': [],
    }
    def _assign_group(name: str) -> str:
        s = (name or '').lower()
        if any(k in s for k in ['encrypt', 'kms', 'public access block', 'versioning']):
            return 'Security'
        if any(k in s for k in ['security group', 'ingress', 'egress', 'cidr', 'public']):
            return 'Network'
        if any(k in s for k in ['policy', 'role', 'wildcard', 'iam', 'principal']):
            return 'IAM'
        if any(k in s for k in ['cloudtrail', 'log', 'retention', 'config']):
            return 'Logging/Monitoring'
        if any(k in s for k in ['s3 bucket policy', 'storage_encrypted', 'rds', 'db']):
            return 'Data Protection'
        if any(k in s for k in ['tag', 'owner', 'environment', 'cost']):
            return 'Compliance/Tagging'
        return 'Security'
    for it in unique_failed:
        name = it.get('check_name') or it.get('check_id') or ''
        grp = _assign_group(name)
        res = it.get('resource', 'resource')
        file_path = it.get('file_path', 'unknown')
        lines = it.get('file_line_range') or []
        md_line = f"- {name} on {res} ({file_path}{':' + '-'.join(map(str, lines)) if lines else ''})"
        groups[grp].append(md_line)
    for gname, items in groups.items():
        if not items:
            continue
        md.append(f"#### {gname}\n\n")
        md.extend([i + "\n" for i in items[:20]])
        md.append("\n")

    # Collapsible details
    md.append("### Detailed Remediation Guidance\n\n")
    for it in unique_failed[:50]:
        chk = it.get('check_id', 'UNKNOWN')
        name = it.get('check_name', '')
        res = it.get('resource', 'resource')
        file_path = it.get('file_path', 'unknown')
        lines = it.get('file_line_range') or []
        guide = it.get('guideline') or ''
        md.append(f"<details><summary>{chk}: {name}</summary>\n\n")
        md.append(f"- Resource: {res}\n")
        md.append(f"- File: {file_path}{(':' + '-'.join(map(str, lines))) if lines else ''}\n")
        if guide:
            md.append(f"- Guideline: {guide}\n")
        # Heuristic fix hint
        lower = (name or '').lower()
        if 'encrypt' in lower or 'kms' in lower:
            md.append("- How to fix: enable encryption at rest (e.g., KMS or SSE where applicable).\n")
        elif 'public' in lower or 'ingress' in lower or 'egress' in lower or 'cidr' in lower:
            md.append("- How to fix: restrict network exposure (tighten CIDRs, remove public access).\n")
        elif 'policy' in lower or 'iam' in lower or 'wildcard' in lower:
            md.append("- How to fix: restrict IAM policies (avoid wildcards, least privilege).\n")
        elif 'log' in lower or 'trail' in lower or 'retention' in lower:
            md.append("- How to fix: ensure logging/monitoring is enabled with appropriate retention.\n")
        elif 'tag' in lower:
            md.append("- How to fix: add required tags (owner, environment, cost-center).\n")
        else:
            md.append("- How to fix: update resource configuration per guideline.\n")
        md.append("\n</details>\n\n")

    # Hygiene & Readiness
    md.append("### Configuration Hygiene Checklist\n\n")
    md.append("- terraform fmt and terraform validate pass\n")
    md.append("- Provider and module versions pinned\n")
    md.append("- .terraform.lock.hcl committed\n")
    md.append("- Remote backend state encryption enabled\n")
    md.append("- Sensitive variables sourced from secrets manager (not plaintext)\n")
    md.append("- Tagging standards (owner, env, cost-center) applied\n\n")

    md.append("### Deployment Readiness Criteria\n\n")
    md.append("- 0 Critical/High failed checks from Checkov\n")
    md.append("- No public exposure of critical resources\n")
    md.append("- Encryption-at-rest enabled for storage resources\n")
    md.append("- Logging/monitoring enabled where applicable\n")

    return "".join(md)


def generate_summary_report(repo_name: str, repo_url: str, requirements_path: str, 
                          safety_result: subprocess.CompletedProcess,
                          pip_audit_result: subprocess.CompletedProcess,
                          npm_audit_result: subprocess.CompletedProcess,
                          govulncheck_result: subprocess.CompletedProcess,
                          bundle_audit_result: subprocess.CompletedProcess,
                          dependency_check_result: subprocess.CompletedProcess,
                          semgrep_result: subprocess.CompletedProcess,
                          semgrep_taint_result: Optional[subprocess.CompletedProcess],
                          checkov_result: Optional[subprocess.CompletedProcess],
                          gitleaks_result: Optional[subprocess.CompletedProcess],
                          bandit_result: Optional[subprocess.CompletedProcess],
                          trivy_fs_result: Optional[subprocess.CompletedProcess],
                          repo_local_path: str,
                          report_dir: str,
                          repo_full_name: str = "",
                          detected_languages: Set[str] = set(),
                          cloc_result: Optional[Dict[str, Any]] = None,
                          architecture_overview: str = "") -> None:
    """Generate a summary report of all scan results."""
    summary_path = os.path.join(report_dir, f"{repo_name}_summary.md")
    
    logging.info(f"Generating summary for {repo_name}. Semgrep result: {semgrep_result.returncode if semgrep_result else 'None'}")
    
    def get_scan_status(result):
        if not result:
            return "Not run"
        if result.returncode == 0:
            return "✅ Success (No issues found)"
        elif result.returncode == 1:
            return "⚠️  Issues found"
        return f"❌ Error (Code: {result.returncode})"
    
    try:
        with open(summary_path, 'w') as f:
            f.write(f"# Security Scan Summary\n\n")
            f.write(f"**Repository:** [{repo_name}]({repo_url})\n")
            f.write(f"**Scan Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            # Executive Summary (Scorecard)
            metrics = calculate_risk_metrics(report_dir, repo_name)
            score_color = "🟢" if metrics['grade'] in ['A', 'B'] else "🟡" if metrics['grade'] == 'C' else "🔴"
            
            f.write(f"\n## Executive Summary\n")
            f.write(f"### Security Grade: {score_color} {metrics['grade']} ({metrics['score']}/100)\n\n")
            
            f.write("| Critical | High | Medium | Low | Secrets |\n")
            f.write("|----------|------|--------|-----|---------|\n")
            f.write(f"| {metrics['critical']} | {metrics['high']} | {metrics['medium']} | {metrics['low']} | {metrics['secrets']} |\n\n")
            
            if metrics['score'] < 60:
                f.write("> [!CAUTION]\n> **Critical Risk**: This repository has a failing security grade. Immediate remediation is required.\n\n")
            elif metrics['score'] < 80:
                f.write("> [!WARNING]\n> **High Risk**: Significant vulnerabilities detected. Prioritize fixing Critical and High issues.\n\n")
            else:
                f.write("> [!NOTE]\n> **Good Standing**: Security posture is acceptable, but continue to monitor Low/Medium issues.\n\n")

            # Architecture Overview
            if architecture_overview:
                f.write("## 🏗️ Architecture Overview\n\n")
                f.write(architecture_overview)
                f.write("\n\n---\n\n")

            # Detected Languages
            if detected_languages:
                langs = ", ".join(sorted(detected_languages))
                f.write(f"**Detected Languages:** {langs}\n")
            else:
                f.write(f"**Detected Languages:** None detected\n")
            f.write("\n")
            
            # Code Statistics (cloc)
            if cloc_result:
                f.write("## Code Statistics\n\n")
                f.write("| Language | Files | Blank | Comment | Code |\n")
                f.write("|----------|-------|-------|---------|------|\n")
                
                # Sort by code lines descending
                sorted_langs = sorted(cloc_result.items(), key=lambda x: x[1].get('code', 0), reverse=True)
                
                for lang, stats in sorted_langs:
                    if lang == 'SUM': continue # Skip summary row for now, or put it at bottom
                    f.write(f"| {lang} | {stats.get('nFiles', 0)} | {stats.get('blank', 0)} | {stats.get('comment', 0)} | {stats.get('code', 0)} |\n")
                
                if 'SUM' in cloc_result:
                    stats = cloc_result['SUM']
                    f.write(f"| **TOTAL** | **{stats.get('nFiles', 0)}** | **{stats.get('blank', 0)}** | **{stats.get('comment', 0)}** | **{stats.get('code', 0)}** |\n")
                f.write("\n")
            
            # Scan Summary Table
            f.write("## Scan Summary\n\n")
            # Derive Bandit and Trivy statuses from JSON outputs (return codes may be 0 even with findings)
            bandit_status = "Not run"
            try:
                bandit_json = os.path.join(report_dir, f"{repo_name}_bandit.json")
                if os.path.exists(bandit_json):
                    bd = json.load(open(bandit_json))
                    results = bd.get('results', []) if isinstance(bd, dict) else []
                    bandit_status = "✅ Success (No issues found)" if not results else "⚠️  Issues found"
            except Exception:
                bandit_status = get_scan_status(bandit_result)

            trivy_status = "Not run"
            try:
                trivy_json = os.path.join(report_dir, f"{repo_name}_trivy_fs.json")
                if os.path.exists(trivy_json):
                    td = json.load(open(trivy_json))
                    results = td.get('Results', []) if isinstance(td, dict) else []
                    total = 0
                    for res in results:
                        vulns = res.get('Vulnerabilities', []) or []
                        total += len(vulns)
                    trivy_status = "✅ Success (No issues found)" if total == 0 else "⚠️  Issues found"
            except Exception:
                trivy_status = get_scan_status(trivy_fs_result)
            f.write("| Tool | Status |\n")
            f.write("|------|--------|\n")
            f.write(f"| Safety | {get_scan_status(safety_result)} |\n")
            f.write(f"| pip-audit | {get_scan_status(pip_audit_result)} |\n")
            f.write(f"| npm audit | {get_scan_status(npm_audit_result)} |\n")
            f.write(f"| govulncheck | {get_scan_status(govulncheck_result)} |\n")
            f.write(f"| bundle audit | {get_scan_status(bundle_audit_result)} |\n")
            f.write(f"| OWASP Dependency-Check | {get_scan_status(dependency_check_result)} |\n")
            f.write(f"| Semgrep | {get_scan_status(semgrep_result)} |\n")
            f.write(f"| Semgrep (taint) | {get_scan_status(semgrep_taint_result)} |\n")
            f.write(f"| Checkov (Terraform) | {get_scan_status(checkov_result)} |\n")
            f.write(f"| Gitleaks (Secrets) | {get_scan_status(gitleaks_result)} |\n")
            f.write(f"| Bandit (Python) | {bandit_status} |\n")
            f.write(f"| Trivy (fs) | {trivy_status} |\n")

            # Policy Gate evaluation (if policy file present)
            try:
                passed, violations = evaluate_policy(report_dir, repo_name)
                gate_status = "PASS" if passed else "FAIL"
                f.write(f"| Policy Gate | {gate_status} |\n\n")
            except Exception as e:
                logging.error(f"Error evaluating policy: {str(e)}")
                f.write("| Policy Gate | ❌ Error (check logs) |\n\n")
            # Compact Threat Intel counts just under the summary table
            try:
                grype_repo_json = os.path.join(report_dir, f"{repo_name}_grype_repo.json")
                if os.path.exists(grype_repo_json):
                    with open(grype_repo_json, 'r') as gf:
                        grype_data = json.load(gf)
                    grype_data = enrich_grype_with_threat_intel(grype_data)
                    matches = grype_data.get('matches', []) if isinstance(grype_data, dict) else []
                    kev_mapped = sum(1 for m in matches if (m.get('_threat') or {}).get('kev'))
                    epss_mapped = sum(1 for m in matches if isinstance((m.get('_threat') or {}).get('epss'), (int, float)) and (m.get('_threat') or {}).get('epss') > 0)
                    f.write(f"- Threat Intel: KEV mapped {kev_mapped}, EPSS mapped {epss_mapped}\n\n")
            except Exception:
                pass
            
            # Syft status based on presence of SBOMs
            syft_repo_path = os.path.join(report_dir, f"{repo_name}_syft_repo.json")
            syft_image_path = os.path.join(report_dir, f"{repo_name}_syft_image.json")
            syft_status = "Not run"
            if os.path.exists(syft_repo_path) or os.path.exists(syft_image_path):
                syft_status = "✅ Generated"
            f.write(f"| Syft SBOM | {syft_status} |\n\n")
            # Small Policy link for reviewers
            try:
                f.write(f"Policy: [policy.yaml](../../policy.yaml)\n\n")
            except Exception:
                pass

            # Grype status based on presence of JSON reports
            grype_repo_path = os.path.join(report_dir, f"{repo_name}_grype_repo.json")
            grype_image_path = os.path.join(report_dir, f"{repo_name}_grype_image.json")
            grype_status = "Not run"
            if os.path.exists(grype_repo_path) or os.path.exists(grype_image_path):
                grype_status = "✅ Generated"
                if getattr(config, 'VEX_FILES', []):
                    grype_status += " (VEX applied)"
            f.write(f"| Grype Vulnerabilities | {grype_status} |\n\n")
            
            # Detailed Reports Section
            f.write("## Detailed Reports\n\n")
            f.write("| Report | Link |\n")
            f.write("|--------|------|\n")
            report_map = {
                "Safety": f"{repo_name}_safety.txt",
                "pip-audit": f"{repo_name}_pip_audit.md",
                "npm audit": f"{repo_name}_npm_audit.md",
                "govulncheck": f"{repo_name}_govulncheck.md",
                "bundle audit": f"{repo_name}_bundle_audit.txt",
                "OWASP DC": f"{repo_name}_dependency_check.md",
                "Semgrep": f"{repo_name}_semgrep.md",
                "Semgrep (taint)": f"{repo_name}_semgrep_taint.md",
            }
            # Dagda links removed
            # Include Syft SBOMs
            report_map["Syft SBOM (repo)"] = f"{repo_name}_syft_repo.json"
            report_map["Syft SBOM (image)"] = f"{repo_name}_syft_image.json"
            # Include Grype reports
            report_map["Grype (repo)"] = f"{repo_name}_grype_repo.json"
            report_map["Grype (image)"] = f"{repo_name}_grype_image.json"
            # Include Checkov report
            report_map["Checkov (Terraform)"] = f"{repo_name}_checkov.md"
            # Include Gitleaks
            report_map["Gitleaks (secrets)"] = f"{repo_name}_gitleaks.md"
            # Bandit & Trivy FS reports
            report_map["Bandit (Python)"] = f"{repo_name}_bandit.md"
            report_map["Trivy (fs)"] = f"{repo_name}_trivy_fs.md"
            for label, filename in report_map.items():
                path = os.path.join(report_dir, filename)
                if os.path.exists(path):
                    f.write(f"| {label} | [{filename}](./{filename}) |\n")
                else:
                    f.write(f"| {label} | Not generated |\n")
            f.write("\n")
            # VEX files used (if any)
            if getattr(config, 'VEX_FILES', []):
                f.write("### VEX files used\n\n")
                for vf in config.VEX_FILES:
                    f.write(f"- {vf}\n")
                f.write("\n")

            # Threat Intel summary (KEV/EPSS mapping coverage)
            try:
                grype_repo_json = os.path.join(report_dir, f"{repo_name}_grype_repo.json")
                if os.path.exists(grype_repo_json):
                    with open(grype_repo_json, 'r') as gf:
                        grype_data = json.load(gf)
                    # Ensure enrichment so _threat is present
                    grype_data = enrich_grype_with_threat_intel(grype_data)
                    matches = grype_data.get('matches', []) if isinstance(grype_data, dict) else []
                    kev_mapped = 0
                    epss_mapped = 0
                    unmapped = 0
                    for m in matches:
                        thr = m.get('_threat') or {}
                        if thr.get('kev'):
                            kev_mapped += 1
                        if isinstance(thr.get('epss'), (int, float)) and thr.get('epss') > 0:
                            epss_mapped += 1
                        # Consider unmapped where no CVE id or missing _threat entirely
                        vul_id = (m.get('vulnerability', {}) or {}).get('id') or ''
                        if not thr or not vul_id.startswith('CVE-'):
                            unmapped += 1
                    f.write("## Threat Intel\n\n")
                    f.write(f"- KEV mapped: {kev_mapped}\n")
                    f.write(f"- EPSS mapped: {epss_mapped}\n")
                    f.write(f"- Unmapped (check identifiers/aliases): {unmapped}\n\n")
            except Exception as e:
                logging.debug(f"Threat Intel summary unavailable: {e}")

            # Terraform Pre-Deploy (from Checkov)
            try:
                tf_predeploy_md = build_tf_predeploy_section(report_dir, repo_name)
                if tf_predeploy_md:
                    f.write(tf_predeploy_md)
                    f.write("\n")
            except Exception as e:
                logging.error(f"Failed to build Terraform Pre-Deploy section: {e}")

            # Policy Gate details
            try:
                passed, violations = evaluate_policy(report_dir, repo_name)
                f.write("## Policy Gate\n\n")
                f.write(f"Status: {'PASS' if passed else 'FAIL'}\n\n")
                if violations:
                    f.write("### Violations\n\n")
                    for v in violations[:20]:
                        f.write(f"- {v}\n")
                    f.write("\n")
                else:
                    f.write("No violations detected under current policy.\n\n")
            except Exception as e:
                logging.error(f"Failed to evaluate policy: {e}")

            # Secrets Findings (from Gitleaks)
            try:
                gitleaks_json = os.path.join(report_dir, f"{repo_name}_gitleaks.json")
                if os.path.exists(gitleaks_json) and os.path.getsize(gitleaks_json) > 0:
                    try:
                        with open(gitleaks_json, 'r', encoding='utf-8') as gf:
                            leaks_data = json.load(gf)
                        
                        # Handle different possible structures of Gitleaks output
                        findings = []
                        if isinstance(leaks_data, list):
                            findings = leaks_data
                        elif isinstance(leaks_data, dict):
                            # Handle different Gitleaks output formats
                            if 'findings' in leaks_data:
                                findings = leaks_data['findings']
                            elif 'matches' in leaks_data:  # Another common Gitleaks output format
                                findings = leaks_data['matches']
                            elif leaks_data:  # If it's a single finding
                                findings = [leaks_data]
                        
                        if not isinstance(findings, list):
                            logging.warning(f"Expected Gitleaks findings to be a list, got {type(findings)}")
                            findings = []
                        
                        f.write("## Secrets Findings (Gitleaks)\n\n")
                        f.write(f"Total findings: {len(findings)}\n\n")
                        
                        if findings:
                            f.write("| Rule | File:Line | Description |\n")
                            f.write("|------|-----------|-------------|\n")
                            for item in findings[:10]:  # Limit to top 10 findings
                                if not isinstance(item, dict):
                                    continue
                                
                                # Safely extract fields with fallbacks for different Gitleaks versions
                                rule = str(item.get('rule', item.get('RuleID', 'unknown')))
                                file = str(item.get('file', item.get('File', 'unknown')))
                                line = str(item.get('line', item.get('StartLine', 'N/A')))
                                desc = str(item.get('description', item.get('Match', 'No description')))
                                
                                # Clean up the output for markdown
                                rule = rule.replace('|', '\\|')
                                file = file.replace('|', '\\|')
                                desc = desc.replace('\n', ' ').replace('|', '\\|')
                                
                                f.write(f"| {rule} | {file}:{line} | {desc} |\n")
                            
                            f.write("\n")
                            f.write("**Remediation:** Rotate and revoke exposed credentials, invalidate tokens, "
                                  "re-issue keys, and purge secrets from history where possible.\n\n")
                    except json.JSONDecodeError as je:
                        logging.error(f"Failed to parse Gitleaks JSON: {je}")
                        f.write("## Secrets Findings (Gitleaks)\n\n")
                        f.write("⚠️ Error: Could not parse Gitleaks results. The output may be malformed.\n\n")
                    except Exception as e:
                        logging.error(f"Error processing Gitleaks results: {e}")
                        f.write("## Secrets Findings (Gitleaks)\n\n")
                        f.write(f"⚠️ Error processing Gitleaks results: {str(e)}\n\n")
                else:
                    # File doesn't exist or is empty
                    f.write("## Secrets Findings (Gitleaks)\n\n")
                    if os.path.exists(gitleaks_json) and os.path.getsize(gitleaks_json) == 0:
                        f.write("No secrets found (empty Gitleaks report).\n\n")
                    else:
                        f.write("No Gitleaks report generated.\n\n")
            except Exception as e:
                logging.error(f"Failed to build Secrets Findings section: {e}")
            
            # Exploitable Flows (from Semgrep taint)
            try:
                semgrep_taint_json = os.path.join(report_dir, f"{repo_name}_semgrep_taint.json")
                if os.path.exists(semgrep_taint_json):
                    with open(semgrep_taint_json, 'r') as sf:
                        taint = json.load(sf)
                    flows = taint.get('results', []) if isinstance(taint, dict) else []
                    f.write("## Exploitable Flows (Semgrep Taint)\n\n")
                    if not flows:
                        f.write("No exploitable flows found.\n\n")
                    else:
                        for r in flows[:5]:
                            path = r.get('path','unknown')
                            msg = r.get('extra',{}).get('message','')
                            start = r.get('start',{}).get('line')
                            end = r.get('end',{}).get('line')
                            f.write(f"- {path}:{start}-{end} — {msg}\n")
                        f.write("\n")
            except Exception as e:
                logging.error(f"Failed to build Exploitable Flows section: {e}")
            
            # Repository Metadata
            if repo_full_name and config.GITHUB_TOKEN:
                try:
                    session = make_session()
                    
                    # 1. Get top contributors
                    contributors = get_repo_contributors(session, repo_full_name)
                    
                    # 2. Get top languages
                    languages = get_repo_languages(session, repo_full_name)
                    
                    # 3. Get commit analysis
                    commit_analysis = analyze_commit_messages(session, repo_full_name)
                    
                    # 4. Get top vulnerabilities
                    scan_results = {
                        'safety': safety_result,
                        'npm_audit': npm_audit_result,
                        'pip_audit': pip_audit_result
                    }
                    # Optionally include Grype (repo) results if present
                    try:
                        grype_repo_json = os.path.join(report_dir, f"{repo_name}_grype_repo.json")
                        if os.path.exists(grype_repo_json):
                            with open(grype_repo_json, 'r') as gf:
                                grype_data = json.load(gf)
                                # Enrich with KEV/EPSS and store
                                grype_data = enrich_grype_with_threat_intel(grype_data)
                                scan_results['grype'] = grype_data
                    except Exception as _e:
                        logging.debug(f"Could not load/enrich Grype results for top vulnerabilities: {_e}")
                    # Include Trivy FS results if present
                    try:
                        trivy_fs_json = os.path.join(report_dir, f"{repo_name}_trivy_fs.json")
                        if os.path.exists(trivy_fs_json):
                            with open(trivy_fs_json, 'r') as tf:
                                trivy_data = json.load(tf)
                                scan_results['trivy_fs'] = trivy_data
                    except Exception as _e:
                        logging.debug(f"Could not load Trivy fs results for top vulnerabilities: {_e}")
                    top_vulnerabilities = get_top_vulnerabilities(scan_results)
                    
                    # Write repository metadata section
                    f.write("## Repository Information\n\n")
                    
                    # Top Contributors
                    f.write("### Top 5 Contributors\n\n")
                    try:
                        # Build contributor stats table with vulnerability attribution
                        contributor_rows, contributor_details = build_contributor_vuln_table(
                            session=session,
                            repo_full_name=repo_full_name,
                            repo_local_path=repo_local_path,
                            report_dir=report_dir,
                            repo_name=repo_name
                        )
                        f.write("| Contributor | Total Number of Commits | Timestamp of Last Commit | Number of Exploitable Vulnerabilities Introduced by Contributor | Exploitable Code Location |\n")
                        f.write("|---|---:|---|---:|---|\n")
                        for row in contributor_rows:
                            f.write("| " + " | ".join(row) + " |\n")
                        f.write("\n")
                        # Collapsible details by contributor
                        for login, details_md in contributor_details.items():
                            f.write(f"<details><summary>Details for {login}</summary>\n\n")
                            f.write(details_md)
                            f.write("\n</details>\n\n")
                    except Exception as e:
                        logging.error(f"Failed to build contributor table: {e}")
                        f.write("(Failed to compute contributor attribution)\n\n")
                        
                    f.write("\n")
                    
                    # Top Languages
                    f.write("### Top 5 Languages\n\n")
                    if languages:
                        for lang, bytes_count in languages:
                            f.write(f"- {lang}: {bytes_count:,} bytes\n")
                    else:
                        f.write("No language data available\n")
                    f.write("\n")
                    
                    # Last Update and Commit Analysis
                    f.write("### Recent Activity\n\n")
                    f.write(f"**Last Updated:** {commit_analysis['last_update']}\n\n")
                    
                    f.write("**Top 5 Commit Patterns:**\n")
                    if commit_analysis['top_commit_reasons']:
                        for pattern, count in commit_analysis['top_commit_reasons']:
                            f.write(f"- `{pattern}` ({count} commits)\n")
                    else:
                        f.write("No commit data available\n")
                    f.write("\n")
                    
                    # Top Vulnerabilities
                    f.write("### Top 5 Vulnerabilities\n\n")
                    if top_vulnerabilities:
                        f.write("| Type | Package | Severity | Exploitability | Affected | Fixed In | Remediation |\n")
                        f.write("|------|---------|----------|----------------|-----------|-----------|-------------|\n")
                        for vuln in top_vulnerabilities:
                            # Visible badges in package name (kept) and a dedicated column
                            name_badged = vuln['name']
                            kev = vuln.get('kev')
                            epss = vuln.get('epss')
                            badges = []
                            if kev:
                                badges.append("[KEV]")
                            if isinstance(epss, (int, float)) and epss > 0:
                                badges.append(f"(EPSS: {epss:.2f})")
                            if badges:
                                name_badged = f"{name_badged} {' '.join(badges)}"

                            # Exploitability column value
                            expl_parts = []
                            if kev:
                                expl_parts.append("[KEV]")
                            if isinstance(epss, (int, float)) and epss > 0:
                                expl_parts.append(f"EPSS: {epss:.2f}")
                            expl_col = " ".join(expl_parts) if expl_parts else "—"

                            f.write(
                                f"| {vuln['type']} | {name_badged} | {vuln['severity']} | {expl_col} | "
                                f"{vuln['affected_versions']} | {vuln['fixed_in']} | {vuln['remediation']} |\n"
                            )
                        # Legend for badges
                        f.write("\n> Legend: [KEV] = Known Exploited Vulnerability; EPSS = Exploit Prediction Scoring System probability.\n\n")

                        # Threat Intel Diagnostics for Top 5
                        try:
                            f.write("#### Threat Intel Diagnostics\n\n")
                            f.write("| Package | KEV | EPSS | Notes |\n")
                            f.write("|---------|-----|------|-------|\n")
                            for vuln in top_vulnerabilities:
                                kev = vuln.get('kev')
                                epss = vuln.get('epss')
                                kev_cell = "✅" if kev else "—"
                                if isinstance(epss, (int, float)):
                                    epss_cell = f"{epss:.2f}" if epss > 0 else "0.00"
                                else:
                                    epss_cell = "—"
                                notes = ""  # Reserved for future mapping notes
                                f.write(f"| {vuln['name']} | {kev_cell} | {epss_cell} | {notes} |\n")
                            f.write("\n")
                        except Exception as _e:
                            logging.debug(f"Threat Intel Diagnostics skipped: {_e}")
                    else:
                        f.write("No critical vulnerabilities found.\n")
                    f.write("\n")
                    
                except Exception as e:
                    logging.error(f"Error fetching repository metadata: {e}")
                    f.write("*Error: Could not fetch repository metadata*\n\n")
            
            # Next Steps
            f.write("## Next Steps\n\n")
            f.write("1. Review the detailed reports for any vulnerabilities found\n")
            f.write("2. Update dependencies to their latest secure versions\n")
            f.write("3. Rerun the scan after making changes to verify fixes\n")
            
            # Repository reference
            f.write("## Repository\n\n")
            f.write(f"**URL:** {repo_url}\n")
            
            # Only attempt cleanup if we have a valid file path
            if requirements_path and isinstance(requirements_path, str):
                try:
                    if os.path.isfile(requirements_path):
                        os.remove(requirements_path)
                except Exception as e:
                    logging.debug(f"Cleanup skipped for requirements file '{requirements_path}': {e}")
    except Exception as e:
        logging.error(f"Error processing {repo_name or repo.get('name', 'unknown')}: {e}", exc_info=True)
    # finally:
    #     # DO NOT clean up config.CLONE_DIR here as it is shared across threads!
    #     # Cleanup happens in main() or signal_handler()
    #     pass

def cleanup_temp_dir(temp_dir: str):
    """Clean up the temporary directory with retries on failure."""
    if not temp_dir or not os.path.exists(temp_dir):
        return
        
    # Log who is calling cleanup
    logging.debug(f"Cleanup called for {temp_dir}")
    # traceback.print_stack()  # Uncomment for debugging
        
    max_retries = 3
    for attempt in range(max_retries):
        try:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                logging.info(f"Cleaned up temporary directory: {temp_dir}")
                return
        except Exception as e:
            if attempt == max_retries - 1:  # Last attempt
                logging.warning(f"Failed to clean up temporary directory {temp_dir} after {max_retries} attempts: {e}")
            else:
                time.sleep(1)  # Wait before retry

def signal_handler(sig, frame):
    """Handle interrupt signals gracefully."""
    global shutdown_requested
    
    if shutdown_requested:
        # Second Ctrl-C - force immediate shutdown
        print("\n⚠️  Force shutdown requested. Exiting immediately...")
        sys.exit(130)
    
    shutdown_requested = True
    print("\n⚠️  Received interrupt signal (Ctrl-C). Shutting down gracefully...")
    print("   The current repository scan will complete, but no new scans will start.")
    print("   Press Ctrl-C again to force immediate shutdown.")
    
    # Set the shutdown event to signal all workers to stop
    shutdown_event.set()

def main():
    """Main function to orchestrate the repository scanning process."""
    # Set up signal handlers for clean exit
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Early console signal that the script started
    try:
        print("[auditgh] Starting scan_repos.py ...")
    except Exception:
        pass
    parser = argparse.ArgumentParser(description="Scan GitHub org repos for security vulnerabilities.")
    parser.add_argument("--org", type=str, default=config.ORG_NAME,
                      help="GitHub organization name")
    parser.add_argument("--api-base", type=str, default=config.GITHUB_API,
                      help="GitHub API base URL (e.g., https://api.github.com or GHE /api/v3)")
    parser.add_argument("--report-dir", type=str, default=config.REPORT_DIR,
                      help="Directory to write reports")
    parser.add_argument("--repo", type=str, default=None,
                      help="Scan a single repository (name or owner/name). If omitted, scans all repos in --org. "
                           "For repos starting with '-', use --repo=\"-name\" or --repo='-name'")
    parser.add_argument("--dry-run", action="store_true",
                      help="Do not run scanners. Print which repo(s) would be scanned and exit.")
    parser.add_argument("--docker-image", type=str, default=None,
                      help="Docker image name to generate an SBOM for using Syft (e.g., repo/image:tag).")
    parser.add_argument("--syft-format", type=str, default=config.SYFT_FORMAT,
                      help="Syft SBOM output format (e.g., cyclonedx-json, spdx-json). Default: cyclonedx-json")
    parser.add_argument("--vex", action="append", default=None,
                      help="Path to a VEX document (repeatable). Passed to Grype to refine vulnerability results.")
    parser.add_argument("--semgrep-taint", type=str, default=None,
                      help="Path to a Semgrep taint-mode ruleset (e.g., p/ci or a local .yaml). If provided, runs a second Semgrep pass.")
    parser.add_argument("--policy", type=str, default=None,
                      help="Path to policy.yaml if not in repo root.")
    parser.add_argument("--token", type=str, default=config.GITHUB_TOKEN,
                      help="GitHub token (or set GITHUB_TOKEN env var)")
    parser.add_argument("--include-forks", action="store_true",
                      help="Include forked repositories")
    parser.add_argument("--include-archived", action="store_true",
                      help="Include archived repositories")
    parser.add_argument("--max-workers", type=int, default=4,
                      help="Max concurrent workers (default: 4)")
    parser.add_argument("--repo-timeout", type=int, default=5,
                      help="Initial timeout in minutes per repository (default: 5). Progress monitoring allows scans to continue if actively working.")
    parser.add_argument("--scanner-timeout", type=int, default=10,
                      help="Timeout in minutes per individual scanner (default: 10)")
    parser.add_argument("--continue-on-timeout", action="store_true", default=True,
                      help="Continue scanning other repositories after a timeout (default: True)")
    
    # AI Agent arguments
    parser.add_argument("--ai-agent", action="store_true",
                      help="Enable AI-powered analysis of stuck scans (requires API key)")
    parser.add_argument("--ai-provider", type=str, choices=["openai", "claude"],
                      help="AI provider to use (default: from env AI_PROVIDER)")
    parser.add_argument("--ai-auto-remediate", action="store_true",
                      help="Allow AI to automatically apply safe fixes")
    parser.add_argument("--no-ai-agent", action="store_true",
                      help="Disable AI agent entirely (overrides env settings)")
    
    # Progress monitoring arguments
    parser.add_argument("--progress-check-interval", type=int, default=30,
                      help="Seconds between progress checks (default: 30)")
    parser.add_argument("--max-idle-time", type=int, default=180,
                      help="Seconds of no progress before timeout (default: 180)")
    parser.add_argument("--min-cpu-threshold", type=float, default=5.0,
                      help="Minimum CPU %% to consider scan active (default: 5.0)")
    
    parser.add_argument("--loglevel", type=str, default="INFO",
                      choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                      help="Set the logging level (default: INFO)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                      help="Increase verbosity (can be used multiple times)")
    parser.add_argument("--no-scan", action="store_true",
                      help="Skip the actual scanning process (useful for testing infrastructure)")
    parser.add_argument("--scanners", type=str, default="all",
                      help="Comma-separated list of scanners to run (e.g., 'syft,trivy'). Default: 'all'")

    # Rescan control arguments
    parser.add_argument("--force-rescan", action="store_true",
                      help="Force rescan of all repositories, ignoring existing reports")
    parser.add_argument("--rescan-days", type=int, default=180,
                      help="Days threshold for rescanning repos with recent activity (default: 180)")
    parser.add_argument("--skipscan", action="store_true",
                      help="Skip repositories that were fully scanned within the last 48 hours")
    parser.add_argument("--overridescan", action="store_true",
                      help="Override all skip logic and scan every repository regardless of activity or scan age")

    # Auto-ingestion control
    parser.add_argument("--no-auto-ingest", action="store_true",
                      help="Disable automatic data ingestion after scan completes (ingestion runs by default)")

    # Resume functionality arguments
    parser.add_argument("--resume", action="store_true",
                      help="Resume from previous interrupted scan (skips already completed repos)")
    parser.add_argument("--clear-resume", action="store_true",
                      help="Clear resume state and start fresh scan")
    parser.add_argument("--resume-state-file", type=str, default=".scan_resume_state.pkl",
                      help="Path to resume state file (default: .scan_resume_state.pkl)")
    
    # Multi-tenant support
    parser.add_argument("--tenant", type=str, default=None,
                      help="Tenant slug/ID to ingest scan data into (for multi-tenant mode)")
    
    # Multi-organization support
    parser.add_argument("--target", "-t", type=str, default=None,
                      help="Target organization name (e.g., sealmindset, sleepnumberinc). "
                           "Loads credentials from secrets manager and uses org-specific database.")
    parser.add_argument("--list-orgs", action="store_true",
                      help="List all configured organizations and exit")
    parser.add_argument("--create-org", type=str, default=None, metavar="NAME",
                      help="Create a new organization (requires --github-org and --github-token)")
    parser.add_argument("--github-org", type=str, default=None,
                      help="GitHub organization name (for --create-org)")
    parser.add_argument("--sync-schemas", action="store_true",
                      help="Sync all organization database schemas with master")
    parser.add_argument("--check-drift", action="store_true",
                      help="Check for schema drift across all organizations")
    parser.add_argument("--reset-org", action="store_true",
                      help="Reset organization data (creates backup first, use with --target)")
    parser.add_argument("--reset-force", action="store_true",
                      help="Skip confirmation prompt for --reset-org")
    parser.add_argument("--list-backups", action="store_true",
                      help="List all organization backups")
    parser.add_argument("--cleanup-backups", action="store_true",
                      help="Remove backups older than 30 days")
    parser.add_argument("--new-repos-only", action="store_true",
                      help="Only scan repositories that have never been scanned (last_scanned_at IS NULL)")

    args = parser.parse_args()

    # ==========================================================================
    # Multi-Organization Management Commands
    # ==========================================================================
    
    # Handle organization reset/backup commands
    if args.reset_org or args.list_backups or args.cleanup_backups:
        try:
            from scripts.reset_organization_data import OrganizationDataManager, reset_organization
            
            manager = OrganizationDataManager()
            
            if args.list_backups:
                backups = manager.list_backups(args.target)
                
                if not backups:
                    print("No backups found")
                else:
                    print(f"\n{'='*80}")
                    print(f"Organization Backups (30-day retention)")
                    print(f"{'='*80}")
                    
                    for backup in backups:
                        status = "⚠️ EXPIRED" if backup.get("expired") else "✓ Active"
                        exists = "✓" if backup.get("backup_exists") else "✗ Missing"
                        
                        print(f"\n{backup.get('organization_name', 'Unknown')}")
                        print(f"  Created: {backup.get('created_at', 'Unknown')}")
                        print(f"  Age: {backup.get('age_days', 0)} days | Status: {status} | File: {exists}")
                        print(f"  Stats: {backup.get('stats', {})}")
                        print(f"  File: {backup.get('backup_file', 'Unknown')}")
                    
                    print(f"\n{'='*80}\n")
                sys.exit(0)
            
            elif args.cleanup_backups:
                deleted = manager.cleanup_old_backups(dry_run=False)
                print(f"✓ Deleted {deleted} expired backup(s)")
                sys.exit(0)
            
            elif args.reset_org:
                if not args.target:
                    print("❌ Error: --target is required for --reset-org")
                    print("   Example: python scan_repos.py --reset-org --target sleepnumberlabs")
                    sys.exit(1)
                
                success = reset_organization(args.target, force=args.reset_force)
                sys.exit(0 if success else 1)
                
        except ImportError as e:
            print(f"❌ Error: Could not import reset module: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error: {e}")
            sys.exit(1)
    
    # Handle organization management commands before main scan logic
    if args.list_orgs or args.create_org or args.sync_schemas or args.check_drift:
        try:
            from execution.ai_org_agent import AIOrganizationAgent, get_org_agent
            from execution.secrets_manager import list_configured_orgs
            
            async def run_org_commands():
                agent = get_org_agent()
                await agent.initialize()
                
                if args.list_orgs:
                    print("\n📋 Registered Organizations:")
                    print("-" * 60)
                    orgs = await agent.list_organizations(include_inactive=True)
                    if not orgs:
                        print("  No organizations registered yet.")
                        print("\n  Create one with: --create-org NAME --github-org ORG --token TOKEN")
                    else:
                        for org in orgs:
                            status = "✓ active" if org.is_active else "✗ inactive"
                            default = " (default)" if org.is_default else ""
                            print(f"  {org.name}{default}")
                            print(f"    GitHub: {org.github_org} | DB: {org.database_name}")
                            print(f"    Status: {status} | Schema: {org.schema_sync_status}")
                            if org.last_scan_at:
                                print(f"    Last scan: {org.last_scan_at}")
                            print()
                    
                    # Also show configured credentials
                    configured = await list_configured_orgs()
                    print(f"🔑 Organizations with credentials: {', '.join(configured) if configured else 'none'}")
                
                elif args.create_org:
                    if not args.github_org:
                        print("❌ Error: --github-org is required when creating an organization")
                        sys.exit(1)
                    if not args.token:
                        print("❌ Error: --token is required when creating an organization")
                        sys.exit(1)
                    
                    print(f"\n🏢 Creating organization: {args.create_org}")
                    org = await agent.create_organization(
                        name=args.create_org,
                        github_org=args.github_org,
                        github_token=args.token,
                        create_database=True
                    )
                    print(f"✓ Created organization: {org.name}")
                    print(f"  GitHub org: {org.github_org}")
                    print(f"  Database: {org.database_name}")
                
                elif args.sync_schemas:
                    print("\n🔄 Syncing all organization schemas...")
                    results = await agent.sync_all_schemas()
                    print(f"\nResults: {results['synced']} synced, "
                          f"{results['already_synced']} already synced, "
                          f"{results['errors']} errors")
                
                elif args.check_drift:
                    print("\n🔍 Checking schema drift...")
                    results = await agent.check_schema_drift()
                    print("\nSchema Drift Report:")
                    print("-" * 60)
                    for r in results:
                        status_icon = "✓" if r['is_synced'] else "⚠️"
                        print(f"  {status_icon} {r['organization']}: {r['status']}")
                        if not r['is_synced'] and 'error' not in r:
                            print(f"     Master: {r['master_hash']} | Org: {r['org_hash']}")
            
            asyncio.run(run_org_commands())
            sys.exit(0)
            
        except ImportError as e:
            print(f"❌ Organization management not available: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error: {e}")
            sys.exit(1)
    
    # Handle --target flag to select organization
    if args.target:
        try:
            from execution.ai_org_agent import get_org_agent
            
            async def select_target_org():
                agent = get_org_agent()
                await agent.initialize()
                
                org = await agent.select_organization(args.target)
                print(f"🎯 Target organization: {org.name} (GitHub: {org.github_org})")
                
                # Return org and the env vars that were set
                return (
                    org, 
                    os.environ.get('GITHUB_TOKEN'), 
                    os.environ.get('GITHUB_ORG'),
                    os.environ.get('DATABASE_URL'),
                    os.environ.get('POSTGRES_DB')
                )
            
            selected_org, new_token, new_github_org, new_db_url, new_db_name = asyncio.run(select_target_org())
            
            # DOE Self-Annealing: Validate scan context before proceeding
            validated_context = org_filtering_annealing.validate_scan_context(
                target_org=args.target,
                github_org=new_github_org or selected_org.github_org,
                org_id=str(selected_org.id)
            )
            
            if validated_context["corrections"]:
                logging.info(f"DOE Self-Annealing: Applied {len(validated_context['corrections'])} corrections to scan context")
            
            # Update config with org credentials AFTER asyncio.run completes
            # Use validated values from self-annealing
            config.ORG_NAME = validated_context["github_org"]
            config.GITHUB_TOKEN = new_token
            
            # CRITICAL: Set organization ID for multi-tenant database scoping
            config.ORGANIZATION_ID = validated_context["org_id"]
            config.ORGANIZATION_NAME = selected_org.name
            
            # Set database environment for KnowledgeBase
            if new_db_url:
                os.environ['DATABASE_URL'] = new_db_url
            if new_db_name:
                os.environ['POSTGRES_DB'] = new_db_name

            # CRITICAL: Re-bind SessionLocal to the tenant database
            # because the initial import occurred before env vars were updated.
            if new_db_url:
                try:
                    from sqlalchemy import create_engine
                    from sqlalchemy.orm import sessionmaker
                    
                    logging.info(f"Connecting to tenant database: {new_db_url.split('@')[-1]}") # Log safe URL
                    tenant_engine = create_engine(new_db_url)
                    
                    # Update global SessionLocal used by process_repo and scanners
                    global SessionLocal
                    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=tenant_engine)
                    logging.info(f"✅ Re-bound SessionLocal to tenant database: {new_db_name}")
                    
                except Exception as e:
                    logging.error(f"Failed to re-bind database session: {e}")
                    # Fallback to default behavior (likely master DB) which is better than crashing

            
            if config.GITHUB_TOKEN:
                config.HEADERS = {
                    "Authorization": f"Bearer {config.GITHUB_TOKEN}",
                    "Accept": "application/vnd.github.v3+json"
                }
            
            logging.info(f"Using organization: {selected_org.name} (GitHub org: {config.ORG_NAME})")
            logging.info(f"Organization ID: {config.ORGANIZATION_ID}")
            logging.info(f"Database: {new_db_name or 'default'}")
            
        except ImportError as e:
            logging.warning(f"Organization management not available: {e}")
            logging.warning("Falling back to environment variables")
            # Use --target value as the GitHub org name when org management is unavailable
            config.ORG_NAME = args.target
            # Resolve org-specific token: ORG_{NAME}_TOKEN (e.g., ORG_SLEEPNUMBERLABS_TOKEN)
            org_token_var = f"ORG_{args.target.upper()}_TOKEN"
            org_token = os.environ.get(org_token_var)
            if org_token:
                config.GITHUB_TOKEN = org_token
                config.HEADERS = {
                    "Authorization": f"Bearer {org_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
                logging.info(f"Using org-specific token from {org_token_var}")
            else:
                logging.warning(f"No org-specific token found ({org_token_var}), using default GITHUB_TOKEN")
            logging.info(f"Using --target as GitHub org: {config.ORG_NAME}")
        except Exception as e:
            logging.error(f"Failed to select organization '{args.target}': {e}")
            sys.exit(1)

    # Check for SKIP_SCAN environment variable
    if args.no_scan or os.getenv("SKIP_SCAN", "false").lower() == "true":
        print("[auditgh] SKIP_SCAN is set. Skipping repository scan.")
        print("[auditgh] The container will remain active (sleeping) to allow exec.")
        # Sleep indefinitely to keep container running if needed, or just exit.
        # User asked to "not have the entire rescan", usually implying they want the stack up.
        # If I exit, the container stops. If they want to exec into it, it needs to run.
        # Let's sleep.
        import time
        while True:
            time.sleep(3600)

    
    # Set log level from command line or use default
    if args.verbose > 0:
        configure_logging(args.verbose)
    else:
        numeric_level = getattr(logging, args.loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(f"Invalid log level: {args.loglevel}")
        logging.basicConfig(level=numeric_level)
    
    # Update config with command line args
    # Don't overwrite ORG_NAME if --target was used (already set above)
    if not args.target:
        config.ORG_NAME = args.org
    config.GITHUB_API = args.api_base.rstrip('/')
    
    # Multi-org: Include organization name in report directory path
    # Structure: vulnerability_reports/{org_name}/{repo_name}/
    base_report_dir = args.report_dir
    if config.ORGANIZATION_NAME:
        config.REPORT_DIR = os.path.join(base_report_dir, config.ORGANIZATION_NAME)
        logging.info(f"📁 Reports will be saved to: {config.REPORT_DIR}")
    else:
        config.REPORT_DIR = base_report_dir
    os.makedirs(config.REPORT_DIR, exist_ok=True)
    
    # Don't overwrite GITHUB_TOKEN if --target was used (already set above)
    if not args.target:
        config.GITHUB_TOKEN = args.token or os.getenv("GITHUB_TOKEN")
    config.DOCKER_IMAGE = args.docker_image
    config.SYFT_FORMAT = args.syft_format
    config.SCANNERS = args.scanners
    config.VEX_FILES = [p for p in (args.vex or []) if p]
    config.SEMGREP_TAINT_CONFIG = args.semgrep_taint
    config.POLICY_PATH = args.policy or 'policy.yaml'

    # Log rescan configuration
    if args.overridescan:
        logging.info("⚡ Override scan enabled - all skip logic disabled, will scan every repository")
    elif args.force_rescan:
        logging.info("🔄 Force rescan enabled - will rescan all repositories regardless of existing reports")
    else:
        logging.info(f"📅 Rescan threshold: {args.rescan_days} days (repos with activity within {args.rescan_days} days will be rescanned)")
        if args.skipscan:
            logging.info("⏭️  Skip scan enabled - will skip repositories scanned within the last 48 hours")

    # Initialize resume state
    resume_state = None
    if args.clear_resume:
        logging.info("🗑️  Clearing resume state...")
        temp_state = ResumeState(args.resume_state_file)
        temp_state.clear()
        logging.info("✓ Resume state cleared")

    if args.resume:
        logging.info("⏯️  Resume mode enabled - checking for previous scan state...")
        resume_state = ResumeState(args.resume_state_file)
        if resume_state.load():
            progress = resume_state.get_progress()
            logging.info(f"📂 Found previous scan state: {progress['completed']}/{progress['total']} repos completed ({progress['percentage']:.1f}%)")
            if progress['completed'] > 0:
                logging.info(f"⏱️  Previous scan started: {progress['scan_start_time']}")
            else:
                logging.info("📝 Starting new scan with resume tracking")
        else:
            logging.info("📝 No previous scan state found - starting fresh with resume tracking")
    elif not args.clear_resume:
        # Implicitly enable resume for safety (can be disabled with explicit flag in future)
        resume_state = ResumeState(args.resume_state_file)
        resume_state.load()  # Try to load, but don't log if not found

    # Update headers if token is available
    if config.GITHUB_TOKEN:
        config.HEADERS = {
            "Authorization": f"Bearer {config.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
    
    # Initialize AI Agent (if enabled)
    global ai_provider, reasoning_engine, remediation_engine, learning_system
    
    ai_agent_enabled = False
    if not args.no_ai_agent:
        # Check if AI should be enabled (CLI flag or env variable)
        ai_agent_enabled = args.ai_agent or os.getenv("AI_AGENT_ENABLED", "false").lower() == "true"
        config.ENABLE_AI = ai_agent_enabled
    
    if ai_agent_enabled and AI_AGENT_AVAILABLE:
        try:
            logging.info("🤖 Initializing AI agent...")
            
            # Determine AI provider
            provider_name = args.ai_provider or os.getenv("AI_PROVIDER", "openai")
            
            # Initialize the appropriate provider
            if provider_name == "openai":
                api_key = os.getenv("OPENAI_API_KEY")
                if not api_key:
                    logging.warning("OpenAI API key not found. AI agent disabled.")
                    ai_agent_enabled = False
                else:
                    model = os.getenv("OPENAI_MODEL", "gpt-4-turbo")
                    ai_provider = OpenAIProvider(api_key=api_key, model=model)
                    logging.info(f"   Using OpenAI provider: {model}")
            
            elif provider_name == "claude":
                api_key = os.getenv("ANTHROPIC_API_KEY")
                if not api_key:
                    logging.warning("Anthropic API key not found. AI agent disabled.")
                    ai_agent_enabled = False
                else:
                    # DOE Self-Annealing: Validate model before use
                    raw_model = os.getenv("CLAUDE_MODEL") or os.getenv("ANTHROPIC_MODEL") or os.getenv("AI_MODEL") or "claude-sonnet-4-20250514"
                    model = ai_model_annealing.validate_and_correct("claude", raw_model)
                    ai_provider = ClaudeProvider(api_key=api_key, model=model)
                    logging.info(f"   Using Claude provider: {model}")
            
            if ai_agent_enabled and ai_provider:
                # Initialize diagnostic collector
                diagnostic_collector = DiagnosticCollector(report_dir=config.REPORT_DIR)
                
                # Initialize reasoning engine
                max_cost = float(os.getenv("AI_MAX_COST_PER_SCAN", "0.50"))
                reasoning_engine = ReasoningEngine(
                    provider=ai_provider,
                    diagnostic_collector=diagnostic_collector,
                    max_cost_per_analysis=max_cost
                )
                
                # Initialize remediation engine
                auto_remediate = args.ai_auto_remediate or os.getenv("AI_AUTO_REMEDIATE", "false").lower() == "true"
                dry_run = os.getenv("AI_DRY_RUN", "false").lower() == "true"
                min_confidence = float(os.getenv("AI_MIN_CONFIDENCE", "0.7"))
                
                # Parse allowed actions from env
                allowed_actions_str = os.getenv("AI_ALLOWED_ACTIONS", "increase_timeout,exclude_patterns")
                from src.ai_agent.providers.base import RemediationAction
                allowed_actions = set()
                for action_str in allowed_actions_str.split(","):
                    try:
                        allowed_actions.add(RemediationAction(action_str.strip()))
                    except ValueError:
                        logging.warning(f"Unknown remediation action: {action_str}")
                
                remediation_engine = RemediationEngine(
                    allowed_actions=allowed_actions if allowed_actions else None,
                    dry_run=dry_run,
                    min_confidence=min_confidence
                )
                
                # Initialize learning system
                if os.getenv("AI_LEARNING_ENABLED", "true").lower() == "true":
                    learning_system = LearningSystem()
                
                logging.info(f"   AI agent initialized successfully")
                logging.info(f"   Auto-remediation: {'enabled' if auto_remediate else 'disabled'}")
                logging.info(f"   Dry-run mode: {'enabled' if dry_run else 'disabled'}")
                logging.info(f"   Max cost per scan: ${max_cost}")
        
        except Exception as e:
            logging.error(f"Failed to initialize AI agent: {e}")
            ai_agent_enabled = False
    
    elif ai_agent_enabled and not AI_AGENT_AVAILABLE:
        logging.warning("AI agent requested but dependencies not available. Install with: pip install openai anthropic psutil")
        ai_agent_enabled = False

    # Initialize AI Agent if enabled
    global ai_agent
    if config.ENABLE_AI:
        try:
            from src.ai_agent.agent import AIAgent
            ai_agent = AIAgent(
                openai_api_key=config.OPENAI_API_KEY,
                anthropic_api_key=config.ANTHROPIC_API_KEY,
                provider=config.AI_PROVIDER,
                model=config.AI_MODEL
            )
            logging.info(f"AI Agent initialized with provider: {config.AI_PROVIDER}")
        except Exception as e:
            logging.error(f"Failed to initialize AI Agent: {e}")
            ai_agent = None
            
    # Initialize Knowledge Base
    kb = None
    try:
        kb = KnowledgeBase()
    except Exception as e:
        logging.warning(f"Failed to initialize Knowledge Base: {e}")
    
    if not config.GITHUB_TOKEN:
        logging.error("GitHub token is required. Set GITHUB_TOKEN environment variable or use --token")
        print("[auditgh] ERROR: Missing GitHub token. Set GITHUB_TOKEN or pass --token.")
        sys.exit(1)

    # Validate the GitHub token
    print("[auditgh] Validating GitHub token...")
    is_valid, result, scopes = validate_github_token(config.GITHUB_TOKEN)
    if not is_valid:
        logging.error(f"GitHub token validation failed: {result}")
        print(f"[auditgh] ERROR: Invalid GitHub token - {result}")
        print("[auditgh] Please generate a new token at: https://github.com/settings/tokens")
        sys.exit(1)
    
    logging.info(f"GitHub token validated for user: {result}")
    if scopes:
        logging.info(f"Token scopes: {', '.join(scopes)}")
    else:
        logging.warning("No OAuth scopes found - token may be a fine-grained PAT or have limited permissions")
    print(f"[auditgh] Token validated for GitHub user: {result}")

    # Ensure report directory exists
    os.makedirs(config.REPORT_DIR, exist_ok=True)
    
    # Set up the temporary directory for cloning
    try:
        temp_dir = setup_temp_dir()
        config.CLONE_DIR = temp_dir
        logging.info(f"Temporary directory for cloning: {temp_dir}")
    except Exception as e:
        logging.error(f"Failed to set up temporary directory: {e}")
        sys.exit(1)
    
    logging.info(f"Reports will be saved to: {os.path.abspath(config.REPORT_DIR)}")
    print(f"[auditgh] Organization: {config.ORG_NAME}")
    print(f"[auditgh] Reports dir: {os.path.abspath(config.REPORT_DIR)}")
    if args.repo:
        print(f"[auditgh] Single repository mode: {args.repo}")
    else:
        print(f"[auditgh] Fetching repositories for organization: {config.ORG_NAME}")
    
    # Initialize scan_results at the start to prevent UnboundLocalError
    scan_results = {
        'success': 0,
        'timeout': 0,
        'error': 0,
        'skipped': 0,
        'total': 0
    }

    try:
        session = make_session()

        if args.repo:
            # Single repository mode
            print(f"[auditgh] Resolving repository: {config.ORG_NAME}/{args.repo}")
            repo = get_single_repo(session, args.repo)
            if not repo:
                logging.error("Aborting: could not resolve the requested repository.")
                print(f"[auditgh] Repository not found or inaccessible: {args.repo}")
                return
            print(f"[auditgh] Found: {repo.get('full_name', args.repo)}")
            if args.dry_run:
                full_name = repo.get("full_name") or f"{repo.get('owner',{}).get('login','?')}/{repo.get('name','?')}"
                logging.info(f"[DRY-RUN] Would scan repository: {full_name}")
                return

            # Initialize resume state and scan_results for single repo
            if resume_state:
                resume_state.initialize_scan(1)

            scan_results['total'] = 1
            scan_results['success'] = 1  # Assume success unless process_repo throws

            process_repo(repo, config.REPORT_DIR, force_rescan=args.force_rescan, rescan_days=args.rescan_days, skip_scan=args.skipscan, override_scan=args.overridescan, resume_state=resume_state, tenant_slug=args.tenant)
        else:
            # Get all repositories
            repos = get_all_repos(
                session=session,
                include_forks=args.include_forks,
                include_archived=args.include_archived
            )
            
            if not repos:
                logging.warning("No repositories found matching the criteria.")
                # Check if we should continue processing
                try:
                    pass
                except KeyboardInterrupt:
                    logging.info("Scan interrupted by user")
                    return

            # Filter to only new (never scanned) repos if requested
            if args.new_repos_only and DATABASE_AVAILABLE:
                original_count = len(repos)
                db = SessionLocal()
                try:
                    new_repos = []
                    for repo in repos:
                        repo_name = repo.get('full_name') or repo.get('name', 'unknown')
                        # Query database to check if repo has been scanned
                        db_repo = db.query(models.Repository).filter(
                            models.Repository.name == repo_name
                        ).first()
                        # Include if not in DB or never scanned
                        if not db_repo or db_repo.last_scanned_at is None:
                            new_repos.append(repo)
                    repos = new_repos
                    logging.info(f"🆕 Filtering to {len(repos)} new repos (never scanned) out of {original_count} total")
                finally:
                    db.close()
            elif args.new_repos_only and not DATABASE_AVAILABLE:
                logging.warning("--new-repos-only requires database access, scanning all repos")

            if args.dry_run:
                for r in repos:
                    logging.info(f"[DRY-RUN] Would scan: {r.get('full_name', r.get('name','unknown'))}")
                logging.info("[DRY-RUN] Exiting without running any scanners.")
                return

            # Initialize resume state for multiple repos
            if resume_state and not resume_state.total_repos:
                resume_state.initialize_scan(len(repos))
                logging.info(f"📝 Initialized resume state for {len(repos)} repositories")

            # ... (rest of the code remains the same)
            # Process repositories in parallel with timeout and self-annealing
            max_workers = max(1, int(args.max_workers))
            repo_timeout = args.repo_timeout

            # Update scan_results for multi-repo mode
            scan_results['total'] = len(repos)

            logging.info(f"Starting parallel scan of {len(repos)} repositories with {max_workers} workers")
            logging.info(f"Repository timeout: {repo_timeout} minutes" + (" (disabled)" if repo_timeout == 0 else ""))
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {}
                
                # Submit all repository scans
                for repo in repos:
                    # Check if shutdown was requested before submitting
                    if shutdown_event.is_set():
                        logging.info("Shutdown requested, not submitting more repositories")
                        break
                    
                    if repo_timeout > 0:
                        # Use timeout wrapper with progress monitoring
                        future = executor.submit(
                            process_repo_with_timeout,
                            repo,
                            config.REPORT_DIR,
                            timeout_minutes=repo_timeout,
                            progress_check_interval=args.progress_check_interval,
                            max_idle_time=args.max_idle_time,
                            min_cpu_threshold=args.min_cpu_threshold,
                            force_rescan=args.force_rescan,
                            rescan_days=args.rescan_days,
                            skip_scan=args.skipscan,
                            override_scan=args.overridescan,
                            resume_state=resume_state,
                            tenant_slug=args.tenant
                        )
                    else:
                        # No timeout - use original process_repo
                        future = executor.submit(process_repo, repo, config.REPORT_DIR, args.force_rescan, args.rescan_days, args.skipscan, args.overridescan, resume_state, args.tenant)
                    
                    futures[future] = repo.get('name', 'unknown')
                
                # Track completed and cancelled repos
                completed_repos = []
                cancelled_repos = []
                
                # Process completed futures
                for future in as_completed(futures):
                    repo_name = futures[future]
                    
                    # Check if shutdown was requested
                    if shutdown_event.is_set():
                        logging.info("Shutdown event detected, completing current scan and cancelling remaining...")
                        # Cancel all pending futures
                        for f in futures:
                            if not f.done():
                                cancelled_repo_name = futures[f]
                                cancelled_repos.append(cancelled_repo_name)
                                f.cancel()
                        
                        # Mark the current one as completed since we're letting it finish
                        try:
                            result = future.result(timeout=1)
                            completed_repos.append(repo_name)
                        except:
                            cancelled_repos.append(repo_name)
                        
                        break
                    
                    try:
                        if repo_timeout > 0:
                            # Get result from timeout wrapper
                            result = future.result()
                            status = result.get('status', 'unknown')
                            
                            if status == 'success':
                                scan_results['success'] += 1
                                completed_repos.append(repo_name)
                            elif status == 'timeout':
                                scan_results['timeout'] += 1
                                logging.warning(f"Repository {repo_name} timed out after {result.get('timeout_limit')} minutes")
                            elif status == 'error':
                                scan_results['error'] += 1
                                logging.error(f"Repository {repo_name} failed: {result.get('error', 'unknown error')}")
                            elif status == 'skipped':
                                scan_results['skipped'] += 1
                        else:
                            # No timeout - just wait for completion
                            future.result()
                            scan_results['success'] += 1
                            completed_repos.append(repo_name)
                            
                    except Exception as e:
                        scan_results['error'] += 1
                        logging.error(f"Error processing repository {repo_name}: {e}")
            
            # Print final summary
            logging.info("=" * 80)
            logging.info("Scan Summary")
            logging.info("=" * 80)
            logging.info(f"Total repositories: {scan_results['total']}")
            logging.info(f"Successful: {scan_results['success']}")
            logging.info(f"Timed out: {scan_results['timeout']}")
            logging.info(f"Errors: {scan_results['error']}")
            logging.info(f"Skipped: {scan_results['skipped']}")
            logging.info("=" * 80)
            
            # Write stuck repos summary if any
            if stuck_repos_log:
                summary_file = os.path.join(config.REPORT_DIR, "stuck_repos_summary.md")
                try:
                    with open(summary_file, 'w') as f:
                        f.write("# Stuck/Timed-Out Repositories Summary\n\n")
                        f.write(f"**Total:** {len(stuck_repos_log)} repositories\n\n")
                        f.write("| Repository | Duration (min) | Phase | Details |\n")
                        f.write("|------------|----------------|-------|----------|\n")
                        for stuck in stuck_repos_log:
                            f.write(f"| {stuck['repo_name']} | {stuck['duration_minutes']} | {stuck['phase']} | {stuck['details'][:50]} |\n")
                    logging.info(f"Stuck repositories summary written to: {summary_file}")
                except Exception as e:
                    logging.warning(f"Failed to write stuck repos summary: {e}")
        
        # Report on shutdown status if applicable
        if shutdown_event.is_set() and shutdown_requested:
            print("\n⚠️  Scan interrupted by user.")
            if 'cancelled_repos' in locals() and cancelled_repos:
                print(f"   ✅ Completed: {len(completed_repos) if 'completed_repos' in locals() else 0} repositories")
                print(f"   ❌ Cancelled: {len(cancelled_repos)} repositories")
                print(f"\n   The following repositories were not scanned:")
                for repo_name in cancelled_repos:
                    print(f"      - {repo_name}")
                
                # Write cancelled repos to a file for reference
                try:
                    cancelled_file = os.path.join(config.REPORT_DIR, "cancelled_repos.txt")
                    with open(cancelled_file, 'w') as f:
                        f.write("# Cancelled Repositories\n\n")
                        f.write(f"Scan interrupted at: {datetime.datetime.now().isoformat()}\n\n")
                        f.write(f"Total cancelled: {len(cancelled_repos)}\n\n")
                        for repo_name in cancelled_repos:
                            f.write(f"- {repo_name}\n")
                    print(f"\n   Cancelled repositories list saved to: {cancelled_file}")
                except Exception as e:
                    logging.warning(f"Failed to write cancelled repos file: {e}")
            
            print("\n✅ Graceful shutdown complete.")
        else:
            logging.info("Scan completed successfully!")

            # Show final progress if resume state is available
            if resume_state:
                progress = resume_state.get_progress()
                if progress['completed'] == progress['total']:
                    logging.info(f"🎉 All {progress['total']} repositories completed!")
                    # Clear resume state since all repos are done
                    resume_state.clear()
                    logging.info("📝 Resume state cleared (all repos completed)")
                else:
                    logging.info(f"📊 Final progress: {progress['completed']}/{progress['total']} repos ({progress['percentage']:.1f}%)")
                    if progress['remaining'] > 0:
                        logging.info(f"⏯️  To resume, run with --resume flag")

            # Ensure a final console line for users
            print(f"[auditgh] Scan completed. Reports saved to: {os.path.abspath(config.REPORT_DIR)}")

            # Print scanner health report if any corrections were made
            health = scanner_annealing.get_health_report()
            if health:
                print("[auditgh] Scanner health report:")
                for name, info in health.items():
                    status_icon = "✓" if info["status"] == "active" else "⏸"
                    print(f"[auditgh]   {status_icon} {name}: {info['success_rate']} success ({info['total_runs']} runs)", flush=True)

            # AUTO-INGEST: Automatically load scan results into database
            if not args.dry_run and not args.no_auto_ingest and scan_results['success'] > 0:
                try:
                    logging.info("=" * 80)
                    logging.info("AUTO-INGEST: Loading scan results into database")
                    logging.info("=" * 80)

                    # Import ingestion module
                    sys.path.insert(0, '/app')
                    sys.path.insert(0, '/app/scripts/maintenance')
                    from ingest_scans import ingest_reports

                    # Run ingestion for scanned reports
                    logging.info(f"Ingesting reports from: {config.REPORT_DIR}")
                    org_id = getattr(config, 'ORGANIZATION_ID', None)
                    ingest_reports(
                        report_dir=config.REPORT_DIR,
                        organization_id=org_id
                    )
                    logging.info("Auto-ingest completed successfully")

                    logging.info("=" * 80)

                except ImportError as e:
                    logging.warning("=" * 80)
                    logging.warning(f"⚠️  Auto-ingest unavailable: {e}")
                    logging.warning("   Database connection may not be available from scanner")
                    logging.warning("   Run manually: docker exec auditgh_api python ingest_reports.py")
                    logging.warning("=" * 80)

                except Exception as e:
                    logging.error("=" * 80)
                    logging.error(f"❌ Auto-ingest failed: {e}")
                    logging.error("   Run manually: docker exec auditgh_api python ingest_reports.py")
                    logging.error("=" * 80)

            elif args.no_auto_ingest:
                logging.info("⏭️  Auto-ingest disabled (--no-auto-ingest flag)")
                logging.info("   Run manually: docker exec auditgh_api python ingest_reports.py")

            print("\n✅ All repositories successfully scanned. Shutting down.")

    except KeyboardInterrupt:
        logging.info("\n🛑 Scan interrupted by user")
        if resume_state:
            progress = resume_state.get_progress()
            logging.info(f"📊 Progress saved: {progress['completed']}/{progress['total']} repos completed ({progress['percentage']:.1f}%)")
            logging.info("⏯️  To resume this scan, run with --resume flag")
        sys.exit(130)  # Standard exit code for SIGINT
    except Exception as e:
        logging.error(f"An error occurred: {e}", exc_info=True)
        sys.exit(1)
    finally:
        # Clean up temporary directory if it exists
        if config.CLONE_DIR and os.path.exists(config.CLONE_DIR):
            try:
                shutil.rmtree(config.CLONE_DIR, ignore_errors=True)
                logging.info(f"Cleaned up temporary directory: {config.CLONE_DIR}")
            except Exception as e:
                logging.warning(f"Failed to clean up temporary directory {config.CLONE_DIR}: {e}")

def run_syft(target: str, repo_name: str, report_dir: str, target_type: str = "repo", sbom_format: str = "cyclonedx-json") -> subprocess.CompletedProcess:
    """Run Anchore Syft to generate SBOMs for a directory (repo) or a docker image.

    target: filesystem path (repo) or image reference (image)
    target_type: 'repo' or 'image'
    sbom_format: syft output format (e.g., cyclonedx-json, spdx-json)
    """
    os.makedirs(report_dir, exist_ok=True)
    syft_bin = shutil.which("syft")
    output_json = os.path.join(report_dir, f"{repo_name}_syft_{'repo' if target_type=='repo' else 'image'}.json")
    output_md = os.path.join(report_dir, f"{repo_name}_syft_{'repo' if target_type=='repo' else 'image'}.md")
    if not syft_bin:
        with open(output_md, 'w') as f:
            f.write("Syft is not installed. Install via: brew install syft or follow https://github.com/anchore/syft\n")
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="syft not installed")
    try:
        # Build syft command
        cmd = [syft_bin, target, f"-o", sbom_format, "--scope", "all-layers"]
        logging.debug(f"Running Syft: {' '.join(cmd)}")
        # Use progress monitoring if available
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="syft",
                cwd=report_dir,
                timeout=3600
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=report_dir)
        # Write JSON output
        with open(output_json, 'w') as f:
            f.write(result.stdout or "")
        # Minimal MD summary
        with open(output_md, 'w') as f:
            f.write(f"# Syft SBOM ({target_type})\n\n")
            f.write(f"**Target:** {target}\n\n")
            try:
                data = json.loads(result.stdout)
                # Heuristic summaries for common formats
                if isinstance(data, dict):
                    pkgs = []
                    for key in ("packages", "components", "artifacts"):
                        if key in data and isinstance(data[key], list):
                            pkgs = data[key]
                            break
                    f.write("## Summary\n\n")
                    f.write(f"- Packages/Components: {len(pkgs)}\n")
                else:
                    f.write("SBOM generated. See JSON for details.\n")
            except Exception:
                f.write("SBOM generated. See JSON for details.\n")
        return result
    except Exception as e:
        with open(output_md, 'w') as f:
            f.write(f"Error running Syft: {e}\n")
        return subprocess.CompletedProcess(args=["syft", target], returncode=1, stdout="", stderr=str(e))

def run_grype(target: str, repo_name: str, report_dir: str, target_type: str = "repo", vex_files: Optional[List[str]] = None) -> subprocess.CompletedProcess:
    """Run Anchore Grype to find vulnerabilities in a directory (repo) or docker image.

    target: filesystem path (repo) or image reference (image)
    """
    os.makedirs(report_dir, exist_ok=True)
    grype_bin = shutil.which("grype")
    output_json = os.path.join(report_dir, f"{repo_name}_grype_{'repo' if target_type=='repo' else 'image'}.json")
    output_md = os.path.join(report_dir, f"{repo_name}_grype_{'repo' if target_type=='repo' else 'image'}.md")
    if not grype_bin:
        with open(output_md, 'w') as f:
            f.write("Grype is not installed. Install via: brew install grype or see https://github.com/anchore/grype\n")
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="grype not installed")
    try:
        cmd = [grype_bin, target, "-o", "json", "--scope", "all-layers"]
        # Append VEX documents if provided
        for vf in (vex_files or []):
            cmd += ["--vex", vf]
        logging.debug(f"Running Grype: {' '.join(cmd)}")
        # Use progress monitoring if available
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="grype",
                cwd=report_dir,
                timeout=3600
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=report_dir)
        # Write JSON output
        with open(output_json, 'w') as f:
            f.write(result.stdout or "")
        # Minimal MD summary
        with open(output_md, 'w') as f:
            f.write(f"# Grype Vulnerability Scan ({target_type})\n\n")
            f.write(f"**Target:** {target}\n\n")
            try:
                data = json.loads(result.stdout)
                matches = data.get("matches", []) if isinstance(data, dict) else []
                sev_counts = {"Critical":0, "High":0, "Medium":0, "Low":0, "Negligible":0, "Unknown":0}
                for m in matches:
                    sev = (m.get('vulnerability', {}).get('severity') or 'Unknown').title()
                    if sev not in sev_counts:
                        sev = 'Unknown'
                    sev_counts[sev] += 1
                f.write("## Summary\n\n")
                for k in ["Critical","High","Medium","Low","Negligible","Unknown"]:
                    f.write(f"- {k}: {sev_counts[k]}\n")
            except Exception:
                f.write("Scan completed. See JSON for details.\n")
        return result
    except Exception as e:
        with open(output_md, 'w') as f:
            f.write(f"Error running Grype: {e}\n")
        return subprocess.CompletedProcess(args=["grype", target], returncode=1, stdout="", stderr=str(e))

def run_checkov(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """Run Checkov to scan Terraform if .tf files are present in repo_path.

    Writes JSON and Markdown summaries. Returns the CompletedProcess on run, or None if not applicable.
    """
    # Detect Terraform files
    has_tf = False
    for root, _dirs, files in os.walk(repo_path):
        if any(fn.endswith('.tf') for fn in files):
            has_tf = True
            break
    if not has_tf:
        return None

    os.makedirs(report_dir, exist_ok=True)
    output_json = os.path.join(report_dir, f"{repo_name}_checkov.json")
    output_md = os.path.join(report_dir, f"{repo_name}_checkov.md")
    checkov_bin = shutil.which('checkov')
    if not checkov_bin:
        with open(output_md, 'w') as f:
            f.write("Checkov is not installed. Install via: pip install checkov or see https://github.com/bridgecrewio/checkov\n")
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="checkov not installed")

    try:
        cmd = [checkov_bin, '-d', repo_path, '-o', 'json']
        logging.debug(f"Running Checkov: {' '.join(cmd)}")
        # Use progress monitoring if available
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="checkov",
                cwd=None,
                timeout=3600
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
        # Write JSON
        with open(output_json, 'w') as f:
            f.write(result.stdout or "")
        # Write MD summary
        with open(output_md, 'w') as f:
            f.write("# Checkov Terraform Scan\n\n")
            f.write(f"**Target:** {repo_path}\n\n")
            try:
                data = json.loads(result.stdout or '{}')
                failed = data.get('results', {}).get('failed_checks', [])
                # Summarize by severity if present
                sev_counts = {"CRITICAL":0, "HIGH":0, "MEDIUM":0, "LOW":0, "UNKNOWN":0}
                for item in failed:
                    sev = (item.get('severity') or 'UNKNOWN').upper()
                    if sev not in sev_counts:
                        sev = 'UNKNOWN'
                    sev_counts[sev] += 1
                f.write("## Summary\n\n")
                for k in ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]:
                    f.write(f"- {k.title()}: {sev_counts[k]}\n")
                # List a few failed checks
                f.write("\n## Sample Findings (up to 10)\n\n")
                for chk in failed[:10]:
                    rid = chk.get('check_id', 'UNKNOWN')
                    res = chk.get('resource', 'resource')
                    file_path = chk.get('file_path', 'unknown')
                    lines = chk.get('file_line_range') or []
                    f.write(f"- {rid} in {res} ({file_path}{':' + str(lines) if lines else ''})\n")
            except Exception:
                f.write("Scan completed. See JSON for details.\n")
        return result
    except Exception as e:
        with open(output_md, 'w') as f:
            f.write(f"Error running Checkov: {e}\n")
        return subprocess.CompletedProcess(args=['checkov', '-d', repo_path], returncode=1, stdout="", stderr=str(e))

def run_gitleaks(repo_path: str, repo_name: str, report_dir: str, db_session=None, repository_id: str=None) -> Optional[subprocess.CompletedProcess]:
    """Run Gitleaks secret scan against the working tree and history.

    Writes JSON and Markdown summaries with detailed findings including actual secrets.
    Returns CompletedProcess or None if tool is missing.
    """
    os.makedirs(report_dir, exist_ok=True)
    gl_bin = shutil.which('gitleaks')
    output_json = os.path.join(report_dir, f"{repo_name}_gitleaks.json")
    output_md = os.path.join(report_dir, f"{repo_name}_gitleaks.md")
    
    if not gl_bin:
        error_msg = "Gitleaks is not installed. Install via: brew install gitleaks or see https://github.com/gitleaks/gitleaks"
        with open(output_md, 'w') as f:
            f.write(f"# Error\n\n{error_msg}\n")
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr=error_msg)
    
    try:
        # Run gitleaks to detect secrets (without --redact to show actual values)
        cmd = [
            gl_bin,
            'detect',
            '--source', repo_path,
            '--report-format', 'json',
            '--report-path', output_json,
            '--verbose'  # Keep verbose for detailed output
        ]
        
        # Execute the command
        # Use progress monitoring if available
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="gitleaks",
                cwd=None,
                timeout=3600
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Create a detailed markdown report
        with open(output_md, 'w') as f:
            f.write(f"# Gitleaks Secrets Scan\n")
            f.write(f"**Repository:** {repo_name}\n")
            f.write(f"**Scanned on:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Command:** `{' '.join(cmd)}`\n\n")
            
            if result.returncode == 1:  # Gitleaks returns 1 when leaks are found
                try:
                    with open(output_json, 'r') as json_file:
                        findings = json.load(json_file)
                    
                    if not isinstance(findings, list):
                        findings = [findings] if findings else []
                    
                    # Persist to database
                    if db_session and repository_id:
                        try:
                            normalized_findings = []
                            for item in findings:
                                normalized_findings.append({
                                    "title": f"Secret found: {item.get('Description', item.get('RuleID', 'Unknown Secret'))}",
                                    "description": item.get('Description', ''),
                                    "severity": "HIGH", # Secrets are always high/critical
                                    "file_path": item.get('File'),
                                    "line_start": item.get('StartLine'),
                                    "line_end": item.get('EndLine'),
                                    "code_snippet": item.get('Secret', item.get('Match', ''))[:1000], # Store actual secret (warning: sensitive!)
                                    "rule_id": item.get('RuleID'),
                                    "cwe_id": "CWE-798" # Use of Hard-coded Credentials
                                })
                            _persist_scan_findings(db_session, repository_id, normalized_findings, "gitleaks")
                        except Exception as e:
                            logging.error(f"Failed to process Gitleaks findings for DB: {e}")

                    
                    f.write(f"## Found {len(findings)} potential secrets\n\n")
                    
                    for idx, finding in enumerate(findings, 1):
                        f.write(f"### Secret {idx}\n")
                        f.write(f"- **File:** `{finding.get('File', 'N/A')}`\n")
                        f.write(f"- **Line:** {finding.get('StartLine', 'N/A')}\n")
                        f.write(f"- **Rule ID:** {finding.get('RuleID', 'N/A')}\n")
                        f.write(f"- **Description:** {finding.get('Rule', {}).get('Description', 'N/A')}\n")
                        f.write(f"- **Secret:** `{finding.get('Secret', 'N/A')}`\n")
                        f.write(f"- **Match:** `{finding.get('Match', 'N/A')}`\n")
                        
                        # Add context if available
                        if 'StartLine' in finding and 'EndLine' in finding and finding['StartLine'] != finding['EndLine']:
                            f.write(f"- **Lines:** {finding['StartLine']}-{finding['EndLine']}\n")
                        
                        # Add commit info if available
                        if 'Commit' in finding:
                            f.write(f"- **Commit:** {finding['Commit']}\n")
                        if 'Author' in finding:
                            f.write(f"- **Author:** {finding['Author']} ({finding.get('Email', 'N/A')})\n")
                        if 'Date' in finding:
                            f.write(f"- **Date:** {finding['Date']}\n")
                        
                        f.write("\n---\n\n")
                    
                    # Add a summary at the top
                    f.seek(0, 2)  # Move to end of file for summary
                    f.write(f"\n## Summary\n")
                    f.write(f"- **Total secrets found:** {len(findings)}")
                    
                    return result
                
                except Exception as e:
                    error_msg = f"Error processing findings: {str(e)}"
                    f.write(f"## Error\n\n{error_msg}\n\n{result.stderr}")
                    return subprocess.CompletedProcess(args=cmd, returncode=1, stdout=result.stdout, stderr=error_msg)
            
            elif result.returncode == 0:
                f.write("## No secrets found\n")
                return result
            
            else:
                error_msg = f"Gitleaks failed with return code {result.returncode}:\n{result.stderr}"
                f.write(f"## Error\n\n{error_msg}")
                return subprocess.CompletedProcess(args=cmd, returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
    
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        with open(output_md, 'w') as f:
            f.write(f"# Error\n\n{error_msg}\n")
        return subprocess.CompletedProcess(args=cmd if 'cmd' in locals() else [], returncode=1, stdout="", stderr=error_msg)
        return subprocess.CompletedProcess(args=['gitleaks','detect','-s',repo_path], returncode=1, stdout="", stderr=str(e))

def run_bandit(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """Run Bandit SAST for Python projects if any .py files exist."""
    # Detect Python files
    has_py = False
    for root, _dirs, files in os.walk(repo_path):
        if any(fn.endswith('.py') for fn in files):
            has_py = True
            break
    if not has_py:
        return None

    os.makedirs(report_dir, exist_ok=True)
    bandit_bin = shutil.which('bandit')
    output_json = os.path.join(report_dir, f"{repo_name}_bandit.json")
    output_md = os.path.join(report_dir, f"{repo_name}_bandit.md")
    if not bandit_bin:
        with open(output_md, 'w') as f:
            f.write("Bandit is not installed. Install via: pip install bandit or brew install bandit\n")
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="bandit not installed")
    try:
        # Aggressive mode, all severity, all confidence
        cmd = [bandit_bin, "-r", repo_path, "-f", "json", "-q", "-a", "-ll", "-ii"]
        # Use progress monitoring if available
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="bandit",
                cwd=None,
                timeout=3600
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
        with open(output_json, 'w') as f:
            f.write(result.stdout or "")
        # MD summary
        with open(output_md, 'w') as f:
            f.write("# Bandit Python Security Scan\n\n")
            try:
                data = json.loads(result.stdout or '{}')
                results = data.get('results', []) if isinstance(data, dict) else []
                counts = {"HIGH":0, "MEDIUM":0, "LOW":0}
                for r in results:
                    sev = (r.get('issue_severity') or '').upper()
                    if sev in counts:
                        counts[sev] += 1
                f.write("## Summary\n\n")
                for k in ["HIGH","MEDIUM","LOW"]:
                    f.write(f"- {k.title()}: {counts[k]}\n")
                if results:
                    f.write("\n## Sample Findings (up to 10)\n\n")
                    for r in results[:10]:
                        test_id = r.get('test_id','')
                        issue = r.get('issue_text','')
                        path = r.get('filename','')
                        line = r.get('line_number','')
                        sev = r.get('issue_severity','')
                        f.write(f"- [{test_id}] {sev} in {path}:{line} — {issue}\n")
            except Exception:
                f.write("Scan completed. See JSON for details.\n")
        return result
    except Exception as e:
        with open(output_md, 'w') as f:
            f.write(f"Error running Bandit: {e}\n")
        return subprocess.CompletedProcess(args=['bandit','-r',repo_path], returncode=1, stdout="", stderr=str(e))

def run_trivy_fs(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """Run Trivy filesystem scan for vulnerabilities/misconfigs."""
    os.makedirs(report_dir, exist_ok=True)
    trivy_bin = shutil.which('trivy')
    output_json = os.path.join(report_dir, f"{repo_name}_trivy_fs.json")
    output_md = os.path.join(report_dir, f"{repo_name}_trivy_fs.md")
    if not trivy_bin:
        with open(output_md, 'w') as f:
            f.write("Trivy is not installed. Install via: brew install trivy or see https://aquasecurity.github.io/trivy/\n")
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="trivy not installed")
    try:
        # Run with vulnerability, config, secret, and license checks; quiet + JSON
        cmd = [trivy_bin, "fs", "-q", "-f", "json", "--scanners", "vuln,config,secret,license", repo_path]
        
        # Use progress monitoring if available
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="trivy",
                cwd=None,
                timeout=3600
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
        with open(output_json, 'w') as f:
            f.write(result.stdout or "")
        # MD summary
        with open(output_md, 'w') as f:
            f.write("# Trivy Filesystem Scan\n\n")
            try:
                data = json.loads(result.stdout or '{}')
                results = data.get('Results', []) if isinstance(data, dict) else []
                counts = {"CRITICAL":0, "HIGH":0, "MEDIUM":0, "LOW":0, "UNKNOWN":0}
                for res in results:
                    for v in res.get('Vulnerabilities', []) or []:
                        sev = (v.get('Severity') or 'UNKNOWN').upper()
                        if sev not in counts: sev = 'UNKNOWN'
                        counts[sev] += 1
                f.write("## Summary\n\n")
                for k in ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]:
                    f.write(f"- {k.title()}: {counts[k]}\n")
            except Exception:
                f.write("Scan completed. See JSON for details.\n")
        return result
    except Exception as e:
        with open(output_md, 'w') as f:
            f.write(f"Error running Trivy fs: {e}\n")
        return subprocess.CompletedProcess(args=['trivy','fs',repo_path], returncode=1, stdout="", stderr=str(e))

def generate_ai_remediations(repo_name: str, report_dir: str, kb: Optional[KnowledgeBase]):
    """
    Generate AI remediation plans for findings.
    Currently supports Semgrep findings.
    """
    if not kb or not kb.enabled or not ai_agent:
        return

    semgrep_json = os.path.join(report_dir, f"{repo_name}_semgrep.json")
    if not os.path.exists(semgrep_json):
        return

    try:
        with open(semgrep_json, 'r') as f:
            data = json.load(f)
            
        findings = data.get('results', [])
        if not findings:
            return
            
        remediation_report = os.path.join(report_dir, f"{repo_name}_remediation_plan.md")
        
        with open(remediation_report, 'w') as f:
            f.write(f"# AI Remediation Plan for {repo_name}\n\n")
            
            # Limit to top 5 findings to save costs for now
            for finding in findings[:5]:
                check_id = finding.get('check_id')
                path = finding.get('path')
                start_line = finding.get('start', {}).get('line')
                extra = finding.get('extra', {})
                message = extra.get('message', '')
                lines = extra.get('lines', '')
                
                f.write(f"## Finding: {check_id}\n")
                f.write(f"- **File:** `{path}:{start_line}`\n")
                f.write(f"- **Message:** {message}\n\n")
                
                # Check Knowledge Base
                cached = kb.get_remediation(check_id, lines)
                
                if cached:
                    f.write("### Remediation (Cached)\n")
                    f.write(cached['remediation'])
                    f.write("\n\n")
                    if cached['diff']:
                        f.write("### Suggested Fix\n")
                        f.write("```diff\n")
                        f.write(cached['diff'])
                        f.write("\n```\n\n")
                else:
                    # Ask AI
                    logging.info(f"Asking AI for remediation of {check_id} in {repo_name}...")
                    # We need to run async method in sync context
                    # Creating a new loop or using asyncio.run if not in loop
                    try:
                        # This is a bit hacky for a sync script, but works for now
                        result = asyncio.run(ai_agent.reasoning_engine.generate_remediation(
                            vuln_type=check_id,
                            description=message,
                            context=lines,
                            language="unknown" # Could infer from extension
                        ))
                        
                        kb.store_remediation(
                            vuln_id=check_id,
                            vuln_type=check_id,
                            context=lines,
                            remediation=result.get('remediation', ''),
                            diff=result.get('diff', '')
                        )
                        
                        f.write("### Remediation (AI Generated)\n")
                        f.write(result.get('remediation', ''))
                        f.write("\n\n")
                        if result.get('diff'):
                            f.write("### Suggested Fix\n")
                            f.write("```diff\n")
                            f.write(result.get('diff'))
                            f.write("\n```\n\n")
                            
                    except Exception as e:
                        logging.error(f"AI generation failed: {e}")
                        f.write(f"Failed to generate remediation: {e}\n\n")
                        
    except Exception as e:
        logging.error(f"Error generating remediation plan: {e}")

def run_retire_js(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """Run Retire.js to find vulnerable client-side libraries."""
    os.makedirs(report_dir, exist_ok=True)
    retire_bin = shutil.which('retire')
    output_json = os.path.join(report_dir, f"{repo_name}_retire.json")
    output_md = os.path.join(report_dir, f"{repo_name}_retire.md")
    
    if not retire_bin:
        with open(output_md, 'w') as f:
            f.write("Retire.js is not installed.\n")
        return None
        
    try:
        # Run retire.js
        cmd = [retire_bin, "--path", repo_path, "--outputformat", "json", "--outputpath", output_json]
        
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="retirejs",
                cwd=report_dir,
                timeout=1800
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
        # Generate Markdown
        with open(output_md, 'w') as f:
            f.write(f"# Retire.js Vulnerability Scan\n\n")
            
            if os.path.exists(output_json):
                try:
                    with open(output_json, 'r') as jf:
                        data = json.load(jf)
                        
                    # Retire.js JSON structure: list of file objects
                    findings_count = 0
                    for file_obj in data:
                        findings_count += len(file_obj.get('results', []))
                        
                    f.write(f"**Total Findings:** {findings_count}\n\n")
                    
                    for file_obj in data:
                        filename = file_obj.get('file', 'unknown')
                        results = file_obj.get('results', [])
                        if results:
                            f.write(f"### File: `{filename}`\n")
                            for res in results:
                                component = res.get('component', 'unknown')
                                version = res.get('version', 'unknown')
                                vulns = res.get('vulnerabilities', [])
                                f.write(f"- **Component:** {component} @ {version}\n")
                                for v in vulns:
                                    info = v.get('info', [])
                                    severity = v.get('severity', 'unknown')
                                    f.write(f"  - **{severity}**: {' '.join(info)}\n")
                            f.write("\n")
                except Exception as e:
                    f.write(f"Error parsing Retire.js output: {e}\n")
            else:
                f.write("No findings or output file missing.\n")
                
        return result
    except Exception as e:
        logging.error(f"Retire.js failed: {e}")
        return None

def run_npm_audit(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """
    Run npm audit, yarn audit, or pnpm audit depending on lockfiles.
    """
    os.makedirs(report_dir, exist_ok=True)
    
    # Detect package manager
    has_package_lock = os.path.exists(os.path.join(repo_path, 'package-lock.json'))
    has_yarn_lock = os.path.exists(os.path.join(repo_path, 'yarn.lock'))
    has_pnpm_lock = os.path.exists(os.path.join(repo_path, 'pnpm-lock.yaml'))
    
    tool = "npm"
    cmd = []
    
    if has_pnpm_lock and shutil.which('pnpm'):
        tool = "pnpm"
        cmd = ["pnpm", "audit", "--json"]
    elif has_yarn_lock and shutil.which('yarn'):
        tool = "yarn"
        cmd = ["yarn", "audit", "--json"]
    elif has_package_lock or os.path.exists(os.path.join(repo_path, 'package.json')):
        tool = "npm"
        # npm audit --json
        cmd = ["npm", "audit", "--json", "--audit-level=high"]
    else:
        logging.info(f"No JS lockfiles found for {repo_name}, skipping audit.")
        return None

    output_json = os.path.join(report_dir, f"{repo_name}_{tool}_audit.json")
    output_md = os.path.join(report_dir, f"{repo_name}_{tool}_audit.md")
    
    try:
        logging.info(f"Running {tool} audit for {repo_name}...")
        
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name=f"{tool}-audit",
                cwd=repo_path,
                timeout=1800
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=repo_path)
            
        # Write JSON
        with open(output_json, 'w') as f:
            f.write(result.stdout)
            
        # Generate Markdown Summary
        with open(output_md, 'w') as f:
            f.write(f"# {tool.capitalize()} Audit Report\n\n")
            f.write(f"**Tool:** {tool}\n")
            
            try:
                # Parsing logic differs slightly by tool, but generally JSON
                data = json.loads(result.stdout)
                
                if tool == "npm":
                    metadata = data.get('metadata', {}).get('vulnerabilities', {})
                    f.write("## Summary\n")
                    for sev, count in metadata.items():
                        f.write(f"- **{sev.capitalize()}**: {count}\n")
                        
                elif tool == "yarn":
                    # Yarn audit --json outputs one JSON object per line
                    # The last line usually contains summary
                    summary = {}
                    for line in result.stdout.splitlines():
                        if not line.strip(): continue
                        obj = json.loads(line)
                        if obj.get('type') == 'auditSummary':
                            summary = obj.get('data', {}).get('vulnerabilities', {})
                    
                    f.write("## Summary\n")
                    for sev, count in summary.items():
                        f.write(f"- **{sev.capitalize()}**: {count}\n")
                        
                elif tool == "pnpm":
                    # pnpm audit --json structure
                    advisories = data.get('advisories', {})
                    f.write(f"## Summary\n")
                    f.write(f"- **Total Advisories:** {len(advisories)}\n")

            except Exception as e:
                f.write(f"\nError parsing output: {e}\n")
                f.write("See JSON file for details.\n")
                
        return result
        
    except Exception as e:
        logging.error(f"{tool} audit failed: {e}")
        return None
def run_trufflehog(repo_path: str, repo_name: str, report_dir: str, db_session=None, repository_id: str=None) -> Optional[subprocess.CompletedProcess]:
    """Run TruffleHog for verified secret scanning."""
    os.makedirs(report_dir, exist_ok=True)
    th_bin = shutil.which('trufflehog')
    output_json = os.path.join(report_dir, f"{repo_name}_trufflehog.json")
    output_md = os.path.join(report_dir, f"{repo_name}_trufflehog.md")
    
    if not th_bin:
        with open(output_md, 'w') as f:
            f.write("TruffleHog is not installed.\n")
        return None
        
    try:
        # Create exclusion file to ignore .git and other non-repo files
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as exclude_file:
            # Regex to exclude .git directory and its contents
            # We use a broad regex to catch .git at root or in subdirs
            exclude_file.write(r".*\.git/.*" + "\n")
            exclude_file.write(r".*\.git$" + "\n")
            exclude_file_path = exclude_file.name

        # Scan filesystem, output JSON
        cmd = [th_bin, "filesystem", repo_path, "--json", "--fail", "--exclude-paths", exclude_file_path]
        
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="trufflehog",
                cwd=report_dir,
                timeout=3600
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
        # Clean up exclusion file
        try:
            os.remove(exclude_file_path)
        except OSError:
            pass

            
        # Parse JSON output (TruffleHog outputs one JSON object per line)
        findings = []
        for line in result.stdout.splitlines():
            try:
                if line.strip():
                    findings.append(json.loads(line))
            except:
                pass
                
        # Write findings to JSON file
        with open(output_json, 'w') as f:
            json.dump(findings, f, indent=2)
            
        # Persist to database
        if db_session and repository_id:
            try:
                normalized_findings = []
                for item in findings:
                    # Extract file path safely from nested structure
                    file_path = "unknown"
                    line_start = 0
                    if 'SourceMetadata' in item and 'Data' in item['SourceMetadata'] and 'Filesystem' in item['SourceMetadata']['Data']:
                        fs_data = item['SourceMetadata']['Data']['Filesystem']
                        file_path = fs_data.get('file', 'unknown')
                        line_start = fs_data.get('line', 0)

                    normalized_findings.append({
                        "title": f"Secret found: {item.get('DetectorName', 'Unknown Secret')}",
                        "description": f"Verified: {item.get('Verified', False)}\nDetector: {item.get('DetectorName')}",
                        "severity": "CRITICAL" if item.get('Verified') else "HIGH",
                        "file_path": file_path,
                        "line_start": int(line_start) if line_start else 0,
                        "line_end": int(line_start) if line_start else 0,
                        "code_snippet": item.get('Raw', '')[:1000],
                        "rule_id": item.get('DetectorName'),
                        "cwe_id": "CWE-798"
                    })
                _persist_scan_findings(db_session, repository_id, normalized_findings, "trufflehog")
            except Exception as e:
                logging.error(f"Failed to process TruffleHog findings for DB: {e}")

            
        # Generate Markdown
        with open(output_md, 'w') as f:
            f.write(f"# TruffleHog Verified Secrets\n\n")
            f.write(f"**Total Findings:** {len(findings)}\n\n")
            
            if findings:
                for finding in findings:
                    detector = finding.get('DetectorName', 'Unknown')
                    verified = finding.get('Verified', False)
                    raw = finding.get('Raw', 'REDACTED')
                    f.write(f"### {detector} {'(VERIFIED)' if verified else ''}\n")
                    f.write(f"- **Verified:** {verified}\n")
                    f.write(f"- **Secret:** `{raw}`\n")  # Full value - no masking per policy
                    if 'SourceMetadata' in finding:
                        meta = finding['SourceMetadata']
                        if 'Data' in meta and 'Filesystem' in meta['Data']:
                            fs = meta['Data']['Filesystem']
                            f.write(f"- **File:** `{fs.get('file', 'unknown')}`\n")
                    f.write("\n")
            else:
                f.write("No secrets found.\n")
                
        return result
    except Exception as e:
        logging.error(f"TruffleHog failed: {e}")
        return None

def run_nuclei(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """Run Nuclei for vulnerability scanning."""
    os.makedirs(report_dir, exist_ok=True)
    nuclei_bin = shutil.which('nuclei')
    output_json = os.path.join(report_dir, f"{repo_name}_nuclei.json")
    output_md = os.path.join(report_dir, f"{repo_name}_nuclei.md")
    
    if not nuclei_bin:
        with open(output_md, 'w') as f:
            f.write("Nuclei is not installed.\n")
        return None
        
    try:
        # Run nuclei on the file target
        cmd = [nuclei_bin, "-target", repo_path, "-json-export", output_json]
        
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="nuclei",
                cwd=report_dir,
                timeout=3600
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
        # Generate Markdown
        with open(output_md, 'w') as f:
            f.write(f"# Nuclei Vulnerability Scan\n\n")
            
            if os.path.exists(output_json):
                try:
                    with open(output_json, 'r') as jf:
                        # Nuclei JSON export is a list of objects or line-delimited?
                        # Usually line-delimited or array depending on version.
                        # Let's try reading as array first, then lines.
                        content = jf.read()
                        try:
                            data = json.loads(content)
                        except:
                            data = [json.loads(line) for line in content.splitlines() if line.strip()]
                            
                    f.write(f"**Total Findings:** {len(data)}\n\n")
                    for finding in data:
                        name = finding.get('info', {}).get('name', 'Unknown')
                        sev = finding.get('info', {}).get('severity', 'unknown').upper()
                        f.write(f"### {name} ({sev})\n")
                        f.write(f"- **Template:** {finding.get('template-id')}\n")
                        f.write(f"- **Matcher:** {finding.get('matcher-name')}\n\n")
                except Exception as e:
                    f.write(f"Error parsing Nuclei output: {e}\n")
            else:
                f.write("No findings or output file missing.\n")
                
        return result
    except Exception as e:
        logging.error(f"Nuclei failed: {e}")
        return None

def run_ossgadget(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """Run OSSGadget for malware/backdoor detection."""
    os.makedirs(report_dir, exist_ok=True)
    # OSSGadget is a dotnet tool
    output_sarif = os.path.join(report_dir, f"{repo_name}_ossgadget.sarif")
    
    try:
        # Check if dotnet is available
        if not shutil.which('dotnet'):
            with open(os.path.join(report_dir, f"{repo_name}_ossgadget.md"), 'w') as f:
                f.write("OSSGadget (.NET) is not installed.\n")
            return None
            
        # Find ossgadget binary
        oss_bin = shutil.which('ossgadget')
        if not oss_bin:
            # Fallback to default install location
            possible_path = os.path.expanduser("~/.dotnet/tools/ossgadget")
            if os.path.exists(possible_path):
                oss_bin = possible_path
        
        if not oss_bin:
            logging.warning("ossgadget binary not found in PATH or default location")
            with open(os.path.join(report_dir, f"{repo_name}_ossgadget.md"), 'w') as f:
                f.write("OSSGadget binary not found.\n")
            return None

        # Run ossgadget detect-backdoor
        # Note: ossgadget requires DOTNET_ROOT to be set if not in standard location
        # We assume the environment is set up correctly or we set it here if needed
        env = os.environ.copy()
        if "DOTNET_ROOT" not in env and os.path.exists("/opt/homebrew/opt/dotnet@8/libexec"):
             env["DOTNET_ROOT"] = "/opt/homebrew/opt/dotnet@8/libexec"

        cmd = [oss_bin, "detect-backdoor", "-d", repo_path, "-f", "sarifv2", "-o", output_sarif]
        
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="ossgadget",
                cwd=report_dir,
                timeout=1800,
                env=env
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, env=env)
            
        return result
    except Exception as e:
        logging.error(f"OSSGadget failed: {e}")
        return None

def run_cloc(repo_path: str, repo_name: str, report_dir: str) -> Optional[Dict[str, Any]]:
    """Run cloc to count lines of code per language."""
    os.makedirs(report_dir, exist_ok=True)
    cloc_bin = shutil.which('cloc')
    output_json = os.path.join(report_dir, f"{repo_name}_cloc.json")
    
    if not cloc_bin:
        return None
        
    try:
        # Run cloc with JSON output
        cmd = [cloc_bin, repo_path, "--json", "--out", output_json]
        subprocess.run(cmd, capture_output=True, check=False)
        
        if os.path.exists(output_json):
            with open(output_json, 'r') as f:
                data = json.load(f)
                # Remove 'header' key if present
                if 'header' in data:
                    del data['header']
                return data
    except Exception as e:
        logging.error(f"cloc failed: {e}")
        
    return None

# =============================================================================
# NEW SECURITY SCANNERS (Phase 1 - December 2024)
# =============================================================================

def sanitize_json_file(file_path: str) -> int:
    """
    DOE Self-Annealing: Sanitize JSON file by removing NUL (0x00) characters.
    
    Horusec and other scanners may produce JSON with NUL characters when scanning
    binary files or files with unusual encodings. These NUL characters cause
    PostgreSQL errors during ingestion.
    
    Returns: Number of NUL characters removed (0 if file was clean)
    """
    if not os.path.exists(file_path):
        return 0
    
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        nul_count = content.count(b'\x00')
        
        if nul_count > 0:
            # Remove NUL characters
            sanitized = content.replace(b'\x00', b'')
            with open(file_path, 'wb') as f:
                f.write(sanitized)
            logging.warning(
                f"DOE Self-Annealing: Removed {nul_count} NUL characters from {os.path.basename(file_path)}"
            )
        
        return nul_count
    except Exception as e:
        logging.error(f"DOE Self-Annealing: Failed to sanitize {file_path}: {e}")
        return 0


def run_horusec(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """
    Run Horusec multi-tool SAST scanner.
    
    Horusec aggregates multiple security tools and provides unified output.
    Supports: Go, C#, Java, Kotlin, Python, Ruby, JavaScript, TypeScript, 
              Terraform, HCL, Dart, Elixir, Shell, PHP, C, HTML, JSON, Nginx.
    
    Install: brew install horusec or https://github.com/ZupIT/horusec
    
    Note: Includes DOE self-annealing to sanitize NUL characters from output.
    """
    os.makedirs(report_dir, exist_ok=True)
    horusec_bin = shutil.which('horusec')
    output_json = os.path.join(report_dir, f"{repo_name}_horusec.json")
    output_md = os.path.join(report_dir, f"{repo_name}_horusec.md")
    
    if not horusec_bin:
        with open(output_md, 'w') as f:
            f.write("# Horusec Not Installed\n\n")
            f.write("Install via: `brew install horusec` or see https://github.com/ZupIT/horusec\n")
        return None
    
    try:
        logging.info(f"Running Horusec for {repo_name}...")
        cmd = [
            horusec_bin, 'start',
            '-p', repo_path,
            '-o', 'json',
            '-O', output_json,
            '--disable-docker', 'true',  # Run without Docker for speed
            '-e', 'true'  # Enable all engines
        ]
        
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="horusec",
                cwd=None,
                timeout=1800  # 30 min timeout
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        
        # DOE Self-Annealing: Sanitize NUL characters from Horusec output
        # Horusec may include NUL chars when scanning binary files or unusual encodings
        nul_removed = sanitize_json_file(output_json)
        
        # Generate markdown report
        with open(output_md, 'w') as f:
            f.write(f"# Horusec Security Scan\n\n")
            f.write(f"**Repository:** {repo_name}\n")
            f.write(f"**Scanned on:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if os.path.exists(output_json):
                try:
                    with open(output_json, 'r') as jf:
                        data = json.load(jf)
                    
                    # Count by severity
                    vulns = data.get('analysisVulnerabilities') or []
                    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
                    
                    for vuln in vulns:
                        v = vuln.get('vulnerabilities', {})
                        sev = v.get('severity', 'INFO').upper()
                        if sev in sev_counts:
                            sev_counts[sev] += 1
                    
                    f.write("## Summary\n\n")
                    for sev, count in sev_counts.items():
                        f.write(f"- **{sev}**: {count}\n")
                    
                    f.write(f"\n**Total Findings:** {len(vulns)}\n")
                    
                except Exception as e:
                    f.write(f"Error parsing results: {e}\n")
            else:
                f.write("No findings or scan failed.\n")
        
        return result
        
    except subprocess.TimeoutExpired:
        logging.error(f"Horusec timed out for {repo_name}")
        with open(output_md, 'w') as f:
            f.write(f"# Horusec Scan Timeout\n\nScan exceeded 30 minute limit.\n")
        return None
    except Exception as e:
        logging.error(f"Horusec failed for {repo_name}: {e}")
        return None


def run_whispers(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """
    Run Whispers secret scanner for structured text and static code.
    
    Whispers specializes in finding hardcoded secrets in config files:
    YAML, JSON, XML, .npmrc, .pypirc, .htpasswd, .properties, pip.conf,
    Dockerfile, Shell scripts, and Python3 AST.
    
    Install: pip install whispers
    """
    os.makedirs(report_dir, exist_ok=True)
    whispers_bin = shutil.which('whispers')
    output_json = os.path.join(report_dir, f"{repo_name}_whispers.json")
    output_md = os.path.join(report_dir, f"{repo_name}_whispers.md")
    
    if not whispers_bin:
        with open(output_md, 'w') as f:
            f.write("# Whispers Not Installed\n\n")
            f.write("Install via: `pip install whispers`\n")
        return None
    
    try:
        logging.info(f"Running Whispers for {repo_name}...")
        cmd = [whispers_bin, '-o', output_json, repo_path]
        
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="whispers",
                cwd=None,
                timeout=600  # 10 min timeout
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        # Generate markdown report
        with open(output_md, 'w') as f:
            f.write(f"# Whispers Secrets Scan\n\n")
            f.write(f"**Repository:** {repo_name}\n")
            f.write(f"**Scanned on:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if os.path.exists(output_json):
                try:
                    with open(output_json, 'r') as jf:
                        findings = json.load(jf)
                    
                    if isinstance(findings, list):
                        f.write(f"## Found {len(findings)} potential secrets\n\n")
                        
                        # Group by severity
                        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
                        for finding in findings:
                            sev = finding.get('severity', 'Info').title()
                            if sev in sev_counts:
                                sev_counts[sev] += 1
                        
                        for sev, count in sev_counts.items():
                            if count > 0:
                                f.write(f"- **{sev}**: {count}\n")
                        
                        # Show first 10 findings
                        f.write("\n## Sample Findings (up to 10)\n\n")
                        for finding in findings[:10]:
                            f.write(f"- **{finding.get('key', 'unknown')}** in `{finding.get('file', 'unknown')}`\n")
                            f.write(f"  - Line: {finding.get('line', '?')}\n")
                            f.write(f"  - Severity: {finding.get('severity', 'unknown')}\n")
                            f.write(f"  - Message: {finding.get('message', 'N/A')}\n\n")
                    else:
                        f.write("No secrets found.\n")
                        
                except Exception as e:
                    f.write(f"Error parsing results: {e}\n")
            else:
                f.write("No findings.\n")
        
        return result
        
    except subprocess.TimeoutExpired:
        logging.error(f"Whispers timed out for {repo_name}")
        return None
    except Exception as e:
        logging.error(f"Whispers failed for {repo_name}: {e}")
        return None


def run_bearer(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """
    Run Bearer for sensitive data flow analysis.
    
    Bearer specializes in finding sensitive data exposure:
    - PII/PHI data flows
    - Data leakage to logs/third parties
    - GDPR/CCPA compliance issues
    - Security vulnerabilities
    
    Install: brew install bearer/tap/bearer
    """
    os.makedirs(report_dir, exist_ok=True)
    bearer_bin = shutil.which('bearer')
    output_json = os.path.join(report_dir, f"{repo_name}_bearer.json")
    output_md = os.path.join(report_dir, f"{repo_name}_bearer.md")
    
    if not bearer_bin:
        with open(output_md, 'w') as f:
            f.write("# Bearer Not Installed\n\n")
            f.write("Install via: `brew install bearer/tap/bearer`\n")
        return None
    
    try:
        logging.info(f"Running Bearer for {repo_name}...")
        cmd = [
            bearer_bin, 'scan', repo_path,
            '--format', 'json',
            '--output', output_json,
            '--quiet'
        ]
        
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="bearer",
                cwd=None,
                timeout=1200  # 20 min timeout
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
        
        # Generate markdown report
        with open(output_md, 'w') as f:
            f.write(f"# Bearer Data Flow Analysis\n\n")
            f.write(f"**Repository:** {repo_name}\n")
            f.write(f"**Scanned on:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if os.path.exists(output_json):
                try:
                    with open(output_json, 'r') as jf:
                        data = json.load(jf)
                    
                    findings = data.get('findings') or []
                    
                    # Count by severity
                    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "warning": 0}
                    for finding in findings:
                        sev = finding.get('severity', 'warning').lower()
                        if sev in sev_counts:
                            sev_counts[sev] += 1
                    
                    f.write("## Summary\n\n")
                    for sev, count in sev_counts.items():
                        f.write(f"- **{sev.title()}**: {count}\n")
                    
                    f.write(f"\n**Total Findings:** {len(findings)}\n")
                    
                    # Data types detected
                    data_types = set()
                    for finding in findings:
                        dt = finding.get('data_type', {})
                        if dt:
                            data_types.add(dt.get('name', 'unknown'))
                    
                    if data_types:
                        f.write("\n## Sensitive Data Types Detected\n\n")
                        for dt in sorted(data_types):
                            f.write(f"- {dt}\n")
                    
                except Exception as e:
                    f.write(f"Error parsing results: {e}\n")
            else:
                f.write("No findings or scan completed without issues.\n")
        
        return result
        
    except subprocess.TimeoutExpired:
        logging.error(f"Bearer timed out for {repo_name}")
        return None
    except Exception as e:
        logging.error(f"Bearer failed for {repo_name}: {e}")
        return None


def run_dockle(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """
    Run Dockle for Dockerfile best practices and security.
    
    Dockle checks Dockerfiles for:
    - CIS Docker Benchmark compliance
    - Security best practices
    - Image efficiency
    - Proper user configuration
    
    Install: brew install goodwithtech/r/dockle
    """
    os.makedirs(report_dir, exist_ok=True)
    
    # Find Dockerfiles in the repo
    dockerfiles = []
    for root, dirs, files in os.walk(repo_path):
        # Skip .git and node_modules
        dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'vendor']]
        for f in files:
            if f == 'Dockerfile' or f.endswith('.dockerfile') or f.startswith('Dockerfile.'):
                dockerfiles.append(os.path.join(root, f))
    
    if not dockerfiles:
        logging.info(f"No Dockerfiles found in {repo_name}, skipping Dockle")
        return None
    
    dockle_bin = shutil.which('dockle')
    output_json = os.path.join(report_dir, f"{repo_name}_dockle.json")
    output_md = os.path.join(report_dir, f"{repo_name}_dockle.md")
    
    if not dockle_bin:
        with open(output_md, 'w') as f:
            f.write("# Dockle Not Installed\n\n")
            f.write("Install via: `brew install goodwithtech/r/dockle`\n")
            f.write(f"\nFound {len(dockerfiles)} Dockerfile(s) that would be scanned.\n")
        return None
    
    try:
        logging.info(f"Running Dockle for {repo_name} ({len(dockerfiles)} Dockerfile(s))...")
        
        all_results = []
        
        # Dockle works on built images, but we can use --input for tar files
        # For Dockerfiles, we use hadolint-style analysis via dockle's dockerfile mode
        # Actually, Dockle requires a built image. For Dockerfile linting, we'll note this.
        
        with open(output_md, 'w') as f:
            f.write(f"# Dockle Container Security Analysis\n\n")
            f.write(f"**Repository:** {repo_name}\n")
            f.write(f"**Scanned on:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Note:** Dockle requires built container images. Found {len(dockerfiles)} Dockerfile(s).\n\n")
            f.write("## Dockerfiles Found\n\n")
            for df in dockerfiles:
                rel_path = os.path.relpath(df, repo_path)
                f.write(f"- `{rel_path}`\n")
            
            f.write("\n## Recommendation\n\n")
            f.write("Build images and scan with:\n")
            f.write("```bash\n")
            f.write(f"docker build -t {repo_name}:scan .\n")
            f.write(f"dockle {repo_name}:scan\n")
            f.write("```\n")
        
        # Store dockerfile locations for reference
        with open(output_json, 'w') as f:
            json.dump({
                "dockerfiles": [os.path.relpath(df, repo_path) for df in dockerfiles],
                "note": "Dockle requires built images. Dockerfiles listed for reference."
            }, f, indent=2)
        
        return subprocess.CompletedProcess(args=['dockle'], returncode=0, stdout="", stderr="")
        
    except Exception as e:
        logging.error(f"Dockle failed for {repo_name}: {e}")
        return None


def run_terrascan(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """
    Run Terrascan for IaC security scanning.
    
    Terrascan provides 500+ policies for:
    - Terraform
    - Kubernetes (YAML, Helm)
    - Dockerfiles
    - CloudFormation
    - Azure ARM
    - Kustomize
    
    Install: brew install terrascan
    """
    os.makedirs(report_dir, exist_ok=True)
    
    # Check for IaC files
    iac_patterns = {
        'terraform': ['.tf', '.tf.json'],
        'kubernetes': ['*.yaml', '*.yml'],
        'dockerfile': ['Dockerfile'],
        'cloudformation': ['*.template', '*.template.json'],
        'helm': ['Chart.yaml']
    }
    
    has_iac = False
    iac_types = []
    
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'vendor']]
        for f in files:
            if f.endswith('.tf') or f.endswith('.tf.json'):
                has_iac = True
                if 'terraform' not in iac_types:
                    iac_types.append('terraform')
            elif f == 'Dockerfile':
                has_iac = True
                if 'docker' not in iac_types:
                    iac_types.append('docker')
            elif f == 'Chart.yaml':
                has_iac = True
                if 'helm' not in iac_types:
                    iac_types.append('helm')
            elif f.endswith('.yaml') or f.endswith('.yml'):
                # Check if it's a Kubernetes manifest
                try:
                    filepath = os.path.join(root, f)
                    with open(filepath, 'r') as yf:
                        content = yf.read(500)
                        if 'apiVersion:' in content and 'kind:' in content:
                            has_iac = True
                            if 'k8s' not in iac_types:
                                iac_types.append('k8s')
                except:
                    pass
    
    if not has_iac:
        logging.info(f"No IaC files found in {repo_name}, skipping Terrascan")
        return None
    
    terrascan_bin = shutil.which('terrascan')
    output_json = os.path.join(report_dir, f"{repo_name}_terrascan.json")
    output_md = os.path.join(report_dir, f"{repo_name}_terrascan.md")
    
    if not terrascan_bin:
        with open(output_md, 'w') as f:
            f.write("# Terrascan Not Installed\n\n")
            f.write("Install via: `brew install terrascan`\n")
            f.write(f"\nFound IaC types: {', '.join(iac_types)}\n")
        return None
    
    try:
        logging.info(f"Running Terrascan for {repo_name} (IaC types: {', '.join(iac_types)})...")
        
        # Run terrascan with auto-detection
        cmd = [
            terrascan_bin, 'scan',
            '-d', repo_path,
            '-o', 'json'
        ]
        
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="terrascan",
                cwd=None,
                timeout=900  # 15 min timeout
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        
        # Save JSON output
        if result.stdout:
            with open(output_json, 'w') as f:
                f.write(result.stdout)
        
        # Generate markdown report
        with open(output_md, 'w') as f:
            f.write(f"# Terrascan IaC Security Scan\n\n")
            f.write(f"**Repository:** {repo_name}\n")
            f.write(f"**Scanned on:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**IaC Types:** {', '.join(iac_types)}\n\n")
            
            try:
                data = json.loads(result.stdout) if result.stdout else {}
                
                results = data.get('results') or {}
                violations = results.get('violations') or []
                
                # Count by severity
                sev_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
                for v in violations:
                    sev = v.get('severity', 'LOW').upper()
                    if sev in sev_counts:
                        sev_counts[sev] += 1
                
                f.write("## Summary\n\n")
                for sev, count in sev_counts.items():
                    f.write(f"- **{sev}**: {count}\n")
                
                f.write(f"\n**Total Violations:** {len(violations)}\n")
                
                # Show sample violations
                if violations:
                    f.write("\n## Sample Violations (up to 10)\n\n")
                    for v in violations[:10]:
                        f.write(f"### {v.get('rule_name', 'Unknown Rule')}\n")
                        f.write(f"- **Severity:** {v.get('severity', 'Unknown')}\n")
                        f.write(f"- **Category:** {v.get('category', 'Unknown')}\n")
                        f.write(f"- **Resource:** `{v.get('resource_name', 'Unknown')}`\n")
                        f.write(f"- **File:** `{v.get('file', 'Unknown')}`\n")
                        f.write(f"- **Description:** {v.get('description', 'N/A')}\n\n")
                
            except Exception as e:
                f.write(f"Error parsing results: {e}\n")
                if result.stderr:
                    f.write(f"\nStderr: {result.stderr}\n")
        
        return result
        
    except subprocess.TimeoutExpired:
        logging.error(f"Terrascan timed out for {repo_name}")
        return None
    except Exception as e:
        logging.error(f"Terrascan failed for {repo_name}: {e}")
        return None


# =============================================================================
# PHASE 3 SCANNERS: Go Security & Mobile Security
# =============================================================================

def run_gosec(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """
    Run gosec for Go source code security analysis.
    
    gosec inspects Go source code for security problems by scanning the AST.
    Detects: SQL injection, command injection, hardcoded credentials, weak crypto, etc.
    
    Install: go install github.com/securego/gosec/v2/cmd/gosec@latest
    """
    os.makedirs(report_dir, exist_ok=True)
    
    # Check for Go files
    has_go = False
    go_mod_path = None
    
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'vendor']]
        for f in files:
            if f == 'go.mod':
                go_mod_path = os.path.join(root, f)
                has_go = True
            elif f.endswith('.go'):
                has_go = True
        if has_go:
            break
    
    if not has_go:
        logging.info(f"No Go files found in {repo_name}, skipping gosec")
        return None
    
    gosec_bin = shutil.which('gosec')
    output_json = os.path.join(report_dir, f"{repo_name}_gosec.json")
    output_md = os.path.join(report_dir, f"{repo_name}_gosec.md")
    
    if not gosec_bin:
        with open(output_md, 'w') as f:
            f.write("# gosec Not Installed\n\n")
            f.write("Install via: `go install github.com/securego/gosec/v2/cmd/gosec@latest`\n")
        return None
    
    try:
        logging.info(f"Running gosec for {repo_name}...")
        
        # Run gosec with JSON output
        cmd = [
            gosec_bin,
            '-fmt=json',
            '-out=' + output_json,
            '-severity=low',  # Report all severities
            '-confidence=low',  # Report all confidence levels
            './...'
        ]
        
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="gosec",
                cwd=repo_path,
                timeout=600  # 10 min timeout
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600, cwd=repo_path)
        
        # Generate markdown report
        with open(output_md, 'w') as f:
            f.write(f"# gosec Go Security Scan\n\n")
            f.write(f"**Repository:** {repo_name}\n")
            f.write(f"**Scanned on:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            try:
                if os.path.exists(output_json):
                    with open(output_json) as jf:
                        data = json.load(jf)
                else:
                    data = {}
                
                issues = data.get('Issues') or []
                stats = data.get('Stats', {})
                
                # Count by severity
                sev_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
                rule_counts = {}
                
                for issue in issues:
                    sev = issue.get('severity', 'LOW').upper()
                    if sev in sev_counts:
                        sev_counts[sev] += 1
                    
                    rule_id = issue.get('rule_id', 'Unknown')
                    rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
                
                f.write("## Summary\n\n")
                f.write(f"- **Files Scanned:** {stats.get('files', 0)}\n")
                f.write(f"- **Lines Scanned:** {stats.get('lines', 0)}\n\n")
                
                f.write("### Findings by Severity\n\n")
                for sev, count in sev_counts.items():
                    emoji = "🔴" if sev == "HIGH" else "🟠" if sev == "MEDIUM" else "🟡"
                    f.write(f"- {emoji} **{sev}**: {count}\n")
                
                f.write(f"\n**Total Issues:** {len(issues)}\n")
                
                # Top rules
                if rule_counts:
                    f.write("\n### Top Rules Triggered\n\n")
                    sorted_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                    for rule_id, count in sorted_rules:
                        f.write(f"- `{rule_id}`: {count} occurrences\n")
                
                # Sample issues
                if issues:
                    f.write("\n## Sample Issues (up to 10)\n\n")
                    for issue in issues[:10]:
                        f.write(f"### {issue.get('rule_id', 'Unknown')} - {issue.get('details', 'No details')[:80]}\n")
                        f.write(f"- **Severity:** {issue.get('severity', 'Unknown')}\n")
                        f.write(f"- **Confidence:** {issue.get('confidence', 'Unknown')}\n")
                        f.write(f"- **File:** `{issue.get('file', 'Unknown')}:{issue.get('line', 0)}`\n")
                        if issue.get('cwe', {}).get('id'):
                            f.write(f"- **CWE:** CWE-{issue['cwe']['id']}\n")
                        f.write(f"- **Code:**\n```go\n{issue.get('code', '')[:200]}\n```\n\n")
                
            except Exception as e:
                f.write(f"Error parsing results: {e}\n")
                if result.stderr:
                    f.write(f"\nStderr: {result.stderr}\n")
        
        return result
        
    except subprocess.TimeoutExpired:
        logging.error(f"gosec timed out for {repo_name}")
        return None
    except Exception as e:
        logging.error(f"gosec failed for {repo_name}: {e}")
        return None


def run_golangci_lint(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """
    Run GolangCI-Lint with security linters enabled.
    
    GolangCI-Lint is a fast Go linters aggregator that includes gosec.
    This provides additional security checks beyond gosec alone.
    
    Install: brew install golangci-lint
    """
    os.makedirs(report_dir, exist_ok=True)
    
    # Check for Go files
    has_go = False
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'vendor']]
        if any(f.endswith('.go') for f in files):
            has_go = True
            break
    
    if not has_go:
        logging.info(f"No Go files found in {repo_name}, skipping golangci-lint")
        return None
    
    lint_bin = shutil.which('golangci-lint')
    output_json = os.path.join(report_dir, f"{repo_name}_golangci.json")
    output_md = os.path.join(report_dir, f"{repo_name}_golangci.md")
    
    if not lint_bin:
        with open(output_md, 'w') as f:
            f.write("# GolangCI-Lint Not Installed\n\n")
            f.write("Install via: `brew install golangci-lint`\n")
        return None
    
    try:
        logging.info(f"Running GolangCI-Lint for {repo_name}...")
        
        # Run with security-focused linters
        cmd = [
            lint_bin, 'run',
            '--out-format=json',
            '--enable=gosec,staticcheck,govet,errcheck,ineffassign,typecheck',
            '--timeout=10m',
            './...'
        ]
        
        if PROGRESS_MONITOR_AVAILABLE:
            result = run_with_progress_monitoring(
                cmd=cmd,
                repo_name=repo_name,
                scanner_name="golangci-lint",
                cwd=repo_path,
                timeout=600
            )
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600, cwd=repo_path)
        
        # Save JSON output
        if result.stdout:
            with open(output_json, 'w') as f:
                f.write(result.stdout)
        
        # Generate markdown report
        with open(output_md, 'w') as f:
            f.write(f"# GolangCI-Lint Security Scan\n\n")
            f.write(f"**Repository:** {repo_name}\n")
            f.write(f"**Scanned on:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            try:
                data = json.loads(result.stdout) if result.stdout else {}
                issues = data.get('Issues', [])
                
                # Count by linter
                linter_counts = {}
                severity_counts = {"error": 0, "warning": 0}
                
                for issue in issues:
                    linter = issue.get('FromLinter', 'unknown')
                    linter_counts[linter] = linter_counts.get(linter, 0) + 1
                    
                    sev = issue.get('Severity', 'warning')
                    if sev in severity_counts:
                        severity_counts[sev] += 1
                
                f.write("## Summary\n\n")
                f.write(f"- **Errors:** {severity_counts['error']}\n")
                f.write(f"- **Warnings:** {severity_counts['warning']}\n")
                f.write(f"\n**Total Issues:** {len(issues)}\n")
                
                # Issues by linter
                if linter_counts:
                    f.write("\n### Issues by Linter\n\n")
                    for linter, count in sorted(linter_counts.items(), key=lambda x: x[1], reverse=True):
                        emoji = "🔒" if linter == "gosec" else "📋"
                        f.write(f"- {emoji} **{linter}**: {count}\n")
                
                # Sample issues
                if issues:
                    f.write("\n## Sample Issues (up to 10)\n\n")
                    for issue in issues[:10]:
                        f.write(f"### [{issue.get('FromLinter', 'unknown')}] {issue.get('Text', 'No description')[:80]}\n")
                        pos = issue.get('Pos', {})
                        f.write(f"- **File:** `{pos.get('Filename', 'Unknown')}:{pos.get('Line', 0)}`\n")
                        if issue.get('SourceLines'):
                            f.write(f"- **Code:**\n```go\n{''.join(issue['SourceLines'][:3])}\n```\n\n")
                
            except Exception as e:
                f.write(f"Error parsing results: {e}\n")
        
        return result
        
    except subprocess.TimeoutExpired:
        logging.error(f"GolangCI-Lint timed out for {repo_name}")
        return None
    except Exception as e:
        logging.error(f"GolangCI-Lint failed for {repo_name}: {e}")
        return None


def run_mobsf_static(repo_path: str, repo_name: str, report_dir: str) -> Optional[subprocess.CompletedProcess]:
    """
    Run MobSF static analysis on mobile app source code.
    
    MobSF (Mobile Security Framework) performs:
    - Android: Java/Kotlin source analysis, manifest analysis, hardcoded secrets
    - iOS: Swift/Objective-C analysis, plist analysis, entitlements check
    
    Note: For APK/IPA binary analysis, MobSF server mode is required.
    This function performs source code analysis only.
    
    Install: pip install mobsf or docker pull opensecurity/mobile-security-framework-mobsf
    """
    os.makedirs(report_dir, exist_ok=True)
    
    # Detect mobile platform
    platform = None
    android_indicators = []
    ios_indicators = []
    
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'vendor', 'build', 'Pods']]
        
        for f in files:
            # Android indicators
            if f == 'AndroidManifest.xml':
                android_indicators.append(os.path.join(root, f))
            elif f == 'build.gradle' or f == 'build.gradle.kts':
                filepath = os.path.join(root, f)
                try:
                    with open(filepath, 'r') as gf:
                        content = gf.read(1000)
                        if 'android' in content.lower() or 'com.android' in content:
                            android_indicators.append(filepath)
                except:
                    pass
            
            # iOS indicators
            elif f == 'Info.plist':
                ios_indicators.append(os.path.join(root, f))
            elif f.endswith('.xcodeproj') or f.endswith('.xcworkspace'):
                ios_indicators.append(os.path.join(root, f))
            elif f == 'Podfile':
                ios_indicators.append(os.path.join(root, f))
    
    if not android_indicators and not ios_indicators:
        logging.info(f"No mobile app found in {repo_name}, skipping MobSF")
        return None
    
    if android_indicators:
        platform = 'android'
    elif ios_indicators:
        platform = 'ios'
    
    output_json = os.path.join(report_dir, f"{repo_name}_mobsf.json")
    output_md = os.path.join(report_dir, f"{repo_name}_mobsf.md")
    
    # MobSF source analysis patterns
    findings = []
    
    try:
        logging.info(f"Running MobSF static analysis for {repo_name} ({platform})...")
        
        # Perform source code analysis
        if platform == 'android':
            findings = _analyze_android_source(repo_path, android_indicators)
        else:
            findings = _analyze_ios_source(repo_path, ios_indicators)
        
        # Save JSON output
        result_data = {
            "platform": platform,
            "repository": repo_name,
            "scan_type": "source",
            "findings": findings,
            "summary": {
                "total": len(findings),
                "high": len([f for f in findings if f.get('severity') == 'high']),
                "medium": len([f for f in findings if f.get('severity') == 'medium']),
                "low": len([f for f in findings if f.get('severity') == 'low']),
            }
        }
        
        with open(output_json, 'w') as f:
            json.dump(result_data, f, indent=2)
        
        # Generate markdown report
        with open(output_md, 'w') as f:
            f.write(f"# MobSF Mobile Security Scan\n\n")
            f.write(f"**Repository:** {repo_name}\n")
            f.write(f"**Platform:** {platform.upper()}\n")
            f.write(f"**Scan Type:** Source Code Analysis\n")
            f.write(f"**Scanned on:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            summary = result_data['summary']
            f.write("## Summary\n\n")
            f.write(f"- 🔴 **High:** {summary['high']}\n")
            f.write(f"- 🟠 **Medium:** {summary['medium']}\n")
            f.write(f"- 🟡 **Low:** {summary['low']}\n")
            f.write(f"\n**Total Findings:** {summary['total']}\n")
            
            # Group by category
            categories = {}
            for finding in findings:
                cat = finding.get('category', 'Other')
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(finding)
            
            for cat, cat_findings in categories.items():
                f.write(f"\n## {cat}\n\n")
                for finding in cat_findings[:5]:  # Limit per category
                    sev_emoji = "🔴" if finding['severity'] == 'high' else "🟠" if finding['severity'] == 'medium' else "🟡"
                    f.write(f"### {sev_emoji} {finding.get('title', 'Finding')}\n")
                    f.write(f"- **Severity:** {finding['severity'].upper()}\n")
                    f.write(f"- **File:** `{finding.get('file', 'Unknown')}`\n")
                    f.write(f"- **Description:** {finding.get('description', 'N/A')}\n\n")
        
        # Create a mock result object
        class MockResult:
            def __init__(self):
                self.returncode = 0
                self.stdout = json.dumps(result_data)
                self.stderr = ""
        
        return MockResult()
        
    except Exception as e:
        logging.error(f"MobSF analysis failed for {repo_name}: {e}")
        return None


def _analyze_android_source(repo_path: str, manifest_files: list) -> list:
    """Analyze Android source code for security issues."""
    findings = []
    
    # Security patterns to check
    patterns = {
        'hardcoded_secret': {
            'patterns': [
                r'(?i)(api[_-]?key|secret|password|token)\s*=\s*["\'][^"\']{8,}["\']',
                r'(?i)Bearer\s+[a-zA-Z0-9_-]{20,}',
            ],
            'severity': 'high',
            'category': 'Hardcoded Secrets',
            'description': 'Hardcoded secret or API key found'
        },
        'insecure_http': {
            'patterns': [r'http://[^\s"\']+'],
            'severity': 'medium',
            'category': 'Network Security',
            'description': 'Insecure HTTP URL found (should use HTTPS)'
        },
        'webview_js': {
            'patterns': [r'setJavaScriptEnabled\s*\(\s*true\s*\)'],
            'severity': 'medium',
            'category': 'WebView Security',
            'description': 'JavaScript enabled in WebView'
        },
        'sql_injection': {
            'patterns': [r'rawQuery\s*\([^)]*\+[^)]*\)', r'execSQL\s*\([^)]*\+[^)]*\)'],
            'severity': 'high',
            'category': 'SQL Injection',
            'description': 'Potential SQL injection via string concatenation'
        },
        'logging_sensitive': {
            'patterns': [r'Log\.[divwe]\s*\([^)]*(?:password|token|secret|key)[^)]*\)'],
            'severity': 'medium',
            'category': 'Information Disclosure',
            'description': 'Sensitive data may be logged'
        },
        'weak_crypto': {
            'patterns': [r'DES|MD5|SHA1(?![\d])|RC4'],
            'severity': 'medium',
            'category': 'Weak Cryptography',
            'description': 'Weak cryptographic algorithm detected'
        },
        'exported_component': {
            'patterns': [r'android:exported\s*=\s*["\']true["\']'],
            'severity': 'low',
            'category': 'Component Security',
            'description': 'Exported component found - verify intent filter security'
        },
        'debuggable': {
            'patterns': [r'android:debuggable\s*=\s*["\']true["\']'],
            'severity': 'high',
            'category': 'Build Configuration',
            'description': 'App is debuggable - must be false for production'
        },
        'backup_enabled': {
            'patterns': [r'android:allowBackup\s*=\s*["\']true["\']'],
            'severity': 'medium',
            'category': 'Data Security',
            'description': 'App backup enabled - sensitive data may be extracted'
        }
    }
    
    import re
    
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in ['.git', 'build', 'node_modules']]
        
        for f in files:
            if not (f.endswith('.java') or f.endswith('.kt') or f.endswith('.xml')):
                continue
            
            filepath = os.path.join(root, f)
            rel_path = os.path.relpath(filepath, repo_path)
            
            try:
                with open(filepath, 'r', errors='ignore') as file:
                    content = file.read()
                    
                    for check_name, check_info in patterns.items():
                        for pattern in check_info['patterns']:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                # Get line number
                                line_num = content[:match.start()].count('\n') + 1
                                
                                findings.append({
                                    'title': check_name.replace('_', ' ').title(),
                                    'severity': check_info['severity'],
                                    'category': check_info['category'],
                                    'description': check_info['description'],
                                    'file': rel_path,
                                    'line': line_num,
                                    'match': match.group()[:100]  # Truncate long matches
                                })
            except Exception:
                pass
    
    return findings


def _analyze_ios_source(repo_path: str, plist_files: list) -> list:
    """Analyze iOS source code for security issues."""
    findings = []
    
    # Security patterns for iOS
    patterns = {
        'hardcoded_secret': {
            'patterns': [
                r'(?i)(api[_-]?key|secret|password|token)\s*=\s*["\'][^"\']{8,}["\']',
                r'(?i)Bearer\s+[a-zA-Z0-9_-]{20,}',
            ],
            'severity': 'high',
            'category': 'Hardcoded Secrets',
            'description': 'Hardcoded secret or API key found'
        },
        'insecure_http': {
            'patterns': [r'http://[^\s"\']+'],
            'severity': 'medium',
            'category': 'Network Security',
            'description': 'Insecure HTTP URL found (should use HTTPS)'
        },
        'ats_disabled': {
            'patterns': [r'NSAllowsArbitraryLoads.*true', r'NSExceptionAllowsInsecureHTTPLoads.*true'],
            'severity': 'high',
            'category': 'App Transport Security',
            'description': 'ATS disabled - allows insecure connections'
        },
        'keychain_accessible': {
            'patterns': [r'kSecAttrAccessibleAlways'],
            'severity': 'high',
            'category': 'Keychain Security',
            'description': 'Keychain item accessible when device locked'
        },
        'weak_crypto': {
            'patterns': [r'CC_MD5|CC_SHA1|kCCAlgorithmDES|kCCAlgorithm3DES'],
            'severity': 'medium',
            'category': 'Weak Cryptography',
            'description': 'Weak cryptographic algorithm detected'
        },
        'jailbreak_detection': {
            'patterns': [r'canOpenURL.*cydia', r'/Applications/Cydia', r'/bin/bash'],
            'severity': 'low',
            'category': 'Jailbreak Detection',
            'description': 'Jailbreak detection code found (verify implementation)'
        },
        'clipboard_sensitive': {
            'patterns': [r'UIPasteboard.*password|UIPasteboard.*token'],
            'severity': 'medium',
            'category': 'Data Leakage',
            'description': 'Sensitive data may be copied to clipboard'
        },
        'logging_sensitive': {
            'patterns': [r'NSLog\s*\([^)]*(?:password|token|secret|key)[^)]*\)', r'print\s*\([^)]*(?:password|token|secret)[^)]*\)'],
            'severity': 'medium',
            'category': 'Information Disclosure',
            'description': 'Sensitive data may be logged'
        }
    }
    
    import re
    
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in ['.git', 'build', 'Pods', 'DerivedData']]
        
        for f in files:
            if not (f.endswith('.swift') or f.endswith('.m') or f.endswith('.h') or f.endswith('.plist')):
                continue
            
            filepath = os.path.join(root, f)
            rel_path = os.path.relpath(filepath, repo_path)
            
            try:
                with open(filepath, 'r', errors='ignore') as file:
                    content = file.read()
                    
                    for check_name, check_info in patterns.items():
                        for pattern in check_info['patterns']:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1
                                
                                findings.append({
                                    'title': check_name.replace('_', ' ').title(),
                                    'severity': check_info['severity'],
                                    'category': check_info['category'],
                                    'description': check_info['description'],
                                    'file': rel_path,
                                    'line': line_num,
                                    'match': match.group()[:100]
                                })
            except Exception:
                pass
    
    return findings


def calculate_risk_metrics(report_dir: str, repo_name: str) -> Dict[str, Any]:
    """
    Aggregates findings from all scanners to calculate a Security Score.
    Returns a dict with counts, score, grade, and critical issues.
    """
    metrics = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "secrets": 0,
        "score": 100, "grade": "A", "summary": []
    }
    
    # Helper to map severity strings to standard levels
    def map_severity(sev: str) -> str:
        s = sev.lower()
        if s in ['critical', 'fatal']: return 'critical'
        if s in ['high', 'error']: return 'high'
        if s in ['medium', 'warning', 'moderate']: return 'medium'
        return 'low'

    # 1. Semgrep
    try:
        with open(os.path.join(report_dir, f"{repo_name}_semgrep.json")) as f:
            data = json.load(f)
            if data and isinstance(data, dict):
                for r in data.get('results', []) or []:
                    sev = map_severity(r.get('extra', {}).get('severity', 'low') if r else 'low')
                    metrics[sev] += 1
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
        logging.debug(f"Failed to parse Semgrep results for {repo_name}: {str(e)}")

    # 2. Bandit
    try:
        with open(os.path.join(report_dir, f"{repo_name}_bandit.json")) as f:
            data = json.load(f)
            if data and isinstance(data, dict):
                for r in data.get('results', []) or []:
                    sev = map_severity(r.get('issue_severity', 'low') if r else 'low')
                    metrics[sev] += 1
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
        logging.debug(f"Failed to parse Bandit results for {repo_name}: {str(e)}")

    # 3. Gitleaks (Secrets)
    try:
        with open(os.path.join(report_dir, f"{repo_name}_gitleaks.json")) as f:
            data = json.load(f)
            if data and isinstance(data, list):
                metrics['secrets'] += len(data)
    except (FileNotFoundError, json.JSONDecodeError, TypeError) as e:
        logging.debug(f"Failed to parse Gitleaks results for {repo_name}: {str(e)}")

    # 4. Trivy (Container/FS)
    try:
        with open(os.path.join(report_dir, f"{repo_name}_trivy_fs.json")) as f:
            data = json.load(f)
            if data and isinstance(data, dict):
                for res in data.get('Results', []) or []:
                    if res:
                        for vuln in res.get('Vulnerabilities', []) or []:
                            sev = map_severity(vuln.get('Severity', 'low') if vuln else 'low')
                            metrics[sev] += 1
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
        logging.debug(f"Failed to parse Trivy results for {repo_name}: {str(e)}")

    # =========================================================================
    # NEW PHASE 1 SCANNERS (December 2024)
    # =========================================================================
    
    # 5. Horusec (multi-tool SAST)
    try:
        with open(os.path.join(report_dir, f"{repo_name}_horusec.json")) as f:
            data = json.load(f)
            if data and isinstance(data, dict):
                for vuln in data.get('analysisVulnerabilities', []) or []:
                    v = vuln.get('vulnerabilities', {}) if vuln else {}
                    sev = map_severity(v.get('severity', 'low') if v else 'low')
                    metrics[sev] += 1
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
        logging.debug(f"Failed to parse Horusec results for {repo_name}: {str(e)}")

    # 6. Whispers (secrets in config files)
    try:
        with open(os.path.join(report_dir, f"{repo_name}_whispers.json")) as f:
            data = json.load(f)
            if isinstance(data, list):
                metrics['secrets'] += len(data)
    except (FileNotFoundError, json.JSONDecodeError, TypeError) as e:
        logging.debug(f"Failed to parse Whispers results for {repo_name}: {str(e)}")

    # 7. Bearer (data flow analysis)
    try:
        with open(os.path.join(report_dir, f"{repo_name}_bearer.json")) as f:
            data = json.load(f)
            if data and isinstance(data, dict):
                for finding in data.get('findings', []) or []:
                    sev = map_severity(finding.get('severity', 'medium') if finding else 'medium')
                    metrics[sev] += 1
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
        logging.debug(f"Failed to parse Bearer results for {repo_name}: {str(e)}")

    # 8. Terrascan (IaC security)
    try:
        with open(os.path.join(report_dir, f"{repo_name}_terrascan.json")) as f:
            data = json.load(f)
            if data and isinstance(data, dict):
                results = data.get('results', {}) or {}
                for v in results.get('violations', []) or []:
                    sev = map_severity(v.get('severity', 'low') if v else 'low')
                    metrics[sev] += 1
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
        logging.debug(f"Failed to parse Terrascan results for {repo_name}: {str(e)}")

    # =========================================================================
    # PHASE 3 SCANNERS: Go Security & Mobile Security
    # =========================================================================

    # 9. gosec (Go security)
    try:
        with open(os.path.join(report_dir, f"{repo_name}_gosec.json")) as f:
            data = json.load(f)
            if data and isinstance(data, dict):
                for issue in data.get('Issues', []) or []:
                    sev = map_severity(issue.get('severity', 'medium') if issue else 'medium')
                    metrics[sev] += 1
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
        logging.debug(f"Failed to parse gosec results for {repo_name}: {str(e)}")

    # 10. GolangCI-Lint (Go linting with security)
    try:
        with open(os.path.join(report_dir, f"{repo_name}_golangci.json")) as f:
            data = json.load(f)
            if data and isinstance(data, dict):
                for issue in data.get('Issues', []) or []:
                    if not issue:
                        continue
                    # Only count gosec issues to avoid double-counting
                    if issue.get('FromLinter') == 'gosec':
                        continue  # Already counted above
                    sev = 'medium' if issue.get('Severity') == 'error' else 'low'
                    metrics[sev] += 1
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
        logging.debug(f"Failed to parse GolangCI-Lint results for {repo_name}: {str(e)}")

    # 11. MobSF (Mobile security)
    try:
        with open(os.path.join(report_dir, f"{repo_name}_mobsf.json")) as f:
            data = json.load(f)
            if data and isinstance(data, dict):
                for finding in data.get('findings', []) or []:
                    sev = map_severity(finding.get('severity', 'medium') if finding else 'medium')
                    metrics[sev] += 1
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
        logging.debug(f"Failed to parse MobSF results for {repo_name}: {str(e)}")

    # Calculate Score
    # Penalties: Critical=-20, High=-10, Medium=-5, Low=-1, Secret=-20
    penalty = (metrics['critical'] * 20) + (metrics['high'] * 10) + \
              (metrics['medium'] * 5) + (metrics['low'] * 1) + (metrics['secrets'] * 20)
              
    metrics['score'] = max(0, 100 - penalty)
    
    # Assign Grade
    if metrics['score'] >= 90: metrics['grade'] = "A"
    elif metrics['score'] >= 80: metrics['grade'] = "B"
    elif metrics['score'] >= 70: metrics['grade'] = "C"
    elif metrics['score'] >= 60: metrics['grade'] = "D"
    else: metrics['grade'] = "F"
    
    return metrics

    
    return metrics

def generate_repo_architecture(repo_path: str, repo_name: str, ai_agent: Any) -> str:
    """
    Generate an architecture overview using the AI agent.
    Collects file structure and config files to send to the AI.
    """
    if not ai_agent:
        return ""
        
    try:
        # 1. Collect File Structure (limit depth and exclude .git)
        file_structure = ""
        for root, dirs, files in os.walk(repo_path):
            if '.git' in root: continue
            level = root.replace(repo_path, '').count(os.sep)
            if level > 2: continue # Limit depth
            indent = ' ' * 4 * (level)
            file_structure += f"{indent}{os.path.basename(root)}/\n"
            subindent = ' ' * 4 * (level + 1)
            for f in files:
                if f.startswith('.'): continue
                file_structure += f"{subindent}{f}\n"
                
        # 2. Collect Config Files
        config_files = {}
        interesting_files = [
            'Dockerfile', 'docker-compose.yml', 'package.json', 'requirements.txt', 
            'pom.xml', 'build.gradle', 'go.mod', 'Cargo.toml', 'README.md', 'pyproject.toml'
        ]
        
        for root, _, files in os.walk(repo_path):
            if '.git' in root: continue
            for f in files:
                if f in interesting_files:
                    path = os.path.join(root, f)
                    try:
                        with open(path, 'r') as cf:
                            # Limit content size
                            content = cf.read(2000)
                            config_files[f"{os.path.basename(root)}/{f}"] = content
                    except (FileNotFoundError, IOError, UnicodeDecodeError) as e:
                        logging.debug(f"Failed to read config file {path}: {str(e)}")
                    
        # 3. Call AI
        # We need to run async method in sync context
        return asyncio.run(ai_agent.reasoning_engine.generate_architecture_overview(
            repo_name=repo_name,
            file_structure=file_structure,
            config_files=config_files
        ))
        
    except Exception as e:
        logging.error(f"Failed to generate architecture: {e}")
        return ""

if __name__ == "__main__":
    main()
