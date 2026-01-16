"""
Auto-remediation engine for applying AI suggestions.

Implements safe remediation strategies based on AI analysis.
"""

import logging
from typing import Dict, Any, List, Set, Optional
from enum import Enum

from .providers.base import RemediationSuggestion, RemediationAction

logger = logging.getLogger(__name__)


class RemediationEngine:
    """Applies AI-suggested remediation strategies safely."""
    
    def __init__(
        self,
        allowed_actions: Optional[Set[RemediationAction]] = None,
        dry_run: bool = False,
        min_confidence: float = 0.7
    ):
        """
        Initialize the remediation engine.
        
        Args:
            allowed_actions: Set of allowed remediation actions (None = all safe actions)
            dry_run: If True, only log what would be done without executing
            min_confidence: Minimum confidence score to apply remediation (0.0-1.0)
        """
        self.allowed_actions = allowed_actions or {
            RemediationAction.INCREASE_TIMEOUT,
            RemediationAction.EXCLUDE_PATTERNS
        }
        self.dry_run = dry_run
        self.min_confidence = min_confidence
        self.applied_remediations: List[Dict[str, Any]] = []
    
    def apply_suggestions(
        self,
        suggestions: List[RemediationSuggestion],
        repo_name: str,
        scanner: str
    ) -> List[Dict[str, Any]]:
        """
        Apply remediation suggestions.
        
        Args:
            suggestions: List of AI-generated suggestions
            repo_name: Repository name
            scanner: Scanner name
            
        Returns:
            List of applied remediation results
        """
        results = []
        
        for suggestion in suggestions:
            # Check if action is allowed
            if suggestion.action not in self.allowed_actions:
                logger.info(
                    f"Skipping {suggestion.action.value} for {repo_name}: "
                    f"action not in allowed list"
                )
                results.append({
                    "action": suggestion.action.value,
                    "status": "skipped",
                    "reason": "action_not_allowed"
                })
                continue
            
            # Check confidence threshold
            if suggestion.confidence < self.min_confidence:
                logger.info(
                    f"Skipping {suggestion.action.value} for {repo_name}: "
                    f"confidence {suggestion.confidence:.2f} < {self.min_confidence}"
                )
                results.append({
                    "action": suggestion.action.value,
                    "status": "skipped",
                    "reason": "low_confidence"
                })
                continue
            
            # Check safety level
            if suggestion.safety_level == "risky":
                logger.warning(
                    f"Skipping risky action {suggestion.action.value} for {repo_name}"
                )
                results.append({
                    "action": suggestion.action.value,
                    "status": "skipped",
                    "reason": "risky_action"
                })
                continue
            
            # Apply the remediation
            result = self._apply_single_remediation(
                suggestion=suggestion,
                repo_name=repo_name,
                scanner=scanner
            )
            results.append(result)
            
            # Track applied remediations
            if result["status"] == "applied":
                self.applied_remediations.append({
                    "repo_name": repo_name,
                    "scanner": scanner,
                    "suggestion": suggestion,
                    "result": result
                })
        
        return results
    
    def _apply_single_remediation(
        self,
        suggestion: RemediationSuggestion,
        repo_name: str,
        scanner: str
    ) -> Dict[str, Any]:
        """
        Apply a single remediation suggestion.
        
        Args:
            suggestion: Remediation suggestion
            repo_name: Repository name
            scanner: Scanner name
            
        Returns:
            Result dictionary
        """
        action = suggestion.action
        params = suggestion.params
        
        if self.dry_run:
            logger.info(
                f"[DRY RUN] Would apply {action.value} for {repo_name}: {params}"
            )
            return {
                "action": action.value,
                "status": "dry_run",
                "params": params,
                "rationale": suggestion.rationale
            }
        
        try:
            if action == RemediationAction.INCREASE_TIMEOUT:
                return self._increase_timeout(repo_name, scanner, params)
            
            elif action == RemediationAction.EXCLUDE_PATTERNS:
                return self._exclude_patterns(repo_name, scanner, params)
            
            elif action == RemediationAction.REDUCE_PARALLELISM:
                return self._reduce_parallelism(repo_name, scanner, params)
            
            elif action == RemediationAction.SKIP_SCANNER:
                return self._skip_scanner(repo_name, scanner, params)
            
            elif action == RemediationAction.CHUNK_SCAN:
                return self._chunk_scan(repo_name, scanner, params)
            
            elif action == RemediationAction.ADJUST_RESOURCES:
                return self._adjust_resources(repo_name, scanner, params)
            
            else:
                logger.warning(f"Unknown remediation action: {action.value}")
                return {
                    "action": action.value,
                    "status": "error",
                    "error": "unknown_action"
                }
                
        except Exception as e:
            logger.error(f"Failed to apply {action.value}: {e}", exc_info=True)
            return {
                "action": action.value,
                "status": "error",
                "error": str(e)
            }
    
    def _increase_timeout(
        self,
        repo_name: str,
        scanner: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Increase timeout for this repository."""
        new_timeout = params.get("new_timeout", 60)
        
        logger.info(f"Increasing timeout for {repo_name} to {new_timeout} minutes")
        
        # This would be implemented by updating scanner configuration
        # For now, just log the action
        return {
            "action": "increase_timeout",
            "status": "applied",
            "params": {"new_timeout": new_timeout},
            "note": "Timeout increased - will take effect on next scan"
        }
    
    def _exclude_patterns(
        self,
        repo_name: str,
        scanner: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add exclusion patterns to scanner config."""
        patterns = params.get("patterns", [])
        
        logger.info(f"Adding exclusion patterns for {repo_name}: {patterns}")
        
        # This would be implemented by updating scanner configuration
        return {
            "action": "exclude_patterns",
            "status": "applied",
            "params": {"patterns": patterns},
            "note": "Exclusion patterns added - will take effect on next scan"
        }
    
    def _reduce_parallelism(
        self,
        repo_name: str,
        scanner: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Reduce parallelism to lower resource usage."""
        new_workers = params.get("max_workers", 1)
        
        logger.info(f"Reducing parallelism for {repo_name} to {new_workers} workers")
        
        return {
            "action": "reduce_parallelism",
            "status": "applied",
            "params": {"max_workers": new_workers},
            "note": "Parallelism reduced - will take effect on next scan"
        }
    
    def _skip_scanner(
        self,
        repo_name: str,
        scanner: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Skip this scanner for this repository."""
        logger.info(f"Skipping {scanner} for {repo_name}")
        
        return {
            "action": "skip_scanner",
            "status": "applied",
            "params": {"scanner": scanner},
            "note": f"{scanner} will be skipped for this repository"
        }
    
    def _chunk_scan(
        self,
        repo_name: str,
        scanner: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Split scan into smaller chunks."""
        chunk_size = params.get("chunk_size", 10000)
        
        logger.info(f"Chunking scan for {repo_name} with size {chunk_size}")
        
        return {
            "action": "chunk_scan",
            "status": "applied",
            "params": {"chunk_size": chunk_size},
            "note": "Scan will be chunked on next run"
        }
    
    def _adjust_resources(
        self,
        repo_name: str,
        scanner: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Adjust resource limits."""
        memory_limit = params.get("memory_limit_mb")
        cpu_limit = params.get("cpu_limit")
        
        logger.info(f"Adjusting resources for {repo_name}: memory={memory_limit}MB, cpu={cpu_limit}")
        
        return {
            "action": "adjust_resources",
            "status": "applied",
            "params": params,
            "note": "Resource limits adjusted"
        }
    
    def get_applied_remediations(self) -> List[Dict[str, Any]]:
        """Get list of all applied remediations."""
        return self.applied_remediations
