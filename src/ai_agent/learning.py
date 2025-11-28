"""
Learning system for improving AI suggestions over time.

Tracks AI suggestions, their outcomes, and identifies patterns to improve future analyses.
"""

import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class LearningSystem:
    """Tracks and learns from AI suggestion outcomes."""
    
    def __init__(self, learning_file: str = "vulnerability_reports/ai_learning.json"):
        """
        Initialize the learning system.
        
        Args:
            learning_file: Path to the learning data file
        """
        self.learning_file = Path(learning_file)
        self.data = self._load_learning_data()
    
    def _load_learning_data(self) -> Dict[str, Any]:
        """Load existing learning data or create new."""
        if self.learning_file.exists():
            try:
                with open(self.learning_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load learning data: {e}")
        
        return {
            "suggestions": [],
            "patterns": {},
            "statistics": {
                "total_analyses": 0,
                "total_suggestions": 0,
                "applied_suggestions": 0,
                "successful_outcomes": 0
            }
        }
    
    def _save_learning_data(self):
        """Save learning data to file."""
        try:
            self.learning_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.learning_file, 'w') as f:
                json.dump(self.data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save learning data: {e}")
    
    def record_suggestion(
        self,
        repo_name: str,
        scanner: str,
        suggestion_action: str,
        applied: bool,
        outcome: Optional[str] = None,
        notes: Optional[str] = None
    ):
        """
        Record an AI suggestion and its outcome.
        
        Args:
            repo_name: Repository name
            scanner: Scanner name
            suggestion_action: The suggested action
            applied: Whether the suggestion was applied
            outcome: Outcome (success/failure/pending)
            notes: Additional notes
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "repo": repo_name,
            "scanner": scanner,
            "suggestion": suggestion_action,
            "applied": applied,
            "outcome": outcome,
            "notes": notes
        }
        
        self.data["suggestions"].append(entry)
        self.data["statistics"]["total_suggestions"] += 1
        
        if applied:
            self.data["statistics"]["applied_suggestions"] += 1
        
        if outcome == "success":
            self.data["statistics"]["successful_outcomes"] += 1
        
        self._save_learning_data()
        logger.debug(f"Recorded suggestion: {suggestion_action} for {repo_name}")
    
    def record_analysis(
        self,
        repo_name: str,
        scanner: str,
        root_cause: str,
        confidence: float,
        suggestions_count: int
    ):
        """
        Record an AI analysis.
        
        Args:
            repo_name: Repository name
            scanner: Scanner name
            root_cause: Identified root cause
            confidence: AI confidence score
            suggestions_count: Number of suggestions provided
        """
        self.data["statistics"]["total_analyses"] += 1
        
        # Update patterns
        pattern_key = f"{scanner}_timeout"
        if pattern_key not in self.data["patterns"]:
            self.data["patterns"][pattern_key] = {
                "count": 0,
                "common_causes": {},
                "successful_remediations": {}
            }
        
        self.data["patterns"][pattern_key]["count"] += 1
        
        # Track common causes
        if root_cause not in self.data["patterns"][pattern_key]["common_causes"]:
            self.data["patterns"][pattern_key]["common_causes"][root_cause] = 0
        self.data["patterns"][pattern_key]["common_causes"][root_cause] += 1
        
        self._save_learning_data()
    
    def update_outcome(
        self,
        repo_name: str,
        suggestion_action: str,
        outcome: str,
        notes: Optional[str] = None
    ):
        """
        Update the outcome of a previously recorded suggestion.
        
        Args:
            repo_name: Repository name
            suggestion_action: The suggestion action
            outcome: Outcome (success/failure)
            notes: Additional notes
        """
        # Find the most recent matching suggestion
        for entry in reversed(self.data["suggestions"]):
            if (entry["repo"] == repo_name and 
                entry["suggestion"] == suggestion_action and
                entry["outcome"] is None):
                entry["outcome"] = outcome
                if notes:
                    entry["notes"] = notes
                
                if outcome == "success":
                    self.data["statistics"]["successful_outcomes"] += 1
                    
                    # Update pattern success rate
                    scanner = entry.get("scanner", "unknown")
                    pattern_key = f"{scanner}_timeout"
                    if pattern_key in self.data["patterns"]:
                        if suggestion_action not in self.data["patterns"][pattern_key]["successful_remediations"]:
                            self.data["patterns"][pattern_key]["successful_remediations"][suggestion_action] = 0
                        self.data["patterns"][pattern_key]["successful_remediations"][suggestion_action] += 1
                
                self._save_learning_data()
                logger.info(f"Updated outcome for {repo_name}/{suggestion_action}: {outcome}")
                break
    
    def get_historical_data(self, repo_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get historical suggestion data.
        
        Args:
            repo_name: Optional repository name to filter by
            
        Returns:
            List of historical suggestions
        """
        if repo_name:
            return [
                entry for entry in self.data["suggestions"]
                if entry["repo"] == repo_name
            ]
        return self.data["suggestions"]
    
    def get_patterns(self) -> Dict[str, Any]:
        """Get identified patterns."""
        return self.data["patterns"]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get learning statistics."""
        stats = self.data["statistics"].copy()
        
        # Calculate success rate
        if stats["applied_suggestions"] > 0:
            stats["success_rate"] = stats["successful_outcomes"] / stats["applied_suggestions"]
        else:
            stats["success_rate"] = 0.0
        
        return stats
    
    def get_recommendations_for_scanner(self, scanner: str) -> Dict[str, Any]:
        """
        Get recommendations based on historical data for a specific scanner.
        
        Args:
            scanner: Scanner name
            
        Returns:
            Dictionary of recommendations
        """
        pattern_key = f"{scanner}_timeout"
        
        if pattern_key not in self.data["patterns"]:
            return {
                "has_data": False,
                "message": f"No historical data for {scanner}"
            }
        
        pattern = self.data["patterns"][pattern_key]
        
        # Find most common cause
        common_causes = pattern.get("common_causes", {})
        most_common_cause = max(common_causes.items(), key=lambda x: x[1])[0] if common_causes else None
        
        # Find most successful remediation
        successful_remediations = pattern.get("successful_remediations", {})
        most_successful = max(
            successful_remediations.items(),
            key=lambda x: x[1]
        )[0] if successful_remediations else None
        
        return {
            "has_data": True,
            "timeout_count": pattern["count"],
            "most_common_cause": most_common_cause,
            "most_successful_remediation": most_successful,
            "success_rate": (
                sum(successful_remediations.values()) / pattern["count"]
                if pattern["count"] > 0 else 0.0
            )
        }
