"""
AI-powered Schedule Recommender service.
Uses AI providers to analyze repository context and recommend optimal scan schedules.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from src.ai_agent.agent import AIAgent
from src.github.models import (
    CommitAnalysisResult,
    ScheduleInput,
    ScheduleRecommendation,
)

logger = logging.getLogger(__name__)


class ScheduleRecommender:
    """AI-powered scan schedule recommendation engine."""

    # Default recommendations when AI unavailable
    DEFAULT_FREQUENCY = "weekly"
    DEFAULT_TIME_WINDOW = "night"

    # New repo defaults
    NEW_REPO_FREQUENCY = "daily"
    NEW_REPO_TIME_WINDOW = "night"

    def __init__(self, ai_agent: AIAgent):
        """Initialize with AI agent for recommendations."""
        self.ai_agent = ai_agent
        self.logger = logging.getLogger(__name__)

    async def recommend_schedule(
        self,
        schedule_input: ScheduleInput
    ) -> ScheduleRecommendation:
        """Generate AI-powered schedule recommendation."""
        # Handle new repos with no data
        if schedule_input.is_new_repo:
            return self._new_repo_default(schedule_input.repository_name)

        # Build prompt and call AI
        prompt = self._build_recommendation_prompt(schedule_input)

        try:
            response = await self.ai_agent.provider.execute_prompt(prompt)
            return self._parse_recommendation(response, schedule_input)
        except Exception as e:
            self.logger.warning(f"AI recommendation failed: {e}, using heuristics")
            return self._heuristic_recommendation(schedule_input)

    def _build_recommendation_prompt(self, input: ScheduleInput) -> str:
        """Build AI prompt for schedule recommendation."""
        commit_context = "No commit data available."
        if input.commit_analysis:
            ca = input.commit_analysis
            commit_context = f"""
Commit Patterns (last 90 days):
- Commits per day: {ca.patterns.commits_per_day}
- Commits per week: {ca.patterns.commits_per_week}
- Peak hours: {ca.patterns.peak_hours}
- Peak days: {ca.patterns.peak_days}
- Suggested frequency (heuristic): {ca.patterns.suggested_frequency}
- Suggested time window (heuristic): {ca.patterns.suggested_time_window}
- Is dormant: {ca.is_dormant}
- Top contributors: {len(ca.top_contributors)}
"""

        finding_context = "\n".join([
            f"- {severity}: {count}"
            for severity, count in input.finding_counts.items()
        ]) or "No findings"

        prompt = f"""You are an expert DevSecOps engineer optimizing security scan schedules.

Repository: {input.repository_name}
Risk Score: {input.risk_score:.2f} (0=low, 1=high)
Last Scan: {input.last_scan_date or 'Never'}

{commit_context}

Current Findings by Severity:
{finding_context}

Based on this context, recommend an optimal scan schedule.

Consider:
1. High-activity repos need more frequent scans
2. Repos with critical/high findings need more attention
3. Scan during low-activity periods to minimize disruption
4. Dormant repos can be scanned less frequently
5. Risk score indicates overall security posture

Return JSON:
{{
    "frequency": "daily|weekly|bi-weekly|monthly",
    "time_window": "morning|afternoon|evening|night",
    "confidence": 0.0-1.0,
    "reasoning": "Explanation of recommendation",
    "factors_considered": ["factor1", "factor2"]
}}
"""
        return prompt

    def _parse_recommendation(
        self,
        response: str,
        input: ScheduleInput
    ) -> ScheduleRecommendation:
        """Parse AI JSON response into ScheduleRecommendation."""
        try:
            # Clean markdown code blocks
            content = response
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()

            data = json.loads(content)

            # Validate frequency
            valid_frequencies = {"daily", "weekly", "bi-weekly", "monthly"}
            frequency = data.get("frequency", self.DEFAULT_FREQUENCY)
            if frequency not in valid_frequencies:
                frequency = self.DEFAULT_FREQUENCY

            # Validate time window
            valid_windows = {"morning", "afternoon", "evening", "night"}
            time_window = data.get("time_window", self.DEFAULT_TIME_WINDOW)
            if time_window not in valid_windows:
                time_window = self.DEFAULT_TIME_WINDOW

            return ScheduleRecommendation(
                frequency=frequency,
                time_window=time_window,
                confidence=min(1.0, max(0.0, float(data.get("confidence", 0.5)))),
                reasoning=data.get("reasoning", "AI-generated recommendation"),
                factors_considered=data.get("factors_considered", [])
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            self.logger.warning(f"Failed to parse AI response: {e}")
            return self._heuristic_recommendation(input)

    def _heuristic_recommendation(
        self,
        input: ScheduleInput
    ) -> ScheduleRecommendation:
        """Fallback heuristic-based recommendation."""
        # Implementation in Task 4
        pass

    def _new_repo_default(self, repo_name: str) -> ScheduleRecommendation:
        """Default schedule for new repositories."""
        return ScheduleRecommendation(
            frequency=self.NEW_REPO_FREQUENCY,
            time_window=self.NEW_REPO_TIME_WINDOW,
            confidence=0.7,
            reasoning="New repository with no commit history. Daily scans recommended until patterns emerge.",
            factors_considered=["new_repository", "no_commit_history"]
        )
