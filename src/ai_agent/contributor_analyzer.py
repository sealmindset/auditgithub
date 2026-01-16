"""
AI-powered contributor analysis for security insights.

Analyzes contributor data to generate security risk assessments,
code ownership concerns, and remediation priorities.
"""
import json
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class ContributorAnalyzer:
    """Analyzes contributor data using AI to generate security insights."""

    def __init__(self, ai_provider):
        """
        Initialize with an AI provider.

        Args:
            ai_provider: AI provider instance with execute_prompt() method
        """
        self.ai_provider = ai_provider

    async def analyze_contributor(
        self,
        contributor: Dict[str, Any],
        repo_name: str,
        total_findings: int
    ) -> Dict[str, Any]:
        """
        Generate AI analysis for a contributor.

        Args:
            contributor: Contributor data with files and severities
            repo_name: Name of the repository
            total_findings: Total findings in the repository

        Returns:
            Dict with ai_summary and enhanced risk assessment
        """
        # Build context for AI
        files = contributor.get('files_contributed', [])
        critical_files = [f for f in files if f.get('severity') == 'critical']
        high_files = [f for f in files if f.get('severity') == 'high']
        medium_files = [f for f in files if f.get('severity') == 'medium']

        # Calculate totals
        total_findings_count = sum(f.get('findings_count', 0) for f in files)

        prompt = f"""Analyze this contributor's security impact for repository "{repo_name}":

**Contributor:** {contributor.get('name')} ({contributor.get('email')})
**Commits:** {contributor.get('commits')} ({contributor.get('commit_percentage', 0):.1f}% of total)
**Last Active:** {contributor.get('last_commit_at', 'Unknown')}
**Languages:** {', '.join(contributor.get('languages', []))}
**Files Modified:** {len(files)}
**Folders:** {', '.join(contributor.get('folders_contributed', [])[:10])}

**Security Impact:**
- Critical severity files: {len(critical_files)}
- High severity files: {len(high_files)}
- Medium severity files: {len(medium_files)}
- Total findings in contributor's files: {total_findings_count}
- Repository total findings: {total_findings}

**Critical Files:**
{json.dumps(critical_files[:5], indent=2) if critical_files else 'None'}

**High Severity Files:**
{json.dumps(high_files[:5], indent=2) if high_files else 'None'}

Provide a concise 2-3 sentence security analysis of this contributor:
1. Their code ownership risk (bus factor consideration)
2. Security debt they may have introduced
3. Priority recommendation for remediation

Format as a brief professional summary. Be specific about risks but constructive."""

        try:
            response = await self.ai_provider.execute_prompt(prompt)

            return {
                'ai_summary': response.strip(),
                'analysis_confidence': 0.8
            }

        except Exception as e:
            logger.error(f"Failed to analyze contributor {contributor.get('name')}: {e}")
            return {
                'ai_summary': f"Analysis unavailable: {str(e)}",
                'analysis_confidence': 0
            }

    async def generate_team_summary(
        self,
        contributors: List[Dict[str, Any]],
        repo_name: str
    ) -> str:
        """
        Generate an overall team security summary.

        Args:
            contributors: List of contributor data
            repo_name: Name of the repository

        Returns:
            AI-generated team summary
        """
        high_risk_contributors = [c for c in contributors if c.get('risk_score', 0) >= 50]
        total_commits = sum(c.get('commits', 0) for c in contributors)

        # Prepare top contributors data
        top_contributors_data = []
        for c in contributors[:5]:
            files = c.get('files_contributed', [])
            critical_count = len([f for f in files if f.get('severity') == 'critical'])
            top_contributors_data.append({
                'name': c.get('name'),
                'commits': c.get('commits'),
                'risk_score': c.get('risk_score', 0),
                'critical_files': critical_count
            })

        prompt = f"""Analyze the contributor team for repository "{repo_name}":

**Team Size:** {len(contributors)} contributors
**Total Commits:** {total_commits}
**High Risk Contributors (score >= 50):** {len(high_risk_contributors)}

**Top 5 Contributors by Commits:**
{json.dumps(top_contributors_data, indent=2)}

Provide a brief team security assessment (3-4 sentences):
1. Bus factor risk
2. Security debt concentration
3. Recommended actions for risk mitigation

Be specific and actionable."""

        try:
            response = await self.ai_provider.execute_prompt(prompt)
            return response.strip()

        except Exception as e:
            logger.error(f"Failed to generate team summary for {repo_name}: {e}")
            return f"Team analysis unavailable: {str(e)}"

    def calculate_risk_score(self, files: List[Dict[str, Any]]) -> int:
        """
        Calculate contributor risk score (0-100) based on file severities.

        Scoring:
        - Critical finding: +25 points per file
        - High finding: +15 points per file
        - Medium finding: +5 points per file
        - Low finding: +1 point per file

        Args:
            files: List of file dictionaries with severity info

        Returns:
            Risk score capped at 100
        """
        score = 0
        severity_points = {'critical': 25, 'high': 15, 'medium': 5, 'low': 1}

        for file in files:
            sev = file.get('severity')
            if sev:
                score += severity_points.get(sev.lower(), 0)

        return min(100, score)


async def analyze_contributors_batch(
    ai_agent,
    contributors: List[Dict[str, Any]],
    repo_name: str,
    total_findings: int,
    max_to_analyze: int = 10
) -> List[Dict[str, Any]]:
    """
    Batch analyze contributors with AI.

    Only analyzes top contributors by commit count to optimize API usage.

    Args:
        ai_agent: AIAgent instance
        contributors: List of contributor data
        repo_name: Repository name
        total_findings: Total findings count
        max_to_analyze: Maximum contributors to analyze (default 10)

    Returns:
        List of contributors with ai_summary populated
    """
    analyzer = ContributorAnalyzer(ai_agent.provider)

    # Sort by commits and take top N
    sorted_contributors = sorted(
        contributors,
        key=lambda x: x.get('commits', 0),
        reverse=True
    )

    for i, contributor in enumerate(sorted_contributors[:max_to_analyze]):
        try:
            result = await analyzer.analyze_contributor(
                contributor=contributor,
                repo_name=repo_name,
                total_findings=total_findings
            )
            contributor['ai_summary'] = result.get('ai_summary', '')
            logger.info(f"Analyzed contributor {i+1}/{min(max_to_analyze, len(contributors))}: {contributor.get('name')}")

        except Exception as e:
            logger.warning(f"Failed to analyze {contributor.get('name')}: {e}")
            contributor['ai_summary'] = ''

    return contributors
