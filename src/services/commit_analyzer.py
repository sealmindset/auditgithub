"""
Commit Analysis Service for extracting GitHub commit patterns.
Used by AI Scheduling Engine to determine optimal scan timing.
"""
import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from src.github.api import GitHubAPI
from src.github.models import (
    CommitAnalysisResult,
    CommitPattern,
    ContributorActivity,
    FileTypeStats,
)


class CommitAnalyzer:
    """Analyzes GitHub commit history to extract scheduling patterns."""

    # Analysis parameters
    LOOKBACK_DAYS = 90  # Analyze last 90 days of commits
    DORMANT_THRESHOLD_DAYS = 90  # No commits = dormant
    MAX_COMMITS_TO_FETCH = 500  # Limit API calls

    # Time window mapping (hour ranges)
    TIME_WINDOWS = {
        "morning": range(6, 12),      # 6am - 12pm
        "afternoon": range(12, 18),   # 12pm - 6pm
        "evening": range(18, 22),     # 6pm - 10pm
        "night": list(range(22, 24)) + list(range(0, 6)),  # 10pm - 6am
    }

    # Frequency thresholds (commits per week)
    FREQUENCY_THRESHOLDS = {
        "daily": 7,       # 7+ commits/week -> daily scans
        "weekly": 2,      # 2-7 commits/week -> weekly scans
        "bi-weekly": 0.5, # 0.5-2 commits/week -> bi-weekly
        "monthly": 0,     # < 0.5 commits/week -> monthly
    }

    def __init__(self, github_api: GitHubAPI):
        self.github = github_api
        self.logger = logging.getLogger(__name__)

    def analyze_repository(self, repo_name: str) -> CommitAnalysisResult:
        """Perform full commit analysis for a repository."""
        since_date = datetime.now(timezone.utc) - timedelta(days=self.LOOKBACK_DAYS)
        since_str = since_date.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Fetch commits
        commits = self._fetch_commits(repo_name, since_str)

        # Check for dormancy
        is_dormant = len(commits) == 0

        # Extract patterns
        patterns = self._analyze_patterns(commits)
        file_types = self._analyze_file_types(commits)
        contributors = self._analyze_contributors(commits)

        return CommitAnalysisResult(
            repository_name=repo_name,
            analyzed_at=datetime.now(timezone.utc),
            commit_count=len(commits),
            patterns=patterns,
            file_types=file_types,
            top_contributors=contributors,
            is_dormant=is_dormant,
        )

    def _fetch_commits(self, repo_name: str, since: str) -> List[Dict]:
        """Fetch commit history with pagination."""
        all_commits = []
        page = 1
        per_page = 100

        while len(all_commits) < self.MAX_COMMITS_TO_FETCH:
            try:
                response = self.github._make_request(
                    'GET',
                    f'repos/{self.github.org_name}/{repo_name}/commits',
                    params={
                        'since': since,
                        'per_page': per_page,
                        'page': page,
                    }
                )
                batch = response.json()

                if not batch:
                    break

                all_commits.extend(batch)

                if len(batch) < per_page:
                    break

                page += 1

            except Exception as e:
                self.logger.warning(f"Failed to fetch commits for {repo_name}: {e}")
                break

        return all_commits[:self.MAX_COMMITS_TO_FETCH]

    def _analyze_patterns(self, commits: List[Dict]) -> CommitPattern:
        """Extract timing patterns from commits."""
        if not commits:
            return CommitPattern(
                commits_per_day=0,
                commits_per_week=0,
                peak_hours=[],
                peak_days=[],
                suggested_time_window="morning",
                suggested_frequency="monthly",
            )

        # Parse commit timestamps
        hours = []
        days = []
        timestamps = []

        for commit in commits:
            commit_date_str = commit.get('commit', {}).get('author', {}).get('date')
            if commit_date_str:
                try:
                    dt = datetime.fromisoformat(commit_date_str.replace('Z', '+00:00'))
                    hours.append(dt.hour)
                    days.append(dt.weekday())
                    timestamps.append(dt)
                except ValueError:
                    continue

        if not timestamps:
            return CommitPattern(
                commits_per_day=0,
                commits_per_week=0,
                peak_hours=[],
                peak_days=[],
                suggested_time_window="morning",
                suggested_frequency="monthly",
            )

        # Calculate frequency
        date_range = (max(timestamps) - min(timestamps)).days or 1
        commits_per_day = len(commits) / date_range
        commits_per_week = commits_per_day * 7

        # Find peak hours (top 3)
        hour_counts = Counter(hours)
        peak_hours = [h for h, _ in hour_counts.most_common(3)]

        # Find peak days (top 2)
        day_counts = Counter(days)
        peak_days = [d for d, _ in day_counts.most_common(2)]

        # Determine suggested time window
        suggested_window = self._suggest_time_window(hour_counts)

        # Determine suggested frequency
        suggested_frequency = self._suggest_frequency(commits_per_week)

        return CommitPattern(
            commits_per_day=round(commits_per_day, 2),
            commits_per_week=round(commits_per_week, 2),
            peak_hours=peak_hours,
            peak_days=peak_days,
            suggested_time_window=suggested_window,
            suggested_frequency=suggested_frequency,
        )

    def _suggest_time_window(self, hour_counts: Counter) -> str:
        """Suggest optimal scan time window based on commit activity."""
        # Count commits per time window
        window_activity = defaultdict(int)
        for hour, count in hour_counts.items():
            for window, hours in self.TIME_WINDOWS.items():
                if hour in hours:
                    window_activity[window] += count
                    break

        if not window_activity:
            return "morning"  # Default

        # Find least active window (best time to scan)
        return min(window_activity, key=window_activity.get)

    def _suggest_frequency(self, commits_per_week: float) -> str:
        """Suggest scan frequency based on commit rate."""
        if commits_per_week >= self.FREQUENCY_THRESHOLDS["daily"]:
            return "daily"
        elif commits_per_week >= self.FREQUENCY_THRESHOLDS["weekly"]:
            return "weekly"
        elif commits_per_week >= self.FREQUENCY_THRESHOLDS["bi-weekly"]:
            return "bi-weekly"
        else:
            return "monthly"

    def _analyze_file_types(self, commits: List[Dict]) -> FileTypeStats:
        """Analyze file extensions modified in commits."""
        extension_counts: Counter = Counter()

        for commit in commits:
            # Note: Basic commit list doesn't include files
            # Would need separate API call per commit for file details
            # For now, return empty - can be enhanced later
            pass

        # Determine primary language from extensions
        primary_language = None
        if extension_counts:
            top_ext = extension_counts.most_common(1)[0][0]
            primary_language = self._extension_to_language(top_ext)

        return FileTypeStats(
            extensions=dict(extension_counts),
            primary_language=primary_language,
        )

    def _extension_to_language(self, ext: str) -> Optional[str]:
        """Map file extension to language name."""
        mapping = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.go': 'Go',
            '.rs': 'Rust',
            '.rb': 'Ruby',
            '.php': 'PHP',
            '.cs': 'C#',
            '.cpp': 'C++',
            '.c': 'C',
        }
        return mapping.get(ext)

    def _analyze_contributors(self, commits: List[Dict]) -> List[ContributorActivity]:
        """Analyze contributor activity from commits."""
        contributor_data: Dict[str, Dict] = defaultdict(lambda: {
            'commits': 0,
            'last_commit': None,
        })

        for commit in commits:
            author = commit.get('author') or {}
            login = author.get('login')
            if not login:
                # Fallback to commit author name
                commit_author = commit.get('commit', {}).get('author', {})
                login = commit_author.get('name', 'unknown')

            contributor_data[login]['commits'] += 1

            # Track last commit date
            commit_date_str = commit.get('commit', {}).get('author', {}).get('date')
            if commit_date_str:
                try:
                    dt = datetime.fromisoformat(commit_date_str.replace('Z', '+00:00'))
                    if not contributor_data[login]['last_commit'] or dt > contributor_data[login]['last_commit']:
                        contributor_data[login]['last_commit'] = dt
                except ValueError:
                    pass

        # Convert to list and sort by commits
        contributors = [
            ContributorActivity(
                login=login,
                commits_last_30_days=data['commits'],  # Actually last 90 days based on LOOKBACK_DAYS
                last_commit_date=data['last_commit'],
            )
            for login, data in contributor_data.items()
        ]

        # Return top 10 contributors
        contributors.sort(key=lambda c: c.commits_last_30_days, reverse=True)
        return contributors[:10]
