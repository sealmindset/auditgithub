"""
Data models for GitHub API responses.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class Repository:
    """Repository information from GitHub API."""
    name: str
    full_name: str
    html_url: str
    description: Optional[str] = None
    language: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    pushed_at: Optional[str] = None
    size: int = 0
    stargazers_count: int = 0
    watchers_count: int = 0
    forks_count: int = 0
    open_issues_count: int = 0
    is_fork: bool = False
    is_archived: bool = False
    is_disabled: bool = False
    default_branch: str = "main"

    @property
    def last_updated(self) -> Optional[datetime]:
        """Get the last update time as a datetime object."""
        if self.pushed_at:
            return datetime.fromisoformat(self.pushed_at.replace('Z', '+00:00'))
        return None


@dataclass
class Contributor:
    """Repository contributor information."""
    login: str
    contributions: int
    avatar_url: Optional[str] = None
    html_url: Optional[str] = None
    type: str = "User"
    site_admin: bool = False


@dataclass
class LanguageStats:
    """Repository language statistics."""
    languages: Dict[str, int] = field(default_factory=dict)
    total_bytes: int = 0

    def add_language(self, language: str, bytes_count: int) -> None:
        """Add language data to the stats."""
        self.languages[language] = bytes_count
        self.total_bytes += bytes_count

    def get_percentage(self, language: str) -> float:
        """Get the percentage of code in a specific language."""
        if not self.total_bytes or language not in self.languages:
            return 0.0
        return (self.languages[language] / self.total_bytes) * 100


@dataclass
class CommitPattern:
    """Commit timing and frequency patterns for scheduling decisions."""
    commits_per_day: float
    commits_per_week: float
    peak_hours: List[int]  # 0-23
    peak_days: List[int]  # 0=Monday, 6=Sunday
    suggested_time_window: str  # morning/afternoon/evening/night
    suggested_frequency: str  # daily/weekly/bi-weekly/monthly


@dataclass
class FileTypeStats:
    """File extension statistics from commits."""
    extensions: Dict[str, int] = field(default_factory=dict)  # extension -> count
    primary_language: Optional[str] = None


@dataclass
class ContributorActivity:
    """Contributor commit activity for scheduling analysis."""
    login: str
    commits_last_30_days: int
    last_commit_date: Optional[datetime] = None


@dataclass
class CommitAnalysisResult:
    """Complete commit analysis result for AI scheduling decisions."""
    repository_name: str
    analyzed_at: datetime
    commit_count: int
    patterns: CommitPattern
    file_types: FileTypeStats
    top_contributors: List[ContributorActivity]
    is_dormant: bool  # No commits in 90+ days
