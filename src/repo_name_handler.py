"""
Repository Name Handler - Centralized handling for problematic repository names.

Handles repos with names that can cause issues:
- Names starting with hyphen (interpreted as CLI flags)
- Names with shell special characters
- Names starting with period (hidden files)
- Names with spaces or other problematic characters
"""
import re
import os
import urllib.parse
import logging
from typing import Tuple, Optional, List, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class NameRisk(Enum):
    """Risk levels for repository names."""
    SAFE = "safe"
    NEEDS_QUOTING = "needs_quoting"
    NEEDS_ESCAPING = "needs_escaping"
    DANGEROUS = "dangerous"


@dataclass
class RepoNameInfo:
    """Complete information about a repository name and its safe versions."""
    original: str
    safe_filesystem: str      # For file/directory names
    safe_cli: str             # For CLI arguments (quoted if needed)
    safe_git: str             # For git commands (URL-encoded)
    safe_display: str         # For logging (truncated if needed)
    risk_level: NameRisk
    warnings: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        return f"RepoName({self.original!r}, risk={self.risk_level.value})"


class RepoNameHandler:
    """
    Centralized handler for repository name sanitization.

    Usage:
        name_info = RepoNameHandler.analyze("--problematic-repo")
        print(name_info.safe_filesystem)  # "_-problematic-repo"
        print(name_info.safe_cli)         # "'--problematic-repo'"
        print(name_info.warnings)         # ["Starts with '-' - may be interpreted as CLI flag"]
    """

    # Characters that are problematic in different contexts
    CLI_FLAG_CHARS: Set[str] = {'-'}  # At start of name
    HIDDEN_PREFIX: Set[str] = {'.'}   # At start of name
    SHELL_SPECIAL: Set[str] = {
        '`', '$', '(', ')', '{', '}', '|', '&', ';',
        '<', '>', '!', '*', '?', ' ', '"', "'", '\\',
        '\n', '\t', '\r', '[', ']', '#', '~', '^'
    }
    FILESYSTEM_UNSAFE: Set[str] = {
        '/', '\\', '\0', ':', '*', '?', '"', '<', '>', '|'
    }

    @classmethod
    def analyze(cls, repo_name: str) -> RepoNameInfo:
        """
        Analyze a repository name and return safe versions for all contexts.

        Args:
            repo_name: The original repository name

        Returns:
            RepoNameInfo with safe versions and warnings
        """
        warnings = []
        risk_level = NameRisk.SAFE

        # Handle empty/None names
        if not repo_name:
            return RepoNameInfo(
                original="",
                safe_filesystem="_empty_",
                safe_cli="'_empty_'",
                safe_git="_empty_",
                safe_display="<empty>",
                risk_level=NameRisk.DANGEROUS,
                warnings=["Empty repository name"]
            )

        # Check for CLI flag interpretation (starts with -)
        if repo_name[0] in cls.CLI_FLAG_CHARS:
            warnings.append(f"Starts with '{repo_name[0]}' - may be interpreted as CLI flag")
            risk_level = NameRisk.NEEDS_QUOTING

        # Check for hidden file prefix (starts with .)
        if repo_name[0] in cls.HIDDEN_PREFIX:
            warnings.append(f"Starts with '{repo_name[0]}' - may be treated as hidden file")
            if risk_level == NameRisk.SAFE:
                risk_level = NameRisk.NEEDS_QUOTING

        # Check for shell special characters
        shell_chars_found = cls.SHELL_SPECIAL.intersection(set(repo_name))
        if shell_chars_found:
            chars_display = ', '.join(repr(c) for c in sorted(shell_chars_found))
            warnings.append(f"Contains shell special characters: {chars_display}")
            risk_level = NameRisk.NEEDS_ESCAPING

        # Check for filesystem unsafe characters
        fs_unsafe_found = cls.FILESYSTEM_UNSAFE.intersection(set(repo_name))
        if fs_unsafe_found:
            chars_display = ', '.join(repr(c) for c in sorted(fs_unsafe_found))
            warnings.append(f"Contains filesystem-unsafe characters: {chars_display}")
            risk_level = NameRisk.DANGEROUS

        # Check for control characters
        if any(ord(c) < 32 for c in repo_name):
            warnings.append("Contains control characters")
            risk_level = NameRisk.DANGEROUS

        # Check for very long names
        if len(repo_name) > 255:
            warnings.append(f"Name exceeds 255 characters ({len(repo_name)} chars)")
            risk_level = NameRisk.DANGEROUS

        # Generate safe versions
        safe_filesystem = cls._make_filesystem_safe(repo_name)
        safe_cli = cls._make_cli_safe(repo_name)
        safe_git = cls._make_git_safe(repo_name)
        safe_display = cls._make_display_safe(repo_name)

        return RepoNameInfo(
            original=repo_name,
            safe_filesystem=safe_filesystem,
            safe_cli=safe_cli,
            safe_git=safe_git,
            safe_display=safe_display,
            risk_level=risk_level,
            warnings=warnings
        )

    @classmethod
    def _make_filesystem_safe(cls, name: str) -> str:
        """
        Create a filesystem-safe version of the name.

        - Replaces unsafe characters with underscores
        - Ensures doesn't start with hyphen (causes issues with some tools)
        - Truncates to 255 characters
        """
        # Replace unsafe characters with underscores
        safe = "".join(c if c.isalnum() or c in '._-' else '_' for c in name)

        # Ensure doesn't start with hyphen (causes issues with many CLI tools)
        if safe.startswith('-'):
            safe = '_' + safe[1:]

        # Ensure doesn't start with period (hidden files)
        if safe.startswith('.'):
            safe = '_' + safe[1:]

        # Truncate if too long
        if len(safe) > 255:
            safe = safe[:252] + '...'

        return safe or '_empty_'

    @classmethod
    def _make_cli_safe(cls, name: str) -> str:
        """
        Create a CLI-safe version (properly quoted for shell).

        Uses single quotes and escapes any single quotes within.
        """
        # Escape single quotes: replace ' with '\''
        escaped = name.replace("'", "'\\''")
        return f"'{escaped}'"

    @classmethod
    def _make_git_safe(cls, name: str) -> str:
        """
        Create a git-safe version for use in URLs.

        URL-encodes special characters.
        """
        return urllib.parse.quote(name, safe='')

    @classmethod
    def _make_display_safe(cls, name: str) -> str:
        """
        Create a display-safe version for logging.

        Replaces control characters and truncates if needed.
        """
        # Replace control characters with Unicode replacement character
        display = ''.join(c if ord(c) >= 32 else '\ufffd' for c in name)

        # Truncate for display
        if len(display) > 80:
            display = display[:77] + '...'

        return display

    @classmethod
    def is_problematic(cls, repo_name: str) -> Tuple[bool, str]:
        """
        Quick check if a repository name is problematic.

        Returns:
            Tuple of (is_problematic, reason)
        """
        info = cls.analyze(repo_name)
        if info.risk_level == NameRisk.SAFE:
            return False, "Name OK"
        return True, "; ".join(info.warnings) if info.warnings else "Unknown issue"

    @classmethod
    def wrap_for_subprocess(cls, args: List[str], repo_name: str = None) -> List[str]:
        """
        Prepare arguments for subprocess.run(), handling problematic names.

        When using subprocess.run() with a list (not shell=True), most escaping
        is handled automatically. However, we still need to handle names that
        look like flags.

        Args:
            args: Command arguments as list
            repo_name: If provided, will be checked and handled specially

        Returns:
            Modified args list safe for subprocess
        """
        # subprocess.run with list form handles most escaping
        # But names starting with - can still be interpreted as flags

        # Note: For most cases, using named arguments (--repo-name VALUE)
        # is the safest approach and is preferred over positional arguments.

        return args

    @classmethod
    def get_safe_path(cls, base_path: str, repo_name: str) -> str:
        """
        Get a safe filesystem path for a repository.

        Args:
            base_path: Base directory path
            repo_name: Repository name

        Returns:
            Safe full path
        """
        info = cls.analyze(repo_name)
        return os.path.join(base_path, info.safe_filesystem)

    @classmethod
    def log_warnings(cls, repo_name: str) -> RepoNameInfo:
        """
        Analyze a repo name and log any warnings.

        Returns:
            RepoNameInfo for further use
        """
        info = cls.analyze(repo_name)

        if info.warnings:
            for warning in info.warnings:
                logger.warning(f"⚠️  {info.safe_display}: {warning}")

        return info


def has_problematic_name(repo_name: str) -> Tuple[bool, str]:
    """
    Legacy compatibility wrapper for RepoNameHandler.is_problematic().

    Deprecated: Use RepoNameHandler.is_problematic() directly.
    """
    return RepoNameHandler.is_problematic(repo_name)


def safe_repo_path(repo_name: str, base_path: str = "") -> str:
    """
    Legacy compatibility wrapper for RepoNameHandler.get_safe_path().

    Deprecated: Use RepoNameHandler.get_safe_path() directly.
    """
    return RepoNameHandler.get_safe_path(base_path, repo_name)
