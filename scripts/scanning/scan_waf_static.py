#!/usr/bin/env python3
"""
AWS WAF v2 Static Terraform Scanner
====================================

Parses .tf files for AWS WAF v2 resource definitions and runs 9 rule
intelligence checks against them.  No AWS credentials required -- all
analysis is performed against the HCL source.

Counterpart to ``scan_waf_auditor.py`` which audits LIVE configurations
via boto3.  This module operates entirely on Terraform source.

Platform integration:
    run_waf_static(repo_path, repo_name, report_dir, ...) -> Optional[CompletedProcess]

Standalone CLI:
    python scan_waf_static.py --repo-path ./infra --format all --output ./reports
"""

import argparse
import datetime
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database imports (optional -- only used inside platform integration)
# ---------------------------------------------------------------------------
try:
    from src.api.database import SessionLocal
    from src.api import models
    from sqlalchemy import func
    DATABASE_AVAILABLE = True
except ImportError:
    DATABASE_AVAILABLE = False


# =============================================================================
# WAF-Specific Severity Model
# =============================================================================

class WAFSeverity:
    """WAF-specific severity tiers.

    These capture the operational risk context better than generic
    critical/high/medium/low labels.  Each tier maps to a traditional
    severity for DB storage compatibility.
    """

    ACTIVE_RISK = "active_risk"          # Live misconfig, exploitable now (cross-ref only)
    CODE_RISK = "code_risk"              # Deployable misconfiguration in Terraform
    DRIFT_RISK = "drift_risk"            # Code and live diverge (cross-ref only)
    INFORMATIONAL = "informational"      # Best-practice suggestions

    # Map WAF severity -> traditional severity for DB storage
    TRADITIONAL_MAP: Dict[str, str] = {
        ACTIVE_RISK: "CRITICAL",
        CODE_RISK: "HIGH",
        DRIFT_RISK: "MEDIUM",
        INFORMATIONAL: "LOW",
    }

    # Ordering for sort (lower = more severe)
    ORDER: Dict[str, int] = {
        ACTIVE_RISK: 0,
        CODE_RISK: 1,
        DRIFT_RISK: 2,
        INFORMATIONAL: 3,
    }


# =============================================================================
# HCL Parser (Regex / State-Machine Approach)
# =============================================================================

# WAF v2 resource types we care about
WAF_RESOURCE_TYPES = (
    "aws_wafv2_web_acl",
    "aws_wafv2_rule_group",
    "aws_wafv2_ip_set",
    "aws_wafv2_regex_pattern_set",
)

# Additional resources referenced by WAF configs
WAF_ASSOCIATION_TYPES = (
    "aws_wafv2_web_acl_logging_configuration",
)


@dataclass
class HCLBlock:
    """A parsed HCL block with its raw content and metadata."""
    block_type: str          # "resource", "data", etc.
    resource_type: str       # "aws_wafv2_web_acl", etc.
    resource_name: str       # The Terraform logical name
    content: str             # Raw HCL content inside the block
    file_path: str
    line_start: int
    line_end: int


@dataclass
class ParsedRule:
    """A WAF rule extracted from a WebACL or rule group."""
    name: str
    priority: Optional[int]
    action: Optional[str]                # "block", "count", "allow", or None
    override_action: Optional[str]       # "count", "none", or None
    statement_types: List[str]           # e.g. ["ip_set_reference_statement", "rate_based_statement"]
    statement_content: str               # Raw HCL of the statement block
    visibility_config: Dict[str, Any]
    ip_set_references: List[str]         # ARN references or Terraform refs
    rate_limit: Optional[int]            # Extracted limit from rate_based_statement
    managed_rule_group: Optional[Dict[str, str]]  # {"vendor_name": ..., "name": ...}
    geo_match_countries: List[str]
    raw_content: str
    line_offset: int                     # Line within the parent resource block


@dataclass
class ParsedWebACL:
    """Fully parsed WAF v2 WebACL resource."""
    resource_name: str
    file_path: str
    line_start: int
    line_end: int
    default_action: str                  # "allow" or "block"
    rules: List[ParsedRule]
    visibility_config: Dict[str, Any]
    has_logging_configuration: bool
    raw_content: str


@dataclass
class ParsedIPSet:
    """Fully parsed WAF v2 IP set resource."""
    resource_name: str
    file_path: str
    line_start: int
    line_end: int
    addresses: List[str]
    ip_address_version: str              # "IPV4" or "IPV6"
    raw_content: str


class HCLParser:
    """Regex/state-machine parser for WAF v2 resources in .tf files.

    This is intentionally NOT a full HCL parser.  It handles the subset
    of HCL syntax encountered in WAF v2 resource definitions:
    - Brace-delimited blocks with nesting
    - Simple attribute assignments (key = value)
    - String literals (double-quoted), numbers, booleans
    - Heredoc strings (<<EOF ... EOF)
    - Line comments (# and //) and block comments (/* ... */)
    """

    # Regex: resource "type" "name" { ... }
    _RESOURCE_PATTERN = re.compile(
        r'^(\s*)resource\s+"([^"]+)"\s+"([^"]+)"\s*\{',
        re.MULTILINE,
    )

    def __init__(self):
        self.web_acls: List[ParsedWebACL] = []
        self.ip_sets: List[ParsedIPSet] = []
        self.rule_groups: List[ParsedWebACL] = []  # Reuse WebACL structure
        self.regex_pattern_sets: List[HCLBlock] = []
        self.logging_configurations: List[HCLBlock] = []
        self._all_blocks: List[HCLBlock] = []

    # ------------------------------------------------------------------
    # Block extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _find_block_end(text: str, start: int) -> int:
        """Find the closing brace of a block starting at the opening brace.

        Handles nested braces, strings, heredocs, and comments.
        Returns the index of the closing brace (inclusive).
        """
        depth = 0
        i = start
        length = len(text)
        while i < length:
            ch = text[i]

            # Skip line comments
            if ch == '#' or (ch == '/' and i + 1 < length and text[i + 1] == '/'):
                while i < length and text[i] != '\n':
                    i += 1
                continue

            # Skip block comments
            if ch == '/' and i + 1 < length and text[i + 1] == '*':
                i += 2
                while i < length - 1:
                    if text[i] == '*' and text[i + 1] == '/':
                        i += 2
                        break
                    i += 1
                continue

            # Skip double-quoted strings (handle escaped quotes)
            if ch == '"':
                i += 1
                while i < length:
                    if text[i] == '\\':
                        i += 2
                        continue
                    if text[i] == '"':
                        i += 1
                        break
                    i += 1
                continue

            # Skip heredoc strings
            if ch == '<' and i + 1 < length and text[i + 1] == '<':
                # Find the delimiter
                heredoc_match = re.match(r'<<-?\s*(\w+)', text[i:])
                if heredoc_match:
                    delimiter = heredoc_match.group(1)
                    end_pattern = re.compile(r'^\s*' + re.escape(delimiter) + r'\s*$', re.MULTILINE)
                    search_start = i + heredoc_match.end()
                    end_match = end_pattern.search(text, search_start)
                    if end_match:
                        i = end_match.end()
                        continue

            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return i

            i += 1

        return len(text) - 1  # Fallback: unterminated block

    def _extract_resource_blocks(self, file_path: str, content: str) -> List[HCLBlock]:
        """Extract all WAF v2 resource blocks from a .tf file."""
        blocks: List[HCLBlock] = []

        for match in self._RESOURCE_PATTERN.finditer(content):
            resource_type = match.group(2)
            resource_name = match.group(3)

            # Filter to WAF resource types + logging config
            all_types = WAF_RESOURCE_TYPES + WAF_ASSOCIATION_TYPES
            if resource_type not in all_types:
                continue

            # Find the opening brace position
            brace_pos = match.end() - 1  # The { in the regex
            block_end = self._find_block_end(content, brace_pos)

            block_content = content[brace_pos + 1:block_end]

            # Calculate line numbers
            line_start = content[:match.start()].count('\n') + 1
            line_end = content[:block_end + 1].count('\n') + 1

            blocks.append(HCLBlock(
                block_type="resource",
                resource_type=resource_type,
                resource_name=resource_name,
                content=block_content,
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
            ))

        return blocks

    # ------------------------------------------------------------------
    # Attribute extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_attribute(content: str, attr_name: str) -> Optional[str]:
        """Extract a simple attribute value: attr_name = "value" or attr_name = value."""
        pattern = re.compile(
            r'(?:^|\n)\s*' + re.escape(attr_name) + r'\s*=\s*(.+)',
        )
        m = pattern.search(content)
        if not m:
            return None
        val = m.group(1).strip()
        # Strip quotes
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        # Strip trailing comments
        for comment_char in ('#', '//'):
            idx = val.find(comment_char)
            if idx > 0:
                val = val[:idx].strip()
        return val

    @staticmethod
    def _extract_bool(content: str, attr_name: str) -> Optional[bool]:
        """Extract a boolean attribute value."""
        val = HCLParser._extract_attribute(content, attr_name)
        if val is None:
            return None
        val_lower = val.lower().strip()
        if val_lower == "true":
            return True
        if val_lower == "false":
            return False
        return None

    @staticmethod
    def _extract_int(content: str, attr_name: str) -> Optional[int]:
        """Extract an integer attribute value."""
        val = HCLParser._extract_attribute(content, attr_name)
        if val is None:
            return None
        try:
            return int(val)
        except ValueError:
            return None

    @staticmethod
    def _extract_list(content: str, attr_name: str) -> List[str]:
        """Extract a list attribute: attr_name = ["a", "b", "c"]."""
        pattern = re.compile(
            r'(?:^|\n)\s*' + re.escape(attr_name) + r'\s*=\s*\[([^\]]*)\]',
            re.DOTALL,
        )
        m = pattern.search(content)
        if not m:
            return []
        raw = m.group(1)
        items = re.findall(r'"([^"]*)"', raw)
        return items

    @staticmethod
    def _extract_named_blocks(content: str, block_name: str) -> List[Tuple[str, int]]:
        """Extract all occurrences of a named block: block_name { ... }.

        Returns list of (block_content, char_offset) tuples.
        """
        results: List[Tuple[str, int]] = []
        pattern = re.compile(
            r'(?:^|\n)\s*' + re.escape(block_name) + r'\s*\{',
            re.MULTILINE,
        )
        for m in pattern.finditer(content):
            brace_pos = m.end() - 1
            block_end = HCLParser._find_block_end(content, brace_pos)
            inner = content[brace_pos + 1:block_end]
            results.append((inner, m.start()))
        return results

    # ------------------------------------------------------------------
    # Parse specific resource types
    # ------------------------------------------------------------------

    def _parse_visibility_config(self, content: str) -> Dict[str, Any]:
        """Parse a visibility_config block."""
        vis_blocks = self._extract_named_blocks(content, "visibility_config")
        if not vis_blocks:
            return {}
        vis_content = vis_blocks[0][0]
        return {
            "cloudwatch_metrics_enabled": self._extract_bool(vis_content, "cloudwatch_metrics_enabled"),
            "metric_name": self._extract_attribute(vis_content, "metric_name"),
            "sampled_requests_enabled": self._extract_bool(vis_content, "sampled_requests_enabled"),
        }

    def _parse_action(self, content: str) -> Optional[str]:
        """Determine the action from an action block: block, count, or allow."""
        action_blocks = self._extract_named_blocks(content, "action")
        if not action_blocks:
            return None
        action_content = action_blocks[0][0]
        for action_type in ("block", "count", "allow"):
            # Look for: block {} or block { ... }
            if re.search(r'\b' + action_type + r'\s*\{', action_content):
                return action_type
        return None

    def _parse_override_action(self, content: str) -> Optional[str]:
        """Parse override_action block for managed rule groups."""
        oa_blocks = self._extract_named_blocks(content, "override_action")
        if not oa_blocks:
            return None
        oa_content = oa_blocks[0][0]
        if re.search(r'\bcount\s*\{', oa_content):
            return "count"
        if re.search(r'\bnone\s*\{', oa_content):
            return "none"
        return None

    def _parse_statement(self, content: str) -> Tuple[
        List[str], List[str], Optional[int],
        Optional[Dict[str, str]], List[str]
    ]:
        """Parse a statement block to extract types, IP refs, rate limit, managed groups, geo.

        Returns:
            (statement_types, ip_set_references, rate_limit, managed_group, geo_countries)
        """
        statement_types: List[str] = []
        ip_set_references: List[str] = []
        rate_limit: Optional[int] = None
        managed_group: Optional[Dict[str, str]] = None
        geo_countries: List[str] = []

        self._walk_statement(
            content, statement_types, ip_set_references,
            rate_limit_ref=[rate_limit],
            managed_group_ref=[managed_group],
            geo_countries_ref=geo_countries,
        )

        # Extract the mutable values
        rate_limit = rate_limit if rate_limit is not None else None
        return (
            statement_types,
            ip_set_references,
            rate_limit_ref[0] if 'rate_limit_ref' in dir() else rate_limit,
            managed_group_ref[0] if 'managed_group_ref' in dir() else managed_group,
            geo_countries,
        )

    def _walk_statement(
        self,
        content: str,
        statement_types: List[str],
        ip_set_references: List[str],
        rate_limit_ref: List[Optional[int]],
        managed_group_ref: List[Optional[Dict[str, str]]],
        geo_countries_ref: List[str],
    ) -> None:
        """Recursively walk statement blocks to extract nested types."""

        # IP set reference
        ip_blocks = self._extract_named_blocks(content, "ip_set_reference_statement")
        if ip_blocks:
            statement_types.append("ip_set_reference_statement")
            for block_content, _ in ip_blocks:
                arn = self._extract_attribute(block_content, "arn")
                if arn:
                    ip_set_references.append(arn)

        # Rate-based
        rate_blocks = self._extract_named_blocks(content, "rate_based_statement")
        if rate_blocks:
            statement_types.append("rate_based_statement")
            for block_content, _ in rate_blocks:
                limit = self._extract_int(block_content, "limit")
                if limit is not None:
                    rate_limit_ref[0] = limit
                # Recurse into scope_down_statement
                scope_down = self._extract_named_blocks(block_content, "scope_down_statement")
                for sd_content, _ in scope_down:
                    self._walk_statement(
                        sd_content, statement_types, ip_set_references,
                        rate_limit_ref, managed_group_ref, geo_countries_ref,
                    )

        # Geo match
        geo_blocks = self._extract_named_blocks(content, "geo_match_statement")
        if geo_blocks:
            statement_types.append("geo_match_statement")
            for block_content, _ in geo_blocks:
                countries = self._extract_list(block_content, "country_codes")
                geo_countries_ref.extend(countries)

        # Managed rule group
        mrg_blocks = self._extract_named_blocks(content, "managed_rule_group_statement")
        if mrg_blocks:
            statement_types.append("managed_rule_group_statement")
            for block_content, _ in mrg_blocks:
                vendor = self._extract_attribute(block_content, "vendor_name") or ""
                name = self._extract_attribute(block_content, "name") or ""
                managed_group_ref[0] = {"vendor_name": vendor, "name": name}

        # Byte match, regex, size constraint, sqli, xss match
        for stmt_type in (
            "byte_match_statement", "regex_pattern_set_reference_statement",
            "size_constraint_statement", "sqli_match_statement",
            "xss_match_statement", "label_match_statement",
            "regex_match_statement",
        ):
            if self._extract_named_blocks(content, stmt_type):
                statement_types.append(stmt_type)

        # Logical wrappers: and_statement, or_statement, not_statement
        for wrapper in ("and_statement", "or_statement", "not_statement"):
            wrapper_blocks = self._extract_named_blocks(content, wrapper)
            for block_content, _ in wrapper_blocks:
                statement_types.append(wrapper)
                # Recurse into nested statement blocks
                nested_stmts = self._extract_named_blocks(block_content, "statement")
                for nested_content, _ in nested_stmts:
                    self._walk_statement(
                        nested_content, statement_types, ip_set_references,
                        rate_limit_ref, managed_group_ref, geo_countries_ref,
                    )

    def _parse_rule_block(self, content: str, char_offset: int) -> ParsedRule:
        """Parse a single rule { } block into a ParsedRule."""
        name = self._extract_attribute(content, "name") or ""
        priority = self._extract_int(content, "priority")
        action = self._parse_action(content)
        override_action = self._parse_override_action(content)

        # Parse statement
        stmt_blocks = self._extract_named_blocks(content, "statement")
        statement_types: List[str] = []
        ip_set_references: List[str] = []
        rate_limit: Optional[int] = None
        managed_group: Optional[Dict[str, str]] = None
        geo_countries: List[str] = []

        stmt_content_str = ""
        for stmt_content, _ in stmt_blocks:
            stmt_content_str = stmt_content
            rl_ref: List[Optional[int]] = [None]
            mg_ref: List[Optional[Dict[str, str]]] = [None]
            self._walk_statement(
                stmt_content, statement_types, ip_set_references,
                rl_ref, mg_ref, geo_countries,
            )
            if rl_ref[0] is not None:
                rate_limit = rl_ref[0]
            if mg_ref[0] is not None:
                managed_group = mg_ref[0]

        vis_config = self._parse_visibility_config(content)

        return ParsedRule(
            name=name,
            priority=priority,
            action=action,
            override_action=override_action,
            statement_types=statement_types,
            statement_content=stmt_content_str,
            visibility_config=vis_config,
            ip_set_references=ip_set_references,
            rate_limit=rate_limit,
            managed_rule_group=managed_group,
            geo_match_countries=geo_countries,
            raw_content=content,
            line_offset=char_offset,
        )

    def _parse_web_acl(self, block: HCLBlock) -> ParsedWebACL:
        """Parse a WebACL resource block."""
        content = block.content

        # Default action
        default_action = "allow"  # AWS default
        da_blocks = self._extract_named_blocks(content, "default_action")
        if da_blocks:
            da_content = da_blocks[0][0]
            if re.search(r'\bblock\s*\{', da_content):
                default_action = "block"
            elif re.search(r'\ballow\s*\{', da_content):
                default_action = "allow"

        # Rules
        rule_blocks = self._extract_named_blocks(content, "rule")
        rules: List[ParsedRule] = []
        for rule_content, offset in rule_blocks:
            rules.append(self._parse_rule_block(rule_content, offset))

        # Visibility config at WebACL level
        vis_config = self._parse_visibility_config(content)

        # Check for inline logging_configuration
        has_logging = bool(self._extract_named_blocks(content, "logging_configuration"))

        return ParsedWebACL(
            resource_name=block.resource_name,
            file_path=block.file_path,
            line_start=block.line_start,
            line_end=block.line_end,
            default_action=default_action,
            rules=rules,
            visibility_config=vis_config,
            has_logging_configuration=has_logging,
            raw_content=block.content,
        )

    def _parse_ip_set(self, block: HCLBlock) -> ParsedIPSet:
        """Parse an IP set resource block."""
        content = block.content
        addresses = self._extract_list(content, "addresses")
        ip_version = self._extract_attribute(content, "ip_address_version") or "IPV4"

        return ParsedIPSet(
            resource_name=block.resource_name,
            file_path=block.file_path,
            line_start=block.line_start,
            line_end=block.line_end,
            addresses=addresses,
            ip_address_version=ip_version,
            raw_content=block.content,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def parse_file(self, file_path: str) -> None:
        """Parse a single .tf file and accumulate WAF resources."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError as exc:
            logger.warning("Could not read %s: %s", file_path, exc)
            return

        blocks = self._extract_resource_blocks(file_path, content)
        self._all_blocks.extend(blocks)

        for block in blocks:
            if block.resource_type == "aws_wafv2_web_acl":
                self.web_acls.append(self._parse_web_acl(block))
            elif block.resource_type == "aws_wafv2_rule_group":
                # Rule groups have the same structure as WebACLs for our purposes
                self.rule_groups.append(self._parse_web_acl(block))
            elif block.resource_type == "aws_wafv2_ip_set":
                self.ip_sets.append(self._parse_ip_set(block))
            elif block.resource_type == "aws_wafv2_regex_pattern_set":
                self.regex_pattern_sets.append(block)
            elif block.resource_type == "aws_wafv2_web_acl_logging_configuration":
                self.logging_configurations.append(block)

    def parse_directory(self, dir_path: str) -> None:
        """Recursively parse all .tf files under a directory."""
        for root, dirs, files in os.walk(dir_path):
            # Skip hidden directories and .terraform
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for fname in sorted(files):
                if fname.endswith(".tf"):
                    self.parse_file(os.path.join(root, fname))


# =============================================================================
# Data Model
# =============================================================================

@dataclass
class WAFStaticFinding:
    """Single finding emitted by the static WAF scanner."""

    scanner_name: str = "waf-static"
    finding_type: str = "waf"
    severity: str = ""                        # WAF-specific severity
    traditional_severity: str = ""            # For DB storage compatibility
    title: str = ""
    description: str = ""
    file_path: str = ""
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: str = ""
    rule_type: str = ""                       # permanent_block, rate_limit, etc.
    web_acl_name: str = ""
    rule_name: str = ""
    recommendation: str = ""
    remediation_terraform: str = ""
    source: str = "static"                    # "static" | "live" | "drift"
    risk_factors: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    def to_platform_dict(self) -> Dict[str, Any]:
        """Return a dict compatible with _persist_scan_findings."""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.traditional_severity,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet[:1000] if self.code_snippet else None,
            "cwe_id": None,
            "risk_factors": self.risk_factors,
        }


# =============================================================================
# Remediation Terraform Templates
# =============================================================================

class RemediationTemplates:
    """Generate Terraform remediation code snippets for each finding type."""

    @staticmethod
    def rate_based_rule(acl_name: str, limit: int = 2000) -> str:
        return f'''\
  rule {{
    name     = "{acl_name}-rate-limit"
    priority = 1

    action {{
      block {{
        custom_response {{
          response_code = 429
        }}
      }}
    }}

    statement {{
      rate_based_statement {{
        limit              = {limit}
        aggregate_key_type = "IP"
      }}
    }}

    visibility_config {{
      cloudwatch_metrics_enabled = true
      metric_name                = "{acl_name}-rate-limit"
      sampled_requests_enabled   = true
    }}
  }}'''

    @staticmethod
    def graduated_response(rule_name: str, ip_set_ref: str) -> str:
        return f'''\
  # --- Graduated Response Pattern ---
  # Tier 1: Rate-limit before blocking
  rule {{
    name     = "{rule_name}-rate-limit"
    priority = 10

    action {{
      block {{
        custom_response {{
          response_code = 429
        }}
      }}
    }}

    statement {{
      rate_based_statement {{
        limit              = 1000
        aggregate_key_type = "IP"

        scope_down_statement {{
          ip_set_reference_statement {{
            arn = {ip_set_ref}
          }}
        }}
      }}
    }}

    visibility_config {{
      cloudwatch_metrics_enabled = true
      metric_name                = "{rule_name}-rate-limit"
      sampled_requests_enabled   = true
    }}
  }}

  # Tier 2: Temporary block for repeat offenders
  # Implement via Lambda automation that adds IPs to a temp-block
  # IP set with TTL-based expiry (e.g., 24h).

  # Tier 3: Permanent block only after repeated violations
  # (3+ temporary blocks within 24h), managed by IP set lifecycle automation.'''

    @staticmethod
    def managed_rule_group(group_name: str, vendor: str = "AWS", priority: int = 20) -> str:
        metric_name = group_name.replace("AWSManagedRules", "").replace("RuleSet", "")
        return f'''\
  rule {{
    name     = "{group_name}"
    priority = {priority}

    override_action {{
      none {{}}
    }}

    statement {{
      managed_rule_group_statement {{
        vendor_name = "{vendor}"
        name        = "{group_name}"
      }}
    }}

    visibility_config {{
      cloudwatch_metrics_enabled = true
      metric_name                = "AWS-{metric_name}"
      sampled_requests_enabled   = true
    }}
  }}'''

    @staticmethod
    def bot_control_rule(priority: int = 50) -> str:
        return f'''\
  rule {{
    name     = "AWSBotControl"
    priority = {priority}

    override_action {{
      count {{}}  # Start in COUNT mode; switch to none {{}} after validation
    }}

    statement {{
      managed_rule_group_statement {{
        vendor_name = "AWS"
        name        = "AWSManagedRulesBotControlRuleSet"

        managed_rule_group_configs {{
          aws_managed_rules_bot_control_rule_set {{
            inspection_level = "COMMON"
          }}
        }}
      }}
    }}

    visibility_config {{
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSBotControl"
      sampled_requests_enabled   = true
    }}
  }}'''

    @staticmethod
    def logging_configuration(acl_ref: str) -> str:
        return f'''\
resource "aws_wafv2_web_acl_logging_configuration" "main" {{
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  resource_arn            = {acl_ref}

  logging_filter {{
    default_behavior = "KEEP"

    filter {{
      behavior    = "KEEP"
      requirement = "MEETS_ANY"

      condition {{
        action_condition {{
          action = "BLOCK"
        }}
      }}

      condition {{
        action_condition {{
          action = "COUNT"
        }}
      }}
    }}
  }}
}}

resource "aws_cloudwatch_log_group" "waf" {{
  name              = "aws-waf-logs-${{var.environment}}"
  retention_in_days = 90

  tags = {{
    Purpose = "WAF Logging"
  }}
}}'''

    @staticmethod
    def narrow_ip_set_suggestion(resource_name: str, broad_cidrs: List[str]) -> str:
        lines = [
            f'# Refactor: Split broad CIDR ranges in "{resource_name}" into targeted /24 blocks.',
            f'# Current broad ranges: {", ".join(broad_cidrs[:5])}',
            '#',
            '# Example: Replace a /16 with specific /24 ranges that contain',
            '# the actual malicious sources identified in WAF logs.',
            '#',
            f'resource "aws_wafv2_ip_set" "{resource_name}_targeted" {{',
            f'  name               = "{resource_name}-targeted"',
            '  scope              = "REGIONAL"',
            '  ip_address_version = "IPV4"',
            '',
            '  addresses = [',
            '    # Replace with specific /24 or /32 ranges from WAF log analysis:',
            '    # "192.0.2.0/24",',
            '    # "198.51.100.128/25",',
            '  ]',
            '}',
        ]
        return '\n'.join(lines)


# =============================================================================
# Static WAF Analyzer
# =============================================================================

class WAFStaticAnalyzer:
    """Runs 9 rule intelligence checks against parsed WAF v2 Terraform resources."""

    ESSENTIAL_MANAGED_GROUPS = [
        "AWSManagedRulesCommonRuleSet",
        "AWSManagedRulesKnownBadInputsRuleSet",
        "AWSManagedRulesSQLiRuleSet",
    ]

    def __init__(self, parser: HCLParser):
        self.parser = parser
        self.findings: List[WAFStaticFinding] = []
        self.scan_timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_finding(
        self,
        severity: str,
        rule_type: str,
        title: str,
        description: str,
        acl: ParsedWebACL,
        rule_name: str = "",
        recommendation: str = "",
        remediation_terraform: str = "",
        code_snippet: str = "",
        risk_factors: Optional[Dict[str, Any]] = None,
    ) -> WAFStaticFinding:
        traditional = WAFSeverity.TRADITIONAL_MAP.get(severity, "MEDIUM")
        finding = WAFStaticFinding(
            severity=severity,
            traditional_severity=traditional,
            title=title,
            description=description,
            file_path=acl.file_path,
            line_start=acl.line_start,
            line_end=acl.line_end,
            code_snippet=code_snippet[:2000] if code_snippet else "",
            rule_type=rule_type,
            web_acl_name=acl.resource_name,
            rule_name=rule_name,
            recommendation=recommendation,
            remediation_terraform=remediation_terraform,
            risk_factors=risk_factors or {},
        )
        self.findings.append(finding)
        return finding

    @staticmethod
    def _snippet_from_rule(rule: ParsedRule, max_lines: int = 15) -> str:
        """Extract a compact code snippet from a rule's raw content."""
        lines = rule.raw_content.strip().split('\n')
        if len(lines) <= max_lines:
            return rule.raw_content.strip()
        return '\n'.join(lines[:max_lines]) + '\n    # ... (truncated)'

    def _resolve_ip_set_by_ref(self, ref: str) -> Optional[ParsedIPSet]:
        """Resolve a Terraform reference to a parsed IP set.

        Handles references like:
        - aws_wafv2_ip_set.blocklist.arn
        - "${aws_wafv2_ip_set.blocklist.arn}"
        - module.waf.ip_set_arn (not resolvable, returns None)
        """
        # Strip interpolation syntax
        clean = ref.strip().replace("${", "").replace("}", "")

        # Match aws_wafv2_ip_set.<name>.arn
        m = re.match(r'aws_wafv2_ip_set\.(\w+)\.arn', clean)
        if m:
            target_name = m.group(1)
            for ip_set in self.parser.ip_sets:
                if ip_set.resource_name == target_name:
                    return ip_set

        return None

    # ------------------------------------------------------------------
    # Check 1: Permanent Blocks
    # ------------------------------------------------------------------

    def _check_permanent_blocks(self, acl: ParsedWebACL) -> None:
        """Find block rules with ip_set_reference but no companion rate_based rule."""
        # Collect rules that have rate-based statements
        rate_based_ip_refs: Set[str] = set()
        for rule in acl.rules:
            if "rate_based_statement" in rule.statement_types:
                rate_based_ip_refs.update(rule.ip_set_references)

        for rule in acl.rules:
            if rule.action != "block":
                continue
            if "ip_set_reference_statement" not in rule.statement_types:
                continue
            if "rate_based_statement" in rule.statement_types:
                continue

            # Check for companion rate-based rule for the same IP set
            orphan_refs = [
                ref for ref in rule.ip_set_references
                if ref not in rate_based_ip_refs
            ]
            if not orphan_refs:
                continue

            ip_ref_display = orphan_refs[0] if orphan_refs else "unknown"
            remediation = RemediationTemplates.graduated_response(
                rule.name or acl.resource_name,
                ip_ref_display,
            )

            self._make_finding(
                severity=WAFSeverity.CODE_RISK,
                rule_type="permanent_block",
                title=f"Permanent IP block without rate-based companion: {rule.name}",
                description=(
                    f"Rule '{rule.name}' in WebACL '{acl.resource_name}' blocks traffic "
                    f"matching an IP set reference without any accompanying rate-based rule "
                    f"for the same IP set. This can lead to over-blocking legitimate users "
                    f"whose IPs are shared (NAT, CDN, corporate egress) or recycled by ISPs."
                ),
                acl=acl,
                rule_name=rule.name,
                recommendation=(
                    "Implement a graduated response: rate-limit first, then temporary "
                    "block, and only permanently block after repeated violations. "
                    "Add a rate_based_statement with a scope_down_statement referencing "
                    "the same IP set."
                ),
                remediation_terraform=remediation,
                code_snippet=self._snippet_from_rule(rule),
                risk_factors={
                    "ip_set_references": orphan_refs,
                    "pattern": "permanent_block_without_rate_limit",
                },
            )

    # ------------------------------------------------------------------
    # Check 2: Rate-Based Rules
    # ------------------------------------------------------------------

    def _check_rate_based_rules(self, acl: ParsedWebACL) -> None:
        """Validate rate-based rule thresholds and flag missing rate limiting."""
        has_any_rate_rule = False

        for rule in acl.rules:
            if "rate_based_statement" not in rule.statement_types:
                continue

            has_any_rate_rule = True
            limit = rule.rate_limit

            if limit is not None and limit < 100:
                self._make_finding(
                    severity=WAFSeverity.CODE_RISK,
                    rule_type="rate_limit",
                    title=f"Rate limit threshold very low ({limit}): {rule.name}",
                    description=(
                        f"Rule '{rule.name}' in WebACL '{acl.resource_name}' has a rate "
                        f"limit of {limit} requests per 5-minute window. Thresholds below "
                        f"100 are likely to cause false positives and block legitimate "
                        f"traffic, especially behind shared NAT gateways or corporate proxies."
                    ),
                    acl=acl,
                    rule_name=rule.name,
                    recommendation=(
                        "Increase the threshold to at least 100. Deploy in COUNT mode "
                        "first to establish a traffic baseline using CloudWatch metrics "
                        "before setting the final threshold."
                    ),
                    code_snippet=self._snippet_from_rule(rule),
                    risk_factors={
                        "current_limit": limit,
                        "threshold_category": "too_low",
                        "false_positive_risk": "high",
                    },
                )

            if limit is not None and limit > 10000:
                self._make_finding(
                    severity=WAFSeverity.CODE_RISK,
                    rule_type="rate_limit",
                    title=f"Rate limit threshold too high ({limit}): {rule.name}",
                    description=(
                        f"Rule '{rule.name}' in WebACL '{acl.resource_name}' has a rate "
                        f"limit of {limit} requests per 5-minute window. Thresholds above "
                        f"10,000 provide minimal protection against application-layer DDoS "
                        f"and credential stuffing attacks."
                    ),
                    acl=acl,
                    rule_name=rule.name,
                    recommendation=(
                        "Lower the threshold to reflect your application's expected "
                        "legitimate traffic patterns. Typical API rate limits range from "
                        "500 to 5,000 requests per 5 minutes."
                    ),
                    code_snippet=self._snippet_from_rule(rule),
                    risk_factors={
                        "current_limit": limit,
                        "threshold_category": "too_high",
                        "protection_effectiveness": "minimal",
                    },
                )

        if not has_any_rate_rule:
            remediation = RemediationTemplates.rate_based_rule(acl.resource_name)
            self._make_finding(
                severity=WAFSeverity.CODE_RISK,
                rule_type="rate_limit",
                title=f"No rate-based rules configured: {acl.resource_name}",
                description=(
                    f"WebACL '{acl.resource_name}' has no rate-based rules defined in "
                    f"Terraform. Without rate limiting, the application is fully exposed "
                    f"to brute-force attacks, credential stuffing, and application-layer "
                    f"DDoS once this configuration is deployed."
                ),
                acl=acl,
                recommendation=(
                    "Add at least one rate_based_statement rule to protect against "
                    "volumetric attacks. Start with a threshold of 2000 requests per "
                    "5-minute window and tune based on production traffic analysis."
                ),
                remediation_terraform=remediation,
                risk_factors={
                    "pattern": "no_rate_limiting",
                    "exposure": "brute_force,credential_stuffing,ddos",
                },
            )

    # ------------------------------------------------------------------
    # Check 3: Mode Analysis (COUNT vs BLOCK)
    # ------------------------------------------------------------------

    def _check_mode_analysis(self, acl: ParsedWebACL) -> None:
        """Find rules in COUNT mode that should be BLOCK."""
        for rule in acl.rules:
            # Managed rule group overridden to count
            if rule.override_action == "count":
                group_name = ""
                if rule.managed_rule_group:
                    group_name = rule.managed_rule_group.get("name", "")

                self._make_finding(
                    severity=WAFSeverity.CODE_RISK,
                    rule_type="mode",
                    title=f"Managed rule group in COUNT mode: {rule.name}",
                    description=(
                        f"Rule '{rule.name}' in WebACL '{acl.resource_name}' overrides "
                        f"the managed rule group '{group_name}' actions to COUNT. Threats "
                        f"matched by this rule group will be logged but not blocked when "
                        f"deployed. If this has been in COUNT mode through a validation "
                        f"cycle, it may be time to promote to BLOCK."
                    ),
                    acl=acl,
                    rule_name=rule.name,
                    recommendation=(
                        "Review CloudWatch metrics for this managed rule group after "
                        "deployment. If false-positive rates are acceptable, change "
                        "override_action from count {} to none {} to allow the managed "
                        "group's native blocking actions."
                    ),
                    code_snippet=self._snippet_from_rule(rule),
                    risk_factors={
                        "managed_group": group_name,
                        "current_mode": "count",
                        "expected_mode": "block",
                    },
                )

            # Custom rule with count action
            if rule.action == "count":
                self._make_finding(
                    severity=WAFSeverity.CODE_RISK,
                    rule_type="mode",
                    title=f"Custom rule in COUNT mode: {rule.name}",
                    description=(
                        f"Rule '{rule.name}' in WebACL '{acl.resource_name}' uses a count "
                        f"action. While COUNT mode is appropriate during initial validation, "
                        f"security rules left in COUNT mode after deployment provide no "
                        f"active protection."
                    ),
                    acl=acl,
                    rule_name=rule.name,
                    recommendation=(
                        "Confirm this is intentional for a validation period. Add a "
                        "comment with the planned promotion date. If the rule has been "
                        "validated, switch the action from count {} to block {}."
                    ),
                    code_snippet=self._snippet_from_rule(rule),
                    risk_factors={
                        "current_mode": "count",
                        "pattern": "custom_rule_not_blocking",
                    },
                )

    # ------------------------------------------------------------------
    # Check 4: Geo Restrictions
    # ------------------------------------------------------------------

    def _check_geo_restrictions(self, acl: ParsedWebACL) -> None:
        """Check for presence of geo_match_statement rules."""
        has_geo = any(
            "geo_match_statement" in rule.statement_types
            for rule in acl.rules
        )

        if not has_geo:
            self._make_finding(
                severity=WAFSeverity.INFORMATIONAL,
                rule_type="geo",
                title=f"No geographic restriction rules: {acl.resource_name}",
                description=(
                    f"WebACL '{acl.resource_name}' defines no geo_match_statement rules. "
                    f"If the application serves a known set of countries, geographic "
                    f"restrictions reduce attack surface from regions with no legitimate "
                    f"business reason to access the service."
                ),
                acl=acl,
                recommendation=(
                    "Add a geo_match_statement rule to block or rate-limit traffic "
                    "from countries outside your expected user base. Even if full "
                    "geo-blocking is not feasible, consider rate-limiting traffic from "
                    "high-risk regions."
                ),
                risk_factors={
                    "pattern": "no_geo_restriction",
                    "impact": "expanded_attack_surface",
                },
            )

    # ------------------------------------------------------------------
    # Check 5: IP Sets
    # ------------------------------------------------------------------

    def _check_ip_sets(self, acl: ParsedWebACL) -> None:
        """Inspect referenced IP sets for broad CIDRs and empty address lists."""
        for rule in acl.rules:
            if "ip_set_reference_statement" not in rule.statement_types:
                continue

            for ref in rule.ip_set_references:
                ip_set = self._resolve_ip_set_by_ref(ref)
                if ip_set is None:
                    # Cannot resolve -- may be a module output or data source
                    continue

                if not ip_set.addresses:
                    self._make_finding(
                        severity=WAFSeverity.INFORMATIONAL,
                        rule_type="ip_set",
                        title=f"Empty IP set referenced: {ip_set.resource_name}",
                        description=(
                            f"IP set '{ip_set.resource_name}' (referenced by rule "
                            f"'{rule.name}' in WebACL '{acl.resource_name}') has an "
                            f"empty addresses list. The rule will have no effect when "
                            f"deployed."
                        ),
                        acl=acl,
                        rule_name=rule.name,
                        recommendation=(
                            "Populate the IP set's addresses list or remove the rule "
                            "referencing it to reduce configuration clutter. If the IP "
                            "set is dynamically managed, add a comment documenting the "
                            "automation source."
                        ),
                        risk_factors={
                            "ip_set_name": ip_set.resource_name,
                            "pattern": "empty_ip_set",
                        },
                    )
                    continue

                # Check for overly broad CIDRs
                broad_cidrs: List[str] = []
                for addr in ip_set.addresses:
                    try:
                        network = ipaddress.ip_network(addr, strict=False)
                        if (network.version == 4 and network.prefixlen <= 16) or \
                           (network.version == 6 and network.prefixlen <= 48):
                            broad_cidrs.append(addr)
                    except ValueError:
                        logger.debug(
                            "Unparseable CIDR in IP set %s: %s",
                            ip_set.resource_name, addr,
                        )

                if broad_cidrs:
                    host_count = sum(
                        ipaddress.ip_network(c, strict=False).num_addresses
                        for c in broad_cidrs
                        if self._is_valid_cidr(c)
                    )
                    remediation = RemediationTemplates.narrow_ip_set_suggestion(
                        ip_set.resource_name, broad_cidrs,
                    )
                    self._make_finding(
                        severity=WAFSeverity.CODE_RISK,
                        rule_type="ip_set",
                        title=f"Overly broad CIDR(s) in IP set: {ip_set.resource_name}",
                        description=(
                            f"IP set '{ip_set.resource_name}' contains "
                            f"{len(broad_cidrs)} CIDR range(s) of /16 or broader, "
                            f"potentially affecting {host_count:,} IP addresses. "
                            f"Broad ranges: {', '.join(broad_cidrs[:5])}"
                            f"{'...' if len(broad_cidrs) > 5 else ''}. "
                            f"This increases collateral damage risk when used in "
                            f"block rules."
                        ),
                        acl=acl,
                        rule_name=rule.name,
                        recommendation=(
                            "Narrow the CIDR ranges to target specific malicious "
                            "sources identified in WAF logs rather than entire "
                            "network blocks. Use /24 or narrower for IPv4 and /64 "
                            "or narrower for IPv6 where possible."
                        ),
                        remediation_terraform=remediation,
                        risk_factors={
                            "ip_set_name": ip_set.resource_name,
                            "broad_cidrs": broad_cidrs[:10],
                            "total_addresses_in_set": len(ip_set.addresses),
                            "estimated_affected_hosts": host_count,
                        },
                    )

    @staticmethod
    def _is_valid_cidr(cidr: str) -> bool:
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False

    # ------------------------------------------------------------------
    # Check 6: Observability
    # ------------------------------------------------------------------

    def _check_observability(self, acl: ParsedWebACL) -> None:
        """Check CloudWatch metrics and logging configuration."""
        # Per-rule metric checks
        for rule in acl.rules:
            vis = rule.visibility_config
            cw_enabled = vis.get("cloudwatch_metrics_enabled")
            if cw_enabled is False:
                self._make_finding(
                    severity=WAFSeverity.INFORMATIONAL,
                    rule_type="observability",
                    title=f"CloudWatch metrics disabled on rule: {rule.name}",
                    description=(
                        f"Rule '{rule.name}' in WebACL '{acl.resource_name}' has "
                        f"cloudwatch_metrics_enabled = false in its visibility_config. "
                        f"Without metrics, you cannot monitor rule effectiveness, "
                        f"detect anomalies, or tune thresholds after deployment."
                    ),
                    acl=acl,
                    rule_name=rule.name,
                    recommendation=(
                        "Set cloudwatch_metrics_enabled = true in the rule's "
                        "visibility_config block. The per-rule metric cost is negligible "
                        "compared to the operational visibility it provides."
                    ),
                    code_snippet=self._snippet_from_rule(rule),
                    risk_factors={
                        "pattern": "metrics_disabled",
                        "rule_name": rule.name,
                    },
                )

        # WebACL-level logging check
        # Check both inline logging_configuration and separate resource
        has_logging = acl.has_logging_configuration

        if not has_logging:
            # Check for a separate aws_wafv2_web_acl_logging_configuration
            # that references this WebACL
            acl_ref_patterns = [
                f"aws_wafv2_web_acl.{acl.resource_name}.arn",
                acl.resource_name,
            ]
            for log_config in self.parser.logging_configurations:
                for pattern in acl_ref_patterns:
                    if pattern in log_config.content:
                        has_logging = True
                        break
                if has_logging:
                    break

        if not has_logging:
            acl_arn_ref = f"aws_wafv2_web_acl.{acl.resource_name}.arn"
            remediation = RemediationTemplates.logging_configuration(acl_arn_ref)
            self._make_finding(
                severity=WAFSeverity.CODE_RISK,
                rule_type="observability",
                title=f"No WAF logging configured: {acl.resource_name}",
                description=(
                    f"WebACL '{acl.resource_name}' has no logging_configuration "
                    f"block, and no separate aws_wafv2_web_acl_logging_configuration "
                    f"resource was found referencing it. WAF logs are essential for "
                    f"forensic analysis, rule tuning, and detecting sophisticated "
                    f"attack patterns that evade individual rules."
                ),
                acl=acl,
                recommendation=(
                    "Add a logging_configuration resource targeting S3, CloudWatch "
                    "Logs, or Kinesis Data Firehose. At minimum, log BLOCK and COUNT "
                    "actions to enable post-incident analysis."
                ),
                remediation_terraform=remediation,
                risk_factors={
                    "pattern": "no_waf_logging",
                    "impact": "no_forensics,no_tuning,blind_to_attacks",
                },
            )

    # ------------------------------------------------------------------
    # Check 7: Bot Control
    # ------------------------------------------------------------------

    def _check_bot_control(self, acl: ParsedWebACL) -> None:
        """Check for presence of AWSManagedRulesBotControlRuleSet."""
        has_bot_control = any(
            rule.managed_rule_group and
            rule.managed_rule_group.get("name") == "AWSManagedRulesBotControlRuleSet"
            for rule in acl.rules
        )

        if not has_bot_control:
            remediation = RemediationTemplates.bot_control_rule()
            self._make_finding(
                severity=WAFSeverity.INFORMATIONAL,
                rule_type="bot_control",
                title=f"No AWS Bot Control rule group: {acl.resource_name}",
                description=(
                    f"WebACL '{acl.resource_name}' does not include "
                    f"AWSManagedRulesBotControlRuleSet. Bot management is critical "
                    f"for preventing credential stuffing, web scraping, inventory "
                    f"hoarding, and form spam. Without bot control, the WAF relies "
                    f"entirely on signature-based detection."
                ),
                acl=acl,
                recommendation=(
                    "Add AWSManagedRulesBotControlRuleSet as a managed rule group. "
                    "Start in COUNT mode (override_action { count {} }) to evaluate "
                    "impact on legitimate bot traffic (search engines, monitoring) "
                    "before switching to BLOCK."
                ),
                remediation_terraform=remediation,
                risk_factors={
                    "pattern": "no_bot_control",
                    "exposure": "credential_stuffing,scraping,form_spam",
                },
            )

    # ------------------------------------------------------------------
    # Check 8: Managed Rule Groups
    # ------------------------------------------------------------------

    def _check_managed_rule_groups(self, acl: ParsedWebACL) -> None:
        """Check for essential AWS managed rule groups."""
        present_groups: Dict[str, Dict[str, Any]] = {}

        for rule in acl.rules:
            if rule.managed_rule_group:
                grp_name = rule.managed_rule_group.get("name", "")
                present_groups[grp_name] = {
                    "rule_name": rule.name,
                    "vendor": rule.managed_rule_group.get("vendor_name", ""),
                    "override_action": rule.override_action,
                }

        priority_base = 20
        for idx, essential in enumerate(self.ESSENTIAL_MANAGED_GROUPS):
            if essential not in present_groups:
                remediation = RemediationTemplates.managed_rule_group(
                    essential, priority=priority_base + idx * 10,
                )
                self._make_finding(
                    severity=WAFSeverity.CODE_RISK,
                    rule_type="managed_rules",
                    title=f"Missing essential managed rule group: {essential}",
                    description=(
                        f"WebACL '{acl.resource_name}' does not include the "
                        f"{essential} managed rule group. This group provides "
                        f"baseline protection against common web exploits and is "
                        f"considered a minimum-viable WAF configuration by AWS "
                        f"security best practices."
                    ),
                    acl=acl,
                    recommendation=(
                        f"Add {essential} to the WebACL. Deploy in COUNT mode "
                        f"initially (override_action {{ count {{}} }}), review "
                        f"CloudWatch metrics for false positives, then switch to "
                        f"override_action {{ none {{}} }} to enable blocking."
                    ),
                    remediation_terraform=remediation,
                    risk_factors={
                        "missing_group": essential,
                        "pattern": "missing_essential_managed_group",
                    },
                )
            else:
                info = present_groups[essential]
                if info["override_action"] == "count":
                    self._make_finding(
                        severity=WAFSeverity.CODE_RISK,
                        rule_type="managed_rules",
                        title=f"Essential managed rule group in COUNT override: {essential}",
                        description=(
                            f"Managed rule group '{essential}' (attached via rule "
                            f"'{info['rule_name']}' in WebACL '{acl.resource_name}') "
                            f"has its override_action set to count. All rules in the "
                            f"group will log only and not block threats when deployed."
                        ),
                        acl=acl,
                        rule_name=info["rule_name"],
                        recommendation=(
                            "Review CloudWatch metrics after deployment. If "
                            "false-positive rates are acceptable, change "
                            "override_action from count {} to none {} to allow "
                            "the managed group's native blocking actions."
                        ),
                        code_snippet="",
                        risk_factors={
                            "group_name": essential,
                            "current_mode": "count",
                            "pattern": "essential_group_in_count",
                        },
                    )

    # ------------------------------------------------------------------
    # Check 9: Adaptive Patterns
    # ------------------------------------------------------------------

    def _check_adaptive_patterns(self, acl: ParsedWebACL) -> None:
        """Recommend graduated response where permanent blocks lack rate-based companions."""
        # Find all IP set refs that have rate-based companions
        rate_based_ip_refs: Set[str] = set()
        for rule in acl.rules:
            if "rate_based_statement" in rule.statement_types:
                rate_based_ip_refs.update(rule.ip_set_references)

        # Find permanent block rules with IP sets
        for rule in acl.rules:
            if rule.action != "block":
                continue
            if "ip_set_reference_statement" not in rule.statement_types:
                continue
            if "rate_based_statement" in rule.statement_types:
                continue

            orphan_refs = [
                ref for ref in rule.ip_set_references
                if ref not in rate_based_ip_refs
            ]
            if not orphan_refs:
                continue

            ip_ref_display = orphan_refs[0]
            remediation = RemediationTemplates.graduated_response(
                rule.name or acl.resource_name,
                ip_ref_display,
            )

            self._make_finding(
                severity=WAFSeverity.INFORMATIONAL,
                rule_type="adaptive",
                title=f"Graduated response recommended: {rule.name}",
                description=(
                    f"Rule '{rule.name}' in WebACL '{acl.resource_name}' permanently "
                    f"blocks traffic from IP set(s) with no accompanying rate-based "
                    f"rule targeting the same set(s). A graduated response pattern "
                    f"(rate-limit -> temporary block -> permanent block) is more "
                    f"resilient to IP churn and reduces collateral damage from shared "
                    f"IPs (NAT, proxies, CDN egress)."
                ),
                acl=acl,
                rule_name=rule.name,
                recommendation=(
                    "Implement a 3-tier graduated response:\n"
                    "  1. RATE-LIMIT: rate_based_statement (e.g., 1000 req/5min) "
                    "scoped to the IP set. Action = block with 429 custom response.\n"
                    "  2. TEMPORARY BLOCK: Second rate_based_statement with lower "
                    "threshold. Manage a separate IP set with TTL-based expiry "
                    "via Lambda automation.\n"
                    "  3. PERMANENT BLOCK: Only add to the permanent block IP set "
                    "after repeated violations (e.g., 3+ temporary blocks in 24h)."
                ),
                remediation_terraform=remediation,
                code_snippet=self._snippet_from_rule(rule),
                risk_factors={
                    "orphan_ip_set_refs": orphan_refs,
                    "pattern": "permanent_block_without_graduation",
                },
            )

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------

    def analyze_all(self) -> List[WAFStaticFinding]:
        """Run all 9 checks against all parsed WebACLs and rule groups."""
        self.findings.clear()

        all_acls = self.parser.web_acls + self.parser.rule_groups

        if not all_acls:
            logger.info("No WAF v2 WebACL or rule group resources found in Terraform files")
            return self.findings

        logger.info(
            "Analyzing %d WebACL(s) and %d rule group(s) across %d IP set(s)",
            len(self.parser.web_acls),
            len(self.parser.rule_groups),
            len(self.parser.ip_sets),
        )

        for acl in all_acls:
            self._check_permanent_blocks(acl)
            self._check_rate_based_rules(acl)
            self._check_mode_analysis(acl)
            self._check_geo_restrictions(acl)
            self._check_ip_sets(acl)
            self._check_observability(acl)
            self._check_bot_control(acl)
            self._check_managed_rule_groups(acl)
            self._check_adaptive_patterns(acl)

        logger.info("Static WAF analysis complete. Total findings: %d", len(self.findings))
        return self.findings

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def _severity_order(self, severity: str) -> int:
        return WAFSeverity.ORDER.get(severity, 99)

    def _sorted_findings(self) -> List[WAFStaticFinding]:
        return sorted(self.findings, key=lambda f: self._severity_order(f.severity))

    def _severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {
            WAFSeverity.ACTIVE_RISK: 0,
            WAFSeverity.CODE_RISK: 0,
            WAFSeverity.DRIFT_RISK: 0,
            WAFSeverity.INFORMATIONAL: 0,
        }
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def _traditional_severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.traditional_severity
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def generate_json_report(self, output_path: str) -> str:
        """Write findings as a JSON report compatible with platform ingestion."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        data = {
            "scanner": "waf-static",
            "source": "static",
            "timestamp": self.scan_timestamp,
            "total_web_acls": len(self.parser.web_acls),
            "total_rule_groups": len(self.parser.rule_groups),
            "total_ip_sets": len(self.parser.ip_sets),
            "total_findings": len(self.findings),
            "severity_counts": self._severity_counts(),
            "traditional_severity_counts": self._traditional_severity_counts(),
            "findings": [f.to_dict() for f in self._sorted_findings()],
        }
        with open(output_path, "w") as fh:
            json.dump(data, fh, indent=2, default=str)
        logger.info("JSON report written to %s", output_path)
        return output_path

    def generate_markdown_report(self, output_path: str) -> str:
        """Write a Markdown report with executive summary and per-WebACL findings."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        counts = self._severity_counts()
        trad_counts = self._traditional_severity_counts()

        lines: List[str] = []
        lines.append("# AWS WAF v2 Static Terraform Analysis Report\n")
        lines.append(f"**Generated:** {self.scan_timestamp}  ")
        lines.append(f"**Source:** Static Terraform analysis (no AWS credentials required)  ")
        lines.append(
            f"**Resources parsed:** {len(self.parser.web_acls)} WebACL(s), "
            f"{len(self.parser.rule_groups)} rule group(s), "
            f"{len(self.parser.ip_sets)} IP set(s)  "
        )
        lines.append(f"**Total findings:** {len(self.findings)}\n")

        # Executive summary -- WAF severity
        lines.append("## Executive Summary\n")
        lines.append("### WAF-Specific Severity\n")
        lines.append("| Severity | Count | Description |")
        lines.append("|----------|-------|-------------|")
        severity_descriptions = {
            WAFSeverity.ACTIVE_RISK: "Live misconfig, exploitable now",
            WAFSeverity.CODE_RISK: "Deployable misconfiguration in Terraform",
            WAFSeverity.DRIFT_RISK: "Code and live state diverge",
            WAFSeverity.INFORMATIONAL: "Best-practice suggestions",
        }
        for sev in (WAFSeverity.ACTIVE_RISK, WAFSeverity.CODE_RISK,
                     WAFSeverity.DRIFT_RISK, WAFSeverity.INFORMATIONAL):
            lines.append(
                f"| {sev} | {counts.get(sev, 0)} | {severity_descriptions[sev]} |"
            )
        lines.append("")

        # Traditional severity mapping
        lines.append("### Traditional Severity Mapping (for DB/dashboard compatibility)\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            lines.append(f"| {sev} | {trad_counts.get(sev, 0)} |")
        lines.append("")

        if counts.get(WAFSeverity.CODE_RISK, 0) > 0:
            lines.append(
                "> **ACTION REQUIRED:** Code-risk findings represent deployable "
                "misconfigurations that should be addressed before the next apply.\n"
            )

        # Group findings by WebACL
        by_acl: Dict[str, List[WAFStaticFinding]] = {}
        for f in self._sorted_findings():
            key = f"{f.web_acl_name} ({f.file_path})"
            by_acl.setdefault(key, []).append(f)

        for acl_key, findings in by_acl.items():
            lines.append(f"## WebACL: {acl_key}\n")
            for idx, f in enumerate(findings, 1):
                sev_display = f.severity.upper().replace("_", " ")
                lines.append(f"### {idx}. [{sev_display}] {f.title}\n")
                lines.append(f"**Type:** {f.rule_type}  ")
                lines.append(f"**Traditional severity:** {f.traditional_severity}  ")
                if f.rule_name:
                    lines.append(f"**Rule:** {f.rule_name}  ")
                lines.append(f"**File:** {f.file_path}:{f.line_start}-{f.line_end}  ")
                lines.append(f"\n{f.description}\n")
                if f.recommendation:
                    lines.append(f"**Recommendation:** {f.recommendation}\n")
                if f.code_snippet:
                    lines.append("<details><summary>Current Code</summary>\n")
                    lines.append(f"```hcl\n{f.code_snippet}\n```\n")
                    lines.append("</details>\n")
                if f.remediation_terraform:
                    lines.append("<details><summary>Suggested Terraform</summary>\n")
                    lines.append(f"```hcl\n{f.remediation_terraform}\n```\n")
                    lines.append("</details>\n")
                if f.risk_factors:
                    lines.append("<details><summary>Risk Factors</summary>\n")
                    lines.append(
                        f"```json\n{json.dumps(f.risk_factors, indent=2, default=str)}\n```\n"
                    )
                    lines.append("</details>\n")

        lines.append("---\n")
        lines.append(
            "*Report generated by WAF Static Analyzer -- AuditGH Security Platform*\n"
        )

        with open(output_path, "w") as fh:
            fh.write("\n".join(lines))
        logger.info("Markdown report written to %s", output_path)
        return output_path


# =============================================================================
# Platform Integration
# =============================================================================

def _persist_waf_static_findings(
    db_session,
    repository_id: str,
    findings: List[WAFStaticFinding],
) -> None:
    """Persist WAF static findings to the database using the platform's Finding model."""
    if not db_session or not repository_id or not DATABASE_AVAILABLE:
        return

    try:
        repo = db_session.query(models.Repository).filter(
            models.Repository.id == repository_id
        ).first()
        if not repo:
            logger.error(
                "Could not find repository %s for WAF static finding persistence",
                repository_id,
            )
            return

        organization_id = repo.organization_id
        count = 0

        for f in findings:
            platform_dict = f.to_platform_dict()
            finding = models.Finding(
                repository_id=repository_id,
                organization_id=organization_id,
                scanner_name="waf-static",
                finding_type="waf",
                title=platform_dict["title"],
                description=platform_dict["description"],
                severity=platform_dict["severity"],
                file_path=platform_dict.get("file_path"),
                line_start=platform_dict.get("line_start"),
                line_end=platform_dict.get("line_end"),
                code_snippet=platform_dict.get("code_snippet"),
                risk_factors=platform_dict.get("risk_factors"),
                status="open",
            )
            db_session.add(finding)
            count += 1

        db_session.commit()
        logger.info("Persisted %d waf-static findings to database", count)

    except Exception as exc:
        logger.error("Failed to persist waf-static findings: %s", exc)
        db_session.rollback()


def run_waf_static(
    repo_path: str,
    repo_name: str,
    report_dir: str,
    db_session=None,
    repository_id: Optional[str] = None,
) -> Optional[subprocess.CompletedProcess]:
    """Platform integration function matching the run_<scanner> pattern.

    Scans Terraform files in the repository for AWS WAF v2 resource
    definitions and runs 9 rule intelligence checks against them.
    No AWS credentials required.

    Args:
        repo_path: Path to the repository checkout.
        repo_name: Repository / project name used in report filenames.
        report_dir: Directory to write reports into.
        db_session: Optional SQLAlchemy session for persisting findings.
        repository_id: Optional repository UUID for DB persistence.

    Returns:
        A synthetic subprocess.CompletedProcess, or None if no .tf files
        are found.
    """
    os.makedirs(report_dir, exist_ok=True)

    output_json = os.path.join(report_dir, f"{repo_name}_waf_static.json")
    output_md = os.path.join(report_dir, f"{repo_name}_waf_static.md")

    try:
        # Find all .tf files
        tf_files: List[str] = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d != "node_modules"]
            for fname in sorted(files):
                if fname.endswith(".tf"):
                    tf_files.append(os.path.join(root, fname))

        if not tf_files:
            logger.info("No .tf files found in %s -- skipping WAF static scan", repo_path)
            return None

        logger.info("WAF static scan: parsing %d .tf file(s) in %s", len(tf_files), repo_path)

        # Parse
        parser = HCLParser()
        for tf_file in tf_files:
            parser.parse_file(tf_file)

        total_waf_resources = (
            len(parser.web_acls) + len(parser.rule_groups) +
            len(parser.ip_sets) + len(parser.regex_pattern_sets)
        )

        if total_waf_resources == 0:
            logger.info(
                "No WAF v2 resources found in %d .tf file(s) -- skipping analysis",
                len(tf_files),
            )
            # Write empty reports for consistency
            empty_data = {
                "scanner": "waf-static",
                "source": "static",
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "total_web_acls": 0,
                "total_rule_groups": 0,
                "total_ip_sets": 0,
                "total_findings": 0,
                "severity_counts": {},
                "findings": [],
            }
            with open(output_json, "w") as fh:
                json.dump(empty_data, fh, indent=2)
            with open(output_md, "w") as fh:
                fh.write(
                    "# WAF Static Analysis\n\n"
                    "No AWS WAF v2 resources found in Terraform files.\n"
                )
            return subprocess.CompletedProcess(
                args=["waf-static"],
                returncode=0,
                stdout="WAF Static: no WAF v2 resources found in Terraform files",
                stderr="",
            )

        # Analyze
        analyzer = WAFStaticAnalyzer(parser)
        analyzer.analyze_all()

        # Reports
        analyzer.generate_json_report(output_json)
        analyzer.generate_markdown_report(output_md)

        # Persist to database
        if db_session and repository_id and analyzer.findings:
            _persist_waf_static_findings(db_session, repository_id, analyzer.findings)

        # Summary
        counts = analyzer._severity_counts()
        summary_parts: List[str] = []
        for sev in (WAFSeverity.ACTIVE_RISK, WAFSeverity.CODE_RISK,
                     WAFSeverity.DRIFT_RISK, WAFSeverity.INFORMATIONAL):
            c = counts.get(sev, 0)
            if c:
                summary_parts.append(f"{sev}: {c}")

        stdout_text = (
            f"WAF Static: parsed {len(tf_files)} .tf file(s), found "
            f"{total_waf_resources} WAF resource(s), "
            f"{len(analyzer.findings)} finding(s) "
            f"[{', '.join(summary_parts) if summary_parts else 'clean'}]"
        )
        logger.info(stdout_text)

        return subprocess.CompletedProcess(
            args=["waf-static", "--repo-path", repo_path],
            returncode=0 if not analyzer.findings else 1,
            stdout=stdout_text,
            stderr="",
        )

    except Exception as exc:
        msg = f"Unexpected error running WAF static scanner: {exc}"
        logger.error(msg, exc_info=True)
        with open(output_md, "w") as fh:
            fh.write(f"# WAF Static Analysis\n\n**Error:** {msg}\n")
        return subprocess.CompletedProcess(
            args=["waf-static"], returncode=1, stdout="", stderr=msg,
        )


# =============================================================================
# Standalone CLI
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AWS WAF v2 Static Terraform Scanner -- analyze WAF configurations in .tf files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scan_waf_static.py --repo-path ./infrastructure\n"
            "  python scan_waf_static.py --repo-path . --format json --output ./reports\n"
            "  python scan_waf_static.py --repo-path ./terraform --loglevel DEBUG\n"
        ),
    )
    parser.add_argument(
        "--repo-path",
        required=True,
        help="Path to the repository or directory containing .tf files",
    )
    parser.add_argument(
        "--output",
        default=".",
        help="Output directory for reports (default: current directory)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "all"],
        default="all",
        help="Report format(s) to generate (default: all)",
    )
    parser.add_argument(
        "--loglevel",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.loglevel),
        format="%(asctime)s [%(levelname)s] %(name)s -- %(message)s",
    )

    if not os.path.isdir(args.repo_path):
        logger.error("Path does not exist or is not a directory: %s", args.repo_path)
        sys.exit(1)

    # Parse
    hcl_parser = HCLParser()
    hcl_parser.parse_directory(args.repo_path)

    total_waf = (
        len(hcl_parser.web_acls) + len(hcl_parser.rule_groups) +
        len(hcl_parser.ip_sets) + len(hcl_parser.regex_pattern_sets)
    )

    if total_waf == 0:
        print("No AWS WAF v2 resources found in .tf files.")
        sys.exit(0)

    print(
        f"Parsed: {len(hcl_parser.web_acls)} WebACL(s), "
        f"{len(hcl_parser.rule_groups)} rule group(s), "
        f"{len(hcl_parser.ip_sets)} IP set(s), "
        f"{len(hcl_parser.regex_pattern_sets)} regex pattern set(s)"
    )

    # Analyze
    analyzer = WAFStaticAnalyzer(hcl_parser)
    analyzer.analyze_all()

    # Reports
    os.makedirs(args.output, exist_ok=True)
    fmt = args.format

    if fmt in ("json", "all"):
        analyzer.generate_json_report(os.path.join(args.output, "waf_static.json"))
    if fmt in ("markdown", "all"):
        analyzer.generate_markdown_report(os.path.join(args.output, "waf_static.md"))

    # Summary
    counts = analyzer._severity_counts()
    total = len(analyzer.findings)
    print(f"\nAnalysis complete: {total} finding(s)")
    for sev in (WAFSeverity.ACTIVE_RISK, WAFSeverity.CODE_RISK,
                 WAFSeverity.DRIFT_RISK, WAFSeverity.INFORMATIONAL):
        c = counts.get(sev, 0)
        if c:
            label = sev.upper().replace("_", " ")
            print(f"  {label}: {c}")

    # Exit code: non-zero if any code_risk or active_risk findings
    if counts.get(WAFSeverity.ACTIVE_RISK, 0) + counts.get(WAFSeverity.CODE_RISK, 0) > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
