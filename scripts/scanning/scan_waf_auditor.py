#!/usr/bin/env python3
"""
AWS WAF v2 Auditor Scanner
==========================

Audits live AWS WAF v2 configurations for security misconfigurations,
overly permissive rules, missing protections, and anti-patterns.

Platform integration:
    run_waf_auditor(repo_path, repo_name, report_dir, ...) -> Optional[CompletedProcess]

Standalone CLI:
    python scan_waf_auditor.py --scope REGIONAL --region us-east-1 --format all --output ./reports
"""

import argparse
import datetime
import ipaddress
import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Graceful boto3 import
# ---------------------------------------------------------------------------
try:
    import boto3
    from botocore.exceptions import (
        BotoCoreError,
        ClientError,
        NoCredentialsError,
        PartialCredentialsError,
    )
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

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
# Data Model
# =============================================================================

@dataclass
class WAFFinding:
    """Single finding emitted by the WAF auditor."""

    rule_type: str            # permanent_block, rate_limit, mode, geo, ip_set, observability, bot_control, managed_rules, adaptive
    severity: str             # critical, high, medium, low, info
    title: str
    description: str
    web_acl_name: str
    web_acl_id: str
    rule_name: Optional[str] = None
    recommendation: Optional[str] = None
    resource_arn: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    # Convenience -----------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Ensure JSON-safe values
        for k, v in d.items():
            if v is None:
                d[k] = None
        return d

    def to_platform_dict(self) -> Dict[str, Any]:
        """Return a dict compatible with _persist_scan_findings."""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.upper(),
            "file_path": self.resource_arn,
            "code_snippet": json.dumps(self.details, default=str)[:1000] if self.details else None,
            "cwe_id": None,
            "risk_factors": {
                "rule_type": self.rule_type,
                "web_acl_name": self.web_acl_name,
                "web_acl_id": self.web_acl_id,
                "rule_name": self.rule_name,
            },
        }


# =============================================================================
# WAF Auditor
# =============================================================================

class WAFAuditor:
    """Audits all WebACLs in a given scope/region for security misconfigurations."""

    # Managed rule groups considered essential
    ESSENTIAL_MANAGED_GROUPS = [
        "AWSManagedRulesCommonRuleSet",
        "AWSManagedRulesKnownBadInputsRuleSet",
        "AWSManagedRulesSQLiRuleSet",
    ]

    def __init__(self, scope: str = "REGIONAL", region: Optional[str] = None):
        """
        Args:
            scope: 'REGIONAL' or 'CLOUDFRONT'.
                   CLOUDFRONT requires region='us-east-1'.
            region: AWS region override.  Defaults to env / instance metadata.
        """
        if not BOTO3_AVAILABLE:
            raise RuntimeError("boto3 is not installed. Install via: pip install boto3")

        self.scope = scope.upper()
        if self.scope not in ("REGIONAL", "CLOUDFRONT"):
            raise ValueError(f"Invalid scope '{self.scope}'. Must be REGIONAL or CLOUDFRONT.")

        # CloudFront WAF resources always live in us-east-1
        effective_region = region
        if self.scope == "CLOUDFRONT":
            effective_region = "us-east-1"

        session_kwargs: Dict[str, Any] = {}
        if effective_region:
            session_kwargs["region_name"] = effective_region

        self._client = boto3.client("wafv2", **session_kwargs)
        self.findings: List[WAFFinding] = []
        self.web_acls: List[Dict[str, Any]] = []
        self._ip_set_cache: Dict[str, Dict[str, Any]] = {}
        self.audit_timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    # ------------------------------------------------------------------
    # AWS helpers
    # ------------------------------------------------------------------

    def _list_web_acls(self) -> List[Dict[str, Any]]:
        """Paginate through all WebACLs in the configured scope."""
        acls: List[Dict[str, Any]] = []
        kwargs: Dict[str, Any] = {"Scope": self.scope, "Limit": 100}
        while True:
            resp = self._client.list_web_acls(**kwargs)
            acls.extend(resp.get("WebACLs", []))
            marker = resp.get("NextMarker")
            if not marker:
                break
            kwargs["NextMarker"] = marker
        return acls

    def _get_web_acl(self, name: str, acl_id: str) -> Dict[str, Any]:
        resp = self._client.get_web_acl(Name=name, Scope=self.scope, Id=acl_id)
        return resp

    def _get_ip_set(self, name: str, ip_set_id: str) -> Dict[str, Any]:
        cache_key = f"{name}:{ip_set_id}"
        if cache_key in self._ip_set_cache:
            return self._ip_set_cache[cache_key]
        try:
            resp = self._client.get_ip_set(Name=name, Scope=self.scope, Id=ip_set_id)
            self._ip_set_cache[cache_key] = resp
            return resp
        except (ClientError, BotoCoreError) as exc:
            logger.warning("Failed to fetch IP set %s/%s: %s", name, ip_set_id, exc)
            return {}

    def _get_logging_configuration(self, acl_arn: str) -> Optional[Dict[str, Any]]:
        try:
            resp = self._client.get_logging_configuration(ResourceArn=acl_arn)
            return resp.get("LoggingConfiguration")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "WAFNonexistentItemException":
                return None
            raise

    # ------------------------------------------------------------------
    # Utility: walk statements looking for a specific type
    # ------------------------------------------------------------------

    @staticmethod
    def _find_statements(statement: Dict[str, Any], target_type: str) -> List[Dict[str, Any]]:
        """Recursively search a rule's Statement tree for a given statement type."""
        found: List[Dict[str, Any]] = []
        if target_type in statement:
            found.append(statement[target_type])
        # Recurse into logical wrappers
        for wrapper_key in ("AndStatement", "OrStatement", "NotStatement"):
            wrapper = statement.get(wrapper_key)
            if wrapper:
                children = wrapper.get("Statements", [])
                if not children and "Statement" in wrapper:
                    children = [wrapper["Statement"]]
                for child in children:
                    found.extend(WAFAuditor._find_statements(child, target_type))
        # Recurse into RateBasedStatement scope-down
        rbs = statement.get("RateBasedStatement")
        if rbs and "ScopeDownStatement" in rbs:
            found.extend(WAFAuditor._find_statements(rbs["ScopeDownStatement"], target_type))
        return found

    @staticmethod
    def _rule_has_statement_type(rule: Dict[str, Any], statement_type: str) -> bool:
        stmt = rule.get("Statement", {})
        return len(WAFAuditor._find_statements(stmt, statement_type)) > 0

    # ------------------------------------------------------------------
    # Audit entry point
    # ------------------------------------------------------------------

    def audit_all(self) -> List[WAFFinding]:
        """Discover all WebACLs and run every check against each one."""
        self.findings.clear()
        self.web_acls.clear()

        summaries = self._list_web_acls()
        logger.info("Discovered %d WebACL(s) in scope=%s", len(summaries), self.scope)

        for summary in summaries:
            acl_name = summary["Name"]
            acl_id = summary["Id"]
            try:
                full = self._get_web_acl(acl_name, acl_id)
            except (ClientError, BotoCoreError) as exc:
                logger.error("Could not fetch WebACL %s: %s", acl_name, exc)
                continue

            self.web_acls.append(full)

            # Run all checks
            self._check_permanent_blocks(full)
            self._check_rate_based_rules(full)
            self._check_mode_analysis(full)
            self._check_geo_restrictions(full)
            self._check_ip_sets(full)
            self._check_observability(full)
            self._check_bot_control(full)
            self._check_managed_rule_groups(full)
            self._check_adaptive_patterns(full)

        logger.info("Audit complete. Total findings: %d", len(self.findings))
        return self.findings

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _acl_meta(self, acl: Dict[str, Any]) -> Tuple[str, str, str, List[Dict[str, Any]]]:
        """Extract common fields from a get_web_acl response."""
        wacl = acl["WebACL"]
        return wacl["Name"], wacl["Id"], wacl["ARN"], wacl.get("Rules", [])

    def _check_permanent_blocks(self, acl: Dict[str, Any]) -> None:
        """Detect rules that permanently block IPs on single criteria without rate-based conditions."""
        name, acl_id, arn, rules = self._acl_meta(acl)

        # Collect all rule names that are rate-based
        rate_based_rule_names = {
            r["Name"] for r in rules
            if self._rule_has_statement_type(r, "RateBasedStatement")
        }

        for rule in rules:
            action = rule.get("Action", {})
            if "Block" not in action:
                continue

            stmt = rule.get("Statement", {})
            has_ip_set = len(self._find_statements(stmt, "IPSetReferenceStatement")) > 0
            has_rate = len(self._find_statements(stmt, "RateBasedStatement")) > 0

            if has_ip_set and not has_rate:
                # Check if a companion rate-based rule exists for the same IP set
                companion_exists = False
                ip_set_refs = self._find_statements(stmt, "IPSetReferenceStatement")
                ip_set_arns = {ref.get("ARN", "") for ref in ip_set_refs}

                for other_rule in rules:
                    if other_rule["Name"] == rule["Name"]:
                        continue
                    if other_rule["Name"] in rate_based_rule_names:
                        other_ip_refs = self._find_statements(
                            other_rule.get("Statement", {}), "IPSetReferenceStatement"
                        )
                        other_arns = {ref.get("ARN", "") for ref in other_ip_refs}
                        if ip_set_arns & other_arns:
                            companion_exists = True
                            break

                if not companion_exists:
                    self.findings.append(WAFFinding(
                        rule_type="permanent_block",
                        severity="high",
                        title=f"Permanent IP block without rate-based companion: {rule['Name']}",
                        description=(
                            f"Rule '{rule['Name']}' blocks traffic matching an IP set reference "
                            "without any accompanying rate-based rule. This can lead to "
                            "over-blocking legitimate users whose IPs are shared or recycled."
                        ),
                        web_acl_name=name,
                        web_acl_id=acl_id,
                        rule_name=rule["Name"],
                        recommendation=(
                            "Implement a graduated response: rate-limit first, then temporary "
                            "block, and only permanently block after repeated violations. "
                            "Use a RateBasedStatement with a scope-down statement referencing "
                            "the same IP set."
                        ),
                        resource_arn=arn,
                        details={"ip_set_arns": list(ip_set_arns)},
                    ))

    def _check_rate_based_rules(self, acl: Dict[str, Any]) -> None:
        """Validate rate-based rule thresholds and flag missing rate limiting."""
        name, acl_id, arn, rules = self._acl_meta(acl)

        has_any_rate_rule = False

        for rule in rules:
            stmt = rule.get("Statement", {})
            rbs_list = self._find_statements(stmt, "RateBasedStatement")
            if not rbs_list:
                continue

            has_any_rate_rule = True

            for rbs in rbs_list:
                limit = rbs.get("Limit", 0)

                if limit < 100:
                    self.findings.append(WAFFinding(
                        rule_type="rate_limit",
                        severity="medium",
                        title=f"Rate limit threshold very low ({limit}): {rule['Name']}",
                        description=(
                            f"Rule '{rule['Name']}' has a rate limit of {limit} requests "
                            "per 5-minute window. Thresholds below 100 are likely to cause "
                            "false positives and block legitimate traffic."
                        ),
                        web_acl_name=name,
                        web_acl_id=acl_id,
                        rule_name=rule["Name"],
                        recommendation=(
                            "Consider increasing the threshold to at least 100. Monitor "
                            "COUNT-mode metrics first to establish a baseline."
                        ),
                        resource_arn=arn,
                        details={"current_limit": limit},
                    ))
                elif limit > 10000:
                    self.findings.append(WAFFinding(
                        rule_type="rate_limit",
                        severity="high",
                        title=f"Rate limit threshold too high ({limit}): {rule['Name']}",
                        description=(
                            f"Rule '{rule['Name']}' has a rate limit of {limit} requests "
                            "per 5-minute window. Thresholds above 10,000 are unlikely to "
                            "stop real attacks and offer minimal protection."
                        ),
                        web_acl_name=name,
                        web_acl_id=acl_id,
                        rule_name=rule["Name"],
                        recommendation=(
                            "Lower the threshold to a value that reflects your application's "
                            "expected legitimate traffic. Typical API rate limits range from "
                            "500 to 5,000 requests per 5 minutes."
                        ),
                        resource_arn=arn,
                        details={"current_limit": limit},
                    ))

                # Flag rate limits without scope-down (too broad)
                if "ScopeDownStatement" not in rbs:
                    self.findings.append(WAFFinding(
                        rule_type="rate_limit",
                        severity="medium",
                        title=f"Rate limit without scope-down statement: {rule['Name']}",
                        description=(
                            f"Rule '{rule['Name']}' applies a rate limit to ALL traffic "
                            "without a scope-down statement. This applies the same limit "
                            "globally, which may be too broad for heterogeneous traffic."
                        ),
                        web_acl_name=name,
                        web_acl_id=acl_id,
                        rule_name=rule["Name"],
                        recommendation=(
                            "Add a ScopeDownStatement to target specific paths, IP ranges, "
                            "or request characteristics for more precise rate limiting."
                        ),
                        resource_arn=arn,
                        details={"limit": limit},
                    ))

        if not has_any_rate_rule:
            self.findings.append(WAFFinding(
                rule_type="rate_limit",
                severity="critical",
                title=f"No rate-based rules configured: {name}",
                description=(
                    f"WebACL '{name}' has no rate-based rules. Without rate limiting, "
                    "the application is fully exposed to brute-force attacks, credential "
                    "stuffing, and application-layer DDoS."
                ),
                web_acl_name=name,
                web_acl_id=acl_id,
                recommendation=(
                    "Add at least one RateBasedStatement rule to protect against volumetric "
                    "attacks. Start with a reasonable threshold (e.g., 2000 requests per "
                    "5-minute window) and tune based on traffic analysis."
                ),
                resource_arn=arn,
            ))

    def _check_mode_analysis(self, acl: Dict[str, Any]) -> None:
        """Detect rules in COUNT mode that may need promotion to BLOCK."""
        name, acl_id, arn, rules = self._acl_meta(acl)

        for rule in rules:
            rule_name = rule["Name"]
            action = rule.get("Action", {})
            override = rule.get("OverrideAction", {})

            # Rules using OverrideAction with Count are managed rule groups kept in count
            if "Count" in override:
                self.findings.append(WAFFinding(
                    rule_type="mode",
                    severity="medium",
                    title=f"Managed rule group in COUNT mode: {rule_name}",
                    description=(
                        f"Rule '{rule_name}' overrides managed rule group actions to COUNT. "
                        "This means threats matched by this rule group are logged but not "
                        "blocked. If this rule has been in COUNT mode for an extended period, "
                        "it may be time to promote it to BLOCK."
                    ),
                    web_acl_name=name,
                    web_acl_id=acl_id,
                    rule_name=rule_name,
                    recommendation=(
                        "Review CloudWatch metrics and WAF logs for this rule group. If "
                        "false-positive rates are acceptable, switch OverrideAction from "
                        "Count to None to allow the managed group's native actions."
                    ),
                    resource_arn=arn,
                ))

            # Direct Count action on a custom rule
            if "Count" in action:
                self.findings.append(WAFFinding(
                    rule_type="mode",
                    severity="low",
                    title=f"Custom rule in COUNT mode: {rule_name}",
                    description=(
                        f"Rule '{rule_name}' uses a Count action. Ensure this is intentional "
                        "and that you are actively monitoring its matches before promoting "
                        "to Block."
                    ),
                    web_acl_name=name,
                    web_acl_id=acl_id,
                    rule_name=rule_name,
                    recommendation=(
                        "Check CloudWatch metrics for this rule. If the rule has been in "
                        "COUNT mode long enough to validate low false-positive rates, "
                        "consider switching to Block."
                    ),
                    resource_arn=arn,
                ))

    def _check_geo_restrictions(self, acl: Dict[str, Any]) -> None:
        """Flag absence of geographic restriction rules."""
        name, acl_id, arn, rules = self._acl_meta(acl)

        has_geo = any(
            self._rule_has_statement_type(r, "GeoMatchStatement") for r in rules
        )

        if not has_geo:
            self.findings.append(WAFFinding(
                rule_type="geo",
                severity="medium",
                title=f"No geographic restriction rules: {name}",
                description=(
                    f"WebACL '{name}' has no GeoMatchStatement rules. If the application "
                    "serves a known set of countries, adding geo-restrictions reduces "
                    "attack surface from regions that should never access the service."
                ),
                web_acl_name=name,
                web_acl_id=acl_id,
                recommendation=(
                    "Add a GeoMatchStatement rule to block or rate-limit traffic from "
                    "countries outside your expected user base. At minimum, consider "
                    "blocking countries with no legitimate business reason to access "
                    "the application."
                ),
                resource_arn=arn,
            ))

    def _check_ip_sets(self, acl: Dict[str, Any]) -> None:
        """Inspect IP sets for overly broad CIDRs or empty sets."""
        name, acl_id, arn, rules = self._acl_meta(acl)

        for rule in rules:
            stmt = rule.get("Statement", {})
            ip_refs = self._find_statements(stmt, "IPSetReferenceStatement")

            for ref in ip_refs:
                ip_set_arn = ref.get("ARN", "")
                # Parse name and ID from ARN
                # ARN format: arn:aws:wafv2:<region>:<account>:<scope>/ipset/<name>/<id>
                arn_parts = ip_set_arn.split("/")
                if len(arn_parts) < 3:
                    continue
                ip_set_name = arn_parts[-2]
                ip_set_id = arn_parts[-1]

                ip_set_resp = self._get_ip_set(ip_set_name, ip_set_id)
                if not ip_set_resp:
                    continue

                ip_set_data = ip_set_resp.get("IPSet", {})
                addresses = ip_set_data.get("Addresses", [])

                if not addresses:
                    self.findings.append(WAFFinding(
                        rule_type="ip_set",
                        severity="low",
                        title=f"Empty IP set referenced: {ip_set_name}",
                        description=(
                            f"IP set '{ip_set_name}' (referenced by rule '{rule['Name']}') "
                            "contains no addresses. The rule has no effect."
                        ),
                        web_acl_name=name,
                        web_acl_id=acl_id,
                        rule_name=rule["Name"],
                        recommendation=(
                            "Populate the IP set or remove the rule referencing it to "
                            "reduce clutter."
                        ),
                        resource_arn=ip_set_arn,
                        details={"ip_set_name": ip_set_name, "ip_set_id": ip_set_id},
                    ))
                    continue

                # Check for overly broad CIDRs
                broad_cidrs: List[str] = []
                for addr in addresses:
                    try:
                        network = ipaddress.ip_network(addr, strict=False)
                        # /16 for IPv4 = 65536 hosts, /48 for IPv6 is roughly equivalent broad range
                        if (network.version == 4 and network.prefixlen <= 16) or \
                           (network.version == 6 and network.prefixlen <= 48):
                            broad_cidrs.append(addr)
                    except ValueError:
                        logger.debug("Unparseable CIDR in IP set %s: %s", ip_set_name, addr)

                if broad_cidrs:
                    self.findings.append(WAFFinding(
                        rule_type="ip_set",
                        severity="high",
                        title=f"Overly broad CIDR(s) in IP set: {ip_set_name}",
                        description=(
                            f"IP set '{ip_set_name}' contains {len(broad_cidrs)} CIDR range(s) "
                            f"of /16 or broader, potentially blocking 65,000+ IPs per range. "
                            f"Broad ranges: {', '.join(broad_cidrs[:5])}"
                            f"{' (and more)' if len(broad_cidrs) > 5 else ''}."
                        ),
                        web_acl_name=name,
                        web_acl_id=acl_id,
                        rule_name=rule["Name"],
                        recommendation=(
                            "Narrow the CIDR ranges to target specific malicious sources "
                            "rather than entire network blocks. Use /24 or narrower for "
                            "IPv4 where possible."
                        ),
                        resource_arn=ip_set_arn,
                        details={
                            "ip_set_name": ip_set_name,
                            "broad_cidrs": broad_cidrs,
                            "total_addresses": len(addresses),
                        },
                    ))

    def _check_observability(self, acl: Dict[str, Any]) -> None:
        """Check CloudWatch metrics and logging configuration."""
        name, acl_id, arn, rules = self._acl_meta(acl)

        # Per-rule metric checks
        for rule in rules:
            vis = rule.get("VisibilityConfig", {})
            if not vis.get("CloudWatchMetricsEnabled", True):
                self.findings.append(WAFFinding(
                    rule_type="observability",
                    severity="medium",
                    title=f"CloudWatch metrics disabled on rule: {rule['Name']}",
                    description=(
                        f"Rule '{rule['Name']}' in WebACL '{name}' has CloudWatch metrics "
                        "disabled. Without metrics, you cannot monitor rule effectiveness "
                        "or detect anomalies."
                    ),
                    web_acl_name=name,
                    web_acl_id=acl_id,
                    rule_name=rule["Name"],
                    recommendation="Enable CloudWatchMetricsEnabled in the rule's VisibilityConfig.",
                    resource_arn=arn,
                ))

        # WebACL-level logging check
        logging_config = self._get_logging_configuration(arn)
        if logging_config is None:
            self.findings.append(WAFFinding(
                rule_type="observability",
                severity="high",
                title=f"No WAF logging configured: {name}",
                description=(
                    f"WebACL '{name}' has no logging configuration. WAF logs are essential "
                    "for forensic analysis, tuning rules, and detecting sophisticated "
                    "attack patterns."
                ),
                web_acl_name=name,
                web_acl_id=acl_id,
                recommendation=(
                    "Enable WAF logging to S3, CloudWatch Logs, or Kinesis Data Firehose. "
                    "At minimum, log sampled requests for high-severity rules."
                ),
                resource_arn=arn,
            ))

    def _check_bot_control(self, acl: Dict[str, Any]) -> None:
        """Check for presence of AWS Bot Control managed rule group."""
        name, acl_id, arn, rules = self._acl_meta(acl)

        has_bot_control = False
        for rule in rules:
            stmt = rule.get("Statement", {})
            mrg_refs = self._find_statements(stmt, "ManagedRuleGroupStatement")
            for mrg in mrg_refs:
                if mrg.get("Name") == "AWSManagedRulesBotControlRuleSet":
                    has_bot_control = True
                    break
            if has_bot_control:
                break

        if not has_bot_control:
            self.findings.append(WAFFinding(
                rule_type="bot_control",
                severity="medium",
                title=f"No AWS Bot Control rule group: {name}",
                description=(
                    f"WebACL '{name}' does not include AWSManagedRulesBotControlRuleSet. "
                    "Bot management is critical for preventing credential stuffing, "
                    "scraping, and inventory hoarding."
                ),
                web_acl_name=name,
                web_acl_id=acl_id,
                recommendation=(
                    "Add AWSManagedRulesBotControlRuleSet as a managed rule group. Start "
                    "in COUNT mode to evaluate impact before switching to BLOCK."
                ),
                resource_arn=arn,
            ))

    def _check_managed_rule_groups(self, acl: Dict[str, Any]) -> None:
        """Check for essential AWS managed rule groups and their action overrides."""
        name, acl_id, arn, rules = self._acl_meta(acl)

        # Collect all managed groups present and their override status
        present_groups: Dict[str, Dict[str, Any]] = {}  # group_name -> info

        for rule in rules:
            stmt = rule.get("Statement", {})
            mrg_refs = self._find_statements(stmt, "ManagedRuleGroupStatement")
            for mrg in mrg_refs:
                grp_name = mrg.get("Name", "")
                vendor = mrg.get("VendorName", "")
                excluded = mrg.get("ExcludedRules", [])

                override = rule.get("OverrideAction", {})
                is_count_override = "Count" in override

                present_groups[grp_name] = {
                    "rule_name": rule["Name"],
                    "vendor": vendor,
                    "excluded_rules": excluded,
                    "count_override": is_count_override,
                }

        # Check for missing essential groups
        for essential in self.ESSENTIAL_MANAGED_GROUPS:
            if essential not in present_groups:
                self.findings.append(WAFFinding(
                    rule_type="managed_rules",
                    severity="high",
                    title=f"Missing essential managed rule group: {essential}",
                    description=(
                        f"WebACL '{name}' does not include {essential}. This managed rule "
                        "group provides baseline protection against common web exploits."
                    ),
                    web_acl_name=name,
                    web_acl_id=acl_id,
                    recommendation=(
                        f"Add {essential} to the WebACL. Start in COUNT mode, review "
                        "CloudWatch metrics, then switch to BLOCK."
                    ),
                    resource_arn=arn,
                ))
            else:
                info = present_groups[essential]
                # Flag if overridden entirely to COUNT
                if info["count_override"]:
                    self.findings.append(WAFFinding(
                        rule_type="managed_rules",
                        severity="medium",
                        title=f"Essential managed rule group in COUNT override: {essential}",
                        description=(
                            f"Managed rule group '{essential}' (attached via rule "
                            f"'{info['rule_name']}') has its OverrideAction set to Count. "
                            "All rules in the group are logging only and not blocking."
                        ),
                        web_acl_name=name,
                        web_acl_id=acl_id,
                        rule_name=info["rule_name"],
                        recommendation=(
                            "Review CloudWatch metrics. If false-positive rates are "
                            "acceptable, remove the Count override to allow blocking."
                        ),
                        resource_arn=arn,
                        details={
                            "group_name": essential,
                            "excluded_rules": [r.get("Name") for r in info["excluded_rules"]],
                        },
                    ))

    def _check_adaptive_patterns(self, acl: Dict[str, Any]) -> None:
        """Suggest graduated response where permanent blocks exist without rate-based companions."""
        name, acl_id, arn, rules = self._acl_meta(acl)

        # Find permanent-block rules that reference IP sets
        block_rules_with_ip = []
        rate_based_ip_arns: set = set()

        for rule in rules:
            stmt = rule.get("Statement", {})
            ip_refs = self._find_statements(stmt, "IPSetReferenceStatement")
            has_rate = len(self._find_statements(stmt, "RateBasedStatement")) > 0

            if has_rate and ip_refs:
                for ref in ip_refs:
                    rate_based_ip_arns.add(ref.get("ARN", ""))

            action = rule.get("Action", {})
            if "Block" in action and ip_refs:
                ip_arns = {ref.get("ARN", "") for ref in ip_refs}
                block_rules_with_ip.append((rule, ip_arns))

        for rule, ip_arns in block_rules_with_ip:
            orphan_arns = ip_arns - rate_based_ip_arns
            if orphan_arns:
                self.findings.append(WAFFinding(
                    rule_type="adaptive",
                    severity="info",
                    title=f"Graduated response recommended: {rule['Name']}",
                    description=(
                        f"Rule '{rule['Name']}' permanently blocks traffic from IP set(s) "
                        "with no accompanying rate-based rule for the same IP set(s). "
                        "A graduated response pattern is more resilient to IP churn and "
                        "reduces collateral damage from shared IPs."
                    ),
                    web_acl_name=name,
                    web_acl_id=acl_id,
                    rule_name=rule["Name"],
                    recommendation=(
                        "Implement a 3-tier graduated response:\n"
                        "  1. RATE-LIMIT: Use a RateBasedStatement (e.g., 1000 req/5min) "
                        "scoped to the IP set. Action = Block with custom response 429.\n"
                        "  2. TEMPORARY BLOCK: Use a second RateBasedStatement with a lower "
                        "threshold (e.g., 200 req/5min after the first block). Action = Block "
                        "for a longer window via a separate IP set with TTL automation.\n"
                        "  3. PERMANENT BLOCK: Only add to the permanent block IP set after "
                        "repeated violations (e.g., 3+ temporary blocks within 24h). Use "
                        "Lambda automation to manage the IP set lifecycle."
                    ),
                    resource_arn=arn,
                    details={"orphan_ip_set_arns": list(orphan_arns)},
                ))

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def _severity_order(self, severity: str) -> int:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return order.get(severity.lower(), 5)

    def _sorted_findings(self) -> List[WAFFinding]:
        return sorted(self.findings, key=lambda f: self._severity_order(f.severity))

    def _severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            key = f.severity.lower()
            counts[key] = counts.get(key, 0) + 1
        return counts

    def generate_json_report(self, output_path: str) -> str:
        """Write findings as a JSON array compatible with platform ingestion."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        data = {
            "scanner": "waf_auditor",
            "scope": self.scope,
            "timestamp": self.audit_timestamp,
            "total_web_acls": len(self.web_acls),
            "total_findings": len(self.findings),
            "severity_counts": self._severity_counts(),
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

        lines: List[str] = []
        lines.append("# AWS WAF v2 Security Audit Report\n")
        lines.append(f"**Generated:** {self.audit_timestamp}  ")
        lines.append(f"**Scope:** {self.scope}  ")
        lines.append(f"**WebACLs audited:** {len(self.web_acls)}  ")
        lines.append(f"**Total findings:** {len(self.findings)}\n")

        # Executive summary
        lines.append("## Executive Summary\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ("critical", "high", "medium", "low", "info"):
            lines.append(f"| {sev.upper()} | {counts.get(sev, 0)} |")
        lines.append("")

        if counts["critical"] > 0:
            lines.append(
                "> **ACTION REQUIRED:** Critical findings require immediate attention.\n"
            )

        # Group findings by WebACL
        by_acl: Dict[str, List[WAFFinding]] = {}
        for f in self._sorted_findings():
            key = f"{f.web_acl_name} ({f.web_acl_id})"
            by_acl.setdefault(key, []).append(f)

        for acl_key, findings in by_acl.items():
            lines.append(f"## WebACL: {acl_key}\n")
            for idx, f in enumerate(findings, 1):
                sev_upper = f.severity.upper()
                lines.append(f"### {idx}. [{sev_upper}] {f.title}\n")
                lines.append(f"**Type:** {f.rule_type}  ")
                if f.rule_name:
                    lines.append(f"**Rule:** {f.rule_name}  ")
                lines.append(f"\n{f.description}\n")
                if f.recommendation:
                    lines.append(f"**Recommendation:** {f.recommendation}\n")
                if f.details:
                    lines.append("<details><summary>Details</summary>\n")
                    lines.append(f"```json\n{json.dumps(f.details, indent=2, default=str)}\n```\n")
                    lines.append("</details>\n")

        lines.append("---\n")
        lines.append("*Report generated by WAF Auditor — AuditGH Security Platform*\n")

        with open(output_path, "w") as fh:
            fh.write("\n".join(lines))
        logger.info("Markdown report written to %s", output_path)
        return output_path

    def generate_html_report(self, output_path: str) -> str:
        """Write a standalone HTML report with inline CSS and expandable details."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        counts = self._severity_counts()

        sev_colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#d97706",
            "low": "#2563eb",
            "info": "#6b7280",
        }

        # Build the findings HTML
        findings_html_parts: List[str] = []
        for idx, f in enumerate(self._sorted_findings(), 1):
            sev_lower = f.severity.lower()
            color = sev_colors.get(sev_lower, "#6b7280")
            details_block = ""
            if f.details:
                details_json = json.dumps(f.details, indent=2, default=str)
                # Escape HTML entities in JSON
                details_json = (
                    details_json.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                )
                details_block = f"""
                <details>
                    <summary>Details</summary>
                    <pre><code>{details_json}</code></pre>
                </details>"""

            rec_block = ""
            if f.recommendation:
                rec_html = (
                    f.recommendation.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\n", "<br>")
                )
                rec_block = f'<div class="recommendation"><strong>Recommendation:</strong> {rec_html}</div>'

            rule_info = f'<span class="rule-name">Rule: {f.rule_name}</span>' if f.rule_name else ""

            findings_html_parts.append(f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="severity-badge" style="background:{color};">{f.severity.upper()}</span>
                    <span class="finding-title">{idx}. {f.title}</span>
                </div>
                <div class="finding-meta">
                    <span class="rule-type">Type: {f.rule_type}</span>
                    {rule_info}
                    <span class="web-acl">WebACL: {f.web_acl_name}</span>
                </div>
                <div class="finding-desc">{f.description}</div>
                {rec_block}
                {details_block}
            </div>""")

        findings_html = "\n".join(findings_html_parts) if findings_html_parts else "<p>No findings.</p>"

        # Severity bar chart
        bar_items: List[str] = []
        for sev in ("critical", "high", "medium", "low", "info"):
            c = counts.get(sev, 0)
            color = sev_colors.get(sev, "#6b7280")
            bar_items.append(
                f'<div class="bar-item">'
                f'<div class="bar-label">{sev.upper()}</div>'
                f'<div class="bar-track"><div class="bar-fill" style="width:{min(c * 10, 100)}%;background:{color};"></div></div>'
                f'<div class="bar-count">{c}</div>'
                f'</div>'
            )
        bar_chart = "\n".join(bar_items)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AWS WAF v2 Audit Report</title>
<style>
  :root {{
    --bg: #f8fafc; --card: #ffffff; --border: #e2e8f0;
    --text: #1e293b; --muted: #64748b;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
  .meta {{ color: var(--muted); font-size: 0.875rem; margin-bottom: 1.5rem; }}
  .summary-card {{ background: var(--card); border: 1px solid var(--border);
                   border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; }}
  .bar-item {{ display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.35rem; }}
  .bar-label {{ width: 70px; font-size: 0.75rem; font-weight: 600; text-align: right; }}
  .bar-track {{ flex: 1; height: 18px; background: #f1f5f9; border-radius: 4px; overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 4px; transition: width 0.4s; min-width: 2px; }}
  .bar-count {{ width: 30px; font-size: 0.8rem; font-weight: 600; }}
  .finding {{ background: var(--card); border: 1px solid var(--border);
              border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1rem; }}
  .finding-header {{ display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }}
  .severity-badge {{ color: #fff; padding: 2px 8px; border-radius: 4px;
                     font-size: 0.7rem; font-weight: 700; letter-spacing: 0.03em; }}
  .finding-title {{ font-weight: 600; }}
  .finding-meta {{ font-size: 0.8rem; color: var(--muted); display: flex; gap: 1rem;
                   flex-wrap: wrap; margin-bottom: 0.5rem; }}
  .finding-desc {{ margin-bottom: 0.5rem; }}
  .recommendation {{ background: #f0fdf4; border-left: 3px solid #22c55e;
                     padding: 0.5rem 0.75rem; margin-bottom: 0.5rem; font-size: 0.9rem; }}
  details {{ margin-top: 0.5rem; }}
  details summary {{ cursor: pointer; font-size: 0.85rem; color: var(--muted); }}
  details pre {{ background: #f1f5f9; padding: 0.75rem; border-radius: 4px;
                 overflow-x: auto; font-size: 0.8rem; margin-top: 0.35rem; }}
  .footer {{ text-align: center; color: var(--muted); font-size: 0.75rem; margin-top: 2rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>AWS WAF v2 Security Audit Report</h1>
  <div class="meta">
    Generated: {self.audit_timestamp} &middot; Scope: {self.scope} &middot;
    WebACLs: {len(self.web_acls)} &middot; Findings: {len(self.findings)}
  </div>

  <div class="summary-card">
    <h2 style="font-size:1.1rem;margin-bottom:0.75rem;">Severity Breakdown</h2>
    {bar_chart}
  </div>

  <h2 style="font-size:1.1rem;margin-bottom:0.75rem;">Findings</h2>
  {findings_html}

  <div class="footer">WAF Auditor &mdash; AuditGH Security Platform</div>
</div>
</body>
</html>"""

        with open(output_path, "w") as fh:
            fh.write(html)
        logger.info("HTML report written to %s", output_path)
        return output_path


# =============================================================================
# Platform Integration
# =============================================================================

def _persist_waf_findings(db_session, repository_id: str, findings: List[WAFFinding]) -> None:
    """Persist WAF findings to the database using the platform's Finding model."""
    if not db_session or not repository_id or not DATABASE_AVAILABLE:
        return

    try:
        repo = db_session.query(models.Repository).filter(
            models.Repository.id == repository_id
        ).first()
        if not repo:
            logger.error("Could not find repository %s for WAF finding persistence", repository_id)
            return

        organization_id = repo.organization_id
        count = 0

        for f in findings:
            platform_dict = f.to_platform_dict()
            finding = models.Finding(
                repository_id=repository_id,
                organization_id=organization_id,
                scanner_name="waf_auditor",
                finding_type="cloud_config",
                title=platform_dict["title"],
                description=platform_dict["description"],
                severity=platform_dict["severity"],
                file_path=platform_dict.get("file_path"),
                code_snippet=platform_dict.get("code_snippet"),
                risk_factors=platform_dict.get("risk_factors"),
                status="open",
            )
            db_session.add(finding)
            count += 1

        db_session.commit()
        logger.info("Persisted %d waf_auditor findings to database", count)

    except Exception as exc:
        logger.error("Failed to persist waf_auditor findings: %s", exc)
        db_session.rollback()


def run_waf_auditor(
    repo_path: str,
    repo_name: str,
    report_dir: str,
    db_session=None,
    repository_id: Optional[str] = None,
    scope: str = "REGIONAL",
) -> Optional[subprocess.CompletedProcess]:
    """Platform integration function matching the run_<scanner> pattern.

    This scanner audits LIVE AWS WAF v2 configs via boto3 and does NOT
    require a repo checkout.  The repo_path argument is accepted for
    signature compatibility but is not used.

    Args:
        repo_path: Unused (kept for signature compatibility with other scanners).
        repo_name: Repository / project name used in report filenames.
        report_dir: Directory to write reports into.
        db_session: Optional SQLAlchemy session for persisting findings.
        repository_id: Optional repository UUID for DB persistence.
        scope: 'REGIONAL' or 'CLOUDFRONT'.

    Returns:
        A synthetic subprocess.CompletedProcess, or None if prerequisites
        are missing (boto3 not installed, no AWS credentials).
    """
    # --- Pre-flight: boto3 ------------------------------------------------
    if not BOTO3_AVAILABLE:
        logger.warning("boto3 is not installed — skipping WAF auditor")
        return None

    # --- Pre-flight: AWS credentials --------------------------------------
    creds_present = any([
        os.environ.get("AWS_ACCESS_KEY_ID"),
        os.environ.get("AWS_PROFILE"),
        os.environ.get("AWS_ROLE_ARN"),
        os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE"),
        os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"),
    ])
    # Also check default credential chain (instance profile, SSO, etc.)
    if not creds_present:
        try:
            boto3.Session().get_credentials()
        except Exception:
            logger.warning("No AWS credentials available — skipping WAF auditor")
            return None

    os.makedirs(report_dir, exist_ok=True)

    output_json = os.path.join(report_dir, f"{repo_name}_waf_auditor.json")
    output_md = os.path.join(report_dir, f"{repo_name}_waf_auditor.md")
    output_html = os.path.join(report_dir, f"{repo_name}_waf_auditor.html")

    try:
        auditor = WAFAuditor(scope=scope)
        auditor.audit_all()

        auditor.generate_json_report(output_json)
        auditor.generate_markdown_report(output_md)
        auditor.generate_html_report(output_html)

        # Persist to database if session provided
        if db_session and repository_id and auditor.findings:
            _persist_waf_findings(db_session, repository_id, auditor.findings)

        summary_lines = []
        counts = auditor._severity_counts()
        for sev in ("critical", "high", "medium", "low", "info"):
            c = counts.get(sev, 0)
            if c:
                summary_lines.append(f"{sev.upper()}: {c}")

        stdout_text = (
            f"WAF Auditor: scanned {len(auditor.web_acls)} WebACL(s), "
            f"{len(auditor.findings)} finding(s) "
            f"[{', '.join(summary_lines) if summary_lines else 'clean'}]"
        )
        logger.info(stdout_text)

        return subprocess.CompletedProcess(
            args=["waf_auditor", "--scope", scope],
            returncode=0 if not auditor.findings else 1,
            stdout=stdout_text,
            stderr="",
        )

    except (NoCredentialsError, PartialCredentialsError) as exc:
        msg = f"AWS credential error: {exc}"
        logger.warning(msg)
        with open(output_md, "w") as fh:
            fh.write(f"# WAF Auditor\n\n**Error:** {msg}\n")
        return subprocess.CompletedProcess(
            args=["waf_auditor"], returncode=1, stdout="", stderr=msg,
        )

    except (ClientError, BotoCoreError) as exc:
        msg = f"AWS API error: {exc}"
        logger.error(msg)
        with open(output_md, "w") as fh:
            fh.write(f"# WAF Auditor\n\n**Error:** {msg}\n")
        return subprocess.CompletedProcess(
            args=["waf_auditor"], returncode=1, stdout="", stderr=msg,
        )

    except Exception as exc:
        msg = f"Unexpected error running WAF auditor: {exc}"
        logger.error(msg, exc_info=True)
        with open(output_md, "w") as fh:
            fh.write(f"# WAF Auditor\n\n**Error:** {msg}\n")
        return subprocess.CompletedProcess(
            args=["waf_auditor"], returncode=1, stdout="", stderr=msg,
        )


# =============================================================================
# Standalone CLI
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AWS WAF v2 Security Auditor — scan live WAF configurations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scan_waf_auditor.py --scope REGIONAL --format all\n"
            "  python scan_waf_auditor.py --scope CLOUDFRONT --format json --output ./reports\n"
            "  python scan_waf_auditor.py --region us-west-2 --format html\n"
        ),
    )
    parser.add_argument(
        "--scope",
        choices=["REGIONAL", "CLOUDFRONT"],
        default="REGIONAL",
        help="WAF scope to audit (default: REGIONAL)",
    )
    parser.add_argument(
        "--region",
        default=None,
        help="AWS region (default: from env/config; CLOUDFRONT forces us-east-1)",
    )
    parser.add_argument(
        "--output",
        default=".",
        help="Output directory for reports (default: current directory)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "html", "markdown", "all"],
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
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    try:
        auditor = WAFAuditor(scope=args.scope, region=args.region)
    except RuntimeError as exc:
        logger.error(str(exc))
        sys.exit(1)

    try:
        auditor.audit_all()
    except (NoCredentialsError, PartialCredentialsError) as exc:
        logger.error("AWS credential error: %s", exc)
        sys.exit(1)
    except (ClientError, BotoCoreError) as exc:
        logger.error("AWS API error: %s", exc)
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)
    fmt = args.format

    if fmt in ("json", "all"):
        auditor.generate_json_report(os.path.join(args.output, "waf_audit.json"))
    if fmt in ("markdown", "all"):
        auditor.generate_markdown_report(os.path.join(args.output, "waf_audit.md"))
    if fmt in ("html", "all"):
        auditor.generate_html_report(os.path.join(args.output, "waf_audit.html"))

    counts = auditor._severity_counts()
    total = len(auditor.findings)
    print(
        f"\nAudit complete: {len(auditor.web_acls)} WebACL(s), "
        f"{total} finding(s)"
    )
    for sev in ("critical", "high", "medium", "low", "info"):
        c = counts.get(sev, 0)
        if c:
            print(f"  {sev.upper()}: {c}")

    # Exit code: non-zero if any critical or high findings
    if counts.get("critical", 0) + counts.get("high", 0) > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
