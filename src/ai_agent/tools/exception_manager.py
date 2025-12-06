from typing import Dict, Any, Optional, List
import logging
import re

logger = logging.getLogger(__name__)

class ExceptionManager:
    """
    Tool for generating exception rules for various security scanners.
    """

    def generate_rule(self, scanner: str, finding: Dict[str, Any], scope: str) -> Dict[str, Any]:
        """
        Generate an exception rule based on the scanner and finding details.

        Args:
            scanner: Name of the scanner (e.g., 'gitleaks', 'trufflehog', 'semgrep').
            finding: Dictionary containing finding details (file_path, line, secret, etc.).
            scope: 'global' or 'specific'.

        Returns:
            Dict containing the generated rule, description, and format.
        """
        scanner = scanner.lower()
        
        if "gitleaks" in scanner:
            return self._generate_gitleaks_rule(finding, scope)
        elif "trufflehog" in scanner:
            return self._generate_trufflehog_rule(finding, scope)
        elif "semgrep" in scanner:
            return self._generate_semgrep_rule(finding, scope)
        else:
            return self._generate_generic_rule(finding, scope)

    def _generate_gitleaks_rule(self, finding: Dict[str, Any], scope: str) -> Dict[str, Any]:
        """Generate Gitleaks allowlist rule."""
        file_path = finding.get("file_path", "")
        secret = finding.get("code_snippet", "") # Assuming secret is in code_snippet for now
        
        rule = {
            "description": f"Allowlist for {finding.get('title', 'finding')}",
            "regex": "",
            "paths": []
        }

        if scope == "global":
            # Global usually means ignoring a file pattern or directory
            if file_path:
                # Simple heuristic: if it's a file, ignore that file. If directory, ignore directory.
                # For now, let's ignore the specific file path globally
                rule["paths"] = [re.escape(file_path)]
                rule["description"] += f" in {file_path}"
        else:
            # Specific means ignoring this specific secret in this specific file
            if secret:
                rule["regex"] = re.escape(secret)
            if file_path:
                rule["paths"] = [re.escape(file_path)]
        
        return {
            "format": "gitleaks.toml",
            "rule": rule,
            "instruction": "Add this to your [allowlist] section in gitleaks.toml"
        }

    def _generate_trufflehog_rule(self, finding: Dict[str, Any], scope: str) -> Dict[str, Any]:
        """Generate TruffleHog exclusion."""
        file_path = finding.get("file_path", "")
        
        if scope == "global":
            return {
                "format": "cli_arg",
                "rule": f"--exclude-paths {file_path}",
                "instruction": "Add this argument to your trufflehog command"
            }
        else:
            # TruffleHog is harder to ignore specific instances without a config file
            # Assuming we can use a similar exclude path mechanism or inline comment if supported
            return {
                "format": "manual",
                "rule": f"Ignore {file_path}",
                "instruction": "TruffleHog requires excluding the file path or using a configuration file."
            }

    def _generate_semgrep_rule(self, finding: Dict[str, Any], scope: str) -> Dict[str, Any]:
        """Generate Semgrep ignore rule."""
        file_path = finding.get("file_path", "")
        rule_id = finding.get("rule_id", "unknown-rule") # We might need to extract this
        
        if scope == "global":
            return {
                "format": ".semgrepignore",
                "rule": f"{file_path}",
                "instruction": "Add this line to your .semgrepignore file"
            }
        else:
            return {
                "format": "inline_comment",
                "rule": f"// nosemgrep: {rule_id}",
                "instruction": "Add this comment above the offending line in your code"
            }

    def _generate_generic_rule(self, finding: Dict[str, Any], scope: str) -> Dict[str, Any]:
        """Fallback for unknown scanners."""
        return {
            "format": "text",
            "rule": f"Ignore {finding.get('title')} in {finding.get('file_path')}",
            "instruction": "Manual exception required for this scanner."
        }
