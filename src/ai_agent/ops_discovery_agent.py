"""
AI-powered Repository Operations Discovery Agent.

Analyzes repository content to infer deployment status, hosting platform,
CI/CD pipeline, infrastructure-as-code, and compliance indicators.
Returns structured suggestions with confidence scores and evidence.
"""
import json
import logging
from typing import Any, Dict, List, Optional

from src.services.prompt_loader import render_prompt

logger = logging.getLogger(__name__)


class OpsDiscoveryAgent:
    """Discovers operational context by analyzing repository files."""

    # Evidence files to look for (ordered by priority)
    EVIDENCE_FILES = [
        # CI/CD
        ".github/workflows",
        ".gitlab-ci.yml",
        "Jenkinsfile",
        "azure-pipelines.yml",
        ".circleci/config.yml",
        # Containers
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        # Kubernetes
        "k8s/",
        "kubernetes/",
        "helm/",
        "charts/",
        # IaC
        "terraform/",
        "*.tf",
        "bicep/",
        "*.bicep",
        "cloudformation/",
        "pulumi/",
        "ansible/",
        # Cloud configs
        ".aws/",
        "ecs-task-def*.json",
        "appspec.yml",
        "serverless.yml",
        "vercel.json",
        "netlify.toml",
        "Procfile",
        "app.yaml",
        "fly.toml",
        # Documentation
        "README.md",
        "CONTRIBUTING.md",
        "docs/",
        # Package managers
        "package.json",
        "requirements.txt",
        "Pipfile",
        "go.mod",
        "pom.xml",
        "build.gradle",
    ]

    # Maximum number of files to read content from
    MAX_FILES_TO_READ = 10

    # Maximum content size per file (characters) to avoid bloating the prompt
    MAX_FILE_CONTENT_SIZE = 8000

    # Priority tiers for file reading (higher priority files get read first)
    HIGH_PRIORITY_PATTERNS = [
        ".github/workflows", ".gitlab-ci.yml", "Jenkinsfile",
        "azure-pipelines.yml", ".circleci/config.yml",
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
        "terraform/", "*.tf", "bicep/", "*.bicep",
        "cloudformation/", "serverless.yml", "vercel.json",
        "netlify.toml", "fly.toml", "appspec.yml",
        "k8s/", "kubernetes/", "helm/", "charts/",
    ]

    def __init__(self, ai_provider, github_api=None):
        """
        Initialize with an AI provider and optional GitHub API client.

        Args:
            ai_provider: AI provider instance with execute_prompt() method
            github_api: GitHubAPI instance for fetching repository contents
        """
        self.ai_provider = ai_provider
        self.github_api = github_api

    async def discover(self, repo_name: str, repo_data: dict = None) -> dict:
        """
        Run full discovery on a repository.

        Args:
            repo_name: Repository name (without org prefix)
            repo_data: Optional dict with repo metadata (language, description, archived, etc.)

        Returns:
            {
                "suggestions": [
                    {"field": "deployment_status", "value": "production", "confidence": 0.92, "evidence": "..."},
                    {"field": "hosting_platform", "value": "aws", "confidence": 0.87, "evidence": "..."},
                    ...
                ],
                "evidence_files": ["Dockerfile", ".github/workflows/deploy.yml", ...],
                "raw_ai_response": "..."
            }
        """
        repo_data = repo_data or {}

        # 1. Gather evidence files from GitHub API
        evidence = await self._gather_evidence(repo_name)

        # 2. Build context for AI analysis
        context = self._build_context(repo_name, evidence, repo_data)

        # 3. Call AI to analyze and produce structured suggestions
        result = await self._analyze_with_ai(repo_name, context)

        # Attach the list of evidence files found
        result["evidence_files"] = list(evidence.keys())

        return result

    async def _gather_evidence(self, repo_name: str) -> Dict[str, Optional[str]]:
        """
        Fetch evidence files from the repository.

        Uses github_api to get the file tree and then reads the contents
        of the most relevant files.

        Args:
            repo_name: Repository name

        Returns:
            Dict mapping file_path -> content (content may be None for dirs)
        """
        if not self.github_api:
            logger.warning("No GitHub API client provided; skipping evidence gathering")
            return {}

        # Get the root file tree (2 levels deep to catch nested configs)
        tree = self.github_api.get_file_tree(repo_name, path="", depth=2)

        if not tree:
            logger.warning("Empty file tree for %s", repo_name)
            return {}

        # Build a set of discovered paths for quick lookup
        tree_paths = {item['path']: item for item in tree}

        # Find which evidence files exist in the repo
        matched_paths = []
        for pattern in self.EVIDENCE_FILES:
            if pattern.endswith('/'):
                # Directory pattern — match any path starting with the dir name
                dir_name = pattern.rstrip('/')
                for path, item in tree_paths.items():
                    if path == dir_name or path.startswith(dir_name + '/'):
                        matched_paths.append(path)
            elif '*' in pattern:
                # Glob-style pattern — simple suffix matching
                suffix = pattern.replace('*', '')
                for path in tree_paths:
                    if path.endswith(suffix):
                        matched_paths.append(path)
            else:
                # Exact match
                if pattern in tree_paths:
                    matched_paths.append(pattern)

        # Deduplicate while preserving order
        seen = set()
        unique_paths = []
        for p in matched_paths:
            if p not in seen:
                seen.add(p)
                unique_paths.append(p)

        # Sort by priority: high-priority patterns first
        def _priority_score(path: str) -> int:
            for idx, pattern in enumerate(self.HIGH_PRIORITY_PATTERNS):
                pat = pattern.rstrip('/')
                if path == pat or path.startswith(pat + '/') or path.endswith(pat):
                    return idx
            return len(self.HIGH_PRIORITY_PATTERNS)

        unique_paths.sort(key=_priority_score)

        # Read file contents for the top N readable files
        evidence: Dict[str, Optional[str]] = {}
        files_read = 0

        for path in unique_paths:
            item = tree_paths.get(path, {})

            if item.get('type') == 'dir':
                # Record directory existence but don't read content
                evidence[path] = None
                continue

            if files_read >= self.MAX_FILES_TO_READ:
                # Still record the file exists, but skip reading
                evidence[path] = None
                continue

            content = self.github_api.get_file_content(repo_name, path)
            if content is not None:
                # Truncate very large files
                if len(content) > self.MAX_FILE_CONTENT_SIZE:
                    content = content[:self.MAX_FILE_CONTENT_SIZE] + "\n... [truncated]"
                evidence[path] = content
                files_read += 1
            else:
                evidence[path] = None

        return evidence

    def _build_context(
        self, repo_name: str, evidence: Dict[str, Optional[str]], repo_data: dict
    ) -> dict:
        """
        Build a structured context dict for the AI prompt.

        Args:
            repo_name: Repository name
            evidence: Dict of file_path -> content (or None)
            repo_data: Repository metadata

        Returns:
            Dict with keys matching the prompt template variables
        """
        # Evidence summary: list of files found with type indicators
        evidence_lines = []
        for path, content in evidence.items():
            if content is not None:
                evidence_lines.append(f"  [FILE] {path} ({len(content)} chars)")
            else:
                evidence_lines.append(f"  [DIR/UNREAD] {path}")
        evidence_summary = "\n".join(evidence_lines) if evidence_lines else "No evidence files found."

        # File contents block
        content_blocks = []
        for path, content in evidence.items():
            if content is not None:
                content_blocks.append(f"--- {path} ---\n{content}\n")
        file_contents = "\n".join(content_blocks) if content_blocks else "No file contents available."

        return {
            "repo_name": repo_name,
            "language": repo_data.get("language") or "Unknown",
            "description": repo_data.get("description") or "No description provided",
            "evidence_summary": evidence_summary,
            "file_contents": file_contents,
        }

    async def _analyze_with_ai(self, repo_name: str, context: dict) -> dict:
        """
        Call AI provider to analyze the evidence and return suggestions.

        Args:
            repo_name: Repository name
            context: Dict of prompt template variables

        Returns:
            {
                "suggestions": [...],
                "evidence_files": [],
                "raw_ai_response": "..."
            }
        """
        # Render the managed prompt
        prompt = render_prompt("repo-ops-discovery", variables=context)
        if not prompt:
            logger.error("Prompt 'repo-ops-discovery' not found in any tier")
            prompt = (
                f"Analyze the operational context of repository \"{repo_name}\".\n\n"
                f"Evidence files:\n{context.get('evidence_summary', 'None')}\n\n"
                f"File contents:\n{context.get('file_contents', 'None')}\n\n"
                "Return JSON with suggestions for deployment_status, hosting_platform, "
                "deployment_method, cicd_platform, iac_type, container_registry, "
                "business_criticality, and data_classification. "
                "Each suggestion should have: field, value, confidence (0-1), evidence."
            )

        try:
            response = await self.ai_provider.execute_prompt(prompt)
            raw_response = response.strip()

            # Parse JSON from the AI response
            suggestions = self._parse_suggestions(raw_response)

            return {
                "suggestions": suggestions,
                "evidence_files": [],
                "raw_ai_response": raw_response,
            }

        except Exception as e:
            logger.error("Failed to analyze ops context for %s: %s", repo_name, e)
            return {
                "suggestions": [],
                "evidence_files": [],
                "raw_ai_response": f"Analysis failed: {str(e)}",
            }

    def _parse_suggestions(self, raw_response: str) -> List[Dict[str, Any]]:
        """
        Parse structured suggestions from the AI response.

        Attempts to extract a JSON object from the response text,
        handling cases where the model wraps JSON in markdown code fences.

        Args:
            raw_response: Raw text response from the AI provider

        Returns:
            List of suggestion dicts with field, value, confidence, evidence
        """
        text = raw_response.strip()

        # Strip markdown code fences if present
        if text.startswith("```"):
            # Remove opening fence (```json or ```)
            first_newline = text.index('\n') if '\n' in text else len(text)
            text = text[first_newline + 1:]
        if text.endswith("```"):
            text = text[:-3].rstrip()

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            # Try to find JSON object within the text
            start = text.find('{')
            end = text.rfind('}')
            if start != -1 and end != -1 and end > start:
                try:
                    parsed = json.loads(text[start:end + 1])
                except json.JSONDecodeError:
                    logger.warning("Could not parse JSON from AI response")
                    return []
            else:
                logger.warning("No JSON object found in AI response")
                return []

        suggestions = parsed.get("suggestions", [])

        # Validate each suggestion has required fields
        validated = []
        for s in suggestions:
            if isinstance(s, dict) and "field" in s and "value" in s:
                validated.append({
                    "field": s["field"],
                    "value": s["value"],
                    "confidence": float(s.get("confidence", 0.0)),
                    "evidence": s.get("evidence", ""),
                })

        return validated
