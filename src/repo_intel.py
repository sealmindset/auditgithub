import os
import logging
import subprocess
import json
import datetime
from typing import Dict, Any, List, Optional
from collections import Counter

logger = logging.getLogger(__name__)

class RepoIntel:
    """
    Repository Intelligence (OSINT) Analyzer.
    Analyzes git history, contributors, and metadata to identify risks.
    """

    def __init__(self, repo_path: str, repo_name: str, findings_by_file: Optional[Dict[str, List[Dict]]] = None):
        """
        Initialize RepoIntel analyzer.

        Args:
            repo_path: Path to the repository
            repo_name: Name of the repository
            findings_by_file: Optional dict mapping file paths to their security findings
                             e.g., {"src/api.py": [{"severity": "high", "type": "sast"}, ...]}
        """
        self.repo_path = repo_path
        self.repo_name = repo_name
        self.findings_by_file = findings_by_file or {}

    def analyze(self) -> Dict[str, Any]:
        """Run all intelligence checks."""
        logger.info(f"Running Repo Intelligence for {self.repo_name}...")

        return {
            "contributors": self._analyze_contributors(),
            "languages": self._analyze_languages(),
            "commit_patterns": self._analyze_commit_patterns(),
            "risk_indicators": self._check_risk_indicators()
        }
        
    def _run_git(self, args: List[str]) -> str:
        """Helper to run git commands."""
        try:
            result = subprocess.run(
                ["git"] + args,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            # 128 usually means empty repo or not a git repo
            if e.returncode != 128:
                logger.warning(f"Git command failed: {e}")
            return ""

    def _analyze_languages(self) -> Dict[str, Any]:
        """Analyze language statistics using cloc."""
        try:
            # Run cloc and get JSON output
            # cloc --json .
            result = subprocess.run(
                ["cloc", "--json", "."],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=False # Don't raise on error, handle it
            )
            
            if result.returncode != 0:
                logger.warning(f"cloc failed: {result.stderr}")
                return {}
                
            # Clean output: cloc might print warnings after JSON
            output = result.stdout.strip()
            if not output.endswith("}"):
                # Try to find the last closing brace
                last_brace = output.rfind("}")
                if last_brace != -1:
                    output = output[:last_brace+1]
            
            data = json.loads(output)
            
            # Remove header/footer keys if present
            if "header" in data:
                del data["header"]
            if "SUM" in data:
                del data["SUM"]
                
            return data
            
        except Exception as e:
            logger.warning(f"Language analysis failed: {e}")
            return {}

    def _analyze_contributors(self) -> Dict[str, Any]:
        """
        Analyze contributor statistics with file-level severity data.

        Collects:
        - Contributor identity (name, email, github_username)
        - Total commits and percentage
        - Files contributed with severity ratings
        - Folders contributed
        - Languages inferred from file extensions
        """
        # Get detailed git log with file changes
        # Format: CommitHash|AuthorName|AuthorEmail|Timestamp followed by changed files
        log_with_files = self._run_git([
            "log",
            "--format=%H|%aN|%aE|%ct",
            "--name-only",
            "--no-merges"
        ])

        if not log_with_files:
            return {}

        contributors_stats = {}  # email -> contributor data
        total_commits = 0
        current_commit = None

        for line in log_with_files.splitlines():
            if not line.strip():
                continue

            if "|" in line:
                # Commit header line: hash|name|email|timestamp
                parts = line.split("|")
                if len(parts) >= 4:
                    commit_hash, name, email, timestamp = parts[0], parts[1], parts[2], parts[3]
                    try:
                        ts = int(timestamp)
                    except ValueError:
                        ts = 0

                    current_commit = {'name': name, 'email': email, 'timestamp': ts}
                    total_commits += 1

                    key = f"{name}|{email}"
                    if key not in contributors_stats:
                        contributors_stats[key] = {
                            'name': name,
                            'email': email,
                            'github_username': self._extract_github_username(email),
                            'commits': 0,
                            'files': {},  # path -> {"count": N, "severity": "high", "findings_count": N}
                            'folders': set(),
                            'languages': set(),
                            'last_commit_ts': 0
                        }

                    contributors_stats[key]['commits'] += 1
                    if ts > contributors_stats[key]['last_commit_ts']:
                        contributors_stats[key]['last_commit_ts'] = ts

            else:
                # File path line
                if current_commit and line.strip():
                    file_path = line.strip()
                    key = f"{current_commit['name']}|{current_commit['email']}"

                    if key in contributors_stats:
                        stats = contributors_stats[key]

                        # Track file with severity from findings
                        if file_path not in stats['files']:
                            # Get severity from findings
                            file_findings = self.findings_by_file.get(file_path, [])
                            max_severity = self._get_max_severity(file_findings)
                            findings_count = len(file_findings)

                            stats['files'][file_path] = {
                                'severity': max_severity,
                                'findings_count': findings_count
                            }

                        # Track folder
                        if '/' in file_path:
                            stats['folders'].add(file_path.split('/')[0])
                        else:
                            stats['folders'].add('(root)')

                        # Infer language from extension
                        lang = self._ext_to_lang(os.path.splitext(file_path)[1].lower())
                        if lang:
                            stats['languages'].add(lang)

        # Build result with file severity data
        top_contributors = []
        for key, data in contributors_stats.items():
            percentage = (data['commits'] / total_commits * 100) if total_commits > 0 else 0

            # Convert files dict to list with severity
            files_with_severity = [
                {
                    'path': path,
                    'severity': info['severity'],
                    'findings_count': info['findings_count']
                }
                for path, info in data['files'].items()
            ]

            # Sort by severity (critical > high > medium > low > none)
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, None: 4}
            files_with_severity.sort(key=lambda x: (severity_order.get(x['severity'], 5), x['path']))

            # Calculate risk score based on file severities
            risk_score = self._calculate_contributor_risk(files_with_severity)

            # Format timestamp
            try:
                last_commit_at = datetime.datetime.fromtimestamp(data['last_commit_ts']).isoformat()
            except (ValueError, OSError):
                last_commit_at = None

            top_contributors.append({
                'name': data['name'],
                'email': data['email'],
                'github_username': data['github_username'],
                'commits': data['commits'],
                'commit_percentage': round(percentage, 2),
                'last_commit_at': last_commit_at,
                'languages': sorted(list(data['languages'])),
                'files_contributed': files_with_severity[:200],  # Limit to 200 files
                'folders_contributed': sorted(list(data['folders'])),
                'risk_score': risk_score
            })

        # Sort by commits descending
        top_contributors.sort(key=lambda x: x['commits'], reverse=True)

        # Calculate bus factor
        running_sum = 0
        bus_factor = 0
        for c in top_contributors:
            running_sum += c['commits']
            bus_factor += 1
            if running_sum > (total_commits * 0.5):
                break

        return {
            'total_contributors': len(top_contributors),
            'total_commits': total_commits,
            'bus_factor': bus_factor,
            'top_contributors': top_contributors
        }

    def _get_max_severity(self, findings: List[Dict]) -> Optional[str]:
        """Get the maximum severity from a list of findings."""
        if not findings:
            return None

        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        max_sev = None
        max_order = 999

        for finding in findings:
            sev = finding.get('severity', '').lower() if finding.get('severity') else ''
            if sev in severity_order and severity_order[sev] < max_order:
                max_order = severity_order[sev]
                max_sev = sev

        return max_sev

    def _calculate_contributor_risk(self, files: List[Dict]) -> int:
        """
        Calculate contributor risk score (0-100) based on file severities.

        Scoring:
        - Critical finding: +25 points per file
        - High finding: +15 points per file
        - Medium finding: +5 points per file
        - Low finding: +1 point per file
        """
        score = 0
        severity_points = {'critical': 25, 'high': 15, 'medium': 5, 'low': 1}

        for file in files:
            sev = file.get('severity')
            if sev:
                score += severity_points.get(sev.lower(), 0)

        return min(100, score)  # Cap at 100

    def _extract_github_username(self, email: str) -> Optional[str]:
        """Extract GitHub username from noreply email."""
        if not email:
            return None
        if 'noreply.github.com' in email:
            local_part = email.split('@')[0]
            if '+' in local_part:
                return local_part.split('+')[1]
            return local_part
        return None

    def _ext_to_lang(self, ext: str) -> Optional[str]:
        """Map file extension to language."""
        map = {
            ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
            ".jsx": "JavaScript", ".go": "Go", ".java": "Java", ".c": "C", ".cpp": "C++",
            ".rb": "Ruby", ".php": "PHP", ".rs": "Rust", ".html": "HTML", ".css": "CSS",
            ".sh": "Shell", ".yml": "YAML", ".yaml": "YAML", ".json": "JSON", ".md": "Markdown",
            ".sql": "SQL", ".dockerfile": "Docker"
        }
        return map.get(ext)

    def _analyze_commit_patterns(self) -> Dict[str, Any]:
        """Analyze when commits happen."""
        # Get timestamps
        timestamps = self._run_git(["log", "--format=%ct"]).splitlines()
        if not timestamps:
            return {}
            
        hours = Counter()
        weekdays = Counter()
        
        for ts in timestamps:
            dt = datetime.datetime.fromtimestamp(int(ts))
            hours[dt.hour] += 1
            weekdays[dt.weekday()] += 1
            
        # Detect "night" commits (10 PM - 5 AM local time of committer)
        # Note: Git stores UTC, but we can infer patterns. 
        # For simplicity, we just report the distribution.
        
        return {
            "hours_distribution": dict(hours),
            "weekdays_distribution": dict(weekdays)
        }

    def _check_risk_indicators(self) -> List[str]:
        """Check for specific risk flags."""
        risks = []
        
        # Check for "drive-by" commits (single commit authors)
        log = self._run_git(["log", "--format=%aN"])
        if log:
            counts = Counter(log.splitlines())
            single_commit_authors = sum(1 for c in counts.values() if c == 1)
            if single_commit_authors / len(counts) > 0.5:
                risks.append("High ratio of drive-by contributors (>50%)")
                
        # Check for recent activity
        last_commit = self._run_git(["log", "-1", "--format=%ct"])
        if last_commit:
            days_since = (datetime.datetime.now().timestamp() - int(last_commit)) / 86400
            if days_since > 365:
                risks.append("Repo is inactive (no commits in >1 year)")
                
        return risks

def analyze_repo(
    repo_path: str,
    repo_name: str,
    report_dir: str,
    findings_by_file: Optional[Dict[str, List[Dict]]] = None
) -> Optional[str]:
    """
    Main entry point for Repo Intelligence.
    Generates a JSON and Markdown report.

    Args:
        repo_path: Path to the repository
        repo_name: Name of the repository
        report_dir: Directory to write reports
        findings_by_file: Optional dict mapping file paths to findings for severity analysis
    """
    try:
        intel = RepoIntel(repo_path, repo_name, findings_by_file=findings_by_file)
        data = intel.analyze()
        
        os.makedirs(report_dir, exist_ok=True)
        json_path = os.path.join(report_dir, f"{repo_name}_intel.json")
        md_path = os.path.join(report_dir, f"{repo_name}_intel.md")
        
        with open(json_path, "w") as f:
            json.dump(data, f, indent=2)
            
        # Generate Markdown
        with open(md_path, "w") as f:
            f.write(f"# Repository Intelligence: {repo_name}\n\n")
            
            # Contributors
            contribs = data.get("contributors", {})
            f.write("## 👥 Contributors\n")
            f.write(f"- **Total Contributors:** {contribs.get('total_contributors', 0)}\n")
            f.write(f"- **Total Commits:** {contribs.get('total_commits', 0)}\n")
            f.write(f"- **Bus Factor:** {contribs.get('bus_factor', '?')} (devs for 50% of code)\n\n")
            
            f.write("### Top Contributors\n")
            f.write("| Name | Commits | %\n")
            f.write("|------|---------|---\n")
            for c in contribs.get("top_contributors", []):
                f.write(f"| {c['name']} | {c['commits']} | {c['commit_percentage']}%\n")
            f.write("\n")
            
            # Risks
            risks = data.get("risk_indicators", [])
            f.write("## 🚩 Risk Indicators\n")
            if risks:
                for r in risks:
                    f.write(f"- ⚠️ {r}\n")
            else:
                f.write("- No obvious contributor risks detected.\n")
                
        return md_path
        
    except Exception as e:
        logger.error(f"Repo Intel failed: {e}")
        return None

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run Repo Intelligence")
    parser.add_argument("--repo-path", required=True, help="Path to repository")
    parser.add_argument("--repo-name", required=True, help="Name of repository")
    parser.add_argument("--report-dir", default="vulnerability_reports", help="Output directory")
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)
    analyze_repo(args.repo_path, args.repo_name, args.report_dir)
