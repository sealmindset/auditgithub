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
    
    def __init__(self, repo_path: str, repo_name: str):
        self.repo_path = repo_path
        self.repo_name = repo_name
        
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
        """Analyze contributor statistics."""
        # Get all committers with timestamp and files changed
        # Format: AuthorName|AuthorEmail|Timestamp
        log = self._run_git(["log", "--format=%aN|%aE|%ct"])
        if not log:
            return {}
            
        lines = log.splitlines()
        total_commits = len(lines)
        
        contributors_stats = {}
        
        for line in lines:
            try:
                parts = line.split("|")
                if len(parts) < 3:
                    continue
                name, email, ts = parts[0], parts[1], int(parts[2])
                
                key = f"{name}|{email}"
                if key not in contributors_stats:
                    contributors_stats[key] = {
                        "name": name,
                        "email": email,
                        "commits": 0,
                        "last_commit_ts": 0,
                        "languages": set()
                    }
                
                stats = contributors_stats[key]
                stats["commits"] += 1
                if ts > stats["last_commit_ts"]:
                    stats["last_commit_ts"] = ts
                    
            except ValueError:
                continue

        # Infer languages (expensive, so we sample recent commits per author)
        # For now, let's just use a simple heuristic:
        # We can't easily get per-commit file stats in a single fast command for all history.
        # So we'll skip per-contributor languages for now to keep it fast, 
        # or we could run a separate pass for top contributors.
        # Let's try to get file extensions from the last 1000 commits and map to authors.
        
        # Optimized approach: Get author and changed files for last 1000 commits
        # git log -n 1000 --name-only --format=">>>%aN|%aE"
        try:
            log_files = self._run_git(["log", "-n", "1000", "--name-only", "--format=>>>%aN|%aE"])
            current_author = None
            if log_files:
                for line in log_files.splitlines():
                    if line.startswith(">>>"):
                        current_author = line[3:].strip()
                    elif line.strip() and current_author:
                        ext = os.path.splitext(line)[1].lower()
                        if ext and current_author in contributors_stats:
                            # Map extension to language (simplified)
                            lang = self._ext_to_lang(ext)
                            if lang:
                                contributors_stats[current_author]["languages"].add(lang)
        except Exception as e:
            logger.warning(f"Failed to analyze languages: {e}")

        # Format results
        top_contributors = []
        for key, stats in contributors_stats.items():
            top_contributors.append({
                "name": stats["name"],
                "email": stats["email"],
                "commits": stats["commits"],
                "percentage": round((stats["commits"] / total_commits) * 100, 1),
                "last_commit_at": datetime.datetime.fromtimestamp(stats["last_commit_ts"]).isoformat(),
                "languages": list(stats["languages"])
            })
            
        # Sort by commits
        top_contributors.sort(key=lambda x: x["commits"], reverse=True)
            
        # Bus Factor
        running_sum = 0
        bus_factor = 0
        for c in top_contributors:
            running_sum += c["commits"]
            bus_factor += 1
            if running_sum > (total_commits * 0.5):
                break
                
        return {
            "total_contributors": len(contributors_stats),
            "total_commits": total_commits,
            "bus_factor": bus_factor,
            "top_contributors": top_contributors
        }

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

def analyze_repo(repo_path: str, repo_name: str, report_dir: str) -> Optional[str]:
    """
    Main entry point for Repo Intelligence.
    Generates a JSON and Markdown report.
    """
    try:
        intel = RepoIntel(repo_path, repo_name)
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
                f.write(f"| {c['name']} | {c['commits']} | {c['percentage']}%\n")
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
