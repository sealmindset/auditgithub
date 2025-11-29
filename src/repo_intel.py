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

    def _analyze_contributors(self) -> Dict[str, Any]:
        """Analyze contributor statistics."""
        # Get all committers
        log = self._run_git(["log", "--format=%aN|%aE"])
        if not log:
            return {}
            
        lines = log.splitlines()
        total_commits = len(lines)
        contributors = Counter(lines)
        
        # Top contributors
        top_contributors = []
        for author, count in contributors.most_common(10):
            name, email = author.split("|", 1)
            top_contributors.append({
                "name": name,
                "email": email,
                "commits": count,
                "percentage": round((count / total_commits) * 100, 1)
            })
            
        # Bus Factor (simple heuristic: how many devs account for 50% of commits?)
        running_sum = 0
        bus_factor = 0
        for _, count in contributors.most_common():
            running_sum += count
            bus_factor += 1
            if running_sum > (total_commits * 0.5):
                break
                
        return {
            "total_contributors": len(contributors),
            "total_commits": total_commits,
            "bus_factor": bus_factor,
            "top_contributors": top_contributors
        }

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
