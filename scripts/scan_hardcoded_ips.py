#!/usr/bin/env python3
"""
Scan GitHub repositories for hardcoded IP addresses and hostnames using Semgrep.
"""
import os
import sys
import json
import logging
import subprocess
import argparse
import tempfile
import shutil
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin

# Load environment variables
from dotenv import load_dotenv
load_dotenv(override=True)

# Configure GitHub API
GITHUB_API = os.getenv('GITHUB_API', 'https://api.github.com')
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
GITHUB_ORG = os.getenv('GITHUB_ORG')

if not GITHUB_TOKEN or not GITHUB_ORG:
    print("Error: GITHUB_TOKEN and GITHUB_ORG must be set in environment or .env file")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class GitHubRepositoryManager:
    """Manages GitHub repository operations."""
    
    def __init__(self, github_token: str, github_org: str, api_url: str = GITHUB_API):
        """Initialize with GitHub credentials."""
        self.github_token = github_token
        self.github_org = github_org
        self.api_url = api_url
        self.headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
    
    def get_repositories(self, include_forks: bool = False, include_archived: bool = False) -> List[Dict]:
        """Fetch all repositories from the organization."""
        url = f"{self.api_url}/orgs/{self.github_org}/repos?per_page=100"
        repos = []
        
        while url:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            for repo in response.json():
                if not include_forks and repo.get('fork'):
                    continue
                if not include_archived and repo.get('archived'):
                    continue
                repos.append({
                    'name': repo['name'],
                    'clone_url': repo['clone_url'],
                    'ssh_url': repo['ssh_url'],
                    'default_branch': repo['default_branch'],
                    'archived': repo.get('archived', False),
                    'fork': repo.get('fork', False)
                })
            
            # Handle pagination
            if 'next' in response.links:
                url = response.links['next']['url']
            else:
                url = None
        
        return repos
    
    def clone_repository(self, repo: Dict, target_dir: Path) -> Optional[Path]:
        """Clone a repository to the target directory."""
        try:
            repo_name = repo['name']
            clone_dir = target_dir / repo_name
            
            if clone_dir.exists():
                logger.info(f"Repository {repo_name} already exists, pulling latest changes...")
                try:
                    subprocess.run(
                        ['git', '-C', str(clone_dir), 'pull'],
                        check=True,
                        capture_output=True,
                        text=True
                    )
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to update repository {repo_name}: {e.stderr}")
                    return None
            else:
                logger.info(f"Cloning {repo_name}...")
                try:
                    subprocess.run(
                        ['git', 'clone', '--depth', '1', repo['clone_url'], str(clone_dir)],
                        check=True,
                        capture_output=True,
                        text=True
                    )
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to clone repository {repo_name}: {e.stderr}")
                    return None
            
            return clone_dir
            
        except Exception as e:
            logger.error(f"Error processing repository {repo.get('name', 'unknown')}: {e}")
            return None


class HardcodedIPScanner:
    """Scanner for detecting hardcoded IP addresses and hostnames in repositories."""
    
    def __init__(self, output_dir: str = "hardcoded_ips_reports", github_token: str = None, github_org: str = None):
        """Initialize the scanner with output directory and GitHub credentials."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.rules_file = Path(__file__).parent / "semgrep-rules" / "hardcoded-ips-hostnames.yaml"
        self.github_token = github_token or GITHUB_TOKEN
        self.github_org = github_org or GITHUB_ORG
        
        if not self.rules_file.exists():
            raise FileNotFoundError(f"Rules file not found: {self.rules_file}")
            
        if self.github_token and self.github_org:
            self.github = GitHubRepositoryManager(self.github_token, self.github_org)
    
    def run_semgrep(self, target_dir: Path) -> Dict[str, Any]:
        """Run Semgrep on the target directory and return results."""
        try:
            cmd = [
                "semgrep",
                "--config", str(self.rules_file),
                "--json",
                "--no-git-ignore",  # Scan all files, including those in .gitignore
                "--metrics", "off",
                "--error",  # Return non-zero exit code on findings
                str(target_dir)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False  # Don't raise exception on non-zero exit code
            )
            
            if result.stderr:
                logger.warning(f"Semgrep stderr: {result.stderr}")
                
            if result.returncode not in (0, 1):  # 0: no findings, 1: findings found
                logger.error(f"Semgrep failed with return code {result.returncode}")
                return {"results": [], "errors": [f"Semgrep failed: {result.stderr}"]}
                
            return json.loads(result.stdout) if result.stdout else {"results": []}
            
        except Exception as e:
            logger.error(f"Error running Semgrep: {e}")
            return {"results": [], "errors": [str(e)]}
    
    def process_repository(self, repo_path: Path) -> Dict[str, Any]:
        """Process a single repository and return findings."""
        repo_name = repo_path.name
        logger.info(f"Scanning repository: {repo_name}")
        
        # Check if the path exists
        if not repo_path.exists():
            logger.error(f"Repository path does not exist: {repo_path}")
            return {
                "repository": repo_name,
                "path": str(repo_path),
                "timestamp": datetime.utcnow().isoformat(),
                "findings": [],
                "findings_count": 0,
                "errors": [f"Repository path does not exist: {repo_path}"]
            }
            
        results = self.run_semgrep(repo_path)
        
        # Process and format the results
        findings = []
        for result in results.get("results", []):
            finding = {
                "check_id": result.get("check_id", ""),
                "path": result.get("path", ""),
                "start_line": result.get("start", {}).get("line", 0),
                "end_line": result.get("end", {}).get("line", 0),
                "message": result.get("extra", {}).get("message", ""),
                "severity": result.get("extra", {}).get("severity", "INFO"),
                "lines": result.get("extra", {}).get("lines", []),
                "metadata": result.get("extra", {}).get("metadata", {})
            }
            findings.append(finding)
        
        return {
            "repository": repo_name,
            "path": str(repo_path),
            "timestamp": datetime.utcnow().isoformat(),
            "findings": findings,
            "findings_count": len(findings),
            "errors": results.get("errors", [])
        }
    
    def generate_markdown_report(self, report_data: Dict[str, Any], output_file: Path):
        """Generate a markdown report from the scan results."""
        with open(output_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("# Hardcoded IPs and Hostnames Scan Report\n\n")
            f.write(f"**Generated on:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
            
            # Summary
            f.write("## Summary\n\n")
            f.write(f"- **Repository:** {report_data.get('repository', 'N/A')}\n")
            f.write(f"- **Path:** `{report_data.get('path', 'N/A')}`\n")
            f.write(f"- **Total Findings:** {report_data.get('findings_count', 0)}\n")
            
            # Findings by severity
            severities = {}
            for finding in report_data.get('findings', []):
                severity = finding.get('severity', 'UNKNOWN')
                severities[severity] = severities.get(severity, 0) + 1
            
            if severities:
                f.write("\n## Findings by Severity\n\n")
                for severity, count in sorted(severities.items()):
                    f.write(f"- **{severity}:** {count}\n")
            
            # Detailed Findings
            if report_data.get('findings'):
                f.write("\n## Detailed Findings\n\n")
                f.write("| Severity | File | Line | Message | Match |\n")
                f.write("|----------|------|------|---------|-------|\n")
                
                for finding in report_data.get('findings', []):
                    # Get relative path for display
                    file_path = finding.get('path', '')
                    try:
                        file_path = str(Path(file_path).relative_to(report_data['path']))
                    except ValueError:
                        pass
                    
                    # Get the matching line(s)
                    match = ' '.join(line.strip() for line in finding.get('lines', []))
                    if len(match) > 100:  # Truncate long matches
                        match = match[:97] + "..."
                    
                    f.write(
                        f"| {finding.get('severity', '')} "
                        f"| `{file_path}` "
                        f"| {finding.get('start_line', '')} "
                        f"| {finding.get('message', '')} "
                        f"| `{match}` |\n"
                    )
            
            # Errors
            if report_data.get('errors'):
                f.write("\n## Errors\n\n")
                for error in report_data.get('errors', []):
                    f.write(f"- {error}\n")
            
            f.write("\n---\n")
            f.write("*This report was automatically generated by scan_hardcoded_ips.py*\n")
    
    def scan_repository(self, repo_path: Path) -> Optional[Path]:
        """Scan a single repository and return the path to the report."""
        try:
            if not repo_path.exists() or not repo_path.is_dir():
                logger.error(f"Repository path does not exist or is not a directory: {repo_path}")
                return None
            
            # Process the repository
            report_data = self.process_repository(repo_path)
            
            # Generate output files
            repo_name = repo_path.name
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            
            # JSON report
            json_report = self.output_dir / f"{repo_name}_hardcoded_ips_{timestamp}.json"
            with open(json_report, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2)
            
            # Markdown report
            md_report = self.output_dir / f"{repo_name}_hardcoded_ips_{timestamp}.md"
            self.generate_markdown_report(report_data, md_report)
            
            logger.info(f"Report generated: {md_report}")
            return md_report
            
        except Exception as e:
            logger.error(f"Error scanning repository {repo_path}: {e}")
            return None

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Scan GitHub repositories for hardcoded IPs and hostnames.')
    
    # GitHub specific arguments
    github_group = parser.add_argument_group('GitHub Options')
    github_group.add_argument('--org', default=GITHUB_ORG,
                           help=f'GitHub organization (default: {GITHUB_ORG})')
    github_group.add_argument('--token', default=GITHUB_TOKEN,
                           help=f'GitHub access token (default: from GITHUB_TOKEN env var)')
    github_group.add_argument('--include-forks', action='store_true',
                           help='Include forked repositories in the scan')
    github_group.add_argument('--include-archived', action='store_true',
                           help='Include archived repositories in the scan')
    github_group.add_argument('--repo',
                           help='Scan a specific repository instead of all repositories')
    
    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('--output-dir', '-o', default='hardcoded_ips_reports',
                         help='Output directory for reports (default: hardcoded_ips_reports)')
    scan_group.add_argument('--cleanup', action='store_true',
                         help='Clean up cloned repositories after scanning')
    
    # General options
    general_group = parser.add_argument_group('General Options')
    general_group.add_argument('--verbose', '-v', action='store_true',
                            help='Enable verbose output')
    general_group.add_argument('--parallel', '-p', type=int, default=1,
                            help='Number of parallel scans to run (default: 1)')
    
    return parser.parse_args()


def scan_repository(scanner: HardcodedIPScanner, repo: Dict, output_dir: Path, cleanup: bool = False) -> Optional[Path]:
    """Clone and scan a single repository."""
    try:
        # Create a temporary directory for cloning
        with tempfile.TemporaryDirectory(prefix=f"{repo['name']}_") as temp_dir:
            temp_path = Path(temp_dir)
            
            # Clone the repository
            clone_dir = scanner.github.clone_repository(repo, temp_path)
            if not clone_dir:
                logger.error(f"Failed to clone repository: {repo['name']}")
                return None
            
            # Scan the repository
            report_path = scanner.scan_repository(clone_dir)
            
            # Move the report to the output directory
            if report_path and report_path.exists():
                target_path = output_dir / report_path.name
                shutil.move(str(report_path), str(target_path))
                return target_path
            
            return None
            
    except Exception as e:
        logger.error(f"Error scanning repository {repo.get('name', 'unknown')}: {e}")
        return None


def main():
    """Main entry point for the script."""
    args = parse_arguments()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    
    # Validate GitHub credentials
    if not args.token:
        logger.error("GitHub token is required. Set GITHUB_TOKEN environment variable or use --token")
        return 1
    
    if not args.org:
        logger.error("GitHub organization is required. Set GITHUB_ORG environment variable or use --org")
        return 1
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        # Initialize the scanner with GitHub credentials
        scanner = HardcodedIPScanner(
            output_dir=args.output_dir,
            github_token=args.token,
            github_org=args.org
        )
        
        # Check if Semgrep is installed
        try:
            if shutil.which("semgrep"):
                ver_cmd = ["semgrep", "--version"]
            else:
                import sys
                ver_cmd = [sys.executable, "-m", "semgrep", "--version"]
            
            subprocess.run(
                ver_cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.error("Semgrep is not installed. Please install it with 'pip install semgrep'")
            return 1
        
        # Create output directory if it doesn't exist
        output_path = Path(args.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Get repositories to scan
        if args.repo:
            # Scan a specific repository
            logger.info(f"Fetching repository: {args.repo}")
            try:
                url = f"{GITHUB_API}/repos/{args.org}/{args.repo}"
                response = requests.get(url, headers={
                    'Authorization': f'token {args.token}',
                    'Accept': 'application/vnd.github.v3+json'
                })
                response.raise_for_status()
                repo_data = response.json()
                
                if not args.include_forks and repo_data.get('fork'):
                    logger.info(f"Skipping forked repository: {args.repo}")
                    return 0
                    
                if not args.include_archived and repo_data.get('archived'):
                    logger.info(f"Skipping archived repository: {args.repo}")
                    return 0
                
                repositories = [{
                    'name': repo_data['name'],
                    'clone_url': repo_data['clone_url'],
                    'ssh_url': repo_data['ssh_url'],
                    'default_branch': repo_data['default_branch'],
                    'archived': repo_data.get('archived', False),
                    'fork': repo_data.get('fork', False)
                }]
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to fetch repository {args.repo}: {e}")
                return 1
        else:
            # Scan all repositories in the organization
            logger.info(f"Fetching repositories from organization: {args.org}")
            try:
                github = GitHubRepositoryManager(args.token, args.org)
                repositories = github.get_repositories(
                    include_forks=args.include_forks,
                    include_archived=args.include_archived
                )
                logger.info(f"Found {len(repositories)} repositories to scan")
            except Exception as e:
                logger.error(f"Failed to fetch repositories: {e}")
                return 1
        
        # Process repositories
        reports = []
        
        if args.parallel > 1:
            # Parallel processing
            from concurrent.futures import ThreadPoolExecutor, as_completed
            
            with ThreadPoolExecutor(max_workers=args.parallel) as executor:
                future_to_repo = {
                    executor.submit(
                        scan_repository,
                        scanner,
                        repo,
                        output_path,
                        args.cleanup
                    ): repo for repo in repositories
                }
                
                for future in as_completed(future_to_repo):
                    repo = future_to_repo[future]
                    try:
                        report_path = future.result()
                        if report_path:
                            reports.append(report_path)
                            logger.info(f"Completed scan for {repo['name']}: {report_path}")
                    except Exception as e:
                        logger.error(f"Error processing {repo.get('name', 'unknown')}: {e}")
        else:
            # Sequential processing
            for repo in repositories:
                try:
                    report_path = scan_repository(
                        scanner,
                        repo,
                        output_path,
                        args.cleanup
                    )
                    if report_path:
                        reports.append(report_path)
                        logger.info(f"Completed scan for {repo['name']}: {report_path}")
                except Exception as e:
                    logger.error(f"Error processing {repo.get('name', 'unknown')}: {e}")
        
        # Generate summary report
        if reports:
            summary_report = output_path / "HARDCODED_IPS_SUMMARY.md"
            
            # Count total findings
            total_findings = 0
            findings_by_severity = {}
            
            # Collect data from all reports
            report_data = []
            for report_path in reports:
                try:
                    with open(report_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    # Extract metadata from the report
                    repo_name = report_path.stem.split('_hardcoded_ips_')[0]
                    findings = 0
                    
                    # Parse findings count
                    for line in content.split('\n'):
                        if line.startswith("- **Total Findings:**"):
                            findings = int(line.split(':')[-1].strip())
                            total_findings += findings
                            break
                    
                    # Parse findings by severity
                    in_severity_section = False
                    severities = {}
                    
                    for line in content.split('\n'):
                        if line.startswith("## Findings by Severity"):
                            in_severity_section = True
                            continue
                        elif line.startswith('##') and in_severity_section:
                            in_severity_section = False
                            continue
                            
                        if in_severity_section and line.startswith('- **') and ':**' in line:
                            severity = line.split('**')[1].split('**')[0]
                            count = int(line.split('**')[-2].strip())
                            severities[severity] = count
                            
                            # Update global severity counts
                            if severity not in findings_by_severity:
                                findings_by_severity[severity] = 0
                            findings_by_severity[severity] += count
                    
                    report_data.append({
                        'name': repo_name,
                        'path': str(report_path.relative_to(output_path)),
                        'findings': findings,
                        'severities': severities
                    })
                    
                except Exception as e:
                    logger.error(f"Error processing report {report_path}: {e}")
            
            # Sort by number of findings (descending)
            report_data.sort(key=lambda x: x['findings'], reverse=True)
            
            # Write summary report
            with open(summary_report, 'w', encoding='utf-8') as f:
                # Header
                f.write("# Hardcoded IPs and Hostnames - Scan Summary\n\n")
                f.write(f"**Organization:** {args.org}\n")
                f.write(f"**Generated on:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
                f.write(f"**Total Repositories Scanned:** {len(reports)}\n")
                f.write(f"**Total Findings:** {total_findings}\n\n")
                
                # Summary by Severity
                if findings_by_severity:
                    f.write("## Findings by Severity\n\n")
                    for severity, count in sorted(findings_by_severity.items(), key=lambda x: x[1], reverse=True):
                        f.write(f"- **{severity}:** {count}\n")
                    f.write("\n")
                
                # Repository Summary
                f.write("## Repository Summary\n\n")
                f.write("| Repository | Findings | Severities | Report |\n")
                f.write("|------------|----------|------------|--------|\n")
                
                for repo in report_data:
                    # Format severities
                    severity_str = ", ".join(
                        f"{s}:{c}" for s, c in sorted(repo['severities'].items(), 
                                                     key=lambda x: x[1], 
                                                     reverse=True)
                    )
                    
                    f.write(
                        f"| {repo['name']} | "
                        f"{repo['findings']} | "
                        f"{severity_str} | "
                        f"[{os.path.basename(repo['path'])}]({repo['path']}) |\n"
                    )
                
                # Footer
                f.write("\n---\n")
                f.write("*This report was automatically generated by scan_hardcoded_ips.py*\n")
                f.write("*For detailed findings, please refer to individual repository reports*\n")
            
            logger.info(f"\n{'='*80}")
            logger.info(f"Scan completed successfully!")
            logger.info(f"Total repositories scanned: {len(reports)}")
            logger.info(f"Total findings: {total_findings}")
            logger.info(f"Summary report: {summary_report}")
            logger.info(f"{'='*80}")
        
        return 0 if reports else 1
        
    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=args.verbose)
        return 1

if __name__ == "__main__":
    sys.exit(main())
