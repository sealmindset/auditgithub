#!/usr/bin/env python3
import os
import sys
import argparse
import json
import logging
import subprocess
import shutil
import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_semgrep(repo_path: str, repo_name: str, report_dir: str):
    """Run Semgrep SAST scan."""
    os.makedirs(report_dir, exist_ok=True)
    semgrep_bin = shutil.which('semgrep')
    output_json = os.path.join(report_dir, f"{repo_name}_semgrep.json")
    output_md = os.path.join(report_dir, f"{repo_name}_semgrep.md")
    
    if not semgrep_bin:
        logger.error("Semgrep is not installed")
        return False
        
    try:
        logger.info(f"Running Semgrep for {repo_name}...")
        cmd = [semgrep_bin, "scan", "--config=auto", "--json", "--output", output_json, repo_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Create MD report
        with open(output_md, 'w') as f:
            f.write(f"# Semgrep SAST Scan\n\n")
            f.write(f"**Repository:** {repo_name}\n")
            f.write(f"**Date:** {datetime.datetime.now().isoformat()}\n\n")
            
            if result.returncode == 0:
                try:
                    with open(output_json, 'r') as jf:
                        data = json.load(jf)
                    results = data.get('results', [])
                    f.write(f"## Found {len(results)} issues\n\n")
                    
                    for res in results:
                        path = res.get('path', 'unknown')
                        line = res.get('start', {}).get('line', '?')
                        msg = res.get('extra', {}).get('message', 'No message')
                        sev = res.get('extra', {}).get('severity', 'UNKNOWN')
                        f.write(f"- **{sev}** in `{path}:{line}`: {msg}\n")
                except Exception as e:
                    f.write(f"Error parsing results: {e}\n")
            else:
                f.write(f"Semgrep failed with code {result.returncode}\n")
                
        return True
    except Exception as e:
        logger.error(f"Error running Semgrep: {e}")
        return False

def run_bandit(repo_path: str, repo_name: str, report_dir: str):
    """Run Bandit Python SAST scan."""
    # Only run if Python files exist
    has_py = False
    for root, _, files in os.walk(repo_path):
        if any(f.endswith('.py') for f in files):
            has_py = True
            break
            
    if not has_py:
        logger.info("No Python files found, skipping Bandit")
        return True
        
    os.makedirs(report_dir, exist_ok=True)
    bandit_bin = shutil.which('bandit')
    output_json = os.path.join(report_dir, f"{repo_name}_bandit.json")
    output_md = os.path.join(report_dir, f"{repo_name}_bandit.md")
    
    if not bandit_bin:
        logger.error("Bandit is not installed")
        return False
        
    try:
        logger.info(f"Running Bandit for {repo_name}...")
        cmd = [bandit_bin, "-r", repo_path, "-f", "json", "-o", output_json, "-q", "-ll", "-ii"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Create MD report
        with open(output_md, 'w') as f:
            f.write(f"# Bandit Python Scan\n\n")
            f.write(f"**Repository:** {repo_name}\n\n")
            
            try:
                with open(output_json, 'r') as jf:
                    data = json.load(jf)
                results = data.get('results', [])
                f.write(f"## Found {len(results)} issues\n\n")
                
                for res in results:
                    issue = res.get('issue_text', 'Unknown')
                    sev = res.get('issue_severity', 'UNKNOWN')
                    path = res.get('filename', 'unknown')
                    line = res.get('line_number', '?')
                    f.write(f"- **{sev}** in `{path}:{line}`: {issue}\n")
            except Exception as e:
                f.write(f"Error parsing results: {e}\n")
                
        return True
    except Exception as e:
        logger.error(f"Error running Bandit: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Run SAST scans")
    parser.add_argument("--path", required=True, help="Path to the repository")
    parser.add_argument("--name", required=True, help="Repository Name")
    parser.add_argument("--output", required=True, help="Output Directory")
    parser.add_argument("--scanners", default="semgrep,bandit", help="Comma-separated list of scanners")
    
    args = parser.parse_args()
    
    scanners = args.scanners.split(',')
    success = True
    
    if 'semgrep' in scanners:
        if not run_semgrep(args.path, args.name, args.output):
            success = False
            
    if 'bandit' in scanners:
        if not run_bandit(args.path, args.name, args.output):
            success = False
            
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
