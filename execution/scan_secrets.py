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

def run_gitleaks(repo_path: str, repo_name: str, report_dir: str):
    """
    Run Gitleaks secret scan against the working tree and history.
    """
    os.makedirs(report_dir, exist_ok=True)
    gl_bin = shutil.which('gitleaks')
    output_json = os.path.join(report_dir, f"{repo_name}_gitleaks.json")
    output_md = os.path.join(report_dir, f"{repo_name}_gitleaks.md")
    
    if not gl_bin:
        error_msg = "Gitleaks is not installed. Install via: brew install gitleaks or see https://github.com/gitleaks/gitleaks"
        with open(output_md, 'w') as f:
            f.write(f"# Error\n\n{error_msg}\n")
        logger.error(error_msg)
        return False
    
    try:
        logger.info(f"Running Gitleaks for {repo_name}...")
        # Run gitleaks to detect secrets
        cmd = [
            gl_bin,
            'detect',
            '--source', repo_path,
            '--report-format', 'json',
            '--report-path', output_json,
            '--verbose'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Create a detailed markdown report
        with open(output_md, 'w') as f:
            f.write(f"# Gitleaks Secrets Scan\n")
            f.write(f"**Repository:** {repo_name}\n")
            f.write(f"**Scanned on:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Command:** `{' '.join(cmd)}`\n\n")
            
            if result.returncode == 1:  # Gitleaks returns 1 when leaks are found
                try:
                    with open(output_json, 'r') as json_file:
                        findings = json.load(json_file)
                    
                    if not isinstance(findings, list):
                        findings = [findings] if findings else []
                    
                    f.write(f"## Found {len(findings)} potential secrets\n\n")
                    
                    for idx, finding in enumerate(findings, 1):
                        f.write(f"### Secret {idx}\n")
                        f.write(f"- **File:** `{finding.get('File', 'N/A')}`\n")
                        f.write(f"- **Line:** {finding.get('StartLine', 'N/A')}\n")
                        f.write(f"- **Rule ID:** {finding.get('RuleID', 'N/A')}\n")
                        f.write(f"- **Description:** {finding.get('Rule', {}).get('Description', 'N/A')}\n")
                        f.write(f"- **Commit:** `{finding.get('Commit', 'N/A')}`\n")
                        f.write(f"- **Author:** {finding.get('Author', 'N/A')}\n")
                        f.write(f"- **Date:** {finding.get('Date', 'N/A')}\n")
                        
                        # Show the secret value
                        secret = finding.get('Secret', 'N/A')
                        f.write(f"- **Secret:** `{secret}`\n\n")
                        
                except Exception as e:
                    f.write(f"Error parsing JSON results: {e}\n")
                    f.write(f"Raw output:\n```\n{result.stdout}\n```\n")
            elif result.returncode == 0:
                f.write("## ✅ No secrets found\n")
            else:
                f.write(f"## ❌ Gitleaks failed with exit code {result.returncode}\n")
                f.write(f"Error: {result.stderr}\n")
        
        logger.info(f"Gitleaks scan complete. Report saved to {output_md}")
        return True
        
    except Exception as e:
        logger.error(f"Error running Gitleaks: {e}")
        with open(output_md, 'w') as f:
            f.write(f"Error running Gitleaks: {e}\n")
        return False

def main():
    parser = argparse.ArgumentParser(description="Run Gitleaks secrets scan")
    parser.add_argument("--path", required=True, help="Path to the repository")
    parser.add_argument("--name", required=True, help="Repository Name")
    parser.add_argument("--output", required=True, help="Output Directory")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        logger.error(f"Repository path does not exist: {args.path}")
        sys.exit(1)
        
    success = run_gitleaks(args.path, args.name, args.output)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
