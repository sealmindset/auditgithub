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

def run_checkov(repo_path: str, repo_name: str, report_dir: str):
    """Run Checkov IaC scan."""
    # Detect IaC files first
    has_iac = False
    iac_exts = {'.tf', '.yaml', '.yml', '.json', 'Dockerfile'}
    
    for root, _, files in os.walk(repo_path):
        if any(f.endswith(tuple(iac_exts)) or f == 'Dockerfile' for f in files):
            has_iac = True
            break
            
    if not has_iac:
        logger.info("No IaC files found, skipping Checkov")
        return True
        
    os.makedirs(report_dir, exist_ok=True)
    checkov_bin = shutil.which('checkov')
    output_json = os.path.join(report_dir, f"{repo_name}_checkov.json")
    output_md = os.path.join(report_dir, f"{repo_name}_checkov.md")
    
    if not checkov_bin:
        logger.error("Checkov is not installed")
        return False
        
    try:
        logger.info(f"Running Checkov for {repo_name}...")
        cmd = [checkov_bin, '-d', repo_path, '-o', 'json']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        with open(output_json, 'w') as f:
            f.write(result.stdout or "")
            
        # Create MD report
        with open(output_md, 'w') as f:
            f.write(f"# Checkov IaC Scan\n\n")
            f.write(f"**Repository:** {repo_name}\n\n")
            
            try:
                data = json.loads(result.stdout or '{}')
                # Checkov output can be a list (multiple frameworks) or dict
                if isinstance(data, dict):
                    data = [data]
                    
                total_failed = 0
                for framework_result in data:
                    failed = framework_result.get('results', {}).get('failed_checks', [])
                    total_failed += len(failed)
                    
                f.write(f"## Found {total_failed} failed checks\n\n")
                
                if total_failed > 0:
                    f.write("## Sample Findings\n\n")
                    count = 0
                    for framework_result in data:
                        failed = framework_result.get('results', {}).get('failed_checks', [])
                        for chk in failed:
                            if count >= 10: break
                            
                            check_id = chk.get('check_id', 'UNKNOWN')
                            resource = chk.get('resource', 'unknown')
                            file_path = chk.get('file_path', 'unknown')
                            
                            f.write(f"- **{check_id}**: {resource} in `{file_path}`\n")
                            count += 1
                            
            except Exception as e:
                f.write(f"Error parsing results: {e}\n")
                
        return True
    except Exception as e:
        logger.error(f"Error running Checkov: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Run IaC scans")
    parser.add_argument("--path", required=True, help="Path to the repository")
    parser.add_argument("--name", required=True, help="Repository Name")
    parser.add_argument("--output", required=True, help="Output Directory")
    
    args = parser.parse_args()
    
    if not run_checkov(args.path, args.name, args.output):
        sys.exit(1)
        
    sys.exit(0)

if __name__ == "__main__":
    main()
