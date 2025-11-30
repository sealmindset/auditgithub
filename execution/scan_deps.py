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

def run_trivy_fs(repo_path: str, repo_name: str, report_dir: str):
    """Run Trivy filesystem scan."""
    os.makedirs(report_dir, exist_ok=True)
    trivy_bin = shutil.which('trivy')
    output_json = os.path.join(report_dir, f"{repo_name}_trivy_fs.json")
    output_md = os.path.join(report_dir, f"{repo_name}_trivy_fs.md")
    
    if not trivy_bin:
        logger.error("Trivy is not installed")
        return False
        
    try:
        logger.info(f"Running Trivy for {repo_name}...")
        cmd = [trivy_bin, "fs", "-q", "-f", "json", "--scanners", "vuln,config,secret,license", repo_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        with open(output_json, 'w') as f:
            f.write(result.stdout or "")
            
        # Create MD report
        with open(output_md, 'w') as f:
            f.write(f"# Trivy Filesystem Scan\n\n")
            f.write(f"**Repository:** {repo_name}\n\n")
            
            try:
                data = json.loads(result.stdout or '{}')
                results = data.get('Results', [])
                counts = {"CRITICAL":0, "HIGH":0, "MEDIUM":0, "LOW":0, "UNKNOWN":0}
                
                for res in results:
                    for v in res.get('Vulnerabilities', []) or []:
                        sev = (v.get('Severity') or 'UNKNOWN').upper()
                        if sev not in counts: sev = 'UNKNOWN'
                        counts[sev] += 1
                        
                f.write("## Summary\n\n")
                for k in ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]:
                    f.write(f"- {k.title()}: {counts[k]}\n")
                    
            except Exception as e:
                f.write(f"Error parsing results: {e}\n")
                
        return True
    except Exception as e:
        logger.error(f"Error running Trivy: {e}")
        return False

def run_npm_audit(repo_path: str, repo_name: str, report_dir: str):
    """Run npm audit if package.json exists."""
    if not os.path.exists(os.path.join(repo_path, 'package.json')):
        logger.info("No package.json found, skipping npm audit")
        return True
        
    os.makedirs(report_dir, exist_ok=True)
    output_json = os.path.join(report_dir, f"{repo_name}_npm_audit.json")
    output_md = os.path.join(report_dir, f"{repo_name}_npm_audit.md")
    
    try:
        logger.info(f"Running npm audit for {repo_name}...")
        # Need to install deps first usually, but we'll try audit directly
        # or use --package-lock-only if lockfile exists
        cmd = ['npm', 'audit', '--json']
        
        result = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True)
        
        with open(output_json, 'w') as f:
            f.write(result.stdout or "")
            
        # Create MD report
        with open(output_md, 'w') as f:
            f.write(f"# npm Audit Scan\n\n")
            f.write(f"**Repository:** {repo_name}\n\n")
            
            try:
                data = json.loads(result.stdout or '{}')
                advisories = data.get('advisories', {})
                metadata = data.get('metadata', {}).get('vulnerabilities', {})
                
                f.write("## Summary\n\n")
                for sev, count in metadata.items():
                    f.write(f"- {sev.title()}: {count}\n")
                    
            except Exception as e:
                f.write(f"Error parsing results: {e}\n")
                
        return True
    except Exception as e:
        logger.error(f"Error running npm audit: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Run dependency scans")
    parser.add_argument("--path", required=True, help="Path to the repository")
    parser.add_argument("--name", required=True, help="Repository Name")
    parser.add_argument("--output", required=True, help="Output Directory")
    parser.add_argument("--scanners", default="trivy,npm", help="Comma-separated list of scanners")
    
    args = parser.parse_args()
    
    scanners = args.scanners.split(',')
    success = True
    
    if 'trivy' in scanners:
        if not run_trivy_fs(args.path, args.name, args.output):
            success = False
            
    if 'npm' in scanners:
        if not run_npm_audit(args.path, args.name, args.output):
            success = False
            
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
