#!/usr/bin/env python3
import os
import subprocess
import json
import shutil
from pathlib import Path
from datetime import datetime

def run_gitleaks(repo_path, output_dir):
    """Run gitleaks on a repository and save the results."""
    try:
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Define output file paths
        repo_name = os.path.basename(repo_path.rstrip('/'))
        output_json = os.path.join(output_dir, f"{repo_name}_gitleaks_detailed.json")
        output_md = os.path.join(output_dir, f"{repo_name}_gitleaks_detailed.md")
        
        # Check if gitleaks is installed
        gitleaks_bin = shutil.which('gitleaks')
        if not gitleaks_bin:
            error_msg = "Gitleaks is not installed. Please install it first: brew install gitleaks"
            with open(output_md, 'w') as f:
                f.write(f"# Error\n\n{error_msg}")
            return False, error_msg
        
        # Run gitleaks with --no-git to scan files directly (no git history)
        cmd = [
            gitleaks_bin, 
            'detect', 
            '--source', repo_path,
            '--report-format', 'json',
            '--report-path', output_json,
            '--verbose',
            '--redact'  # This will show the actual secrets in the report
        ]
        
        # Execute the command
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Create a markdown report
        with open(output_md, 'w') as f:
            f.write(f"# Gitleaks Scan Report\n")
            f.write(f"**Repository:** {repo_name}\n")
            f.write(f"**Scanned on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if result.returncode == 1:  # Gitleaks returns 1 when leaks are found
                try:
                    with open(output_json, 'r') as json_file:
                        findings = json.load(json_file)
                    
                    f.write(f"## Found {len(findings)} potential secrets\n\n")
                    
                    for idx, finding in enumerate(findings, 1):
                        f.write(f"### Secret {idx}\n")
                        f.write(f"- **File:** `{finding.get('File', 'N/A')}`\n")
                        f.write(f"- **Line:** {finding.get('StartLine', 'N/A')}\n")
                        f.write(f"- **Rule ID:** {finding.get('RuleID', 'N/A')}\n")
                        f.write(f"- **Description:** {finding.get('Rule', {}).get('Description', 'N/A')}\n")
                        f.write(f"- **Secret:** `{finding.get('Secret', 'N/A')}`\n")
                        f.write(f"- **Match:** `{finding.get('Match', 'N/A')}`\n")
                        f.write("\n---\n\n")
                    
                    return True, f"Found {len(findings)} potential secrets in {repo_name}"
                
                except Exception as e:
                    error_msg = f"Error processing findings: {str(e)}"
                    f.write(f"## Error\n\n{error_msg}\n\n{result.stderr}")
                    return False, error_msg
            
            elif result.returncode == 0:
                f.write("## No secrets found\n")
                return True, "No secrets found"
            
            else:
                error_msg = f"Gitleaks failed with return code {result.returncode}:\n{result.stderr}"
                f.write(f"## Error\n\n{error_msg}")
                return False, error_msg
    
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        with open(output_md, 'w') as f:
            f.write(f"# Error\n\n{error_msg}")
        return False, error_msg

def main():
    # Define the base directory containing the repositories
    base_dir = os.path.expanduser("~/Documents/GitHub")
    
    # Define the output directory for the reports
    output_base_dir = os.path.expanduser("~/Documents/GitHub/auditgh/detailed_secrets_reports")
    os.makedirs(output_base_dir, exist_ok=True)
    
    # Get a list of repositories to scan
    repos_to_scan = []
    with open("repositories_with_secrets.md", 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('|') and '|' in line[1:]:
                # Skip header rows
                if any(header in line.lower() for header in ['repository', '---']):
                    continue
                # Extract repository name (second column in the table)
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 3:  # Should have at least 3 parts: empty, number, repo name, ...
                    repo_name = parts[2]  # Third part is the repository name
                    if repo_name and repo_name != 'Repository Name':
                        # Handle repository names that might be prefixed with 'sleepnumberinc/'
                        if '/' in repo_name:
                            repo_name = repo_name.split('/')[-1]
                        repo_path = os.path.join(base_dir, repo_name)
                        if os.path.exists(repo_path):
                            repos_to_scan.append((repo_name, repo_path))
                        else:
                            print(f"  ! Repository not found: {repo_path}")
    
    if not repos_to_scan:
        print("No valid repository paths found. Please check the repositories_with_secrets.md file and ensure the repositories are cloned in ~/Documents/GitHub/")
        return
    
    if not repos_to_scan:
        print("No repositories found to scan. Please check the repositories_with_secrets.md file.")
        return
    
    print(f"Found {len(repos_to_scan)} repositories to scan for secrets...\n")
    
    # Process each repository
    for idx, (repo_name, repo_path) in enumerate(repos_to_scan, 1):
        print(f"[{idx}/{len(repos_to_scan)}] Scanning {repo_name}...")
        success, message = run_gitleaks(repo_path, output_base_dir)
        if success:
            print(f"  ✓ {message}")
        else:
            print(f"  ✗ {message}")
    
    print("\nScan complete! Check the detailed_secrets_reports directory for results.")

if __name__ == "__main__":
    main()
