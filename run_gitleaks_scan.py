#!/usr/bin/env python3
import os
import subprocess
import json
import sys
from typing import Dict, Any, Optional

def run_gitleaks(repo_path: str, output_dir: str) -> Dict[str, Any]:
    """
    Run gitleaks scan on the specified repository and return results.
    
    Args:
        repo_path: Path to the repository to scan
        output_dir: Directory to store the output files
        
    Returns:
        Dictionary containing the scan results
    """
    os.makedirs(output_dir, exist_ok=True)
    output_json = os.path.join(output_dir, "gitleaks_results.json")
    output_md = os.path.join(output_dir, "gitleaks_report.md")
    
    # Check if gitleaks is installed
    if not shutil.which('gitleaks'):
        error_msg = "Gitleaks is not installed. Please install it first: brew install gitleaks"
        print(error_msg, file=sys.stderr)
        return {"error": error_msg}
    
    try:
        # Run gitleaks with detailed output
        cmd = [
            'gitleaks',
            'detect',
            '--source', repo_path,
            '--report-format', 'json',
            '--report-path', output_json,
            '--verbose'
        ]
        
        print(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Create a markdown report
        with open(output_md, 'w') as f:
            f.write("# Gitleaks Secret Scan Report\n\n")
            
            if result.returncode == 1:  # Secrets found
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
                        f.write(f"- **Secret:** `{finding.get('Secret', 'N/A')}`\n")
                        f.write(f"- **Match:** `{finding.get('Match', 'N/A')}`\n")
                        
                        if 'Commit' in finding:
                            f.write(f"- **Commit:** {finding['Commit']}\n")
                        if 'Author' in finding:
                            f.write(f"- **Author:** {finding['Author']} ({finding.get('Email', 'N/A')})\n")
                        if 'Date' in finding:
                            f.write(f"- **Date:** {finding['Date']}\n")
                        
                        f.write("\n---\n\n")
                    
                    print(f"Found {len(findings)} potential secrets. Report saved to {output_md}")
                    
                except Exception as e:
                    error_msg = f"Error processing findings: {str(e)}"
                    f.write(f"## Error\n\n{error_msg}\n\n{result.stderr}")
                    print(error_msg, file=sys.stderr)
            
            elif result.returncode == 0:
                f.write("## No secrets found\n")
                print("No secrets found in the repository.")
            
            else:
                error_msg = f"Gitleaks failed with return code {result.returncode}:\n{result.stderr}"
                f.write(f"## Error\n\n{error_msg}")
                print(error_msg, file=sys.stderr)
        
        return {
            "returncode": result.returncode,
            "output_file": output_json,
            "report_file": output_md,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    
    except Exception as e:
        error_msg = f"Error running gitleaks: {str(e)}"
        print(error_msg, file=sys.stderr)
        return {"error": error_msg}

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Run gitleaks scan on a repository')
    parser.add_argument('repo_path', help='Path to the repository to scan')
    parser.add_argument('--output-dir', '-o', default='gitleaks_reports',
                      help='Directory to store the output files (default: gitleaks_reports)')
    
    args = parser.parse_args()
    
    # Add shutil to the globals for the script
    import shutil
    
    result = run_gitleaks(args.repo_path, args.output_dir)
    print("\nScan completed with result:", json.dumps(result, indent=2))
