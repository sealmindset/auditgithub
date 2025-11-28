#!/usr/bin/env python3
import json
import os
import glob
from pathlib import Path
from datetime import datetime

def find_gitleaks_json_files():
    """Find all gitleaks JSON report files."""
    return glob.glob('vulnerability_reports/**/*_gitleaks.json', recursive=True)

def parse_gitleaks_json(file_path):
    """Parse a single gitleaks JSON file and extract secrets information."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Extract repository name from the file path
        repo_name = Path(file_path).parent.name
        
        # Process each finding in the gitleaks report
        findings = []
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                    
                # Extract relevant information
                finding = {
                    'repository': repo_name,
                    'file': item.get('file', 'N/A'),
                    'line': item.get('line', 'N/A'),
                    'secret': item.get('match', 'N/A'),
                    'rule_id': item.get('rule', {}).get('id', 'N/A'),
                    'description': item.get('rule', {}).get('description', 'N/A'),
                    'severity': item.get('rule', {}).get('severity', 'N/A'),
                    'commit': item.get('commit', 'N/A'),
                    'author': item.get('author', 'N/A'),
                    'email': item.get('email', 'N/A'),
                    'date': item.get('date', 'N/A')
                }
                findings.append(finding)
                
        return findings
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return []

def generate_secrets_report(findings):
    """Generate a markdown report from the findings."""
    if not findings:
        return "# No Secrets Found\n\nNo secrets were found in the gitleaks reports."
    
    # Sort findings by repository and file
    findings_sorted = sorted(findings, key=lambda x: (x['repository'].lower(), x['file'].lower()))
    
    # Generate markdown report
    report = [
        "# Secrets Found in Code",
        "",
        f"**Report generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Total secrets found:** {len(findings_sorted)}",
        f"**Repositories affected:** {len({f['repository'] for f in findings_sorted})}",
        "",
        "## Secrets by Repository and File",
        ""
    ]
    
    # Group findings by repository and file
    current_repo = None
    current_file = None
    
    for idx, finding in enumerate(findings_sorted, 1):
        # Add repository header if changed
        if finding['repository'] != current_repo:
            current_repo = finding['repository']
            report.append(f"\n## Repository: {current_repo}\n")
            current_file = None
        
        # Add file header if changed
        if finding['file'] != current_file:
            current_file = finding['file']
            report.append(f"### File: `{current_file}`\n")
            
        # Add finding details
        report.append(f"#### Secret {idx}")
        report.append(f"- **Line:** {finding['line']}")
        report.append(f"- **Rule ID:** {finding['rule_id']}")
        report.append(f"- **Severity:** {finding['severity']}")
        report.append(f"- **Description:** {finding['description']}")
        report.append(f"- **Secret:** `{finding['secret']}`")
        report.append(f"- **Commit:** {finding['commit']}")
        report.append(f"- **Author:** {finding['author']} ({finding['email']})")
        report.append(f"- **Date:** {finding['date']}\n")
    
    return "\n".join(report)

def main():
    print("Scanning for gitleaks reports...")
    json_files = find_gitleaks_json_files()
    
    if not json_files:
        print("No gitleaks JSON files found in vulnerability_reports/")
        return
    
    print(f"Found {len(json_files)} gitleaks report files. Processing...")
    
    # Process all JSON files
    all_findings = []
    for json_file in json_files:
        findings = parse_gitleaks_json(json_file)
        if findings:
            all_findings.extend(findings)
    
    if not all_findings:
        print("No secrets found in any of the gitleaks reports.")
        return
    
    # Generate and save the report
    report = generate_secrets_report(all_findings)
    output_file = "detailed_secrets_report.md"
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"\nReport generated: {output_file}")
        print(f"Total secrets found: {len(all_findings)}")
        print(f"Repositories affected: {len({f['repository'] for f in all_findings})}")
    except Exception as e:
        print(f"Error writing report: {e}")

if __name__ == "__main__":
    main()
