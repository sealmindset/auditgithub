#!/usr/bin/env python3
import json
import os
from pathlib import Path
import pandas as pd
from collections import defaultdict

# Base directory containing vulnerability reports
REPORTS_DIR = 'vulnerability_reports'

def process_gitleaks_report(report_path):
    """Process a single gitleaks report JSON file."""
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
        return data
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error processing {report_path}: {e}")
        return []

def find_gitleaks_reports():
    """Find all gitleaks report files in the reports directory."""
    reports = []
    for root, _, files in os.walk(REPORTS_DIR):
        for file in files:
            if file.endswith('_gitleaks.json'):
                project_name = file.replace('_gitleaks.json', '')
                reports.append({
                    'project': project_name,
                    'path': os.path.join(root, file)
                })
    return reports

def analyze_secrets():
    """Analyze all gitleaks reports and generate a summary."""
    reports = find_gitleaks_reports()
    findings = []
    
    for report in reports:
        project = report['project']
        leaks = process_gitleaks_report(report['path'])
        
        for leak in leaks:
            findings.append({
                'Project': project,
                'File': leak.get('file', 'N/A'),
                'Line': leak.get('line', 'N/A'),
                'Secret Type': leak.get('rule', 'Unknown'),
                'Match': leak.get('match', 'N/A')[:50] + '...' if leak.get('match') else 'N/A',
                'Commit': leak.get('commit', 'N/A')[:8] if leak.get('commit') else 'N/A',
                'Date': leak.get('date', 'N/A')
            })
    
    # Convert to DataFrame and save as markdown
    if findings:
        df = pd.DataFrame(findings)
        markdown_table = df.to_markdown(index=False, tablefmt='github')
        
        with open('secrets_report.md', 'w') as f:
            f.write("# Secrets Detection Report\n\n")
            f.write("## Summary\n")
            f.write(f"Total secrets found: {len(findings)}\n")
            f.write(f"Projects affected: {len(set(f['Project'] for f in findings))}\n\n")
            f.write("## Detailed Findings\n")
            f.write(markdown_table)
        
        print(f"Report generated: secrets_report.md")
        return df
    else:
        print("No secrets found in the reports.")
        return None

if __name__ == "__main__":
    analyze_secrets()
