#!/usr/bin/env python3
import json
import os
from pathlib import Path
import pandas as pd
import glob

def find_gitleaks_reports():
    """Find all gitleaks report files in the vulnerability_reports directory."""
    report_files = []
    for file_path in glob.glob('vulnerability_reports/**/*_gitleaks.json', recursive=True):
        project_name = Path(file_path).parent.name
        report_files.append({
            'project': project_name,
            'path': file_path
        })
    return report_files

def process_gitleaks_report(report_path):
    """Process a single gitleaks report JSON file."""
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error processing {report_path}: {e}")
        return []

def generate_secrets_report():
    """Generate a markdown report of all secrets found."""
    reports = find_gitleaks_reports()
    findings = []
    
    for report in reports:
        leaks = process_gitleaks_report(report['path'])
        for leak in leaks:
            # Skip if no matches found
            if not leak.get('matches'):
                continue
                
            for match in leak['matches']:
                findings.append({
                    'Project': report['project'],
                    'File': match.get('file', 'N/A'),
                    'Line': match.get('lineNumber', 'N/A'),
                    'Secret Type': leak.get('description', 'Unknown'),
                    'Commit': match.get('commit', 'N/A')[:8] if match.get('commit') else 'N/A',
                    'Date': match.get('date', 'N/A'),
                    'Match Preview': (match.get('secret', '')[:50] + '...') if match.get('secret') else 'N/A'
                })
    
    if findings:
        # Create markdown table
        df = pd.DataFrame(findings)
        markdown_table = df.to_markdown(index=False, tablefmt='github')
        
        # Write to file
        with open('secrets_report.md', 'w', encoding='utf-8') as f:
            f.write("# Secrets Detection Report\n\n")
            f.write(f"## Summary\n")
            f.write(f"Total secrets found: {len(findings)}\n")
            f.write(f"Projects affected: {df['Project'].nunique()}\n\n")
            f.write("## Detailed Findings\n")
            f.write("| Project | File | Line | Secret Type | Commit | Date | Match Preview |\n")
            f.write("|---------|------|------|-------------|--------|------|----------------|\n")
            
            for finding in findings:
                f.write(f"| {finding['Project']} | {finding['File']} | {finding['Line']} | {finding['Secret Type']} | {finding['Commit']} | {finding['Date']} | {finding['Match Preview']} |\n")
        
        print(f"Report generated: secrets_report.md")
        return df
    else:
        print("No secrets found in the reports.")
        return None

if __name__ == "__main__":
    generate_secrets_report()
