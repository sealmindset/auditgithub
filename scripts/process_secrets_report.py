#!/usr/bin/env python3
import re
import os
from datetime import datetime

def read_file_safely(file_path):
    """Read file content with error handling."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        return None
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None

def extract_repos_with_secrets(content):
    """Extract repository names with secrets from the vulnerability analysis summary."""
    if not content:
        return []
    
    # Find all lines with "Secrets found in code" and extract the repo names
    pattern = r'### (.+?)\n- Secrets found in code'
    repos_with_secrets = re.findall(pattern, content)
    
    # Clean up repository names
    cleaned_repos = []
    for repo in repos_with_secrets:
        # Remove any leading/trailing whitespace and special characters
        cleaned = repo.strip()
        # Remove any markdown formatting if present
        cleaned = cleaned.replace('**', '').strip()
        if cleaned:
            cleaned_repos.append(cleaned)
    
    return cleaned_repos

def generate_secrets_report(repos):
    """Generate a formatted markdown report of repositories with secrets."""
    if not repos:
        return "No repositories with secrets found in the vulnerability analysis summary."
    
    # Remove duplicates and sort
    unique_repos = sorted(list(set(repos)))
    
    # Create a more readable format with proper line wrapping
    report = []
    report.append("# Repositories with Secrets in Code")
    report.append("")
    report.append("## Summary")
    report.append(f"- **Total repositories with secrets:** {len(unique_repos)}")
    report.append(f"- **Report generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")
    report.append("## Repository List")
    
    # Group repositories by prefix for better organization
    repo_groups = {}
    for repo in unique_repos:
        # Extract prefix (first part before first hyphen)
        prefix = repo.split('-')[0] if '-' in repo else 'Other'
        if prefix not in repo_groups:
            repo_groups[prefix] = []
        repo_groups[prefix].append(repo)
    
    # Sort the groups
    for prefix in sorted(repo_groups.keys()):
        repo_list = sorted(repo_groups[prefix])
        report.append(f"\n### {prefix} ({len(repo_list)} repositories)")
        for repo in repo_list:
            # Remove the prefix for cleaner display
            display_name = repo[len(prefix):].lstrip('- ') if repo.startswith(prefix) else repo
            report.append(f"- {display_name}")
    
    return '\n'.join(report)

def main():
    print("Processing vulnerability analysis report...")
    
    # Input and output file paths
    input_file = "vulnerability_analysis_summary.md"
    output_file = "secrets_analysis_report.md"
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"Error: Input file not found: {input_file}")
        return
    
    # Read the input file
    content = read_file_safely(input_file)
    if content is None:
        return
    
    # Extract repository information
    repos = extract_repos_with_secrets(content)
    
    # Generate the report
    report = generate_secrets_report(repos)
    
    # Write the output file
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"Report generated successfully: {output_file}")
        print(f"Found {len(repos)} repositories with secrets (after removing duplicates).")
    except Exception as e:
        print(f"Error writing to {output_file}: {e}")

if __name__ == "__main__":
    main()
