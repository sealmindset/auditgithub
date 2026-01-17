#!/usr/bin/env python3
import re
import os
from pathlib import Path

def read_file_safely(file_path):
    """Read file content with error handling."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
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

def generate_secrets_table(repos):
    """Generate a markdown table of repositories with secrets."""
    if not repos:
        return "No repositories with secrets found in the vulnerability analysis summary."
    
    # Sort repositories alphabetically
    repos_sorted = sorted(list(set(repos)))  # Remove duplicates and sort
    
    # Generate markdown table with better formatting
    markdown = "# Repositories with Secrets in Code\n\n"
    markdown += "| # | Repository Name |\n"
    markdown += "|---|-----------------|\n"
    
    for idx, repo in enumerate(repos_sorted, 1):
        # Ensure the repository name is properly escaped for markdown
        repo_escaped = repo.replace('|', '\\|')
        markdown += f"| {idx} | {repo_escaped} |\n"
    
    # Add summary with more details
    from datetime import datetime
    markdown += f"\n## Summary\n"
    markdown += f"- **Total repositories with secrets:** {len(repos_sorted)}\n"
    markdown += f"- **Report generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    
    return markdown

def main():
    print("Generating secrets table...")
    
    # Input and output file paths
    input_file = "vulnerability_analysis_summary.md"
    output_file = "repositories_with_secrets.md"
    
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
    
    # Generate the markdown table
    table = generate_secrets_table(repos)
    
    # Write the output file
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(table)
        print(f"Report generated successfully: {output_file}")
        print(f"Found {len(repos)} unique repositories with secrets.")
    except Exception as e:
        print(f"Error writing to {output_file}: {e}")

if __name__ == "__main__":
    main()
