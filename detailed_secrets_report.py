#!/usr/bin/env python3
import re
import os
import json
from datetime import datetime
from pathlib import Path

def read_file_safely(file_path):
    """Read file content with error handling."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def find_secret_details():
    """Find all JSON files that might contain secret details."""
    secrets_data = []
    base_dir = Path("vulnerability_reports")
    
    # Look for JSON files that might contain secret details
    for json_file in base_dir.rglob("*.json"):
        try:
            content = read_file_safely(json_file)
            if not content:
                continue
                
            data = json.loads(content)
            
            # Handle different JSON structures that might contain secrets
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and 'file' in item and 'match' in item:
                        secrets_data.append({
                            'file': item.get('file', 'N/A'),
                            'secret': item.get('match', 'N/A'),
                            'line': item.get('line', 'N/A'),
                            'repo': json_file.parent.name
                        })
            elif isinstance(data, dict):
                # Handle different JSON structures
                if 'results' in data and isinstance(data['results'], list):
                    for result in data['results']:
                        if 'path' in result and 'extra' in result and 'message' in result['extra']:
                            secrets_data.append({
                                'file': result.get('path', 'N/A'),
                                'secret': result['extra'].get('message', 'N/A'),
                                'line': result.get('start', {}).get('line', 'N/A'),
                                'repo': json_file.parent.name
                            })
                
        except json.JSONDecodeError:
            # Skip files that aren't valid JSON
            continue
        except Exception as e:
            print(f"Error processing {json_file}: {e}")
    
    return secrets_data

def generate_detailed_report(secrets):
    """Generate a detailed markdown report with secrets information."""
    if not secrets:
        return "No secrets found in the vulnerability reports."
    
    report = [
        "# Detailed Secrets Report",
        "",
        f"**Report generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Total secrets found:** {len(secrets)}",
        f"**Repositories affected:** {len({s['repo'] for s in secrets})}",
        "",
        "## Secrets Overview",
        "",
        "| # | Repository | File | Line | Secret |",
        "|---|------------|------|------|--------|"
    ]
    
    for idx, secret in enumerate(secrets, 1):
        # Truncate long secrets for display
        secret_preview = (secret['secret'][:100] + '...') if len(secret['secret']) > 100 else secret['secret']
        
        report.append(
            f"| {idx} | {secret['repo']} | {secret['file']} | {secret['line']} | `{secret_preview}` |"
        )
    
    return '\n'.join(report)

def main():
    print("Scanning for detailed secrets information...")
    secrets = find_secret_details()
    
    if not secrets:
        print("No secrets found in the vulnerability reports.")
        return
    
    report = generate_detailed_report(secrets)
    
    output_file = "detailed_secrets_report.md"
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"Detailed report generated: {output_file}")
        print(f"Found {len(secrets)} secrets across {len({s['repo'] for s in secrets})} repositories.")
    except Exception as e:
        print(f"Error writing report: {e}")

if __name__ == "__main__":
    main()
