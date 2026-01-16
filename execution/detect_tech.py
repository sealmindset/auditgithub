#!/usr/bin/env python3
import os
import sys
import argparse
import json
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def detect_languages(repo_path: str):
    """
    Detect programming languages used in the repository.
    Returns a set of normalized language names.
    """
    languages = set()
    
    # Extensions mapping
    ext_map = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'javascript', # Treat TS as JS for CodeQL purposes usually
        '.tsx': 'javascript',
        '.go': 'go',
        '.java': 'java',
        '.rb': 'ruby',
        '.php': 'php',
        '.cs': 'csharp',
        '.cpp': 'cpp',
        '.c': 'cpp',
        '.h': 'cpp',
    }
    
    # Walk the directory
    for root, _, files in os.walk(repo_path):
        if '.git' in root: continue
        
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in ext_map:
                languages.add(ext_map[ext])
                
    return list(languages)

def detect_iac(repo_path: str) -> bool:
    """
    Detect if the repository contains Infrastructure as Code (IaC).
    Checks for Terraform, CloudFormation, Kubernetes, Dockerfiles, etc.
    """
    iac_filenames = {'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'}
    
    for root, _, files in os.walk(repo_path):
        if '.git' in root: continue
        
        for file in files:
            if file in iac_filenames:
                return True
            
            ext = os.path.splitext(file)[1].lower()
            if ext == '.tf':
                return True
            
            if ext in {'.yaml', '.yml'} and ('k8s' in root or 'kubernetes' in root or 'chart' in root):
                return True
                
    return False

def main():
    parser = argparse.ArgumentParser(description="Detect technologies in a repository")
    parser.add_argument("--path", required=True, help="Path to the repository")
    parser.add_argument("--output", help="Output JSON file path")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        logger.error(f"Repository path does not exist: {args.path}")
        sys.exit(1)
        
    languages = detect_languages(args.path)
    has_iac = detect_iac(args.path)
    
    result = {
        "languages": languages,
        "has_iac": has_iac
    }
    
    # Print to stdout
    print(json.dumps(result, indent=2))
    
    # Write to file if requested
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
            logger.info(f"Results written to {args.output}")
        except Exception as e:
            logger.error(f"Failed to write output file: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
