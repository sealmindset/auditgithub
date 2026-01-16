#!/usr/bin/env python3
import os
import sys
import argparse
import logging
import subprocess
import shutil
from urllib.parse import urlparse, urlunparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def clone_repo(repo_url: str, repo_name: str, output_dir: str, token: str = None) -> bool:
    """
    Clone a repository from GitHub.
    """
    if not output_dir:
        logger.error("Output directory is required")
        return False
        
    dest_path = os.path.join(output_dir, repo_name)
    
    # Handle authentication
    final_url = repo_url
    if token and "github.com" in repo_url and repo_url.startswith("https://"):
        parsed = urlparse(repo_url)
        if parsed.scheme == 'https':
            # Rebuild the URL with the token
            netloc = f"x-access-token:{token}@{parsed.netloc}"
            final_url = urlunparse((
                parsed.scheme,
                netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))

    try:
        # Create parent directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Remove existing directory if it exists
        if os.path.exists(dest_path):
            logger.info(f"Removing existing directory: {dest_path}")
            shutil.rmtree(dest_path, ignore_errors=True)
            
        logger.info(f"Cloning {repo_name} from {repo_url} to {dest_path}...")
        
        # Run git clone
        # Use the token-embedded URL for the actual command, but log the safe one
        cmd = ["git", "clone", "--depth", "1", final_url, dest_path]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )
        
        if result.returncode == 0:
            logger.info(f"Successfully cloned {repo_name}")
            return True
        else:
            logger.error(f"Failed to clone {repo_name}: {result.stderr}")
            return False
            
    except Exception as e:
        logger.error(f"Error cloning repository: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Clone a GitHub repository")
    parser.add_argument("--url", required=True, help="Repository URL")
    parser.add_argument("--name", required=True, help="Repository Name")
    parser.add_argument("--output", required=True, help="Output Directory")
    parser.add_argument("--token", help="GitHub Token")
    
    args = parser.parse_args()
    
    success = clone_repo(args.url, args.name, args.output, args.token)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
