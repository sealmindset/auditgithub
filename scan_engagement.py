#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import requests
import json
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EngagementScanner:
    def __init__(self, org_name, github_token, postgrest_url=None):
        self.org_name = org_name
        self.github_token = github_token
        self.postgrest_url = postgrest_url or os.getenv("POSTGREST_URL", "http://localhost:3000")
        self.headers = {
            "Authorization": f"Bearer {self.github_token}",
            "Accept": "application/vnd.github.v3+json"
        }

    def get_repo_engagement(self, repo_name):
        """Fetch engagement metrics for a single repository."""
        url = f"https://api.github.com/repos/{self.org_name}/{repo_name}"
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()
            
            return {
                "stars": data.get("stargazers_count", 0),
                "forks": data.get("forks_count", 0),
                "watchers": data.get("watchers_count", 0),
                "open_issues": data.get("open_issues_count", 0),
                "updated_at": data.get("updated_at"),
                "pushed_at": data.get("pushed_at"),
                "size": data.get("size", 0),
                "language": data.get("language"),
                "archived": data.get("archived", False)
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch engagement data for {repo_name}: {e}")
            return None

    def get_contributors_count(self, repo_name):
        """Get approximate contributor count (first page only to avoid heavy API usage)."""
        url = f"https://api.github.com/repos/{self.org_name}/{repo_name}/contributors?per_page=1&anon=true"
        try:
            response = requests.get(url, headers=self.headers)
            # Check Link header for last page to get total count
            if "link" in response.headers:
                # Parse link header to find "last" page
                links = response.headers["link"].split(",")
                for link in links:
                    if 'rel="last"' in link:
                        # Extract page number
                        try:
                            return int(link[link.find("&page=")+6 : link.find(">")])
                        except:
                            pass
            
            # If no link header or parsing failed, count items in current page (if successful)
            if response.status_code == 200:
                return len(response.json())
            return 0
            
        except requests.exceptions.RequestException:
            return 0

    def persist_engagement(self, repo_name, data):
        """Persist engagement data to PostgREST."""
        if not self.postgrest_url:
            logger.warning("No PostgREST URL provided, skipping persistence")
            return

        payload = {
            "repo_name": repo_name,
            "org_name": self.org_name,
            "stars": data["stars"],
            "forks": data["forks"],
            "watchers": data["watchers"],
            "open_issues": data["open_issues"],
            "contributors_count": data.get("contributors_count", 0),
            "last_updated": data["updated_at"],
            "scanned_at": datetime.now().isoformat()
        }

        # Assuming we have an endpoint/table for this. 
        # Based on CHANGELOG, it might be 'repositories' or a separate 'engagement' table.
        # For now, let's try to update 'repositories' if it exists, or just log it.
        # The CHANGELOG mentions "persist via PostgREST" but doesn't specify the exact table structure for engagement ONLY.
        # However, it says "Projects list... display stars/forks". So likely updating the `repositories` table.
        
        try:
            # Upsert into repositories table
            # We need to find the repo by name/org first or use an upsert endpoint
            url = f"{self.postgrest_url}/repositories?name=eq.{repo_name}"
            
            # First check if repo exists
            check = requests.get(url)
            if check.status_code == 200 and len(check.json()) > 0:
                # Update
                patch_url = f"{self.postgrest_url}/repositories?name=eq.{repo_name}"
                requests.patch(patch_url, json=payload)
                logger.info(f"Updated engagement data for {repo_name}")
            else:
                # Insert (might fail if other required fields are missing, but let's try)
                requests.post(f"{self.postgrest_url}/repositories", json=payload)
                logger.info(f"Inserted engagement data for {repo_name}")
                
        except Exception as e:
            logger.error(f"Failed to persist data for {repo_name}: {e}")

    def run(self, repo_name=None):
        if repo_name:
            repos = [repo_name]
        else:
            # Fetch all repos (simplified)
            repos = [] # TODO: Implement get_all_repos if needed, or rely on external orchestration
            logger.info("Scanning all repos not yet implemented in this script, please provide --repo")
            return

        for repo in repos:
            logger.info(f"Scanning engagement for {repo}...")
            data = self.get_repo_engagement(repo)
            if data:
                data["contributors_count"] = self.get_contributors_count(repo)
                print(json.dumps(data, indent=2))
                self.persist_engagement(repo, data)

def main():
    parser = argparse.ArgumentParser(description="Scan repository engagement metrics")
    parser.add_argument("--org", required=True, help="GitHub Organization")
    parser.add_argument("--repo", help="Specific repository to scan")
    parser.add_argument("--token", help="GitHub Token (or set GITHUB_TOKEN env)")
    parser.add_argument("--postgrest-url", help="PostgREST API URL")
    
    args = parser.parse_args()
    
    token = args.token or os.getenv("GITHUB_TOKEN")
    if not token:
        logger.error("GitHub token required")
        sys.exit(1)
        
    scanner = EngagementScanner(args.org, token, args.postgrest_url)
    scanner.run(args.repo)

if __name__ == "__main__":
    main()
