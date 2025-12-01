#!/usr/bin/env python3
import argparse
import logging
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class Orchestrator:
    def __init__(self, org, profile="balanced", report_dir="vulnerability_reports", max_workers=4):
        self.org = org
        self.profile = profile
        self.report_dir = report_dir
        self.max_workers = max_workers
        self.scanners = []
        
        self._configure_profile()

    def _configure_profile(self):
        """Configure scanners based on profile."""
        # Base scanners (always run)
        self.scanners.append("scan_repos.py") # OSS/Dependency scan
        self.scanners.append("scan_engagement.py")
        
        if self.profile == "fast":
            # Skip deep code analysis
            pass
        elif self.profile == "balanced":
            # Add lighter SAST if available
            pass
        elif self.profile == "deep":
            # Add CodeQL or deep SAST
            # self.scanners.append("scan_codeql.py") # Assuming this exists or will exist
            pass
            
    def run_scanner(self, script_name, repo_arg=None):
        """Run a single scanner script."""
        cmd = [sys.executable, script_name, "--org", self.org]
        if repo_arg:
            cmd.extend(["--repo", repo_arg])
            
        # Add profile-specific flags if the script supports them
        if script_name == "scan_repos.py":
             cmd.extend(["--report-dir", self.report_dir])
             
        logger.info(f"Starting {script_name}...")
        try:
            subprocess.run(cmd, check=True)
            logger.info(f"Finished {script_name}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"{script_name} failed: {e}")
            return False

    def run(self, repo=None):
        """Run all configured scanners."""
        os.makedirs(self.report_dir, exist_ok=True)
        
        logger.info(f"Orchestrating scans for {self.org} (Profile: {self.profile})")
        
        # In a real orchestrator, we might want to run scanners in parallel 
        # OR run them sequentially per repo. 
        # For now, let's run them sequentially to ensure stability.
        
        for scanner in self.scanners:
            if not os.path.exists(scanner):
                logger.warning(f"Scanner script {scanner} not found, skipping.")
                continue
                
            self.run_scanner(scanner, repo)
            
        logger.info("Orchestration complete.")
        
        # Run ingestion
        logger.info("Starting ingestion to database...")
        ingest_cmd = [sys.executable, "ingest_scans.py"]
        try:
            subprocess.run(ingest_cmd, check=True)
            logger.info("Ingestion complete.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Ingestion failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Orchestrate security scans")
    parser.add_argument("--org", required=True, help="GitHub Organization")
    parser.add_argument("--repo", help="Specific repository to scan")
    parser.add_argument("--profile", choices=["fast", "balanced", "deep"], default="balanced", help="Scan profile")
    parser.add_argument("--report-dir", default="vulnerability_reports", help="Directory for reports")
    
    args = parser.parse_args()
    
    orchestrator = Orchestrator(args.org, args.profile, args.report_dir)
    orchestrator.run(args.repo)

if __name__ == "__main__":
    main()
