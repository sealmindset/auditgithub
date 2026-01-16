#!/usr/bin/env python3
import os
import sys
import subprocess
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def batch_ingest():
    """Ingest all reports from vulnerability_reports directory."""
    base_dir = os.path.dirname(os.path.dirname(__file__))
    reports_dir = os.path.join(base_dir, "vulnerability_reports")
    ingest_script = os.path.join(base_dir, "execution", "ingest_results.py")
    
    if not os.path.exists(reports_dir):
        logger.error(f"Reports directory not found: {reports_dir}")
        return
        
    logger.info(f"Scanning {reports_dir} for reports...")
    
    success_count = 0
    fail_count = 0
    
    for item in os.listdir(reports_dir):
        item_path = os.path.join(reports_dir, item)
        
        if os.path.isdir(item_path):
            repo_name = item
            logger.info(f"Ingesting {repo_name}...")
            
            try:
                cmd = [ingest_script, repo_name, item_path]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    logger.info(f"✓ Successfully ingested {repo_name}")
                    success_count += 1
                else:
                    logger.error(f"✗ Failed to ingest {repo_name}: {result.stderr}")
                    fail_count += 1
            except Exception as e:
                logger.error(f"Error running ingestion for {repo_name}: {e}")
                fail_count += 1
                
    logger.info("="*50)
    logger.info(f"Batch Ingestion Complete")
    logger.info(f"Success: {success_count}")
    logger.info(f"Failed:  {fail_count}")
    logger.info("="*50)

if __name__ == "__main__":
    batch_ingest()
