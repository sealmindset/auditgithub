#!/usr/bin/env python3
import os
import sys
import logging
from sqlalchemy import text

# Add src to path to import models
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from api.database import SessionLocal
from api import models

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fix_repo_urls():
    db = SessionLocal()
    try:
        # Get repos with missing URLs
        repos = db.query(models.Repository).filter(models.Repository.url == None).all()
        
        if not repos:
            logger.info("No repositories found with missing URLs.")
            return

        github_org = os.getenv("GITHUB_ORG", "sealmindset")
        logger.info(f"Found {len(repos)} repositories with missing URLs. Using org: {github_org}")
        
        for repo in repos:
            repo_url = f"https://github.com/{github_org}/{repo.name}"
            repo.url = repo_url
            logger.info(f"Updating {repo.name} -> {repo_url}")
            
        db.commit()
        logger.info("Successfully updated repository URLs.")
        
    except Exception as e:
        logger.error(f"Failed to update URLs: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    fix_repo_urls()
