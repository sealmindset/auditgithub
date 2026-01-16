from src.api.database import SessionLocal
from src.api import models
import sys

def debug_findings():
    db = SessionLocal()
    # Get repo
    repo = db.query(models.Repository).filter(models.Repository.name == "auditgithub").first()
    if not repo:
        print("Repo not found")
        return

    print(f"Repo: {repo.name}")
    
    # Get findings
    findings = db.query(models.Finding).filter(models.Finding.repository_id == repo.id).all()
    print(f"Total Findings: {len(findings)}")
    
    for f in findings:
        print(f"[{f.scanner_name}] {f.finding_type}: {f.title} ({f.severity})")
    
    db.close()

if __name__ == "__main__":
    debug_findings()
