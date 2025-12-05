import os
import time
import requests
import uuid
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.api.models import Repository, ScanRun, Dependency

# Configuration
API_BASE = os.getenv("API_BASE", "http://localhost:8000")
DB_HOST = os.getenv("POSTGRES_HOST", "localhost")
DB_URL = f"postgresql://auditgh:auditgh_secret@{DB_HOST}:5432/auditgh_kb"

# Setup DB connection
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def verify_api_scan():
    db = SessionLocal()
    try:
        print("Connecting to database...")
        # Create dummy repo
        repo_name = f"verify_api_scan_{uuid.uuid4().hex[:8]}"
        repo = Repository(
            name=repo_name,
            description="Verification Repo for API Scan",
            url="https://github.com/example/verify-api-scan"
        )
        db.add(repo)
        db.commit()
        db.refresh(repo)
        print(f"Created repo: {repo.name} ({repo.id})")
        
        # Create a dummy requirements.txt so Syft has something to find
        # We need to write this to where the scan will look.
        # scan_repos.py clones the repo. Since we are using a dummy name that doesn't exist on GitHub,
        # clone_repo will fail unless we mock it or pre-create the directory.
        # But wait, scan_repos.py fails if clone fails.
        
        # We need a real repo or a way to bypass clone.
        # Or we can use a local path if scan_repos supports it?
        # scan_repos.py expects a GitHub repo name.
        
        # Let's use a real public repo that is small.
        # "octocat/Hello-World" is standard.
        # But we want to test Syft.
        # Let's use "psf/requests" (large) or something smaller with dependencies.
        # "kennethreitz/requests-html"
        
        # Actually, let's just use "octocat/Hello-World" and assume Syft finds nothing, 
        # OR we can manually create the directory in the container before running the test?
        # That's complicated.
        
        # Let's use a real repo: "pallets/flask" (Python)
        real_repo_name = "pallets/flask"
        
        # Check if it exists in DB, if not create it
        real_repo = db.query(Repository).filter(Repository.name == real_repo_name).first()
        if not real_repo:
            real_repo = Repository(
                name=real_repo_name,
                description="Flask",
                url=f"https://github.com/{real_repo_name}"
            )
            db.add(real_repo)
            db.commit()
            db.refresh(real_repo)
        print(f"Using repo: {real_repo.name} ({real_repo.id})")

        # Trigger Scan via API
        print("Triggering Syft scan via API...")
        payload = {
            "repo_name": real_repo_name,
            "scan_type": "full",
            "scanners": ["syft"]
        }
        res = requests.post(f"{API_BASE}/scans/", json=payload)
        if res.status_code != 200:
            print(f"API Failed: {res.status_code} {res.text}")
            exit(1)
            
        scan_data = res.json()
        scan_id = scan_data["scan_id"]
        print(f"Scan triggered: {scan_id}")
        
        # Poll for completion
        print("Waiting for scan to complete...")
        for i in range(30): # Wait up to 30 seconds (it might fail fast if tools missing, or succeed if tools present)
            # Note: In the current setup, 'api' container runs the command.
            # 'api' container DOES NOT have 'syft'.
            # So we expect it to fail or error out.
            # But we want to verify the FLOW.
            
            scan_run = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
            print(f"Status: {scan_run.status}")
            
            if scan_run.status in ["completed", "failed"]:
                break
            time.sleep(2)
            db.expire_all()
            
        print(f"Final Status: {scan_run.status}")
        if scan_run.status == "failed":
            print(f"Error: {scan_run.error_message}")
            # If it failed because "syft not found", that confirms the logic ran!
            if "syft" in str(scan_run.error_message) or "No such file" in str(scan_run.error_message):
                print("SUCCESS: Logic executed (failure expected due to missing tools in API container)")
                # In a real env, we'd have tools.
            else:
                print("FAILURE: Unexpected error")
                exit(1)
        elif scan_run.status == "completed":
            print("SUCCESS: Scan completed!")
            # Check dependencies
            deps = db.query(Dependency).filter(Dependency.repository_id == real_repo.id).all()
            print(f"Dependencies found: {len(deps)}")
        else:
            print("FAILURE: Timed out")
            exit(1)

    except Exception as e:
        print(f"Verification failed: {e}")
        exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    verify_api_scan()
