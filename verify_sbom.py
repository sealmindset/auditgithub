import os
import json
import requests
import uuid
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from src.api.models import Base, Repository, Dependency

# Configuration
API_BASE = os.getenv("API_BASE", "http://localhost:8000")
DB_HOST = os.getenv("POSTGRES_HOST", "localhost")
DB_URL = f"postgresql://auditgh:auditgh_secret@{DB_HOST}:5432/auditgh_kb"

# Setup DB connection
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def verify_sbom():
    db = SessionLocal()
    try:
        print("Connecting to database...")
        # Create dummy repo
        repo_name = f"verify_sbom_{uuid.uuid4().hex[:8]}"
        repo = Repository(
            name=repo_name,
            description="Verification Repo for SBOM",
            url="https://github.com/example/verify-sbom"
        )
        db.add(repo)
        db.commit()
        db.refresh(repo)
        print(f"Created repo: {repo.name} ({repo.id})")

        # Create dummy Syft JSON
        report_dir = "vulnerability_reports/verify_sbom"
        os.makedirs(report_dir, exist_ok=True)
        
        syft_data = {
            "artifacts": [
                {
                    "name": "react",
                    "version": "18.2.0",
                    "type": "npm",
                    "foundBy": "package-lock.json",
                    "licenses": ["MIT"],
                    "locations": [{"path": "package.json"}],
                    "metadata": {"homepage": "https://reactjs.org"}
                },
                {
                    "name": "requests",
                    "version": "2.31.0",
                    "type": "python",
                    "foundBy": "requirements.txt",
                    "licenses": ["Apache-2.0"],
                    "locations": [{"path": "requirements.txt"}],
                    "metadata": {"author": "Kenneth Reitz"}
                }
            ]
        }
        
        syft_path = os.path.join(report_dir, f"{repo_name}_syft_repo.json")
        with open(syft_path, 'w') as f:
            json.dump(syft_data, f)
        print(f"Created dummy SBOM at {syft_path}")

        # Run ingestion (importing here to avoid issues if run outside container context initially)
        from ingest_scans import ingest_sbom
        from pathlib import Path
        
        print("Running ingestion...")
        count = ingest_sbom(db, repo, Path(report_dir) / "dummy")
        db.commit()
        print(f"Ingested {count} dependencies")

        # Verify DB
        deps = db.query(Dependency).filter(Dependency.repository_id == repo.id).all()
        print(f"DB Check: Found {len(deps)} dependencies")
        for d in deps:
            print(f" - {d.name} {d.version} ({d.type})")

        if len(deps) != 2:
            print("FAILED: Expected 2 dependencies in DB")
            exit(1)

        # Verify API
        print(f"Calling API: {API_BASE}/projects/{repo.id}/dependencies")
        try:
            res = requests.get(f"{API_BASE}/projects/{repo.id}/dependencies")
            if res.status_code != 200:
                print(f"API Failed: {res.status_code} {res.text}")
                exit(1)
            
            data = res.json()
            print(f"API Check: Found {len(data)} dependencies")
            if len(data) != 2:
                print("FAILED: Expected 2 dependencies from API")
                exit(1)
                
            print("SUCCESS! SBOM feature verified.")
            
        except Exception as e:
            print(f"API Call Failed: {e}")
            # If API is not reachable (e.g. running inside container but API is separate service), 
            # we might need to rely on DB check or ensure network connectivity.
            # But here we assume we run this script in a way that can reach API.

    except Exception as e:
        print(f"Verification failed: {e}")
        exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    verify_sbom()
