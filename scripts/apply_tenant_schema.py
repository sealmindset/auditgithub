
import os
from sqlalchemy import create_engine
from src.api.database import Base

# Connect to the tenant DB
host = os.environ.get("POSTGRES_HOST", "db")
user = os.environ.get("POSTGRES_USER", "postgres")
password = os.environ.get("POSTGRES_PASSWORD", "postgres")
dbname = f"auditgh_{os.environ.get('GITHUB_ORG', 'example-org')}"
db_url = f"postgresql://{user}:{password}@{host}/{dbname}"

print(f"Connecting to {db_url}...")
engine = create_engine(db_url)

print("Creating schema in tenant DB...")
Base.metadata.create_all(bind=engine)
print("Schema creation complete.")
