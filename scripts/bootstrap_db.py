
import os
import sys
from sqlalchemy import create_engine, text
from src.api.database import Base
from src.api.models import Organization

# Ensure we use the correct DB
db_url = os.environ.get("SQLALCHEMY_DATABASE_URL")
if not db_url:
    host = os.environ.get("POSTGRES_HOST", "db")
    user = os.environ.get("POSTGRES_USER", "postgres")
    password = os.environ.get("POSTGRES_PASSWORD", "postgres")
    dbname = os.environ.get("POSTGRES_DB", "security_portal")
    db_url = f"postgresql://{user}:{password}@{host}/{dbname}"

print(f"Connecting to {db_url}...")
engine = create_engine(db_url)

print("Creating schema...")
Base.metadata.create_all(bind=engine)

print("Seeding organizations...")
from sqlalchemy.orm import sessionmaker
Session = sessionmaker(bind=engine)
session = Session()

github_org = os.environ.get("GITHUB_ORG", "example-org")
org_db_name = f"auditgh_{os.environ.get('GITHUB_ORG', 'example-org')}"

if not session.query(Organization).filter_by(name=github_org).first():
    org = Organization(
        name=github_org,
        github_org=github_org,
        display_name=github_org,
        database_name=org_db_name,
        is_active=True,
        is_default=True
    )
    session.add(org)
    print(f"Created organization: {github_org}")
else:
    org = session.query(Organization).filter_by(name=github_org).first()
    org.database_name = org_db_name
    org.is_default = True
    print(f"Updated organization: {github_org} (database_name set)")

session.commit()
session.close()
print("Bootstrap complete.")
