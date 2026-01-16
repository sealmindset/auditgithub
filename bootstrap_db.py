
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

if not session.query(Organization).filter_by(name="sealmindset").first():
    org = Organization(
        name="sealmindset",
        github_org="sealmindset",
        display_name="Seal Mindset",
        database_name="auditgh_sealmindset",
        is_active=True,
        is_default=True
    )
    session.add(org)
    print("Created organization: sealmindset")
else:
    org = session.query(Organization).filter_by(name="sealmindset").first()
    org.database_name = "auditgh_sealmindset"
    org.is_default = True
    print("Updated organization: sealmindset (database_name set)")

session.commit()
session.close()
print("Bootstrap complete.")
