
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.api.models import Organization

# Connect to the tenant DB
host = os.environ.get("POSTGRES_HOST", "db")
user = os.environ.get("POSTGRES_USER", "postgres")
password = os.environ.get("POSTGRES_PASSWORD", "postgres")
dbname = "auditgh_sealmindset"
db_url = f"postgresql://{user}:{password}@{host}/{dbname}"

print(f"Connecting to {db_url}...")
engine = create_engine(db_url)
Session = sessionmaker(bind=engine)
session = Session()

print("Seeding organization in tenant DB...")
# We need the exact ID that the agent uses. 
# The log said: Organization ID: b672ae3e-9f19-4f71-892b-9062fbabc5ab
# I should fetch it from Master DB or hardcode it if I can verify it.
# Actually, I can query Master DB first, get the ID, then insert to Tenant DB.

# Connect to Master DB
master_dbname = "security_portal"
master_db_url = f"postgresql://{user}:{password}@{host}/{master_dbname}"
master_engine = create_engine(master_db_url)
MasterSession = sessionmaker(bind=master_engine)
master_session = MasterSession()

org = master_session.query(Organization).filter_by(name="sealmindset").first()
if not org:
    print("Error: Organization not found in Master DB")
    exit(1)

print(f"Found master org: {org.id}, {org.name}")

# Check if exists in Tenant
tenant_org = session.query(Organization).filter_by(id=org.id).first()
if not tenant_org:
    # Clone it
    new_org = Organization(
        id=org.id,
        name=org.name,
        github_org=org.github_org,
        display_name=org.display_name,
        database_name=org.database_name,
        is_active=org.is_active,
        is_default=org.is_default,
        created_at=org.created_at,
        updated_at=org.updated_at
    )
    session.add(new_org)
    session.commit()
    print("Seeded organization into Tenant DB.")
else:
    print("Organization already exists in Tenant DB.")

session.close()
master_session.close()
