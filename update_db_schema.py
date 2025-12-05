
from sqlalchemy import create_engine
from src.api.config import settings
from src.api.database import Base
from src.api.models import *  # Import all models to ensure they are registered with Base

def init_db():
    # Use the Docker connection string if running inside container, or construct local one
    # But since we are likely running this locally, we need local connection.
    # settings.DATABASE_URL usually points to 'db' host which is for docker.
    
    # Override for local execution if needed, or rely on correct env setup.
    # We found local url is 'postgresql://postgres:postgres@localhost:5432/auditgh_kb'
    
    url = 'postgresql://postgres:postgres@localhost:5432/auditgh_kb'
    print(f"Connecting to {url}...")
    engine = create_engine(url)
    
    print("Creating missing tables...")
    Base.metadata.create_all(bind=engine)
    print("Tables created successfully.")

if __name__ == "__main__":
    init_db()
