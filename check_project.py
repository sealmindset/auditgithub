import sys
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.api import models

# Environment check
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://auditgh:auditgh_secret@localhost:5432/auditgh_kb")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

import uuid

repos = db.query(models.Repository).all()
print(f"Total repos: {len(repos)}")
for r in repos:
    print(f"{r.id} | {r.name} | {r.description}")
