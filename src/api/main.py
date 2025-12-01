from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AuditGitHub Security Platform",
    description="API for managing security scans, findings, and remediation workflows.",
    version="1.0.0"
)

from .database import engine
from . import models

# Create database tables
models.Base.metadata.create_all(bind=engine)

from .routers import repositories, jira, ai, scans, analytics, findings, projects, settings

app.include_router(repositories.router)
app.include_router(jira.router)
app.include_router(ai.router)
app.include_router(scans.router)
app.include_router(analytics.router)
app.include_router(findings.router)
app.include_router(projects.router)
app.include_router(settings.router)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {
        "message": "Welcome to AuditGitHub Security Platform API",
        "docs": "/docs",
        "version": "1.0.0"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
