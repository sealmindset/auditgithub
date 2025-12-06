import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.api import models

# Docker container has appropriate env vars set
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    # Fallback if not set (should be set in container)
    user = os.getenv("POSTGRES_USER", "auditgh")
    password = os.getenv("POSTGRES_PASSWORD", "auditgh_secret")
    host = os.getenv("POSTGRES_HOST", "db")
    port = os.getenv("POSTGRES_PORT", "5432")
    dbname = os.getenv("POSTGRES_DB", "auditgh_kb")
    DATABASE_URL = f"postgresql://{user}:{password}@{host}:{port}/{dbname}"

print(f"Connecting to {DATABASE_URL}")

try:
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()

    repo = db.query(models.Repository).filter(models.Repository.name == "auditgithub").first()
    if repo:
        print(f"Updating Repo: {repo.name} ({repo.id})")
        
        report = """# Architecture Overview: AuditGithub (Secure Table Viewer)

## High-Level Overview
AuditGithub is a secure, comprehensive security operations dashboard designed to aggregate, analyze, and visualize security findings from various scanners (TruffleHog, Gitleaks, Semgrep, Trivy, etc.). It acts as a central "Table Viewer" for security posture, providing advanced filtering, sorting, and management of vulnerabilities.

## Tech Stack
- **Frontend**: Next.js 14 (React) with Tailwind CSS and Shadcn UI.
- **Backend**: FastAPI (Python) for high-performance API endpoints.
- **Database**: PostgreSQL with pgvector for finding storage and AI-driven vector search.
- **AI Integration**: Anthropic Claude & OpenAI for triage, remediation, and architectural analysis.
- **Infrastructure**: Docker & Docker Compose for containerized deployment.

## Architecture Patterns
- **Layered Architecture**: Clear separation between UI, API, and Data/AI services.
- **Agentic AI**: Uses an AI Agent pattern for autonomous analysis and remediation.
- **Event-Driven Ingestion**: Scanners produce reports which are ingested and normalized into a unified schema.

## Core Components
1. **Web UI (Next.js)**:
   - Dynamic Tables (`TanStack Table`) for Findings, Repositories, Contributors.
   - Dashboards for metrics and trends.
   - Interactive AI Chat interface for Zero-Day analysis.
2. **API Layer (FastAPI)**:
   - RESTful endpoints for data retrieval.
   - AI orchestration (`/ai/*`) for triage and architecture generation.
   - Websockets (future) or polling for scan status.
3. **Data Layer (PostgreSQL)**:
   - Relational tables for `Repositories`, `Findings`, `Scans`.
   - Vector embeddings for semantic search (AI features).
4. **Scanner Integration**:
   - Python scripts (`scan_repos.py`) orchestrate tools like TruffleHog and Semgrep.
   - Normalized JSON outputs are ingested into the DB.

## Security Features
- **Secret Detection**: extensive scanning for leaked credentials.
- **Zero-Day Analysis**: AI-powered search across all dependencies and code.
- **Secure Defaults**: Docker non-root users, reduced surface area."""

        diagram_code = """from diagrams import Diagram, Cluster
from diagrams.onprem.client import User
from diagrams.onprem.compute import Server
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.container import Docker
from diagrams.programming.framework import React, FastAPI
from diagrams.programming.language import Python

with Diagram("AuditGithub Architecture", show=False, filename="architecture_diagram", graph_attr={"splines": "ortho", "nodesep": "0.8", "ranksep": "1.0"}):
    user = User("Security Analyst")

    with Cluster("Docker Containerized Environment"):
        with Cluster("Frontend"):
            ui = React("Web UI\n(Next.js)")

        with Cluster("Backend Services"):
            api = FastAPI("API Layer\n(FastAPI)")
            # GAP: AI Agent specific icon missing, using Python
            agent = Python("AI Agent\n(Custom)")
            scanner = Docker("Security Scanners\n(Trivy/Semgrep)")

        with Cluster("Data Persistence"):
            db = PostgreSQL("PostgreSQL\n(AuditGH KB)")

    user >> ui
    ui >> api
    api >> db
    api >> agent
    agent >> db
    scanner >> db
    api >> scanner"""

        repo.architecture_report = report
        repo.architecture_diagram = diagram_code
        db.commit()
        print("Successfully updated architecture report and diagram.")
    else:
        print("Repo 'auditgithub' not found in this DB.")
        
except Exception as e:
    print(f"Error: {e}")
