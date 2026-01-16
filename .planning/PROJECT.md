# AuditGH Enterprise Security Platform

## What This Is

A multi-tenant SaaS security auditing platform that scans GitHub repositories for vulnerabilities, provides AI-powered remediation guidance, and delivers comprehensive security insights. Transforms from a prototype into an enterprise-grade platform with full authentication, authorization, multi-tenant isolation, and production-ready deployment on AWS EKS.

## Core Value

Provide secure, isolated, enterprise-grade security auditing for multiple organizations with comprehensive RBAC, ensuring that each tenant's sensitive security data is completely protected while maintaining a seamless, scalable SaaS experience.

## Requirements

### Validated

- ✓ GitHub repository scanning and analysis - existing
- ✓ AI-powered vulnerability analysis (Claude, GPT-4, Gemini, Ollama) - existing
- ✓ 15+ security scanner integrations (Gitleaks, Semgrep, Grype, CodeQL, etc.) - existing
- ✓ FastAPI backend with REST API - existing
- ✓ Next.js/React frontend with data visualization - existing
- ✓ PostgreSQL database with SQLAlchemy ORM - existing
- ✓ Docker containerization (API, Scanner, UI, DB) - existing
- ✓ Basic multi-tenant organization model - existing
- ✓ Security finding management and tracking - existing
- ✓ Attack surface analysis capabilities - existing
- ✓ Contributor intelligence and developer profiles - existing
- ✓ PDF/DOCX report generation - existing
- ✓ Jira integration for issue tracking - existing

### Active

- [ ] **Critical Security Fixes** - Address SQL injection vulnerabilities, rotate exposed credentials, fix 50+ bare exception handlers
- [ ] **Authentication & Authorization** - Full OIDC/SSO integration with Entra ID and Okta
- [ ] **RBAC System** - 5-tier role hierarchy (Super Admin, Admin, Analyst, Manager, User) with granular permissions
- [ ] **Enhanced Multi-Tenancy** - Schema-per-tenant PostgreSQL architecture with complete data isolation
- [ ] **Cribl Integration** - Centralized log management with structured logging pipeline
- [ ] **AWS EKS Deployment** - Production Kubernetes deployment with Helm charts and infrastructure as code
- [ ] **Minikube Local Testing** - Complete local development and testing environment
- [ ] **Test Infrastructure** - Comprehensive test suite (unit, integration, E2E)
- [ ] **API Authentication** - Secure API endpoints with JWT token validation
- [ ] **Session Management** - Secure session handling with token refresh
- [ ] **Audit Logging** - Complete audit trail of user actions and data access
- [ ] **Database Migrations** - Alembic integration for controlled schema evolution

### Out of Scope

- Mobile/responsive UI optimization - Desktop-first design, mobile support deferred to v2
- AI-powered local log analysis - Cribl handles centralized logging, local AI analysis is future enhancement
- Multi-cloud deployment (Azure, GCP) - AWS EKS is v1 target, other clouds are v2+
- Advanced analytics dashboard - Beyond basic security metrics, complex analytics are v2+
- Additional third-party integrations - Beyond Jira, other ticketing systems (ServiceNow, PagerDuty) are future work
- Real-time collaboration features - Comments, mentions, notifications are v2+
- Custom scanner development SDK - Plugin system exists, formal SDK/marketplace is v2+

## Context

**Existing Platform:**
The codebase is a sophisticated security auditing platform with:
- Hybrid monolith architecture (Python backend, TypeScript frontend)
- 25+ database models tracking organizations, repositories, findings, contributors
- Plugin architecture for security scanners and AI providers
- 22+ API routers handling different domains
- Multi-language scanning support (Python, JavaScript, TypeScript, Go, Java, Ruby, .NET)

**Technical Debt Identified:**
Codebase mapping revealed critical issues requiring immediate attention:
- **Security:** SQL injection in `database_router.py`, hardcoded secrets in `.env`
- **Stability:** 50+ bare `except:` blocks silently swallowing errors
- **Maintainability:** 8,653-line `scan_repos.py` monolith
- **Testing:** No automated test framework or test coverage
- **Error Handling:** Missing proper exception handling and logging

**Current State:**
- Development environment using Docker Compose
- Basic organization-based multi-tenancy (row-level filtering)
- No authentication system - trusts client-provided organization context
- Manual testing only - no CI/CD pipeline
- Local deployment only - no production infrastructure

## Constraints

- **Technology Stack**: Python 3.11+ (FastAPI), TypeScript (Next.js 16), PostgreSQL 15+ - established ecosystem
- **Container Platform**: Docker required - entire stack containerized
- **Cloud Provider**: AWS EKS for production - Kubernetes orchestration chosen
- **Identity Providers**: Must support Entra ID and Okta - enterprise SSO requirement
- **Database**: PostgreSQL only - existing data model and queries
- **Security**: Zero tolerance for data leakage between tenants - absolute isolation required
- **Backward Compatibility**: Existing security scanner integrations must continue working

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Fix critical security issues before new features | SQL injection and exposed credentials are unacceptable risks in a security platform | — Pending |
| Schema-per-tenant multi-tenancy | Stronger isolation than row-level security while simpler than database-per-tenant | — Pending |
| AWS EKS over ECS | Kubernetes provides better orchestration for complex multi-container application | — Pending |
| OIDC/SSO as primary auth | Enterprise customers require SSO, avoids password management burden | — Pending |
| Cribl for centralized logging | Proven enterprise log management, integrates with existing loguru setup | — Pending |
| Defer AI local log analysis | Cribl handles centralized needs, AI analysis is enhancement not requirement | — Pending |

---
*Last updated: 2026-01-12 after initialization*
