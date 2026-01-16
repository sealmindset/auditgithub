# Roadmap: AuditGH Enterprise Security Platform

## Overview

Transform the existing security auditing platform from a prototype into a production-ready enterprise SaaS. The journey begins with critical security remediation, then builds authentication and authorization infrastructure, implements proper multi-tenant isolation, and culminates with production deployment on AWS EKS with comprehensive testing and centralized logging.

## Domain Expertise

None

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Critical Security Remediation** - Fix SQL injection, rotate credentials, implement proper error handling (Completed 2026-01-12)
- [x] **Phase 2: Authentication Foundation** - Set up OIDC/SSO infrastructure with Entra ID and Okta (Completed 2026-01-12)
- [ ] **Phase 3: RBAC System** - Implement 5-tier role hierarchy with permission system
- [ ] **Phase 4: Multi-Tenant Architecture** - Schema-per-tenant PostgreSQL with complete isolation
- [ ] **Phase 5: API Security & Sessions** - JWT authentication, token refresh, secure endpoints
- [ ] **Phase 6: Cribl Log Integration** - Centralized logging with structured pipeline
- [ ] **Phase 7: Test Infrastructure** - Pytest, test coverage, CI/CD foundation
- [ ] **Phase 8: AWS EKS Deployment** - Kubernetes manifests, Helm charts, production infrastructure

## Phase Details

### Phase 1: Critical Security Remediation
**Goal**: Eliminate critical security vulnerabilities identified in codebase analysis before building new features
**Depends on**: Nothing (first phase)
**Research**: Unlikely (internal code fixes, established patterns)
**Plans**: 3 plans

1. **01-01: Fix SQL Injection Vulnerabilities** - Replace f-string SQL with parameterized queries in database_router.py and init_db.py
2. **01-02: Rotate Exposed Credentials** - Rotate GitHub, Azure AI, and Jira credentials; implement .env.example template
3. **01-03: Replace Bare Exception Handlers** - Fix 50+ bare except blocks with specific exceptions and proper logging

### Phase 2: Authentication Foundation
**Goal**: Implement OIDC/SSO authentication with Entra ID and Okta for enterprise user access
**Depends on**: Phase 1
**Research**: Completed (2026-01-12)
**Research topics**: OIDC/OAuth2 flows, Entra ID app registration and configuration, Okta app setup, FastAPI auth middleware patterns, token validation strategies
**Plans**: 3 plans

1. **02-01: OIDC Foundation & Provider Setup** - Install Authlib and dependencies, create src/auth/ module, configure Entra ID and Okta with OIDC discovery, integrate SessionMiddleware
2. **02-02: Login Flow with PKCE** - Implement /auth/login/{provider} with forced PKCE, /auth/callback/{provider} with token exchange and email_verified validation, /auth/logout and /auth/me endpoints
3. **02-03: JWT Validation & Protected Routes** - Create JWT validation middleware with JWKS 24-hour caching, implement algorithm whitelist and claim validation, build FastAPI auth dependencies, protect 3 representative API routes

### Phase 3: RBAC System
**Goal**: Build comprehensive role-based access control with 5-tier hierarchy (Super Admin, Admin, Analyst, Manager, User)
**Depends on**: Phase 2
**Research**: Completed (2026-01-12)
**Research topics**: RBAC implementation patterns in FastAPI, permission decorator design, role hierarchy best practices, resource-level permissions, audit logging for access control
**Plans**: 4 plans (recommended)

1. **03-01: RBAC Database Schema** - ✅ Completed (2026-01-12) - Create Role, Permission, RolePermission, UserRole tables with 5-tier hierarchy and tenant-scoped roles
2. **03-02: Permission Dependencies & Decorators** - ✅ Completed (2026-01-13) - Implement require_permissions(), require_role(), get_user_permissions() with Redis caching (5-min TTL)
3. **03-03: Audit Logging Infrastructure** - ✅ Completed (2026-01-13) - Structured audit logging for authorization decisions with Cribl integration and automatic logging
4. **03-04: Protect API Routes** - Add permission dependencies to all 22+ API routers with RBAC enforcement

Plans will be finalized during phase planning.

### Phase 4: Multi-Tenant Architecture
**Goal**: Implement schema-per-tenant PostgreSQL architecture with complete data isolation between organizations
**Depends on**: Phase 3
**Research**: Likely (schema isolation patterns)
**Research topics**: PostgreSQL schema-per-tenant implementation, SQLAlchemy multi-schema configuration, tenant resolution from authentication context, schema migration strategies, connection pooling per tenant
**Plans**: TBD

Plans will be defined during phase planning.

### Phase 5: API Security & Sessions
**Goal**: Secure all API endpoints with JWT authentication, implement token refresh, and proper session management
**Depends on**: Phase 4
**Research**: Unlikely (JWT is well-established, building on Phase 2 auth foundation)
**Plans**: TBD

Plans will be defined during phase planning.

### Phase 6: Cribl Log Integration
**Goal**: Integrate Cribl for centralized log management with structured logging pipeline
**Depends on**: Phase 5
**Research**: Likely (external service integration)
**Research topics**: Cribl HTTP Event Collector API, structured logging formats for security events, loguru-to-Cribl pipeline configuration, log retention policies, sensitive data redaction
**Plans**: TBD

Plans will be defined during phase planning.

### Phase 7: Test Infrastructure
**Goal**: Establish comprehensive test infrastructure with Pytest, achieve test coverage, and set up CI/CD foundation
**Depends on**: Phase 6
**Research**: Unlikely (Pytest is established, standard testing patterns)
**Plans**: TBD

Plans will be defined during phase planning.

### Phase 8: AWS EKS Deployment
**Goal**: Deploy platform to AWS EKS with Kubernetes manifests, Helm charts, and Minikube local testing environment
**Depends on**: Phase 7
**Research**: Likely (Kubernetes deployment architecture)
**Research topics**: EKS cluster setup and best practices, Helm chart structure for multi-container apps, PostgreSQL in Kubernetes (StatefulSet vs managed RDS), AWS Secrets Manager integration, Minikube local development workflow, ingress controller configuration
**Plans**: TBD

Plans will be defined during phase planning.

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Critical Security Remediation | 3/3 | Complete | 2026-01-12 |
| 2. Authentication Foundation | 3/3 | Complete | 2026-01-12 |
| 3. RBAC System | 4/4 | Complete | 2026-01-13 |
| 4. Multi-Tenant Architecture | 0/TBD | Not started | - |
| 5. API Security & Sessions | 0/TBD | Not started | - |
| 6. Cribl Log Integration | 0/TBD | Not started | - |
| 7. Test Infrastructure | 0/TBD | Not started | - |
| 8. AWS EKS Deployment | 0/TBD | Not started | - |
