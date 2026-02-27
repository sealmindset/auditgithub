# What Is API-First Architecture?

**Source:** [API_First.md](API_First.md) - Section 2

---

## Definition

API-First is a development methodology where APIs are designed, documented, and treated as first-class products before any implementation begins. The API contract is the source of truth.

## Contrast with Traditional Approaches

| Approach | How it works | Risk |
|----------|-------------|------|
| **UI-First** | Build the screens, then bolt on a backend | Backend becomes a grab-bag of UI-specific endpoints; hard to reuse |
| **Code-First** | Build the backend, then figure out the interface | API shape is dictated by implementation details; poor developer experience |
| **API-First** | Design the contract, then build backend and clients in parallel | Requires discipline, but produces the most maintainable and extensible system |

## Core Principles in AuditGitHub

| Principle | AuditGitHub Implementation |
|-----------|---------------------------|
| **API is the product** | Every capability — scanning, findings, AI analysis, scheduling — is an API endpoint first |
| **Contract before code** | OpenAPI 3.0.3 spec (`swagger/openapi.yaml`) with 50+ path definitions and reusable schemas |
| **Clients are equal consumers** | Web UI, CLI, scanner, AI agent all use the same endpoints with the same auth |
| **No client has privileged access** | Zero direct database connections from any client; all queries go through the API |
| **Security at the boundary** | Auth, RBAC, rate limiting, and audit enforced uniformly in the API middleware stack |
