MACH Architectural Analysis: AuditGitHub (AGH) Security Scanning Platform

1. Architectural Foundation: MACH Alignment Assessment

AuditGitHub is an enterprise-grade, AI-powered GitHub repository security scanning platform that detects secrets, vulnerabilities, misconfigurations, and code security issues across multiple organizations. While the platform was not explicitly designed around the MACH framework, its architecture exhibits strong alignment with several MACH principles through pragmatic engineering decisions. The system is best characterized as a modular monolith with microservice-adjacent patterns, achieving many MACH benefits while maintaining operational simplicity.

The following table maps the four MACH principles to AGH's actual implementation behaviors, along with an alignment rating:

MACH Principle	AGH Implementation	Alignment
Microservices	Modular monolith with pluggable scanner components (15+ tools), isolated AI agent system, and decoupled frontend. Scanners operate as on-demand Docker containers with functional isolation, though core orchestration shares a single FastAPI process.	Partial
API-first	RESTful API with OpenAPI/Swagger documentation serves as the single integration point. All clients (Web UI, CLI, AI agents, external scripts) interact exclusively through the API layer. No client has direct database access.	Strong
Cloud-native	AWS ECS Fargate deployment via Terraform IaC, Docker containerization, Redis caching, RDS PostgreSQL, S3-compatible storage. CI/CD via GitHub Actions with environment-based promotion.	Strong
Headless	Fully decoupled Next.js frontend, CLI with Device Flow auth, AI agent integrations, and scriptable API. Core logic is entirely UI-agnostic.	Strong

2. Microservices: Modular Tooling and Functional Isolation

AGH employs a modular monolith architecture rather than true microservices. The FastAPI backend serves as a unified process, but internally the system is composed of well-isolated functional domains that mirror microservice boundaries. The scanning subsystem most closely resembles a microservice pattern, with each tool operating as an independent, stateless execution unit.

2.1 Service Decomposition

The system's functional modules operate with clear domain boundaries:

* Scanner Engine (Microservice-Like): 15+ security tools run as on-demand Docker containers with no shared state. Each scanner (Gitleaks, Semgrep, Trivy, etc.) operates independently and can be replaced, updated, or scaled without affecting other scanners. Results are ingested via standardized report formats.
* AI Agent System (`src/ai_agent/`): A self-contained subsystem with its own orchestration (`agent.py`), reasoning (`reasoning.py`), remediation (`remediation.py`), and multi-provider LLM abstraction (`providers/`). Functions as an internal service boundary within the monolith.
* Authentication Service (`src/auth/`): Isolated module handling OIDC, JWT, API Keys, Device Flow, break-glass access, and session management with its own middleware pipeline.
* RBAC Service (`src/rbac/`): Dedicated role-based access control with Redis-backed permission caching, audit logging, and seed data management.
* Scheduling Service (`src/services/schedule_executor.py`): Background job orchestration via APScheduler, operating independently from request processing.

2.2 Where AGH Diverges from Pure Microservices

The core API, database access, and business logic share a single FastAPI process and a single PostgreSQL database. This is a deliberate architectural trade-off: the platform optimizes for operational simplicity and deployment efficiency over distributed system complexity. The modular internal structure, however, means the system could be decomposed into true microservices if scaling demands require it.

Key Differences from the MACH Reference Model:
* No inter-service messaging (no RabbitMQ, Kafka, or event bus)
* Shared database rather than per-service data stores
* Synchronous request-response rather than event-driven choreography
* APScheduler cron jobs rather than event-triggered workflows

3. API-First: Programmatic Orchestration and Integration

This is AGH's strongest MACH alignment. The platform was designed from the ground up with the API as the primary integration surface. Every capability is exposed programmatically.

3.1 API Design Characteristics

* Standard: RESTful HTTP with JSON payloads
* Documentation: Full OpenAPI specification at `/openapi.json` with interactive Swagger UI at `/docs`
* Versioning: Implicit via route structure (21 router modules)
* Authentication: Multi-method (JWT Bearer, API Key via `X-API-Key`, OIDC, Session cookies, Device Flow)
* Multi-Organization Context: Requests are scoped via `X-Organization-ID` header, `X-Organization-Name` header, or `org` query parameter, enforced by `OrganizationContextMiddleware`

3.2 API Router Domains (21 Modules)

The API surface is organized into clear functional domains:

| Domain | Routers | Purpose |
|--------|---------|---------|
| Identity & Access | auth, users, invitations, api_keys, device_flow | Authentication, authorization, user lifecycle |
| Core Data | repositories, findings, scans, secrets | Security data management and retrieval |
| AI & Analysis | ai, ai_chat, analytics, attack_surface, attack_paths, api_audit, contributor_profiles | Intelligent analysis and reporting |
| Operations | organizations, projects, schedules, scheduler, tenants | Platform management and orchestration |
| Integration | github_sync, git_sync, cicd, jira, cribl, settings | External system connectivity |
| Utility | sla, feedback, sandbox | Supporting capabilities |

3.3 Consumer Patterns

The API-first design enables multiple consumer types:

1. Web UI (Next.js): Primary user interface, fully decoupled
2. CLI Tool: Headless operation via Device Flow authentication
3. AI Agents: Claude, GPT-4, and Gemini access findings and generate recommendations via API
4. Scanner Engine: Reports ingested through API after on-demand execution
5. External Scripts: Backup, maintenance, and integration scripts
6. CI/CD Pipelines: Automated scanning triggered via API

3.4 Feedback Loop Pattern

Similar to the MACH reference model's orchestration loop, AGH implements a structured feedback cycle:

1. Request: Client or scheduler initiates a scan via API
2. Execution: Scanner containers execute domain-specific tools against target repositories
3. Standardized Response: Findings are returned in normalized formats (severity, category, location, remediation)
4. Informed Iteration: AI agents analyze structured findings to generate remediation recommendations, risk scores, and attack path visualizations
5. Human Gate: Analysts review AI-generated insights and take action through the dashboard

4. Cloud-Native: Infrastructure and Elastic Deployment

AGH demonstrates strong cloud-native characteristics across its deployment and infrastructure patterns.

4.1 Containerization

Every component runs in Docker containers with dedicated Dockerfiles:

* `Dockerfile.api` - FastAPI backend (Python 3.11)
* `Dockerfile.scanner` - Scanner engine with security tools
* `Dockerfile.ui` - Next.js frontend (Node.js)
* `docker-compose.yml` - Local development orchestration (7 services: api, web-ui, scanner, db, redis, mock-oidc, mailhog)

4.2 Cloud Infrastructure (AWS)

Production deployment uses fully managed AWS services via Terraform IaC:

| Component | AWS Service | Purpose |
|-----------|-------------|---------|
| Compute | ECS Fargate | Serverless container orchestration |
| Database | RDS PostgreSQL | Managed relational database (Multi-AZ for prod) |
| Caching | ElastiCache Redis | Sessions, permissions, rate limiting |
| Storage | S3 | Scan logs and report artifacts |
| Networking | VPC + ALB | Isolated networking with load balancing |
| Security | Security Groups + TLS | Network isolation and encryption |
| Identity | IAM + OIDC | Service authentication |
| Container Registry | ECR | Docker image storage |

Terraform modules (`infrastructure/terraform/modules/`) provide clean separation:
`vpc/`, `rds/`, `elasticache/`, `alb/`, `ecs/`, `s3/`, `iam/`

4.3 CI/CD Pipeline

GitHub Actions workflow (`.github/workflows/deploy-ecs.yml`) implements environment-based promotion:

* `develop` branch deploys to dev
* `staging` branch deploys to staging
* `main` branch deploys to prod

Pipeline stages: Checkout, AWS OIDC Auth, ECR Login, Docker Build & Push, ECS Task Definition Update, Service Deployment, Health Check Verification.

4.4 Where AGH Diverges from Cloud-Native Ideals

* No auto-scaling policies defined (ECS supports them but they are not configured)
* No service mesh or distributed tracing
* No serverless functions (Lambda) for event-driven workloads
* Single-region deployment (no multi-region failover)
* Background jobs run in-process (APScheduler) rather than as separate scalable workers

5. Headless: Decoupled Presentation and UI-Agnostic Automation

AGH achieves full headless architecture. The core platform logic has zero dependency on any presentation layer.

5.1 Decoupled Client Architecture

The system supports five distinct client types, all consuming the same API:

1. Web Dashboard (Next.js 16.0 / React 19): Full-featured UI with organization management, findings explorer, analytics dashboards, and schedule management. Communicates exclusively via API. Can be replaced entirely without affecting backend logic.

2. CLI Tool: Authenticated via Device Flow (RFC 8628). Enables headless scanning and reporting from developer workstations or CI/CD pipelines.

3. AI Agents: Multi-provider LLM integration (Claude, GPT-4, Gemini, Ollama) that consumes findings data and generates remediation recommendations, architecture analysis, and threat assessments. Operates autonomously through the API.

4. External Integrations: Jira (ticket creation), Cribl (log forwarding), GitHub (README generation via git push). All interact through the API layer.

5. Scheduled Automation: APScheduler triggers scans, backups, and maintenance tasks without any UI involvement.

5.2 Human Operator Role

Mirroring the MACH reference model's asynchronous oversight pattern, AGH separates human involvement into:

* Configuration: Setting up organizations, credentials, scan schedules, and security policies via `policy.yaml`
* Strategic Review: Analyzing AI-generated insights, triaging findings, and approving remediation actions through the dashboard
* Gating: RBAC controls determine which users can trigger scans, modify findings, or access sensitive data

The human operator is a director of policy and review, not a participant in the execution layer.

6. Phased Execution Analysis: AGH Scanning Lifecycle

AGH's scanning workflow parallels the MACH reference model's phased approach, adapted for continuous security monitoring rather than point-in-time penetration testing.

* Phase 1 (Configuration): Organization onboarding with GitHub credentials, repository selection, scan schedule creation, and policy definition. Multi-organization support allows parallel management of multiple GitHub organizations.

* Phase 2 (Discovery & Scanning): Broad-spectrum execution of 15+ security tools across repositories. Scanners operate in parallel Docker containers. Results are normalized into a unified findings schema with severity, category, file location, and remediation metadata.

* Phase 3 (Analysis & Enrichment): AI agents analyze structured findings to generate:
  - Risk scores and severity assessments
  - Attack path visualizations
  - Contributor risk profiles
  - API endpoint security analysis
  - Remediation recommendations with code suggestions

* Phase 4 (Reporting & Action): Findings flow to multiple output channels:
  - Web dashboard with filtering, search, and export (PDF/Excel)
  - Jira ticket creation for remediation tracking
  - Cribl log forwarding for SIEM integration
  - Analytics dashboards with trend analysis and compliance metrics

* Phase 5 (Continuous Monitoring): Self-healing operations maintain platform integrity:
  - Scheduled re-scanning with AI-adaptive schedule recommendations
  - Data integrity checks (self-annealing)
  - Automatic new repository detection and scanning
  - Session and credential lifecycle management

7. Multi-Tenancy: An Extension Beyond MACH

AGH extends MACH principles with a robust multi-tenancy model not addressed in the reference architecture:

* Single Database, Organization-Scoped: All tables include `organization_id` with enforced filtering via middleware
* Credential Isolation: Per-organization GitHub tokens stored with encryption
* RBAC Scoping: Roles and permissions are organization-specific
* Data Isolation: Queries are automatically scoped; cross-organization data access is architecturally prevented
* Tenant Provisioning: Dynamic organization creation with schema seeding

8. System Integrity and Architectural Conclusion

AGH achieves strong MACH alignment through pragmatic architectural decisions that balance enterprise capability with operational simplicity. The platform is not a textbook MACH implementation, but it captures the essential benefits of each principle.

8.1 MACH Scorecard

| Principle | Rating | Justification |
|-----------|--------|---------------|
| Microservices | Partial (60%) | Modular monolith with microservice-adjacent scanner pattern. Internal boundaries are clean but share process and database. |
| API-first | Strong (90%) | Comprehensive RESTful API with OpenAPI docs. All clients use API exclusively. Multi-auth support. |
| Cloud-native | Strong (85%) | Full containerization, AWS managed services, Terraform IaC, GitHub Actions CI/CD. Lacks auto-scaling and service mesh. |
| Headless | Strong (95%) | Five decoupled client types. Zero UI dependency in core logic. Full automation support. |

8.2 Key Architectural Advantages

1. Composability Through Modularity: The pluggable scanner architecture allows security teams to add, remove, or replace individual tools (e.g., swapping Gitleaks for a newer secrets scanner) without re-engineering the platform. The AI provider abstraction enables the same flexibility for LLM integrations.

2. API-Driven Multi-Client Architecture: The strict API-first design supports simultaneous consumption by web dashboards, CLI tools, AI agents, and external integrations. New client types can be added without backend modifications.

3. AI-Augmented Human Oversight: The headless architecture enables AI agents to execute analysis at machine speed while human operators maintain strategic control through RBAC policies, finding triage, and remediation approval. This mirrors the MACH reference model's "synchronous AI execution with asynchronous oversight" pattern.

8.3 Recommendations for Deeper MACH Alignment

To achieve full MACH compliance, AGH could consider:

1. Extract Scanner Orchestration: Move the scanner execution engine into a dedicated microservice with its own API, enabling independent scaling and deployment.
2. Introduce Event Streaming: Add an event bus (e.g., AWS EventBridge or SQS) to decouple scan completion from finding ingestion, enabling true event-driven workflows.
3. Per-Service Data Stores: Separate the findings database from the authentication/RBAC database to enable independent scaling and deployment.
4. Auto-Scaling Policies: Configure ECS auto-scaling based on scan queue depth and API request volume.
5. Distributed Tracing: Add OpenTelemetry instrumentation for cross-component observability.
