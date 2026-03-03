AuditGitHub (AGH) is built as a **modular monolith** that integrates a wide range of security tools and specialized internal services to monitor GitHub repository security.

### Security Scanners
The platform utilizes a **scanner engine** composed of over **15 security tools** that run as independent, stateless, on-demand Docker containers. These scanners are used to detect secrets, vulnerabilities, and misconfigurations. Specifically named tools in the sources include:
*   **Gitleaks:** Used for secret detection.
*   **Semgrep:** Used for static analysis and code security issues.
*   **Trivy:** Used for vulnerability scanning.

The results from these tools are ingested through the API and normalized into a unified schema that includes severity, category, file location, and remediation metadata.

### Core Software Components
The platform's logic is divided into well-defined functional modules and client types:
*   **FastAPI Backend:** The central process that handles the core API, business logic, and database access.
*   **AI Agent System:** A self-contained subsystem responsible for orchestration, reasoning, and remediation, featuring a multi-provider abstraction for LLMs like **Claude, GPT-4, Gemini, and Ollama**.
*   **Authentication & RBAC Services:** Dedicated modules for identity management (OIDC, JWT, API Keys) and role-based access control with Redis-backed permission caching.
*   **Scheduling Service:** Uses **APScheduler** for background job orchestration and automated scan triggers.
*   **Next.js Web Dashboard:** A decoupled frontend that serves as the primary user interface.
*   **CLI Tool:** A headless client authenticated via Device Flow for use in developer workstations or CI/CD pipelines.

### Core Infrastructure Components
Deployment is managed through **Terraform Infrastructure as Code (IaC)** and **GitHub Actions** for CI/CD, primarily utilizing **AWS** services:
*   **ECS Fargate:** Provides serverless container orchestration for compute.
*   **RDS PostgreSQL:** Serves as the primary managed relational database for all modules.
*   **ElastiCache Redis:** Used for session management, rate limiting, and permission caching.
*   **S3:** Used for storing scan logs and report artifacts.