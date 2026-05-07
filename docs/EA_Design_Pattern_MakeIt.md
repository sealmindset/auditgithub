# Design Pattern: AI-Assisted Application Factory — /make-it Platform

> **Confluence Wiki Format** — Enterprise Architecture Design Pattern
> Follows the [refactoring.guru](https://refactoring.guru/design-patterns/) pattern documentation structure adapted for Enterprise Architecture deliverables.

---

## Pattern Metadata

| Field | Value |
|-------|-------|
| **Pattern Name** | AI-Assisted Application Factory |
| **Category** | Creational — Abstract Factory + Builder + Template Method |
| **Domain** | Application Delivery, Platform Engineering, Citizen Development Governance |
| **Status** | Active — Production Use |
| **Owner** | Enterprise Architecture — Application Platforms |
| **Last Updated** | 2026-05-05 |
| **Reference Implementation** | [/make-it](https://github.com/sealmindset/make-it) skill suite for Claude Code |

---

## Intent

Provide a governed, repeatable factory for producing enterprise-grade applications from plain-language requirements — ensuring that every application ships with identical security, auth, RBAC, observability, and compliance foundations regardless of who builds it or what domain it serves.

**One-liner:** Standardize application creation so that security, auth, and compliance are inherited — not invented — by every team.

---

## Problem

Enterprise application delivery suffers from four systemic failures:

| Failure | Symptom | Cost |
|---------|---------|------|
| **Inconsistent foundations** | Each team builds auth, RBAC, Docker, and logging differently | Security review backlog, audit finding clusters, rework |
| **Security as afterthought** | Security bolted on post-build, if at all | Vulnerabilities in production, compliance gaps, incident response overhead |
| **Expert bottleneck** | Only senior developers can produce production-ready apps | 6-12 week delivery cycles, innovation starvation, shadow IT |
| **Non-repeatable quality** | Quality depends on who built it, not what standards exist | Inconsistent code review outcomes, tribal knowledge dependencies |

Traditional approaches (coding standards docs, architecture review boards, reference architecture PDFs) fail because they require **human interpretation and discipline** at every step. Standards that exist as documents are aspirational; standards that exist as code are enforceable.

---

## Motivation (When to Apply)

Apply this pattern when:

- Enterprise produces **internal applications at volume** (>5/year)
- **Non-developer personas** ("citizen developers", analysts, product managers) need to build functional applications
- **Security and compliance must be guaranteed**, not inspected after the fact
- **Time-to-production** matters — weeks, not quarters
- Multiple teams need **identical foundation patterns** (auth, RBAC, Docker, observability) across different business domains

Do **not** apply for:

- One-off scripts or automation tasks with no UI
- Applications with exotic runtime requirements (real-time, embedded, GPU-intensive)
- Teams with established, mature platform engineering already delivering equivalent consistency

---

## Structure

### Factory Lifecycle

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    APPLICATION FACTORY LIFECYCLE                         │
│                                                                         │
│   /make-it          /try-it          /resume-it         /ship-it        │
│   ┌─────────┐       ┌─────────┐      ┌──────────┐      ┌─────────┐    │
│   │ Preflight│──────▶│ Verify  │◀────▶│ Iterate  │─────▶│ Deploy  │    │
│   │ Ideation │       │ Explore │      │ Features │      │ CI/CD   │    │
│   │ Design   │       │ Fix     │      │ Test     │      │ PR      │    │
│   │ Build    │       │ Report  │      │ Readiness│      │ Promote │    │
│   └─────────┘       └─────────┘      └──────────┘      └─────────┘    │
│        │                                    │                           │
│        ▼                                    ▼                           │
│   /retrofit-it                         /nemo-it ──▶ /fix-it            │
│   ┌───────────┐                        ┌─────────┐  ┌─────────┐       │
│   │ Discovery  │                       │ Scan    │  │ Triage  │       │
│   │ Gap Analysis│                      │ Attest  │  │ Auto-fix│       │
│   │ Risk Score │                       │ Report  │  │ Re-scan │       │
│   │ Retrofit   │                       └─────────┘  └─────────┘       │
│   │ Verify     │                                                       │
│   └───────────┘                                                        │
│                                                                         │
│   /wrap-it                  /argo-it                                    │
│   ┌──────────┐              ┌──────────┐                               │
│   │ Save state│             │ K8s Gen  │                               │
│   │ Shutdown  │             │ CI/CD Gen│                               │
│   │ Breadcrumb│             │ GitOps   │                               │
│   └──────────┘              └──────────┘                               │
└──────────────────────────────────────────────────────────────────────────┘
```

### Layered Architecture of Every Produced Application

```
┌──────────────────────────────────────────────────────────────────┐
│              APPLICATION (produced by factory)                    │
│                                                                  │
│  ┌─── Domain Layer (generated per app) ──────────────────────┐  │
│  │  Pages · APIs · Models · Seed Data · Migrations           │  │
│  │  (Unique to each application — generated from Q&A)        │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌─── AI Safety Layer (if AI features detected) ─────────────┐  │
│  │  Input Sanitization · Output Validation · Rate Limiting   │  │
│  │  PII Masking · Error Sanitization · Prompt Management     │  │
│  │  System Prompt Hardening · NeMo Guardrails Testing        │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌─── Foundation Layer (inherited from scaffold) ────────────┐  │
│  │  OIDC Auth · RBAC (4 roles) · Database + Migrations      │  │
│  │  DataTable · Sidebar · Breadcrumbs · Command Palette      │  │
│  │  Activity Logs · Application Settings · Dark Mode         │  │
│  │  Docker Compose · Health Checks · Mock Services           │  │
│  │  Security Headers · Parameterized Queries                 │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌─── Quality Gate Layer (enforced at build time) ───────────┐  │
│  │  100+ Build Standards · Build-Verify (static + live)      │  │
│  │  Self-Healing Loop (3 cycles) · Security Scan             │  │
│  │  Guardrail Tiers (0-5) · Compliance Checks               │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Participants (Roles & Responsibilities)

| Participant | Role | Owns |
|-------------|------|------|
| **Enterprise Architect** | Pattern owner. Defines guardrails, build standards, compliance mapping, scaffold architecture | Pattern template, tier system, governance framework |
| **Platform Engineering** | Maintains scaffolds, skill code, build-verify logic, fix strategies | Scaffold codebase, skill updates, quality gate implementation |
| **Application Builder ("Vibe Coder")** | Describes requirements in plain language, verifies output, iterates | Domain knowledge, acceptance criteria, feature verification |
| **Security / GRC** | Validates attestations, reviews risk-flagged items, accepts residual risk | Attestation review, compliance sign-off, exception register |
| **DevOps / SRE** | Consumes Terraform artifacts, manages CI/CD pipelines, operates production | Infrastructure provisioning, deployment automation, runtime monitoring |

---

## Design Pattern Analogs

Each component of the /make-it platform maps to a classical design pattern — applied at enterprise architecture scale:

### Creational Patterns

| Pattern | EA Application | /make-it Implementation |
|---------|---------------|------------------------|
| **Abstract Factory** | Produces families of related, compatible components (auth + RBAC + Docker + UI + AI safety) that work together | Scaffold system: `fastapi-nextjs` and `nextjs-fullstack` each produce a complete, compatible application family. Selecting one scaffold guarantees all components integrate |
| **Builder** | Constructs complex applications step by step, same process produces different representations | 5-phase lifecycle: Preflight → Ideation → Design → Build → Ship. Same process, different applications. `app-context.json` accumulates decisions at each step |
| **Prototype** | Clones pre-verified templates instead of building from scratch | Scaffolds are golden prototypes — 98 files of battle-tested code with `[BRACKET_PLACEHOLDERS]` replaced per application. Clone + customize, never reinvent |
| **Factory Method** | Subclasses (project types) determine what gets created while the interface stays the same | Tier system: Web App (Tier 1), IDE Extension (Tier 2), CLI (Tier 3), Library (Tier 4), API Service (Tier 5). Each type activates different creation logic while the `/make-it` interface is identical |

### Structural Patterns

| Pattern | EA Application | /make-it Implementation |
|---------|---------------|------------------------|
| **Decorator** | Wraps applications with cross-cutting concerns without modifying business logic | AI safety layer wraps AI calls (sanitize → invoke → validate). RASP middleware wraps all requests (detect, never block). Security headers wrap all responses. None modify domain code |
| **Facade** | Provides simplified interface hiding internal complexity | Every `/` skill is a facade. User says `/make-it` — behind it: 14 prompt templates, scaffold selection, placeholder replacement, Docker orchestration, build-verify, self-healing. User sees: Q&A → working app |
| **Composite** | Treats individual components and groups uniformly | Guardrail tier system: Tier 0 (universal) applies to all. Tier 1 (web) adds web-specific. AI guardrails add if detected. The system composes tiers — each application gets exactly the guardrails it needs, treated uniformly by build-verify |
| **Proxy** | Controls access to the underlying service | Mock services act as proxies during development: mock-OIDC proxies for real Entra ID/Okta, mock Jira proxies for real Jira. Same interface, controlled access, swappable at deploy time |

### Behavioral Patterns

| Pattern | EA Application | /make-it Implementation |
|---------|---------------|------------------------|
| **Template Method** | Fixed algorithm skeleton with customizable steps | Build process is the template: Preflight → Ideation → Design → Build → Verify is fixed. Domain-specific generation (models, pages, APIs) is the customizable step. Security foundations are locked steps that cannot be skipped |
| **Strategy** | Swappable algorithms selected at runtime based on context | AI provider abstraction: `AI_PROVIDER` env var swaps between Anthropic, OpenAI, Azure AI Foundry, Ollama. Same interface, different strategy. Fix strategies: 12 interchangeable remediation algorithms selected per finding type |
| **Chain of Responsibility** | Request passes through handler chain; each decides to process or pass | Build-verify pipeline: static checks → container health → auth flow → API endpoints → page rendering → permission boundaries. Each handler passes or triggers self-healing before passing |
| **Observer** | Event-driven notifications across system boundaries | RASP → LogStore → Cribl Stream → SIEM → Jira. Security events observed at application layer, published through log infrastructure, consumed by SecOps. Application builder never sees it |
| **State** | Object behavior changes based on internal state | Application lifecycle states: Ideation → Design → Build → Verified → Shipped → Production. Each state enables different operations. `/resume-it` reads `.make-it-state.md` to determine current state and available transitions |
| **Memento** | Captures and restores state without exposing implementation | `git tag pre-fix-it` and `git tag pre-retrofit` create rollback points. `.make-it-state.md` captures session state. `app-context.json` captures all design decisions. Full state restoration at any checkpoint |
| **Command** | Encapsulates requests as objects with undo capability | Each `/` skill is a command object: self-contained, auditable, reversible. `/fix-it` captures each fix as a discrete action with rollback. `/ship-it` creates PR as atomic command with full audit trail |
| **Visitor** | New operations on existing structures without modifying them | `/nemo-it` visits any existing application — runs 6 security assessment categories across the codebase without modifying it. New scan categories can be added without changing application structure |

---

## Guardrail Tier System

**Design Pattern Analog:** Composite — tiers compose additively per application type

| Tier | Scope | What It Enforces | Activated When |
|------|-------|-----------------|----------------|
| **Tier 0** | Universal | Git, changelog, secrets hygiene, input validation, dependency currency | Every project |
| **Tier 1** | Web Application | OIDC auth, RBAC, Docker, standard UI, security headers, parameterized queries | App has UI + backend |
| **Tier 2** | IDE Extension | Extension manifest, scoped activation, SecretStorage, bundled output | VS Code extension detected |
| **Tier 3** | CLI Tool | Argument parser, --help/--version, exit codes, structured output | CLI tool detected |
| **Tier 4** | Library | Package manifest, type declarations, public API surface, no circular deps | Library/SDK detected |
| **Tier 5** | API Service | Health check, OpenAPI spec, structured logging, consistent errors | Backend-only service |
| **AI Additive** | AI Features | Safety pipeline, prompt management, NeMo Guardrails, rate limiting | `ai_features.needed = true` |

**Deliverable:** Guardrail tier matrix showing which checks apply to which project type, with severity levels ([BLOCK], [FIX], [WARN]).

---

## Quality Assurance Layers

**Design Pattern Analog:** Chain of Responsibility — each layer processes or escalates

```
Layer 1: Foundation     Scaffold provides pre-verified patterns
                        (debugged once, reused always)
                               │
                               ▼
Layer 2: Prevention     14 prompt templates encode lessons learned
                        (API contracts, seed data alignment, auth flows)
                               │
                               ▼
Layer 3: Detection      Build-verify silently tests auth, APIs, pages, permissions
                        (static checks + live Docker checks)
                               │
                               ▼
Layer 4: Security       AI safety wiring, dependency scan, SAST
Hardening               (15 AI checks + standard security checks)
                               │
                               ▼
Layer 5: Demo           /try-it presents working app, fix cycle is safety net
                        (user verifies golden path + edge cases)
                               │
                               ▼
Layer 6: Attestation    /nemo-it scans → attestation → /fix-it auto-remediates
                        (formal security posture documentation)
```

**Deliverable:** Quality layer specification with pass/fail criteria per layer.

---

## AI Safety Architecture

**Design Pattern Analog:** Decorator (runtime wrapping) + Template Method (fixed safety steps) + Strategy (swappable providers)

### Three Protection Layers

| Layer | What It Protects | Controls |
|-------|-----------------|----------|
| **Runtime Controls** | Every AI invocation at execution time | `sanitizePromptInput()`, `validateAgentOutput()`, rate limiting, PII masking, error sanitization, prompt size validation, system prompt hardening |
| **Prompt Template Validation** | Admin editing surface (supply-chain injection) | `validatePromptTemplate()` blocklist, immutable safety preamble, draft/test/publish workflow, variable interpolation sanitization |
| **Behavioral Testing** | AI behavior under adversarial conditions | NeMo Guardrails: 6 categories (prompt injection, jailbreak, toxicity/bias, topic boundaries, PII leakage, hallucination), 60+ test cases |

### Compliance Mapping (AI-Specific)

| Framework | Control | /make-it Implementation |
|-----------|---------|------------------------|
| NIST AI RMF — GOVERN 1.2 | Trustworthy AI characteristics | AI safety controls enforced at build time — not optional |
| NIST AI RMF — MEASURE 2.5 | AI system evaluated for safety | NeMo Guardrails: 18 tests at build, 60+ at deploy, self-healing loop |
| ISO 42001 — 6.1.2 | AI risk assessment | Build-verify AI safety wiring checks (15 items) + behavioral testing |
| ISO 42001 — 8.3 | AI risk treatment | 12 fix strategies with AUTO/SEMI-AUTO/MANUAL classification |
| OWASP AI Top 10 — AI01 | Prompt Injection | `sanitizePromptInput()` + delimiter tags + system prompt hardening |
| OWASP AI Top 10 — AI02 | Sensitive Info Disclosure | PII masking + error sanitization + URL sanitization in logs |
| OWASP AI Top 10 — AI05 | Improper Output Handling | `validateAgentOutput()` + schema validation + XSS scanning |
| OWASP AI Top 10 — AI06 | Excessive Agency | Rate limiting + prompt size validation + conversation depth limits |

**Deliverable:** AI safety control matrix mapping each OWASP/NIST/ISO control to specific code implementation.

---

## Applicability to Other Enterprise Platforms

This pattern is **not specific to Claude Code or /make-it**. The factory model applies wherever the enterprise needs governed, repeatable application creation:

| Component | /make-it | Backstage / IDP | Low-Code (Power Apps) | Cookiecutter / Yeoman |
|-----------|---------|-----------------|----------------------|----------------------|
| **Conversational intake** | Natural language Q&A | Portal forms + templates | Drag-and-drop UI | CLI prompts |
| **Scaffold / golden path** | Pre-built scaffold with placeholders | Software templates + TechDocs | Built-in connectors | Project templates |
| **Guardrails** | Tiered build standards (100+ checks) | Scorecards + policies | DLP + environment policies | Linting rules |
| **Build verification** | Automated Docker-based testing | CI pipeline integration | Built-in testing (limited) | Post-generation scripts |
| **Security attestation** | /nemo-it scan + formal attestation | Plugin-based scanning | Microsoft Secure Score | External tool integration |
| **Auto-remediation** | /fix-it (12 strategies) | PR-based policy enforcement | Auto-patching (limited) | Manual |
| **Lifecycle management** | /resume-it + /wrap-it + /ship-it | Software catalog lifecycle | Environment management | Manual |

**Enterprise Architecture value:** The pattern defines *what governance the factory must provide*, not *which tool provides it*. Any platform that satisfies the participant roles, guardrail tiers, and quality layers implements this pattern.

---

## Related Patterns

| Pattern | Relationship |
|---------|-------------|
| **[Defense-in-Depth for Managed AI Services](./EA_Design_Pattern_AWS_Bedrock.md)** | Complementary — Bedrock pattern governs AI *infrastructure*; this pattern governs AI *application construction*. Apps built by /make-it consume Bedrock through the safety layers defined here |
| **Abstract Factory** | Core concept — the scaffold system is a concrete factory producing compatible component families |
| **Builder** | Core concept — the 5-phase lifecycle is a step-by-step construction process |
| **Template Method** | Core concept — fixed build skeleton with customizable domain-specific steps |
| **Decorator** | Applied throughout — safety layers, RASP, security headers wrap without modifying domain logic |
| **Facade** | Every `/` skill is a facade hiding orchestration complexity |
| **Visitor** | `/nemo-it` is a pure visitor — assesses any application without modifying it |

---

## Repeatable Deliverable Checklist

Every architect applying this pattern produces:

- [ ] **Factory Lifecycle Diagram** — phases from intake to production with skill/tool mapping
- [ ] **Scaffold Architecture Spec** — what the golden path includes, what it generates per-app
- [ ] **Guardrail Tier Matrix** — check IDs, severity levels, activation criteria per project type
- [ ] **Quality Layer Specification** — pass/fail criteria per layer, self-healing rules
- [ ] **AI Safety Control Matrix** — controls mapped to OWASP AI/NIST AI RMF/ISO 42001 (if AI features)
- [ ] **Participant RACI** — who owns pattern, scaffolds, guardrails, attestation, deployment
- [ ] **Platform Comparison** — how the factory maps to available tooling (IDP, low-code, CLI generators)
- [ ] **Build Standards Document** — enumerated checks with unique IDs, tiers, and severity ([BLOCK], [FIX], [WARN])
- [ ] **Attestation Template** — formal security posture report template for GRC consumption
- [ ] **State Breadcrumb Spec** — what gets captured at each lifecycle stage for continuity

---

## References

- [refactoring.guru — Design Patterns](https://refactoring.guru/design-patterns/) — Pattern documentation structure
- [/make-it Repository](https://github.com/sealmindset/make-it) — Reference implementation
- [AI Governance: Homegrown Applications](https://github.com/sealmindset/make-it/blob/main/docs/AI-GOVERNANCE-HOMEGROWN.md) — NIST AI RMF + ISO 42001 + OWASP AI mapping
- [RASP Design](https://github.com/sealmindset/make-it/blob/main/docs/RASP-DESIGN.md) — Runtime Application Self-Protection architecture
- [Defense-in-Depth for Managed AI Services](./EA_Design_Pattern_AWS_Bedrock.md) — Complementary infrastructure pattern
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [ISO/IEC 42001:2023](https://www.iso.org/standard/81230.html) — AI Management System
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
