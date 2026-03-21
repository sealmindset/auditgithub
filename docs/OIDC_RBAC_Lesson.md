You are a **principal security architect + staff software engineer**. Your task is to generate a **comprehensive, thorough, complete implementation plan** for **OIDC + RBAC** integration, **reverse engineered from the conversation** and the repository context, with an emphasis on **lessons learned** and **preventing pitfalls/blockers** encountered previously.

### 0) Inputs you MUST read first (repo-aware)

1.  Read the full conversation context provided in this chat (treat it as the “source of truth” for requirements, constraints, blockers, and decisions).
2.  In the repo, open and summarize:
    *   `@CHANGELOG.md` (identify auth/RBAC-related changes, regressions, breaking changes, migration notes, and any implicit requirements). (This file exists in the workspace context.) [\[selectcomf...epoint.com\]](https://selectcomfort-my.sharepoint.com/personal/rob_vance_example-org_com/Documents/Forms/DispForm.aspx?ID=7783&web=1)
    *   `@CLAUDE.md` (identify dev workflow, repo conventions, required commands, test strategy, CI expectations, and any architectural constraints; treat it as binding).
3.  Search the repo for auth-related code and docs:
    *   keywords: `oidc`, `openid`, `jwt`, `jwks`, `pkce`, `authorization code`, `rbac`, `roles`, `permissions`, `claims`, `scopes`, `audience`, `issuer`, `tenant`, `entra`, `azure ad`, `passport`, `next-auth`, `express`, `middleware`, `authz`, `policy`, `casl`, `opa`, `rego`, `gate`, `subject`, `principal`.
    *   find: current auth implementation, env vars, config, docs, any half-finished branches, feature flags, TODOs, failing tests, and integration points.

### 1) Objective

Create a **complete implementation plan** to deliver **OIDC authentication + RBAC authorization** end-to-end, including:

*   architecture, configuration, code changes, rollout strategy
*   lessons learned / pitfalls and blockers (root causes + mitigations)
*   acceptance criteria, security controls, observability, and runbooks
*   a task breakdown that’s directly executable (tickets/epics) and maps to repo modules

This is NOT a generic guide. It must be specific to the repo/conversation you just read.

### 2) Non-negotiable security + governance alignment (must incorporate)

Align the plan to these policy patterns and constraints (use them as guardrails, not as optional suggestions):

*   **Least privilege + role-based access** expectations (avoid unnecessary custom roles, prefer built-in role patterns where applicable, scope correctly). [\[Sleep Numb...chitecture \| Word\]](https://selectcomfort.sharepoint.com/sites/ConcurrencyProject/_layouts/15/Doc.aspx?sourcedoc=%7B266644D7-F711-41E6-AE8C-A888D67C5B56%7D&file=Sleep%20Number%20Azure%20Technical%20Reference%20Architecture.docx&action=default&mobileredirect=true&DefaultItemOpen=1)
*   **MFA enforced for cloud resource access** and **access reviews at least bi-annually**, with clear owner responsibilities and auditability. [\[Cloud Gove...nce Policy \| Word\]](https://selectcomfort-my.sharepoint.com/personal/samuel_swafford_example-org_com/_layouts/15/Doc.aspx?sourcedoc=%7BD39E3EF7-A1BC-45CD-B372-21DEEB1F9CA4%7D&file=Cloud%20Governance%20Policy.docx&action=default&mobileredirect=true&DefaultItemOpen=1)
*   If using Entra ID patterns, explicitly plan for **Assignment Required**, preventing unintended access, and document required admin roles to configure. [\[Accessing...t Entra ID \| PDF\]](https://selectcomfort-my.sharepoint.com/personal/lauren_carr_example-org_com/Documents/Microsoft%20Teams%20Chat%20Files/Accessing%20the%20Critical%20Start%20Platform%20-%20SSO%20via%20Microsoft%20Entra%20ID.pdf?web=1)
*   Assume the org uses **PIM / JIT elevation** patterns; include operational guidance and blast-radius controls. [\[\[EXTERNAL\]...t Entra ID \| Outlook\]](https://outlook.office365.com/owa/?ItemID=AAMkADI4ODA0N2NhLWNjZjYtNDYyMi05MTBmLWNjYTA2Y2FiYTc1ZgBGAAAAAAAapIOKOV6ySoZtLT%2fWpILRBwBkZ%2fDxpXF6QprIr%2f27JTzSAAAAAAEMAABkZ%2fDxpXF6QprIr%2f27JTzSAAUBhtycAAA%3d&exvsurl=1&viewmodel=ReadMessageItem)
*   Include app registration / API permissions hygiene and any conditional access considerations that are relevant for this integration (call out where those decisions live). [\[PromptInje...itigations \| Word\]](https://selectcomfort-my.sharepoint.com/personal/samuel_swafford_example-org_com/_layouts/15/Doc.aspx?sourcedoc=%7B3F0E032E-CBC2-40BB-91DB-6560AE25876E%7D&file=PromptInjectionMitigations.docx&action=default&mobileredirect=true&DefaultItemOpen=1)

### 3) Deliverables (your output must include ALL)

Produce a single cohesive plan with the following sections:

#### A) Executive summary (1–2 pages)

*   what will be built, why, and what “done” means
*   key risks, top pitfalls, and mitigation themes
*   dependencies and decision points

#### B) Reverse-engineered requirements (from conversation + repo)

*   functional requirements (login, session, API access, logout, token refresh, etc.)
*   authorization requirements (roles/permissions model, enforcement points, admin flows)
*   constraints (hosting, proxies, CI/CD, libraries, runtime, multi-tenant vs single-tenant)
*   explicit “lesson learned” items: what previously blocked progress and why

#### C) Target architecture

Include diagrams in text form (boxes/arrows) covering:

*   OIDC flow (browser/app → IdP → callback → token validation)
*   token validation path (JWKS fetch/cache/rotation, issuer/audience checks, clock skew)
*   RBAC enforcement path (claims → principal → role mapping → permission evaluation)
*   service-to-service auth (if applicable) and separation from user auth
*   data model changes (if any) and audit logging

#### D) OIDC implementation details (repo-specific)

*   chosen OIDC flow and why (e.g., auth code + PKCE)
*   config matrix: issuer, tenant, client\_id, client\_secret or cert, redirect URIs, logout URIs
*   token handling policy: access token vs id token usage, refresh strategy, session storage
*   claim strategy: groups/app roles/scopes mapping into internal principal
*   error handling and recovery: invalid\_state, redirect mismatch, nonce replay, key rotation, etc.
*   local dev + test env strategy (how to run without production IdP fragility)

#### E) RBAC model + mapping strategy

*   define roles and permissions (recommend a permission taxonomy)
*   how roles are assigned (IdP groups/appRoles → internal roles; or internal DB)
*   edge cases: “group overage”/large claims, nested groups, missing claims, disabled users
*   admin and change management: who can grant roles, audit trail, review cadence
*   enforcement patterns: middleware guards, policy objects, per-route/per-resource checks

#### F) Pitfalls & blockers (must be explicit and exhaustive)

Create a table:

*   **Pitfall/Blocker**
*   **Symptom**
*   **Root cause**
*   **Detection signal**
*   **Preventative design**
*   **Runbook fix**
*   **Owner**

Must include at least:

*   redirect URI mismatches, callback route drift
*   issuer/audience mismatches across envs
*   JWKS caching/rotation bugs
*   clock skew and token expiry handling
*   incorrect use of id token vs access token
*   missing consent / wrong permission type (delegated vs app-only)
*   inconsistent claim mapping across services
*   multi-tenant confusion (if applicable)
*   CI failing due to env var/config divergence
*   local dev friction / secrets handling
*   “assignment required” and unintended access gaps

#### G) Implementation plan (phased)

Break into phases with:

*   goals, scope, exit criteria
*   code changes (by repo module / file areas)
*   test plan additions (unit/integration/e2e)
*   migration steps, feature flags, and rollback strategy
*   security validation steps (threat modeling deltas, abuse cases)
*   comms + enablement (docs, runbooks, onboarding)

#### H) Validation & acceptance criteria

*   measurable checks (auth works, RBAC denies correctly, logging present, metrics)
*   security test cases (token tampering, replay, role escalation attempts, etc.)
*   operational readiness (alerts, dashboards, runbooks, incident triage)

#### I) Work items / tickets

Provide:

*   epics → stories → tasks
*   estimated complexity (S/M/L) and dependencies
*   owners/roles (dev, platform, IAM, security)

### 4) Style constraints (important)

*   Be **repo-anchored**: cite exact files/modules/commands you discovered.
*   If something is unknown, **state assumptions explicitly** and continue.
*   Prefer “build it once, enforce everywhere” patterns (central auth module/middleware).
*   Favor least privilege, auditability, and clean rollback paths.
*   Optimize for preventing rework and eliminating integration blockers.

### 5) First actions (do these before writing the plan)

1.  Summarize `@CHANGELOG.md` items relevant to auth/identity/rbac and extract implied requirements.
2.  Summarize `@CLAUDE.md` rules that constrain how we implement and test.
3.  Provide a short “repo auth inventory”:
    *   current auth approach
    *   where request identity is determined
    *   where authorization is enforced (if at all)
    *   where configuration lives
4.  Then produce the full plan following Deliverables A–I.

Begin now.

***

### One quick note (so you’re not surprised)

I can see multiple instances of CHANGELOG.md in your environment metadata, but I **can’t directly open file contents from here**—the prompt above is designed so the repo-aware agent **will** open `@CHANGELOG.md` and `@CLAUDE.md` locally and incorporate them. [\[selectcomf...epoint.com\]](https://selectcomfort-my.sharepoint.com/personal/rob_vance_example-org_com/Documents/Forms/DispForm.aspx?ID=7783&web=1), [\[selectcomf...epoint.com\]](https://selectcomfort-my.sharepoint.com/personal/rob_vance_example-org_com/Documents/Forms/DispForm.aspx?ID=7765&web=1), [\[selectcomf...epoint.com\]](https://selectcomfort-my.sharepoint.com/personal/rob_vance_example-org_com/Documents/Forms/DispForm.aspx?ID=7749&web=1), [\[selectcomf...epoint.com\]](https://selectcomfort-my.sharepoint.com/personal/rob_vance_example-org_com/Documents/Forms/DispForm.aspx?ID=7722&web=1), [\[selectcomf...epoint.com\]](https://selectcomfort-my.sharepoint.com/personal/rob_vance_example-org_com/Documents/Forms/DispForm.aspx?ID=7799&web=1), [\[selectcomf...epoint.com\]](https://selectcomfort.sharepoint.com/sites/SiebelCRMUpgrade/Shared%20Documents/Forms/DispForm.aspx?ID=4547&web=1)

When implementing, make the **actual code changes in small, testable commits** aligned to your repo conventions—still keeping the plan-first approach.
