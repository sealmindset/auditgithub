# Appendix A — Full Endpoint Inventory

**Source:** [API_First.md](API_First.md) - Appendix A

---

## Core Security

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/findings` | Paginated findings with filters (severity, status, repo, scanner) |
| GET | `/findings/{id}` | Finding details with risk score, AI triage, remediations |
| PATCH | `/findings/{id}/status` | Update finding status |
| POST | `/findings/{id}/snooze` | Snooze finding for specified duration |
| GET | `/secrets` | Secret findings with filtering |
| GET | `/secrets/dashboard` | Secrets dashboard with active/high-risk secrets |
| POST | `/secrets/{id}/validate` | Validate if secret is still active |
| POST | `/scans` | Trigger security scan (background task) |
| GET | `/scans/{id}` | Get scan status |
| GET | `/attack-surface/*` | Summary, secrets, abandoned repos, stale contributors, high-risk repos |
| GET | `/attack-paths` | Attack path visualization for high-risk repos |

## Repository Management

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/repositories` | List repositories with pagination |
| POST | `/repositories` | Register new repository |
| GET | `/repositories/{name}` | Get repository by name |
| GET | `/projects` | List projects with summary stats |
| POST | `/github/repos/{name}/sync` | Sync repository metadata from GitHub |
| POST | `/github/sync-all` | Sync all repositories (background) |
| GET | `/github/sync-status` | Get sync status |

## Organization & Tenant

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/organizations` | List organizations |
| POST | `/organizations` | Create organization with database |
| POST | `/organizations/{id}/select` | Switch organization context |
| PATCH | `/organizations/{id}/credentials` | Update GitHub token |
| GET | `/tenants` | List tenants |
| POST | `/tenants` | Create tenant with schema isolation |
| POST | `/tenants/{slug}/provision` | Trigger database provisioning |

## Authentication & Users

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/auth/login/{provider}` | Initiate OIDC login (Entra ID / Okta) |
| POST | `/auth/break-glass/login` | Emergency local password login |
| GET | `/auth/me` | Get current user info |
| POST | `/auth/refresh` | Refresh tokens (one-time use rotation) |
| POST | `/auth/revoke` | Revoke access token |
| POST | `/auth/device/code` | Initiate device flow |
| POST | `/auth/device/token` | Poll for device token |
| GET | `/auth/device/authorizations` | List authorized devices |
| GET | `/api/users` | List users (admin) |
| POST | `/api/invitations` | Send user invitation |

## AI & Analysis

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/projects/{id}/repositories/{id}/ai-chat` | AI security conversation |
| GET | `/api/projects/{id}/repositories/{id}/ai-context` | AI context summary |

## Integrations

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/integrations/jira/webhook` | Jira status webhook |
| POST | `/cribl/forward` | Forward log entry to Cribl Stream |
| POST | `/cribl/test` | Test Cribl connectivity |
| POST | `/cicd/sync` | Sync CI/CD data from GitHub Actions |
| GET | `/cicd/stats` | Deployment and workflow statistics |

## Operations

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/analytics/*` | Hero metrics, threat radar, AI insights, trends |
| GET | `/sla/dashboard` | SLA compliance dashboard |
| GET | `/sla/mttr` | Mean Time to Remediate statistics |
| GET | `/scheduler/status` | Scheduler status and job info |
| POST | `/scheduler/jobs/{name}/trigger` | Manually trigger scheduled job |
| GET | `/schedules` | List scan schedules |
| PUT | `/schedules/{repoId}` | Update scan schedule |
| GET | `/settings` | Get system settings |
| POST | `/settings` | Save system settings |
