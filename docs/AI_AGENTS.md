# AI Agents Guide

AuditGH uses multiple AI agents to enhance security scanning with intelligent analysis, correlation, remediation recommendations, and automated self-healing.

## Overview

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           AuditGH AI Agent System                          │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────┐ │
│  │  Organization Agent │    │  Credential Matcher │    │  API Discovery  │ │
│  │  (ai_org_agent.py)  │    │ (ai_credential_     │    │ (ai_api_        │ │
│  │                     │    │  matcher.py)        │    │  discovery.py)  │ │
│  │  • Multi-org mgmt   │    │                     │    │                 │ │
│  │  • Schema sync      │    │  • Service detect   │    │  • Path fuzzing │ │
│  │  • Credential mgmt  │    │  • URL correlation  │    │  • OpenAPI find │ │
│  │  • Scan orchestrate │    │  • LLM inference    │    │  • Code clues   │ │
│  └─────────────────────┘    └─────────────────────┘    └─────────────────┘ │
│           │                          │                          │          │
│           └──────────────────────────┼──────────────────────────┘          │
│                                      │                                     │
│                    ┌─────────────────────────────────┐                     │
│                    │    Credential URL Test Agent    │                     │
│                    │  (ai_credential_url_agent.py)   │                     │
│                    │                                 │                     │
│                    │  • AuthN/Z testing              │                     │
│                    │  • Path discovery & fuzzing     │                     │
│                    │  • Sample data retrieval        │                     │
│                    │  • OSINT gathering              │                     │
│                    │  • Risk assessment              │                     │
│                    │  • Executive summaries          │                     │
│                    └─────────────────────────────────┘                     │
│                                      │                                     │
│           ┌──────────────────────────┼──────────────────────────┐          │
│           │                          │                          │          │
│           ▼                          ▼                          ▼          │
│  ┌─────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐ │
│  │  Self-Annealing │    │    LLM Provider     │    │   Scheduler         │ │
│  │  Agent          │    │ (Claude/GPT/Ollama) │    │   Service           │ │
│  │                 │    │                     │    │                     │ │
│  │  • Data repair  │    │  • Analysis         │    │  • Cron jobs        │ │
│  │  • DOE approach │    │  • Summaries        │    │  • Auto-triggers    │ │
│  │  • Quality score│    │  • Recommendations  │    │  • Job management   │ │
│  └─────────────────┘    └─────────────────────┘    └─────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Agent Inventory

| Agent | File | Purpose | LLM Required | Scheduled |
|-------|------|---------|--------------|-----------|
| **Organization Agent** | `execution/ai_org_agent.py` | Multi-org orchestration | No | No |
| **Credential Matcher** | `execution/ai_credential_matcher.py` | Credential-to-URL correlation | Optional | No |
| **API Discovery** | `execution/ai_api_discovery.py` | API path reverse engineering | Optional | No |
| **Credential URL Tester** | `execution/ai_credential_url_agent.py` | Security testing & analysis | Yes | No |
| **Self-Annealing Agent** | `scripts/self_annealing_agent.py` | Data integrity & repair | No | Yes |

---

## Quick Reference

| What | Where | Why |
|------|-------|-----|
| **Organization Agent** | `execution/ai_org_agent.py` | Manages multi-tenant organizations, credentials, and database schemas |
| **Credential Matcher** | `execution/ai_credential_matcher.py` | Correlates discovered secrets to their target API services |
| **API Discovery Agent** | `execution/ai_api_discovery.py` | Reverse engineers API paths from code and live probing |
| **Credential URL Tester** | `execution/ai_credential_url_agent.py` | Tests credentials against APIs, generates risk assessments |
| **Self-Annealing Agent** | `scripts/self_annealing_agent.py` | Detects and repairs data integrity issues automatically |

---

## 1. Organization Agent

**File:** `execution/ai_org_agent.py`

### What
Manages multi-organization orchestration including database provisioning, schema synchronization, and credential management for multi-tenant deployments.

### Where
- **Main Script**: `execution/ai_org_agent.py`
- **Secrets Manager**: `execution/secrets_manager.py`
- **API Router**: `src/api/routers/organizations.py`
- **UI Component**: `src/web-ui/components/OrganizationSelector.tsx`
- **Migration**: `migrations/002_organizations.sql`

### Why
Enterprise deployments need to:
- Scan multiple GitHub organizations with different PATs
- Isolate data between organizations
- Maintain consistent database schemas across tenants
- Securely store and rotate credentials

### Capabilities

| Capability | Description |
|------------|-------------|
| **Organization CRUD** | Create, read, update, delete organizations |
| **Database Provisioning** | Create org-specific databases |
| **Schema Synchronization** | Keep all org schemas in sync |
| **Drift Detection** | Identify schema differences |
| **Credential Management** | Secure PAT storage via Fernet encryption |
| **Scan Orchestration** | Context switching between organizations |

### Workflow Position
```
User Request → Organization Agent → Select Org → Load Credentials → Execute Scan
```

### LLM Requirement
**None** - This agent uses deterministic logic only.

### Usage
```bash
# List organizations
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --list-orgs'

# Create organization
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --create-org mycompany --github-org my-org --token ghp_xxx'

# Check schema drift
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --check-drift'

# Select organization for scanning
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --target mycompany'
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/organizations/` | GET | List all organizations |
| `/organizations/current` | GET | Get current organization |
| `/organizations/{name}/select` | POST | Select organization (loads PAT) |
| `/organizations/{name}/credentials` | PUT | Update organization's PAT |
| `/organizations/{name}/credentials/status` | GET | Check if PAT configured |
| `/organizations/schema/drift` | GET | Check for schema drift |

---

## 2. Credential Matcher

**File:** `execution/ai_credential_matcher.py`

### What
Intelligently matches discovered credentials (API keys, tokens, secrets) to their target API services using pattern matching, domain analysis, and optional LLM inference.

### Where
- **Main Script**: `execution/ai_credential_matcher.py`
- **Used By**: `execution/ai_credential_url_agent.py`
- **API Integration**: `src/api/routers/api_audit.py`

### Why
Security scanners find credentials but don't know what service they belong to. This agent:
- Correlates secrets to their target APIs for validation testing
- Identifies the authentication method (Bearer, API Key, Basic Auth)
- Enables automated credential-URL testing

### Capabilities

| Capability | Description |
|------------|-------------|
| **Service Detection** | Identify service from credential patterns (Azure, AWS, Stripe, etc.) |
| **Domain Matching** | Correlate credentials to URLs by domain |
| **File Proximity** | Use file location context for matching |
| **Naming Convention Analysis** | Parse variable names for service hints |
| **LLM Inference** | Use AI for ambiguous cases (optional) |

### Supported Services

| Service | Detection Patterns | Auth Headers |
|---------|-------------------|--------------|
| **Azure** | `azure`, `ocp-apim`, `subscription`, `microsoft` | `Ocp-Apim-Subscription-Key` |
| **AWS** | `aws`, `cognito`, `s3`, `lambda`, `dynamodb` | `Authorization: AWS4-HMAC-SHA256` |
| **Firebase** | `firebase`, `fcm`, `google` | `Authorization: key=` |
| **Stripe** | `stripe`, `payment` | `Authorization: Bearer sk_` |
| **Mixpanel** | `mixpanel` | `Authorization: Basic` |
| **Instabug** | `instabug` | `X-Instabug-App-Token` |
| **Generic API** | `api_key`, `x-api-key` | `X-API-Key` |

### Workflow Position
```
Secret Scanner → Findings → Credential Matcher → Matched Pairs → URL Tester
```

### LLM Requirement
**Optional** - Works without LLM using pattern matching. LLM improves accuracy for ambiguous cases.

### Usage
```python
from execution.ai_credential_matcher import detect_service_from_credential

credential = {
    "type": "api_key",
    "value": "sk-...",
    "file_path": "config/azure.json"
}

service, confidence = detect_service_from_credential(credential)
# Returns: ("Azure", 85)
```

---

## 3. API Discovery Agent

**File:** `execution/ai_api_discovery.py`

### What
Reverse engineers API paths from discovered servers using static code analysis, dynamic probing, and LLM inference to find hidden endpoints.

### Where
- **Main Script**: `execution/ai_api_discovery.py`
- **Used By**: `execution/ai_credential_url_agent.py`
- **API Integration**: `src/api/routers/api_audit.py`

### Why
Discovered API servers often have undocumented endpoints. This agent:
- Finds hidden admin, debug, and internal endpoints
- Discovers OpenAPI/Swagger specifications
- Extracts API paths from source code (Retrofit, REST clients)
- Enables comprehensive API security testing

### Capabilities

| Capability | Description |
|------------|-------------|
| **Static Code Analysis** | Extract API paths from source code |
| **Dynamic Probing** | Test common API paths against live servers |
| **OpenAPI Discovery** | Find and parse swagger/openapi specs |
| **Pattern Recognition** | Identify API patterns (REST, GraphQL) |
| **LLM Path Inference** | Generate likely paths based on context |

### Probe Levels

| Level | Paths | Use Case |
|-------|-------|----------|
| **Light** | ~10 | Quick health check |
| **Medium** | ~30 | Standard discovery |
| **Full** | ~100+ | Deep enumeration |

### Common Paths Probed

| Category | Example Paths |
|----------|---------------|
| **OpenAPI/Swagger** | `/swagger.json`, `/openapi.json`, `/api-docs` |
| **Health/Status** | `/health`, `/status`, `/ping` |
| **Authentication** | `/auth`, `/login`, `/oauth`, `/token` |
| **User Management** | `/users`, `/me`, `/profile`, `/account` |
| **Hidden/Debug** | `/debug`, `/internal`, `/admin`, `/.env` |

### Workflow Position
```
Server Discovery → API Discovery Agent → Discovered Paths → Credential URL Tester
```

### LLM Requirement
**Optional** - Pattern matching works without LLM. LLM improves path prediction.

---

## 4. Credential URL Test Agent

**File:** `execution/ai_credential_url_agent.py`

### What
Comprehensive security testing agent that validates credentials against API endpoints, performs path discovery, retrieves sample data, and generates AI-powered risk assessments.

### Where
- **Main Script**: `execution/ai_credential_url_agent.py`
- **API Router**: `src/api/routers/api_audit.py`
- **UI Component**: `src/web-ui/components/APIAuditView.tsx`
- **Database Model**: `src/api/models.py` (CredentialURLTestResult)

### Why
Discovered credentials need validation to determine:
- Are they still active/valid?
- What access level do they provide?
- What data can be accessed?
- What is the business risk?

This agent automates the entire credential validation workflow.

### Capabilities

| Capability | Description |
|------------|-------------|
| **Authentication Testing** | Verify credentials work (AuthN) |
| **Authorization Testing** | Check access levels (AuthZ) |
| **Path Discovery** | Fuzz for hidden endpoints |
| **Sample Data Retrieval** | Fetch accessible data |
| **Sensitive Data Detection** | Find PII, credentials, secrets |
| **OSINT Gathering** | Search GitHub, documentation |
| **Risk Assessment** | AI-generated threat analysis |
| **Executive Summaries** | Human-readable reports |

### Test Modes

| Mode | Description | Rate Limiting | Use Case |
|------|-------------|---------------|----------|
| **none** | Aggressive testing | No delays | Internal APIs |
| **cautious** | Evasion techniques | Random delays, UA rotation | Production APIs |
| **insane** | All safeties off | Includes POST/PUT/DELETE | Authorized pentests |

### Sensitive Data Patterns Detected

| Pattern | Regex | Risk |
|---------|-------|------|
| **Email** | `[a-zA-Z0-9._%+-]+@...` | Medium |
| **Phone** | `\b\d{3}[-.]?\d{3}[-.]?\d{4}\b` | Medium |
| **SSN** | `\b\d{3}-\d{2}-\d{4}\b` | Critical |
| **Credit Card** | `\b(?:\d{4}[-\s]?){3}\d{4}\b` | Critical |
| **JWT** | `eyJ[a-zA-Z0-9_-]*\.eyJ...` | High |
| **AWS Key** | `AKIA[0-9A-Z]{16}` | Critical |
| **Private Key** | `-----BEGIN.*PRIVATE KEY-----` | Critical |

### Workflow Position
```
Matched Credentials → URL Test Agent → Test Results → AI Analysis → Report
                                            │
                                            ▼
                                    ┌───────────────┐
                                    │  LLM Provider │
                                    │  (Required)   │
                                    └───────────────┘
```

### LLM Requirement
**Required** - This agent needs an LLM for:
- Executive summary generation
- Risk assessment
- Remediation recommendations
- Data sensitivity classification

### Usage
```bash
# Via Web UI: API Audit → Test Credentials
# Via API:
curl -X POST http://localhost:8000/api-audit/test-credential-url \
  -H "Content-Type: application/json" \
  -d '{
    "credential_id": "uuid",
    "url": "https://api.example.com",
    "mode": "cautious"
  }'
```

---

## 5. Self-Annealing Data Integrity Agent

**File:** `scripts/self_annealing_agent.py`

### What
An automated data integrity agent that implements Design of Experiments (DOE) principles to detect, diagnose, and repair data quality issues across all repositories.

### Where
- **Script**: `scripts/self_annealing_agent.py`
- **Scheduler Integration**: `src/api/scheduler.py`
- **API Endpoints**: `src/api/routers/scheduler.py`
- **Configuration**: `.env` (ANNEALING_* variables)

### Why
During security scanning, data can become inconsistent due to:
- Interrupted scans leaving partial data
- Scanner failures not ingesting all findings
- Schema changes causing data drift
- Missing correlations between tables

The Self-Annealing Agent automatically detects and repairs these issues.

### Capabilities

| Capability | Description |
|------------|-------------|
| **Detection** | Scans all repositories for data integrity issues |
| **Diagnosis** | Analyzes root causes and categorizes by severity |
| **Repair** | Automatically fixes repairable issues |
| **Reporting** | Generates quality metrics and JSON reports |
| **Prevention** | Scheduled runs prevent issue accumulation |

### Issue Types Detected

| Issue Type | Description | Auto-Repair | Severity |
|------------|-------------|-------------|----------|
| `missing_contributors` | Contributors in intel file but not in DB | ✅ Yes | Medium |
| `missing_languages` | Languages in intel file but not in DB | ✅ Yes | Low |
| `missing_sbom` | SBOM in syft file but not in DB | ✅ Yes | Medium |
| `missing_findings` | Findings in scanner files but not in DB | ⚠️ Manual | High |
| `incorrect_finding_type` | Wrong finding_type classification | ✅ Yes | Medium |
| `stale_data` | Data older than scan files | ⚠️ Manual | Low |
| `orphaned_records` | Records without parent repository | ⚠️ Manual | Low |

### DOE Methodology

The agent follows Design of Experiments principles:

```
┌─────────────────────────────────────────────────────────────────┐
│                    DOE Self-Annealing Process                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. FACTOR IDENTIFICATION                                        │
│     └─> Identify all data dimensions (contributors, languages,  │
│         SBOM, findings, finding_types)                          │
│                                                                  │
│  2. LEVEL SETTING                                                │
│     └─> Define expected state (file data) vs actual (DB data)   │
│                                                                  │
│  3. EXPERIMENTAL DESIGN                                          │
│     └─> Systematic scanning of all repositories                 │
│                                                                  │
│  4. ANALYSIS                                                     │
│     └─> Statistical evaluation of data completeness             │
│                                                                  │
│  5. OPTIMIZATION                                                 │
│     └─> Iterative repair and quality improvement                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Workflow Position

```
Scan Complete → Data Stored → Self-Annealing Agent → Verify Integrity
                                      │
                    ┌─────────────────┼─────────────────┐
                    │                 │                 │
                    ▼                 ▼                 ▼
              ┌──────────┐    ┌──────────┐    ┌──────────┐
              │ Detect   │    │ Diagnose │    │ Repair   │
              │ Issues   │    │ Causes   │    │ Data     │
              └──────────┘    └──────────┘    └──────────┘
                    │                 │                 │
                    └─────────────────┼─────────────────┘
                                      │
                                      ▼
                              ┌──────────────┐
                              │ Quality      │
                              │ Report       │
                              └──────────────┘
```

### LLM Requirement
**None** - This agent uses deterministic logic and database queries only.

### Configuration

```bash
# In .env
SCHEDULER_ENABLED=true

# Self-Annealing Agent settings
ANNEALING_CRON=0 3 * * *    # Daily at 3 AM
ANNEALING_ENABLED=true       # Enable scheduled runs
ANNEALING_DRY_RUN=false      # Actually repair (false) or detect only (true)
```

### Usage

**Manual Execution:**
```bash
# Dry run - detect only
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/self_annealing_agent.py --dry-run'

# Full run - detect and repair
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/self_annealing_agent.py'

# Verbose output
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/self_annealing_agent.py --verbose'
```

**Via Scheduler API:**
```bash
# Trigger manually via API
curl -X POST http://localhost:8000/scheduler/jobs/annealing/trigger

# Check status
curl http://localhost:8000/scheduler/jobs/annealing
```

### Output Example

```
============================================================
SELF-ANNEALING DATA INTEGRITY AGENT
============================================================

[Phase 1] DETECTION - Scanning for data integrity issues...

Issue Summary:
  missing_contributors: 25 repositories affected
  missing_languages: 30 repositories affected
  missing_sbom: 15 repositories affected

[Phase 2] DIAGNOSIS - Analyzing 70 issues...

[Phase 3] REPAIR - Fixing auto-repairable issues...
  ✓ Repaired: repo-name - missing_contributors
  ✓ Repaired: repo-name - missing_languages
  ✓ Repaired: repo-name - missing_sbom

============================================================
SELF-ANNEALING REPORT
============================================================
Timestamp: 2025-12-15 03:00:00
Repositories Scanned: 273
Issues Detected: 115
Issues Repaired: 59
Issues Failed: 56
Data Quality Score: 94.9%

Recommendations:
  • Run contributor ingestion for affected repositories
  • Run language stats ingestion for affected repositories

Report saved to: logs/annealing_report_20251215_030000.json
```

### Data Quality Score

The agent calculates a quality score:

```
Score = (total_checks - issues + repaired) / total_checks × 100
```

Where:
- `total_checks` = repositories × 4 data dimensions
- `issues` = detected issues
- `repaired` = successfully repaired issues

### Reports

JSON reports are saved to `logs/annealing_report_*.json`:

```json
{
  "timestamp": "2025-12-15T03:00:00+00:00",
  "repositories_scanned": 273,
  "data_quality_score": 94.9,
  "issues_detected": 115,
  "issues_repaired": 59,
  "issues_failed": 56,
  "issues": [
    {
      "type": "missing_contributors",
      "severity": "medium",
      "repository": "my-repo",
      "organization": "my-org",
      "description": "Contributors exist in intel file (10) but not in database",
      "can_auto_repair": true
    }
  ],
  "recommendations": [
    "Run contributor ingestion for affected repositories"
  ]
}
```

---

## LLM Provider Configuration

### Supported Providers

| Provider | Models | Best For | Cost |
|----------|--------|----------|------|
| **Anthropic Claude** | claude-3-opus, claude-3-sonnet | Complex analysis, low hallucination | $$$ |
| **OpenAI GPT-4** | gpt-4o, gpt-4-turbo | General purpose, fast | $$ |
| **Ollama** | llama3, mistral, codellama | Local/private, free | Free |

### Configuration

```bash
# In .env file

# Option 1: Anthropic Claude (Recommended for security analysis)
AI_PROVIDER=claude
ANTHROPIC_API_KEY=sk-ant-...

# Option 2: OpenAI GPT-4
AI_PROVIDER=openai
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o  # or gpt-4-turbo

# Option 3: Ollama (Local)
AI_PROVIDER=ollama
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3
```

### Model Recommendations

| Use Case | Recommended Model | Why |
|----------|-------------------|-----|
| **Security Analysis** | Claude 3 Opus | Lowest hallucination, best reasoning |
| **General Scanning** | GPT-4o | Good balance of speed/quality |
| **Cost-Sensitive** | Claude 3 Sonnet | Cheaper, still accurate |
| **Air-Gapped/Private** | Ollama + Llama3 | No external API calls |
| **Code Analysis** | GPT-4 or CodeLlama | Better at code patterns |

### Hallucination & Drift Mitigation

To minimize AI hallucination and drift:

1. **Use Claude for security-critical analysis** - Anthropic's models have lower hallucination rates
2. **Provide structured prompts** - All agents use carefully crafted system prompts
3. **Validate AI outputs** - Agents cross-check AI suggestions against actual data
4. **Use temperature=0** - Deterministic outputs where possible
5. **Limit context windows** - Only send relevant data to LLM

---

## Enabling AI Features

### Via CLI

```bash
# Enable AI agent during scan
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --target myorg --ai-agent'

# With specific provider
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --target myorg --ai-agent --ai-provider claude'

# Enable auto-remediation suggestions
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --target myorg --ai-agent --ai-auto-remediate'
```

### Via Environment

```bash
# In .env
ENABLE_AI=true
AI_PROVIDER=claude
ANTHROPIC_API_KEY=sk-ant-...
```

---

## Agent Workflow Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          Complete Scan Workflow                           │
└──────────────────────────────────────────────────────────────────────────┘

1. INITIALIZATION
   ┌─────────────────┐
   │ Organization    │ ──→ Load credentials from secrets manager
   │ Agent           │ ──→ Set database context
   └─────────────────┘ ──→ Initialize scan run

2. SCANNING
   ┌─────────────────┐
   │ Security        │ ──→ Gitleaks, TruffleHog (secrets)
   │ Scanners        │ ──→ Semgrep, CodeQL (SAST)
   └─────────────────┘ ──→ Grype, Trivy (dependencies)

3. DISCOVERY
   ┌─────────────────┐
   │ API Discovery   │ ──→ Find servers in code
   │ Agent           │ ──→ Probe for OpenAPI specs
   └─────────────────┘ ──→ Extract API paths

4. CORRELATION
   ┌─────────────────┐
   │ Credential      │ ──→ Match secrets to services
   │ Matcher         │ ──→ Correlate credentials to URLs
   └─────────────────┘ ──→ Build credential-URL pairs

5. TESTING (Optional - requires LLM)
   ┌─────────────────┐
   │ Credential URL  │ ──→ Test authentication
   │ Test Agent      │ ──→ Discover hidden paths
   └─────────────────┘ ──→ Generate risk assessment

6. REPORTING
   ┌─────────────────┐
   │ Report          │ ──→ Aggregate findings
   │ Generator       │ ──→ AI executive summary (if enabled)
   └─────────────────┘ ──→ Store in database
```

---

## Troubleshooting

### "AI provider not configured"

```bash
# Check environment
echo $AI_PROVIDER
echo $ANTHROPIC_API_KEY  # or OPENAI_API_KEY

# Verify in .env
grep AI_ .env
```

### "Rate limit exceeded"

```bash
# Use cautious mode
--ai-provider claude --ai-mode cautious

# Or reduce parallel workers
--max-workers 2
```

### "Hallucinated findings"

1. Switch to Claude (lower hallucination)
2. Review AI confidence scores
3. Cross-reference with raw scanner output
4. Report false positives for prompt improvement

### "Ollama connection refused"

```bash
# Start Ollama
ollama serve

# Pull model
ollama pull llama3

# Verify
curl http://localhost:11434/api/tags
```

---

## Cost Estimation

| Operation | Claude Opus | GPT-4o | Ollama |
|-----------|-------------|--------|--------|
| Scan 10 repos | ~$0.50 | ~$0.30 | Free |
| Scan 100 repos | ~$5.00 | ~$3.00 | Free |
| Credential test (each) | ~$0.05 | ~$0.03 | Free |
| Full org scan (50 repos) | ~$2.50 | ~$1.50 | Free |

*Estimates based on typical token usage. Actual costs vary.*

---

## Related Documentation

| Document | Description |
|----------|-------------|
| [SCHEDULER.md](SCHEDULER.md) | Cron-based job scheduling for agents |
| [SELF_ANNEALING.md](SELF_ANNEALING.md) | Detailed self-annealing documentation |
| [BACKUP.md](BACKUP.md) | Organization backup and restore |
| [SECURITY_TOOLS.md](SECURITY_TOOLS.md) | Security scanner integration |
| [CHEATSHEET.md](CHEATSHEET.md) | Quick command reference |

---

[← Back to README](../README.md) | [Scheduler →](SCHEDULER.md)
