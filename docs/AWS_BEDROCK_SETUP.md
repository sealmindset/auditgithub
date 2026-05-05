# AWS Bedrock Setup Guide

Complete guide covering two Bedrock integration paths at Sleep Number:

1. **Claude Code via AWS Bedrock** — Developer tooling (Claude Code CLI/VS Code) using Bedrock as the model provider
2. **Security Hub AI — IR Automation** — Multi-agent Bedrock system for automated incident response

---

## Part 1: Claude Code with AWS Bedrock

Connect Claude Code (CLI or VS Code extension) to AWS Bedrock via IAM Identity Center (SSO).

### 1.1 Prerequisites

| Requirement | Details |
|-------------|---------|
| Claude Code | CLI or VS Code extension installed |
| AWS CLI v2 | Must be v2.x (`aws --version` to verify) |
| Okta Group | Must be member of `aws-bedrock-model-access` — submit EMB ticket if not |

### 1.2 AWS CLI Configuration

Add to `~/.aws/config`:

```ini
# Reusable SSO session
[sso-session aws-sso]
sso_start_url = https://d-90675b2903.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access

# Bedrock profile
[profile sso-bedrock-model-access]
sso_session = aws-sso
sso_account_id = 622711945934
sso_role_name = bedrock-model-access
region = us-east-1
output = json
```

> **Note:** Replace `sso-bedrock-model-access` with any profile name that makes sense for your function.

### 1.3 SSO Login

```bash
# macOS
aws sso login --profile sso-bedrock-model-access
export AWS_PROFILE=sso-bedrock-model-access

# Windows
aws sso login --profile sso-bedrock-model-access
set AWS_PROFILE=sso-bedrock-model-access
```

Opens browser for IAM Identity Center authentication. Stores temporary credentials for profile.

### 1.4 Verify Bedrock Access

```bash
aws bedrock list-inference-profiles
```

Should return JSON listing available foundation models. If authorization error: confirm `aws-bedrock-model-access` Okta group membership, check account ID, role name, region.

### 1.5 Claude Code Settings

Create/edit `~/.claude/settings.json`:

```json
{
  "$schema": "https://json.schemastore.org/claude-code-settings.json",
  "awsAuthRefresh": "aws sso login --profile sso-bedrock-model-access",
  "env": {
    "AWS_PROFILE": "sso-bedrock-model-access",
    "CLAUDE_CODE_USE_BEDROCK": "1",
    "ANTHROPIC_MODEL": "sonnet",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL": "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "ANTHROPIC_DEFAULT_SONNET_MODEL": "us.anthropic.claude-sonnet-4-6",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "us.anthropic.claude-opus-4-6-v1",
    "DISABLE_PROMPT_CACHING": "0"
  },
  "permissions": {
    "deny": [
      "Read(~/.aws/**)",
      "Read(./.env)",
      "Read(./.env.*)",
      "Read(./secrets/**)"
    ],
    "ask": ["WebFetch", "Bash(curl:*)"]
  }
}
```

Key settings:
- `CLAUDE_CODE_USE_BEDROCK=1` — Routes requests through Bedrock instead of Anthropic API
- `awsAuthRefresh` — Auto-refreshes SSO session when credentials expire
- `permissions.deny` — Prevents Claude from reading sensitive credential files

### 1.6 Test

Restart Claude Code, open new session, ask: `what model are you?`

Should respond via Bedrock. If errors, check SSO session is active and profile matches.

### 1.7 VS Code Extension

Configure VS Code to use Bedrock by adding same settings to VS Code's Claude Code extension settings. Ensure `AWS_PROFILE` environment variable is set in your terminal before launching VS Code.

---

## Part 2: Security Hub AI — Bedrock IR Automation

Multi-agent Amazon Bedrock system for automated incident response. HIGH/CRITICAL Security Hub findings flow through an async pipeline into Bedrock agents that collect evidence, analyze CloudTrail, generate runbooks, and notify via Microsoft Teams.

### 2.1 Architecture

```
Security Hub finding (HIGH/CRITICAL)
  └─► EventBridge → Normalizer Lambda → SQS → Worker Lambda
        └─► Bedrock ir-orchestratorAgent (SUPERVISOR)
              ├─► ir-contextAgent       — account owner / team / environment
              ├─► ir-evidenceAgent      — live resource snapshot + blast radius
              ├─► ir-logAnalysisAgent   — CloudTrail 5W1H investigation
              └─► ir-remediationAgent   — KB lookup or GitHub runbook PR
                    └─► post_to_teams   — Adaptive Card to Microsoft Teams
```

Execution order enforced: context → evidence → log-analysis → remediation → Teams notification.

### 2.2 AWS Resources Created

#### Bedrock Agents (5 total, all us-east-1)

| Agent | Name | Collaboration Mode | Action Group Lambda |
|-------|------|--------------------|-------------------|
| Orchestrator | `prod-use1-bedrock-agent-orchestrator` | SUPERVISOR | `ir-teams-notifier` |
| Context | `prod-use1-bedrock-agent-context` | DISABLED (sub-agent) | `ir-business-context` |
| Evidence | `prod-use1-bedrock-agent-evidence` | DISABLED (sub-agent) | `ir-evidence` |
| Log Analysis | `prod-use1-bedrock-agent-log-analysis` | DISABLED (sub-agent) | `ir-log-analysis` |
| Remediation | `prod-use1-bedrock-agent-remediation` | DISABLED (sub-agent) | `ir-remediation` |

#### Agent Aliases

All named `prod` (environment stage, scoped per agent). Track DRAFT by default — every apply is immediately live. Pin to immutable version via `alias_routing_version` variable.

#### Action Groups

| Agent | Action Group | API Operation | Lambda |
|-------|-------------|---------------|--------|
| contextAgent | BusinessContext | `get_aws_account_info` | `ir-business-context` |
| evidenceAgent | Evidence | `get_resource_snapshot_config` | `ir-evidence` |
| logAnalysisAgent | LogAnalysis | `lookup_cloudtrail_events` | `ir-log-analysis` |
| remediationAgent | Remediation | `create_runbook_pr` | `ir-remediation` |
| orchestratorAgent | TeamsNotifier | `post_to_teams` | `ir-teams-notifier` |

#### Knowledge Base (optional)

One optional KB attached to `remediationAgent` for runbook lookups. Enable via `runbook_knowledge_base_id` Terraform variable. Associated via `aws_bedrockagent_agent_knowledge_base_association`.

### 2.3 Foundation Model

- **Model**: `anthropic.claude-sonnet-4-6` (Claude Sonnet 4.6)
- **ARN**: `arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-6`
- All 5 agents use same model (overrideable per agent via module variable)
- IAM allows wildcard `anthropic.claude-*` for future model upgrades
- **Must enable model access in Bedrock console** for us-east-1

### 2.4 IAM Roles & Policies

#### Bedrock Agent Execution Role

**Name:** `prod-iam-role-bedrock-agent-execution` (created by Terraform)

| Permission | Scope |
|-----------|-------|
| `bedrock:InvokeModel` | `anthropic.claude-sonnet-4-6` + `anthropic.claude-*` |
| `bedrock:GetAgentAlias` + `bedrock:InvokeAgent` | Agent alias ARNs (multi-agent collaboration) |
| `bedrock:Retrieve` + `bedrock:RetrieveAndGenerate` | Knowledge base ARNs |

Trust policy: `bedrock.amazonaws.com` principal, scoped by `aws:SourceAccount` and `AWS:SourceArn`.

Lambda invoke permissions: resource-based policies on each Lambda (not identity policy), scoped to `bedrock.amazonaws.com` with `ArnLike` condition.

#### Action Group Lambda Roles (5 distinct)

| Role | Key Permission |
|------|---------------|
| `prod-iam-role-business-context` | `sts:AssumeRole` into metadata account |
| `prod-iam-role-evidence` | `sts:AssumeRole` into member accounts |
| `prod-iam-role-log-analysis` | `sts:AssumeRole` into member accounts |
| `prod-iam-role-remediation` | `secretsmanager:GetSecretValue`, DynamoDB access |
| `prod-iam-role-teams-notifier` | `secretsmanager:GetSecretValue` |

#### Cross-Account Evidence Role

**Name:** `prod-iam-role-ir-evidence-read` (created by Terraform in member accounts)

Permissions: EC2, ELB, ECS, DynamoDB, SSM, CloudTrail read. Trust allows Lambda roles from security account to assume.

### 2.5 Accounts

| Account | ID | Purpose |
|---------|----|---------|
| siq-security | `085133881264` | All infrastructure deployed here (Bedrock, Lambda, DynamoDB, SQS) |
| siq-aft | `675128633990` | Metadata account (AFT DynamoDB tables) |
| Member accounts | Various | Evidence collection targets |

### 2.6 Secrets Manager

Must exist **before** `task apply`:

| Secret Name | Purpose |
|-------------|---------|
| `ir/github-pat` | GitHub PAT for runbook PR creation |
| `ir/teams-webhook` | Microsoft Teams incoming webhook URL |

Lambdas call `GetSecretValue` at runtime — never stored in environment variables.

### 2.7 Terraform Deployment

#### Prerequisites

| Tool | Version |
|------|---------|
| Terraform | >= 1.14.9 |
| [Task](https://taskfile.dev) | >= 3.x |
| AWS CLI | >= 2.x with deployment account credentials |
| Python | 3.14 (Lambda testing only) |

Pre-existing AWS resources:
- S3 bucket: `prod-use1-s3-terraform-state`
- DynamoDB table: `tfstates-lock`
- IAM role: `role-siq-ops-automation` (state backend access)
- IAM role: `role-siq-org-ops-automation` (resource deployment)

#### Setup

```bash
cd vulnerability_reports/devops-security-hub-ai/terraform/envs/prod
```

Create `terraform.tfvars`:

```hcl
aws_region                = "us-east-1"
aws_profile               = "siq-security"
metadata_account_id       = "<siq-aft account ID>"
github_pat_secret_name    = "ir/github-pat"
github_runbooks_repo      = "sleepnumberlabs/security-playbooks"
runbook_knowledge_base_id = ""          # fill after KB created
teams_webhook_secret_name = "ir/teams-webhook"
```

Deploy:

```bash
task init
task plan
task apply
```

#### Provider Configuration

```hcl
provider "aws" {
  region  = var.aws_region    # us-east-1
  profile = var.aws_profile   # siq-security
}
```

No `assume_role` in provider — SSO credentials from profile. Terraform deployment assumes `role-siq-org-ops-automation` in `085133881264`. State backend uses `role-siq-ops-automation` in `270996056496`.

### 2.8 Runtime Invocation

Worker Lambda invokes orchestrator:

```python
import boto3, json

br = boto3.client("bedrock-agent-runtime", region_name="us-east-1")

resp = br.invoke_agent(
    agentId=SUPERVISOR_AGENT_ID,
    agentAliasId=SUPERVISOR_AGENT_ALIAS_ID,
    sessionId=case["caseId"],    # UUID from Security Hub finding ARN
    enableTrace=True,
    inputText=json.dumps({"case": case}, ensure_ascii=False)
)

# Stream response
chunks = []
for ev in resp["completion"]:
    if "chunk" in ev and "bytes" in ev["chunk"]:
        chunks.append(ev["chunk"]["bytes"].decode("utf-8"))
final_output = "".join(chunks).strip()
```

**Worker Lambda Environment Variables:**

| Variable | Value |
|----------|-------|
| `SUPERVISOR_AGENT_ID` | Terraform output |
| `SUPERVISOR_AGENT_ALIAS_ID` | Terraform output |
| `AWS_REGION` | `us-east-1` |
| `CASE_TABLE_NAME` | `IRCaseState` |
| `STATUS_IN_PROGRESS` | `IN_PROGRESS` |
| `STATUS_NOTIFIED` | `NOTIFIED` |
| `STATUS_FAILED` | `FAILED` |

Session management: `sessionId` = `caseId` (UUID). Same case reprocessed reuses session. Bedrock maintains conversation state across invocations within session.

### 2.9 Member Account Deployment

Deploy cross-account evidence role to member accounts:

```bash
# 1. Get Lambda role ARNs from prod
cd terraform/envs/prod
terraform output evidence_lambda_role_arn
terraform output log_analysis_lambda_role_arn
terraform output business_context_lambda_role_arn   # siq-aft only

# 2. Fill ARNs in tfvars files
vim terraform/envs/member-roles/accounts/siq-aft.tfvars

# 3. Deploy all
cd terraform/envs/member-roles
task deploy-all
```

Add new member account:

```bash
cp terraform/envs/member-roles/accounts/workloads-prod.tfvars \
   terraform/envs/member-roles/accounts/new-account.tfvars
vim terraform/envs/member-roles/accounts/new-account.tfvars
cd terraform/envs/member-roles
task apply -- accounts/new-account.tfvars
```

### 2.10 Resource Naming Convention

| Pattern | Format | Example |
|---------|--------|---------|
| Regional + counter | `<env>-<region_code>-<type>-<function>-<counter>` | `prod-use1-lambda-normalizer-001` |
| Bedrock Agents | `<env>-<region_code>-bedrock-agent-<function>` | `prod-use1-bedrock-agent-context` |
| Agent aliases | `<env>` | `prod` |
| IAM roles | `<env>-iam-role-<function>` | `prod-iam-role-normalizer` |

Tags module outputs:
- `local.n["type/function/counter"]` — regional with counter
- `local.r["function"]` — IAM roles
- `local.b["agent/function"]` — Bedrock Agent names

### 2.11 Day-to-Day Operations

| Task | Command |
|------|---------|
| Update agent instructions | Edit `agents/instructions/<agent>.md` → `task apply` |
| Update Lambda handler | Edit handler → `task apply` |
| Update action group schema | Edit schema JSON → `task apply` |
| Add Security Hub control | Append `"security-control/<ID>"` to `control_ids` in `main.tf` → `task apply` |
| Pin agent version | `aws bedrock-agent create-agent-version --agent-id <id>` → set `alias_routing_version` → `task apply` |
| Add runbook | Create YAML in `runbooks/` → commit and push |
| Rotate secret | Update in Secrets Manager directly (no Terraform change) |

### 2.12 Observability

| Signal | Location |
|--------|----------|
| Lambda logs | CloudWatch `/aws/lambda/ir-prod-<name>` |
| Bedrock Agent traces | `enableTrace=True` in Worker Lambda |
| DLQ alarm | `prod-use1-cw-alarm-dlq-depth-001` (fires at depth >= 1) |
| IR case state | DynamoDB `IRCaseState` — `NEW → IN_PROGRESS → NOTIFIED / FAILED` |

### 2.13 Multi-Region / Multi-Environment

**Second region (HA):**
```bash
cp -r terraform/envs/prod terraform/envs/prod-us-west-2
# Change: provider.tf region → us-west-2, main.tf local.env → prod-usw2
cd terraform/envs/prod-us-west-2
task init && task apply
```

**New environment (staging):**
```bash
cp -r terraform/envs/prod terraform/envs/staging
# Change: main.tf local.env → staging
# Taskfile auto-routes to non-prod S3 bucket
cd terraform/envs/staging
task init && task apply
```

---

## Part 3: Setup Checklist

### Claude Code via Bedrock

- [ ] Join Okta group `aws-bedrock-model-access` (EMB ticket if needed)
- [ ] AWS CLI v2 installed (`aws --version`)
- [ ] SSO session + profile added to `~/.aws/config`
- [ ] `aws sso login --profile sso-bedrock-model-access` successful
- [ ] `aws bedrock list-inference-profiles` returns model list
- [ ] `~/.claude/settings.json` created with `CLAUDE_CODE_USE_BEDROCK=1`
- [ ] Test: new Claude Code session responds to `what model are you?`

### Security Hub IR Automation

- [ ] AWS CLI configured with `siq-security` SSO profile
- [ ] Terraform >= 1.14.9 + Task >= 3.x installed
- [ ] S3 state bucket `prod-use1-s3-terraform-state` exists
- [ ] DynamoDB lock table `tfstates-lock` exists
- [ ] Enable `anthropic.claude-sonnet-4-6` model access in Bedrock console (us-east-1)
- [ ] Create Secrets Manager: `ir/github-pat` + `ir/teams-webhook`
- [ ] `terraform.tfvars` created with correct values
- [ ] `task init && task plan && task apply` succeeds
- [ ] Deploy member-roles to each target account
- [ ] Verify EventBridge rule catches test finding
- [ ] Confirm Teams notification received

---

## Repository Layout (Security Hub AI)

```
devops-security-hub-ai/
├── action_groups/              Lambda handlers + schemas per action group
│   ├── business_context/
│   ├── evidence/
│   ├── log_analysis/
│   ├── remediation/
│   └── teams_notifier/
├── agents/instructions/        Bedrock Agent instruction markdown files
├── lambdas/
│   ├── normalizer/             EventBridge → SQS ingestion
│   └── worker/                 SQS → Bedrock InvokeAgent
├── runbooks/                   Example runbook YAMLs
└── terraform/
    ├── modules/
    │   ├── tags/               Centralized naming + org tags
    │   ├── action_group_lambda/ Reusable Lambda + IAM + Bedrock permission
    │   ├── bedrock_agent/      Reusable Agent + action groups + alias
    │   ├── pipeline/           DynamoDB + SQS + EventBridge + alarms
    │   └── member_iam_role/    Cross-account evidence role
    └── envs/
        ├── prod/               Production (siq-security, us-east-1)
        └── member-roles/       Per-account evidence role deployment
```
