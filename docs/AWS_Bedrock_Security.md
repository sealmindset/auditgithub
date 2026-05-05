# AWS Bedrock Security Analysis

Security posture assessment of AWS Bedrock as deployed at Sleep Number, based on evidence from the Claude Code Bedrock setup guide (SLA) and the devops-security-hub-ai Terraform infrastructure.

---

## Is AWS Bedrock Directly Accessible on the Internet?

**No — but Bedrock API endpoints are public AWS endpoints.**

Bedrock runtime endpoints (`bedrock-runtime.us-east-1.amazonaws.com`) are internet-facing, same as S3, DynamoDB, and other AWS managed services. All requests require SigV4-signed IAM credentials. No anonymous or unauthenticated access path exists.

---

## Authentication & Authorization Layers

### Developer Access (Claude Code via Bedrock)

| Layer | Control | Evidence |
|-------|---------|----------|
| **Okta** | Must be member of `aws-bedrock-model-access` group | SLA setup guide |
| **IAM Identity Center** | SSO session issues temporary credentials (auto-expire) | SLA setup guide |
| **IAM Role** | `bedrock-model-access` role in account `622711945934` | SLA setup guide — `~/.aws/config` profile |
| **IAM Policy** | `bedrock:InvokeModel` scoped to specific foundation models | Terraform IAM policy documents |
| **Claude Code** | `awsAuthRefresh` auto-renews SSO session on expiry | `~/.claude/settings.json` |

Authentication chain: **Okta → IAM Identity Center (SSO) → Temporary Credentials → SigV4-signed API calls**

### IR Automation Access (Security Hub AI)

| Layer | Control | Evidence |
|-------|---------|----------|
| **IAM Execution Role** | `prod-iam-role-bedrock-agent-execution` — trust limited to `bedrock.amazonaws.com` | Terraform `bedrock_agent` module |
| **Model Scope** | `bedrock:InvokeModel` restricted to `anthropic.claude-sonnet-4-6` + `anthropic.claude-*` | Terraform IAM policy document |
| **Agent Scope** | `bedrock:InvokeAgent` restricted to specific agent alias ARNs | Terraform IAM policy document |
| **Lambda Invoke** | Resource-based policy on each Lambda — `bedrock.amazonaws.com` with `ArnLike` source condition | Terraform `action_group_lambda` module |
| **Cross-Account** | `sts:AssumeRole` scoped to named role in specific member accounts | Terraform `member_iam_role` module |
| **Secrets** | GitHub PAT + Teams webhook retrieved from Secrets Manager at runtime, never in env vars | Lambda handler code |

Authentication chain: **EventBridge → Lambda (IAM role) → Bedrock Agent Runtime (SigV4) → Sub-agents (IAM trust)**

All IR invocations stay AWS-internal: Lambda → Bedrock SDK. No traffic leaves AWS network boundary for agent orchestration.

---

## Network Security

### Current State

| Control | Status | Evidence |
|---------|--------|----------|
| **TLS in Transit** | Enforced | AWS SDK enforces HTTPS for all Bedrock API calls |
| **VPC Endpoints** | Not configured | No `aws_vpc_endpoint` for Bedrock in Terraform |
| **PrivateLink** | Not configured | No `com.amazonaws.us-east-1.bedrock-runtime` endpoint |
| **IP Restrictions** | Not configured | No `aws:SourceIp` conditions in IAM policies |
| **VPC Source Restrictions** | Not configured | No `aws:SourceVpc` or `aws:SourceVpce` conditions |

### Traffic Flow

```
Developer (Claude Code)
  └─► Public Internet (HTTPS/TLS)
        └─► bedrock-runtime.us-east-1.amazonaws.com
              └─► IAM SigV4 authentication
                    └─► Bedrock model invocation

Lambda (IR Automation)
  └─► AWS Internal Network
        └─► bedrock-agent-runtime.us-east-1.amazonaws.com
              └─► IAM SigV4 authentication
                    └─► Bedrock agent invocation
```

**Key distinction:** Developer traffic traverses public internet (encrypted). Lambda traffic stays within AWS network.

---

## Data Security

### Data at Rest

| Concern | Status | Evidence |
|---------|--------|----------|
| **Model Isolation** | AWS guarantees per-customer isolation | AWS Bedrock service terms |
| **No Training on Customer Data** | Bedrock does not use customer inputs for model training | AWS Bedrock data privacy policy |
| **IR Case State** | Stored in DynamoDB `IRCaseState` with encryption at rest | Terraform pipeline module |
| **Secrets** | Secrets Manager with default AWS KMS encryption | Terraform — `secretsmanager:GetSecretValue` |

### Data in Transit

| Concern | Status | Evidence |
|---------|--------|----------|
| **API Calls** | TLS 1.2+ enforced by AWS SDK | AWS service default |
| **Cross-Account** | STS AssumeRole over HTTPS | Terraform IAM trust policies |
| **Teams Notifications** | HTTPS webhook | Lambda handler — `post_to_teams` action group |

### Prompt / Response Data

| Concern | Status |
|---------|--------|
| **Session Persistence** | Bedrock maintains session state for agent conversations (TTL: 600s) |
| **Trace Logging** | `enableTrace=True` in Worker Lambda — agent reasoning logged to CloudWatch |
| **Output Capture** | First 800 chars stored in DynamoDB (`STORE_OUTPUT_PREFIX=true`) |

---

## Access Control Matrix

| Principal | Access Path | Scope |
|-----------|------------|-------|
| Developers (Okta group) | SSO → `bedrock-model-access` role | `bedrock:InvokeModel` on approved models |
| Bedrock Agent Execution | `prod-iam-role-bedrock-agent-execution` | `bedrock:InvokeModel`, `bedrock:InvokeAgent`, `bedrock:Retrieve` |
| Worker Lambda | IAM role → `invoke_agent()` | Orchestrator agent + alias only |
| Action Group Lambdas | Resource-based policy from `bedrock.amazonaws.com` | Invoked by Bedrock, not self-invoking |
| Cross-Account Evidence | `prod-iam-role-ir-evidence-read` assumed by Lambdas | Read-only EC2, ELB, ECS, SSM, CloudTrail, DynamoDB |

---

## Risk Assessment

### Strengths

1. **Multi-layer authentication** — Okta → SSO → IAM → model-scoped policies. No single credential grants access.
2. **Least-privilege IAM** — Model invocation scoped to specific ARNs, not `bedrock:*`.
3. **No persistent credentials** — SSO issues temporary credentials. Lambda roles use instance credentials.
4. **Secrets isolation** — GitHub PAT and Teams webhook in Secrets Manager, fetched at runtime, never in environment variables.
5. **Audit trail** — CloudTrail logs all Bedrock API calls. Agent traces captured with `enableTrace=True`.
6. **IR stays AWS-internal** — Lambda-to-Bedrock traffic never leaves AWS network.

### Gaps

| Gap | Risk | Recommendation |
|-----|------|----------------|
| **No VPC Endpoints** | Developer Bedrock traffic traverses public internet (encrypted but not network-isolated) | Add VPC endpoint `com.amazonaws.us-east-1.bedrock-runtime` for Lambda invocations; evaluate for developer access |
| **No IP/VPC source conditions** | Any valid IAM credential can invoke from any network location | Add `aws:SourceVpc` condition to Lambda roles; consider `aws:SourceIp` for developer access |
| **Trace logging in CloudWatch** | Agent reasoning traces may contain sensitive finding details | Ensure CloudWatch log groups have encryption + restricted access policies |
| **DynamoDB output prefix** | First 800 chars of agent output stored — may include sensitive IR details | Ensure DynamoDB table has encryption at rest + access restricted to IR Lambdas |
| **Wildcard model access** | `anthropic.claude-*` allows any future Claude model without explicit approval | Restrict to specific model versions; update IAM when new models are approved |
| **DRAFT alias tracking** | All agents track DRAFT — every Terraform apply is immediately live | Pin production aliases to published versions via `alias_routing_version` |
| **No rate limiting** | No Bedrock throttling configuration beyond AWS service defaults | Configure Bedrock provisioned throughput or account-level throttling if needed |

---

## Recommendations

### Priority 1 — Network Isolation

Add VPC endpoints for Bedrock to eliminate public internet traversal for Lambda invocations:

```hcl
resource "aws_vpc_endpoint" "bedrock_runtime" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.us-east-1.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.bedrock_endpoint.id]
}

resource "aws_vpc_endpoint" "bedrock_agent_runtime" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.us-east-1.bedrock-agent-runtime"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.bedrock_endpoint.id]
}
```

### Priority 2 — IAM Hardening

Add source conditions to Lambda execution roles:

```json
{
  "Condition": {
    "StringEquals": {
      "aws:SourceVpc": "vpc-xxxxxxxxx"
    }
  }
}
```

Pin model access to specific versions instead of wildcard:

```json
{
  "Resource": [
    "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-6"
  ]
}
```

### Priority 3 — Observability Hardening

- Encrypt CloudWatch log groups with customer-managed KMS key
- Set log retention policies (90 days recommended)
- Add CloudWatch metric filter for unauthorized Bedrock API calls
- Enable AWS Config rule for Bedrock resource compliance

### Priority 4 — Production Readiness

- Pin all agent aliases to published versions (stop tracking DRAFT)
- Configure Bedrock model invocation logging to S3 for long-term audit
- Establish runbook for SSO credential rotation and emergency access revocation

---

## Defense-in-Depth: Beyond IAM

IAM (identity and access management) is necessary but insufficient as the sole security layer. If a token is stolen, an SSO session is hijacked, or a prompt injection manipulates agent behavior, IAM alone cannot detect or prevent abuse. The following layers address network isolation, application-level AI safety, credential abuse prevention, cross-account containment, and real-time monitoring.

### Layer 1: Network Isolation — PrivateLink & VPC Endpoints

**Problem:** Bedrock API calls from Lambdas currently traverse AWS public endpoints. A compromised Lambda or leaked credentials could invoke Bedrock from any network location.

**Solution:** AWS PrivateLink VPC endpoints force all Bedrock traffic through private network — never touching public internet.

```hcl
# Bedrock Runtime (model invocation)
resource "aws_vpc_endpoint" "bedrock_runtime" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.us-east-1.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.bedrock_vpce.id]
}

# Bedrock Agent Runtime (agent invocation)
resource "aws_vpc_endpoint" "bedrock_agent_runtime" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.us-east-1.bedrock-agent-runtime"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.bedrock_vpce.id]
}

# Security group — restrict to Lambda security group only
resource "aws_security_group" "bedrock_vpce" {
  name_prefix = "bedrock-vpce-"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
  }
}
```

Then lock IAM to VPC-only access:

```json
{
  "Effect": "Deny",
  "Action": "bedrock:*",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:SourceVpce": "vpce-xxxxxxxxxxxxxxxxx"
    }
  }
}
```

**Impact:** Even with valid credentials, Bedrock cannot be invoked from outside the VPC. Stolen tokens are useless from attacker infrastructure.

### Layer 2: Prompt Injection & AI Guardrails

**Problem:** Bedrock agents process Security Hub findings as input. A crafted finding description or resource tag could contain prompt injection payloads attempting to manipulate agent behavior (exfiltrate data, skip analysis, generate false runbooks).

**Solution A: AWS Bedrock Guardrails (native)**

```hcl
resource "aws_bedrock_guardrail" "ir_guardrail" {
  name                      = "prod-bedrock-guardrail-ir"
  blocked_input_messaging   = "Input blocked by security policy."
  blocked_outputs_messaging = "Output blocked by security policy."
  description               = "IR automation guardrails"

  content_policy_config {
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
    filters_config {
      type            = "INSULTS"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
  }

  sensitive_information_policy_config {
    pii_entities_config {
      type   = "AWS_ACCESS_KEY"
      action = "BLOCK"
    }
    pii_entities_config {
      type   = "AWS_SECRET_KEY"
      action = "BLOCK"
    }
    pii_entities_config {
      type   = "IP_ADDRESS"
      action = "ANONYMIZE"
    }
  }

  word_policy_config {
    managed_word_lists_config {
      type = "PROFANITY"
    }
  }
}
```

Attach to each agent:

```hcl
resource "aws_bedrockagent_agent" "context" {
  # ... existing config ...
  guardrail_configuration {
    guardrail_identifier = aws_bedrock_guardrail.ir_guardrail.guardrail_id
    guardrail_version    = aws_bedrock_guardrail.ir_guardrail.version
  }
}
```

**Solution B: Input validation in Lambda (pre-Bedrock)**

Add input sanitization in the Worker Lambda before invoking Bedrock:

```python
import re

INJECTION_PATTERNS = [
    r"ignore\s+(previous|above|all)\s+instructions",
    r"you\s+are\s+now\s+a",
    r"system\s*:\s*",
    r"<\s*system\s*>",
    r"ADMIN\s*OVERRIDE",
    r"reveal\s+(your|the)\s+(system|instructions|prompt)",
]

def sanitize_finding_input(finding: dict) -> dict:
    """Strip potential prompt injection from Security Hub finding fields."""
    text_fields = ["Description", "Title", "Remediation.Recommendation.Text"]
    for field in text_fields:
        value = finding.get(field, "")
        if isinstance(value, str):
            for pattern in INJECTION_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    logger.warning(f"Prompt injection pattern detected in {field}")
                    finding[field] = re.sub(pattern, "[REDACTED]", value, flags=re.IGNORECASE)
    return finding
```

**Solution C: Output validation (post-Bedrock)**

Validate agent responses before acting on them (creating PRs, sending Teams notifications):

```python
def validate_agent_output(output: str) -> bool:
    """Ensure agent output doesn't contain leaked credentials or injection artifacts."""
    sensitive_patterns = [
        r"AKIA[0-9A-Z]{16}",           # AWS access key
        r"(?i)aws_secret_access_key",    # AWS secret reference
        r"ghp_[a-zA-Z0-9]{36}",         # GitHub PAT
        r"xoxb-[0-9]+-[a-zA-Z0-9]+",    # Slack token
    ]
    for pattern in sensitive_patterns:
        if re.search(pattern, output):
            logger.error(f"Sensitive data detected in agent output")
            return False
    return True
```

### Layer 3: Credential & Token Abuse Prevention

**Problem:** SSO tokens, IAM credentials, and GitHub PATs could be exfiltrated and used from external locations.

**Solution A: Service Control Policies (SCPs) at AWS Organization level**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyBedrockFromOutsideOrg",
      "Effect": "Deny",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeAgent",
        "bedrock-agent-runtime:InvokeAgent"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-xxxxxxxxxx"
        }
      }
    },
    {
      "Sid": "DenyBedrockOutsideAllowedRegions",
      "Effect": "Deny",
      "Action": "bedrock:*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["us-east-1"]
        }
      }
    }
  ]
}
```

**Solution B: IAM session policies with source IP restriction**

For developer access via SSO, restrict to corporate IP ranges:

```json
{
  "Condition": {
    "NotIpAddress": {
      "aws:SourceIp": [
        "203.0.113.0/24",
        "198.51.100.0/24"
      ]
    }
  }
}
```

**Solution C: CloudTrail anomaly detection for credential abuse**

```hcl
resource "aws_cloudwatch_metric_alarm" "bedrock_anomaly" {
  alarm_name          = "prod-use1-cw-alarm-bedrock-anomaly-001"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BedrockInvocationCount"
  namespace           = "Custom/Bedrock"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  alarm_description   = "Unusual Bedrock invocation volume — possible credential abuse"
  alarm_actions       = [var.sns_alarm_arn]
}
```

### Layer 4: Cross-Account Containment

**Problem:** IR Lambdas assume roles into member accounts. A compromised agent could attempt lateral movement beyond read-only evidence collection.

**Solution A: Strict role boundaries**

`prod-iam-role-ir-evidence-read` must be read-only with no write permissions:

```json
{
  "Effect": "Deny",
  "Action": [
    "ec2:Terminate*",
    "ec2:Delete*",
    "ec2:Modify*",
    "iam:*",
    "s3:Delete*",
    "s3:Put*",
    "dynamodb:Delete*",
    "dynamodb:Put*",
    "dynamodb:Update*"
  ],
  "Resource": "*"
}
```

**Solution B: Session duration limits**

```hcl
resource "aws_iam_role" "ir_evidence_read" {
  max_session_duration = 900   # 15 minutes max — just enough for evidence collection
}
```

**Solution C: External ID for cross-account assume**

```json
{
  "Condition": {
    "StringEquals": {
      "sts:ExternalId": "ir-automation-2026"
    }
  }
}
```

### Layer 5: Real-Time Monitoring & Alerting

**Problem:** Without active monitoring, abuse of Bedrock (prompt injection, data exfil, excessive invocations) goes undetected.

**Solution A: Bedrock Model Invocation Logging**

```hcl
resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    embedding_data_delivery_enabled = true
    image_data_delivery_enabled     = false
    text_data_delivery_enabled      = true

    s3_config {
      bucket_name = var.logging_bucket
      key_prefix  = "bedrock-invocation-logs/"
    }

    cloudwatch_config {
      log_group_name = "/aws/bedrock/invocation-logs"

      large_data_delivery_s3_config {
        bucket_name = var.logging_bucket
        key_prefix  = "bedrock-large-logs/"
      }
    }
  }
}
```

**Solution B: CloudWatch metric filters for security events**

```hcl
# Detect throttling (possible brute-force or abuse)
resource "aws_cloudwatch_log_metric_filter" "bedrock_throttled" {
  name           = "BedrockThrottled"
  log_group_name = "/aws/bedrock/invocation-logs"
  pattern        = "{ $.errorCode = \"ThrottlingException\" }"

  metric_transformation {
    name      = "BedrockThrottledCount"
    namespace = "Custom/Bedrock"
    value     = "1"
  }
}

# Detect access denied (credential probing)
resource "aws_cloudwatch_log_metric_filter" "bedrock_access_denied" {
  name           = "BedrockAccessDenied"
  log_group_name = "/aws/cloudtrail/logs"
  pattern        = "{ ($.eventSource = \"bedrock.amazonaws.com\") && ($.errorCode = \"AccessDenied*\") }"

  metric_transformation {
    name      = "BedrockAccessDeniedCount"
    namespace = "Custom/Bedrock"
    value     = "1"
  }
}

# Detect unusual model invocation patterns
resource "aws_cloudwatch_log_metric_filter" "bedrock_invocations" {
  name           = "BedrockInvocations"
  log_group_name = "/aws/cloudtrail/logs"
  pattern        = "{ ($.eventSource = \"bedrock.amazonaws.com\") && ($.eventName = \"InvokeModel\") }"

  metric_transformation {
    name      = "BedrockInvocationCount"
    namespace = "Custom/Bedrock"
    value     = "1"
  }
}
```

**Solution C: GuardDuty integration**

AWS GuardDuty detects anomalous API behavior including unusual Bedrock invocation patterns:

```hcl
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
  }
}
```

GuardDuty findings for Bedrock abuse (unusual invocation volume, access from anomalous IP, credential exfiltration) feed back into Security Hub — creating a feedback loop with the IR automation itself.

**Solution D: Automated response via EventBridge**

```hcl
# Auto-revoke compromised role on GuardDuty HIGH finding
resource "aws_cloudwatch_event_rule" "guardduty_bedrock" {
  name        = "prod-use1-eb-rule-guardduty-bedrock-001"
  description = "Trigger on GuardDuty Bedrock-related findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
      resource = {
        resourceType = ["AccessKey"]
      }
      service = {
        action = {
          awsApiCallAction = {
            api = [{ prefix = "InvokeModel" }, { prefix = "InvokeAgent" }]
          }
        }
      }
    }
  })
}
```

### Layer 6: Data Loss Prevention (DLP)

**Problem:** Bedrock agents process sensitive security findings. Agent responses sent to Teams or stored in DynamoDB could leak account IDs, resource ARNs, IP addresses, or vulnerability details.

**Solution A: Bedrock Guardrails PII filtering** (covered in Layer 2)

**Solution B: Teams notification content filtering**

In the `post_to_teams` Lambda, strip sensitive details before sending:

```python
REDACT_PATTERNS = {
    r"\b\d{12}\b": "[ACCOUNT_ID]",                    # AWS account IDs
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b": "[IP_ADDRESS]",   # IPv4 addresses
    r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:": "arn:aws:***:***:***:",  # ARN prefix
    r"AKIA[0-9A-Z]{16}": "[AWS_KEY]",                  # Access keys
    r"sg-[0-9a-f]{8,17}": "[SG_ID]",                   # Security groups
    r"i-[0-9a-f]{8,17}": "[INSTANCE_ID]",              # EC2 instances
}

def redact_for_external(text: str) -> str:
    for pattern, replacement in REDACT_PATTERNS.items():
        text = re.sub(pattern, replacement, text)
    return text
```

**Solution C: S3 bucket policy for invocation logs**

```json
{
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::bedrock-logs-bucket/bedrock-invocation-logs/*",
  "Condition": {
    "StringNotEquals": {
      "aws:PrincipalOrgID": "o-xxxxxxxxxx"
    }
  }
}
```

---

## Defense-in-Depth Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEFENSE-IN-DEPTH LAYERS                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Layer 6: DLP                                                   │
│  ├── PII filtering in Guardrails                                │
│  ├── Content redaction before Teams/external delivery            │
│  └── S3 bucket policies on invocation logs                      │
│                                                                 │
│  Layer 5: Real-Time Monitoring                                  │
│  ├── Bedrock model invocation logging (S3 + CloudWatch)         │
│  ├── CloudWatch metric filters (throttling, access denied)      │
│  ├── GuardDuty anomalous API detection                          │
│  └── EventBridge auto-response on HIGH severity                 │
│                                                                 │
│  Layer 4: Cross-Account Containment                             │
│  ├── Explicit deny on write actions in evidence role            │
│  ├── 15-minute max session duration                             │
│  └── External ID requirement for AssumeRole                     │
│                                                                 │
│  Layer 3: Credential Abuse Prevention                           │
│  ├── SCPs restrict Bedrock to org + region                      │
│  ├── Source IP conditions on developer SSO roles                │
│  └── CloudTrail anomaly alarms on invocation volume             │
│                                                                 │
│  Layer 2: AI Application Security                               │
│  ├── Bedrock Guardrails (prompt attack + PII blocking)          │
│  ├── Input sanitization (pre-Bedrock injection patterns)        │
│  └── Output validation (post-Bedrock credential detection)      │
│                                                                 │
│  Layer 1: Network Isolation                                     │
│  ├── VPC endpoints for bedrock-runtime + bedrock-agent-runtime  │
│  ├── Security groups restrict to Lambda SG only                 │
│  └── IAM deny outside VPC endpoint                              │
│                                                                 │
│  Layer 0: Identity & Access (CURRENT STATE)                     │
│  ├── Okta group membership                                      │
│  ├── IAM Identity Center (SSO) temporary credentials            │
│  ├── IAM roles with least-privilege model-scoped policies       │
│  └── Resource-based Lambda permissions                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation Priority Matrix

| Priority | Layer | Effort | Impact | Timeline |
|----------|-------|--------|--------|----------|
| **P0** | Network — VPC Endpoints | Medium | Eliminates public internet traversal | Week 1 |
| **P0** | Credential — SCPs | Low | Org-wide Bedrock region + account lock | Week 1 |
| **P1** | AI Safety — Bedrock Guardrails | Medium | Native prompt injection + PII blocking | Week 2 |
| **P1** | Monitoring — Invocation Logging | Low | Full audit trail for all model calls | Week 2 |
| **P1** | Credential — Source IP on SSO | Low | Limits developer access to corporate network | Week 2 |
| **P2** | AI Safety — Input/Output validation | Medium | Defense against crafted findings | Week 3 |
| **P2** | Monitoring — CloudWatch filters | Low | Real-time alerting on abuse patterns | Week 3 |
| **P2** | Cross-Account — Session limits + external ID | Low | Reduces blast radius of compromised Lambda | Week 3 |
| **P3** | DLP — Content redaction | Medium | Prevents data leakage to Teams | Week 4 |
| **P3** | Monitoring — GuardDuty + auto-response | Medium | Automated incident response for Bedrock abuse | Week 4 |
| **P3** | AI Safety — Output validation Lambda | Medium | Catches credential leakage in agent responses | Week 4 |

---

## Compliance Notes

| Framework | Relevant Control | Status |
|-----------|-----------------|--------|
| SOC 2 | CC6.1 — Logical Access | Covered — Okta + IAM + least-privilege |
| SOC 2 | CC6.6 — External Threats | **Gap** — no VPC endpoints, no prompt injection defense |
| SOC 2 | CC6.7 — Restricting Access to System Components | **Gap** — no network-level boundary |
| SOC 2 | CC7.2 — Monitoring for Anomalous Behavior | **Gap** — no Bedrock-specific monitoring |
| NIST 800-53 | AC-3 — Access Enforcement | Covered — multi-layer IAM |
| NIST 800-53 | AC-4 — Information Flow Enforcement | **Gap** — no DLP on agent outputs |
| NIST 800-53 | SC-7 — Boundary Protection | **Gap** — no network boundary for Bedrock |
| NIST 800-53 | SC-13 — Cryptographic Protection | Covered — TLS + KMS |
| NIST 800-53 | SI-4 — System Monitoring | **Gap** — no Bedrock invocation logging |
| NIST 800-53 | SI-10 — Information Input Validation | **Gap** — no prompt injection filtering |
| CIS AWS | 2.1 — Encryption in Transit | Covered — TLS enforcement |
| CIS AWS | 3.1 — CloudTrail Enabled | Covered — CloudTrail logs Bedrock API calls |
| OWASP LLM Top 10 | LLM01 — Prompt Injection | **Gap** — no input sanitization or Guardrails |
| OWASP LLM Top 10 | LLM02 — Insecure Output Handling | **Gap** — no output validation |
| OWASP LLM Top 10 | LLM06 — Sensitive Information Disclosure | **Gap** — no PII filtering on responses |

---

## References

- [SLA: Claude Code Setup for AWS Bedrock](../docs/AWS_BEDROCK_SETUP.md) — Developer setup guide
- [devops-security-hub-ai README](../vulnerability_reports/devops-security-hub-ai/README.md) — IR automation architecture
- [AWS Bedrock Security Documentation](https://docs.aws.amazon.com/bedrock/latest/userguide/security.html)
- [AWS Bedrock VPC Endpoints](https://docs.aws.amazon.com/bedrock/latest/userguide/vpc-interface-endpoints.html)
- [AWS Bedrock Guardrails](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html)
- [AWS Bedrock Model Invocation Logging](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [AWS Service Control Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
