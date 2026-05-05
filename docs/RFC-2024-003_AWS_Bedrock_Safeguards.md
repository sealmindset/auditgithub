# RFC-2024-003: AWS Bedrock Safeguards

## RFC-2024-003: AWS Bedrock Safeguards — Defense-in-Depth for AI Model Access

| Field | Value |
|-------|-------|
| **RFC** | RFC-2024-003 |
| **Title** | AWS Bedrock Safeguards — Defense-in-Depth for AI Model Access |
| **Author** | AI Center of Excellence / Security Engineering |
| **Status** | DRAFT — Open for Comment |
| **Created** | 2026-05-05 |
| **Repository** | https://github.com/SleepNumberInc/auditgithub |
| **Companion RFCs** | RFC-2024-002: /make-it |
| **Governing Pattern** | [EA Design Pattern: Defense-in-Depth for Managed AI Services](./EA_Design_Pattern_AWS_Bedrock.md) |
| **Audience** | Security Engineering, Cloud/Platform Engineering, Network Engineering, AI CoE, DevOps/SRE, IAM/Identity, Compliance/GRC |

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Current State Assessment](#2-current-state-assessment)
3. [Proposed Safeguards](#3-proposed-safeguards)
4. [Layer 1: Network Isolation](#4-layer-1--network-isolation)
5. [Layer 2: AI Application Security](#5-layer-2--ai-application-security)
6. [Layer 3: Credential & Token Abuse Prevention](#6-layer-3--credential--token-abuse-prevention)
7. [Layer 4: Cross-Account Containment](#7-layer-4--cross-account-containment)
8. [Layer 5: Real-Time Monitoring & Alerting](#8-layer-5--real-time-monitoring--alerting)
9. [Layer 6: Data Loss Prevention](#9-layer-6--data-loss-prevention)
10. [Implementation Priority Matrix](#10-implementation-priority-matrix)
11. [Compliance Mapping](#11-compliance-mapping)
    - [11a. Multi-Cloud Applicability](#11a-multi-cloud-applicability)
    - [11b. Deliverables Checklist](#11b-deliverables-checklist)
12. [Rollout Plan](#12-rollout-plan)
13. [Open Questions for Reviewers](#13-open-questions-for-reviewers)
14. [How to Review / Comment](#14-how-to-review--comment)
15. [References](#references)

---

## 1. Problem Statement

Sleep Number is expanding its use of Amazon Bedrock across two active workloads:

1. **Claude Code via Bedrock** — Developers use Claude Code (CLI and VS Code extension) with AWS Bedrock as the model provider. Authentication flows through Okta SSO → IAM Identity Center → a `bedrock-model-access` IAM role in account `622711945934`.

2. **Security Hub AI — IR Automation** — A multi-agent Bedrock system (`devops-security-hub-ai`) that processes HIGH/CRITICAL Security Hub findings through an orchestrator agent and four sub-agents, collecting evidence, analyzing CloudTrail, generating runbooks, and sending Teams notifications. Deployed in the `siq-security` account (`085133881264`).

Today, the **only security layer protecting Bedrock access is IAM** — identity and access management. While IAM is well-configured (Okta group gating, least-privilege policies, model-scoped permissions), it represents a single plane of defense. This creates exposure across multiple threat vectors:

- **Stolen credentials** — A compromised SSO session or leaked IAM credentials could invoke Bedrock from any network location worldwide. IAM cannot distinguish legitimate use from credential theft if the token is valid.

- **Prompt injection** — The IR automation system processes Security Hub findings as input to Bedrock agents. A crafted finding description or malicious resource tag could contain prompt injection payloads that manipulate agent behavior — exfiltrating data, skipping analysis, or generating false runbooks.

- **Data exfiltration** — Agent responses sent to Microsoft Teams or stored in DynamoDB could leak AWS account IDs, resource ARNs, IP addresses, or vulnerability details to channels with broader access than intended.

- **Lateral movement** — IR Lambdas assume roles into member accounts for evidence collection. A compromised agent could attempt actions beyond read-only scope if role boundaries are insufficient.

- **No visibility** — Without Bedrock-specific monitoring, abuse patterns (unusual invocation volume, off-hours access, model probing) go undetected until damage is done.

**The gap is not access control — it's defense-in-depth.** IAM answers "who can call Bedrock?" but not "from where?", "with what input?", "producing what output?", or "how do we know if something is wrong?"

This RFC proposes six additional security layers to address these gaps.

---

## 2. Current State Assessment

### What Exists Today

| Control | Status | Evidence |
|---------|--------|----------|
| Okta group gating | Implemented | `aws-bedrock-model-access` group required |
| IAM Identity Center (SSO) | Implemented | Temporary credentials, auto-expire |
| IAM least-privilege | Implemented | `bedrock:InvokeModel` scoped to specific model ARNs |
| Model-scoped policies | Implemented | `anthropic.claude-sonnet-4-6` + wildcard `anthropic.claude-*` |
| Resource-based Lambda policies | Implemented | `bedrock.amazonaws.com` principal with `ArnLike` condition |
| Secrets Manager for runtime secrets | Implemented | GitHub PAT + Teams webhook, never in env vars |
| CloudTrail logging | Implemented | All Bedrock API calls logged |
| TLS in transit | Enforced | AWS SDK enforces HTTPS |

### What Does NOT Exist Today

| Control | Gap | Risk |
|---------|-----|------|
| VPC Endpoints for Bedrock | All traffic traverses public AWS endpoints | Stolen credentials usable from any network |
| Bedrock Guardrails | No prompt injection or PII filtering | Crafted inputs can manipulate agent behavior |
| Input validation (pre-Bedrock) | No sanitization of Security Hub finding content | Prompt injection via finding descriptions |
| Output validation (post-Bedrock) | No credential/PII detection in responses | Data leakage to Teams or DynamoDB |
| Service Control Policies | No org-level Bedrock restrictions | No region or account lockdown |
| Source IP conditions | Developer access unrestricted by network | Off-network credential use undetectable |
| Bedrock invocation logging | No model input/output audit trail | Cannot investigate what was asked or answered |
| CloudWatch metric filters | No Bedrock-specific alerting | Abuse patterns invisible |
| GuardDuty integration | No anomalous API behavior detection | No automated threat detection |
| Cross-account session limits | Default session duration on evidence roles | Extended access window if compromised |
| Content redaction | No PII/sensitive data filtering before external delivery | Account IDs, IPs in Teams messages |

> **Q for Security Engineering:** Is the current IAM configuration sufficient for a compliance audit, or have auditors already flagged the absence of network-level controls for AI services? See [Section 13, Q1](#q1).

> **Q for Compliance/GRC:** Does Sleep Number's risk framework require defense-in-depth for AI/ML workloads specifically, or are they governed by the same controls as general compute? See [Section 13, Q2](#q2).

---

## 3. Proposed Safeguards

Six defense-in-depth layers, each addressing a distinct threat vector:

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEFENSE-IN-DEPTH LAYERS                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Layer 6: Data Loss Prevention                                  │
│  ├── PII filtering in Bedrock Guardrails                        │
│  ├── Content redaction before Teams/external delivery            │
│  └── S3 bucket policies on invocation logs                      │
│                                                                 │
│  Layer 5: Real-Time Monitoring & Alerting                       │
│  ├── Bedrock model invocation logging (S3 + CloudWatch)         │
│  ├── CloudWatch metric filters (throttling, access denied)      │
│  ├── GuardDuty anomalous API detection                          │
│  └── EventBridge auto-response on HIGH severity                 │
│                                                                 │
│  Layer 4: Cross-Account Containment                             │
│  ├── Explicit deny on write actions in evidence roles           │
│  ├── 15-minute max session duration                             │
│  └── External ID requirement for AssumeRole                     │
│                                                                 │
│  Layer 3: Credential & Token Abuse Prevention                   │
│  ├── SCPs restrict Bedrock to org + approved regions            │
│  ├── Source IP conditions on developer SSO roles                │
│  └── CloudTrail anomaly alarms on invocation volume             │
│                                                                 │
│  Layer 2: AI Application Security                               │
│  ├── Bedrock Guardrails (prompt attack + PII blocking)          │
│  ├── Input sanitization (pre-Bedrock injection patterns)        │
│  └── Output validation (post-Bedrock credential detection)      │
│                                                                 │
│  Layer 1: Network Isolation                                     │
│  ├── VPC Endpoints for bedrock-runtime + bedrock-agent-runtime  │
│  ├── Security groups restrict to Lambda SG only                 │
│  └── IAM deny outside VPC endpoint                              │
│                                                                 │
│  Layer 0: Identity & Access Management (EXISTS TODAY)           │
│  ├── Okta group membership                                      │
│  ├── IAM Identity Center temporary credentials                  │
│  ├── Model-scoped least-privilege IAM policies                  │
│  └── Resource-based Lambda invoke permissions                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Where Each Team Is Involved

| Layer | Security | Cloud/Platform | Network | AI CoE | DevOps/SRE | IAM/Identity | Compliance |
|-------|----------|---------------|---------|--------|------------|-------------|------------|
| 1 — Network | Reviews design | Implements VPC endpoints | Allocates subnets, SGs | — | Deploys Terraform | — | Validates SC-7 |
| 2 — AI Safety | Reviews Guardrail policies | — | — | Defines content filters | Deploys Guardrails | — | Reviews OWASP LLM |
| 3 — Credential Abuse | Defines SCP rules | — | Provides corporate IP ranges | — | Deploys SCPs | Configures IP conditions | Validates AC-3 |
| 4 — Cross-Account | Reviews role boundaries | — | — | — | Deploys session limits | Configures external ID | Validates least-privilege |
| 5 — Monitoring | Defines alert thresholds | Configures GuardDuty | — | Reviews AI-specific patterns | Deploys alarms + dashboards | — | Validates SI-4 |
| 6 — DLP | Defines redaction rules | — | — | Reviews PII categories | Deploys redaction Lambda | — | Validates AC-4 |

---

## 4. Layer 1 — Network Isolation

### Problem

Bedrock API endpoints (`bedrock-runtime.us-east-1.amazonaws.com`) are public AWS endpoints. Any valid IAM credential can invoke Bedrock from any IP address on the internet. If a developer's SSO session token or a Lambda's IAM credentials are stolen, they can be used from attacker infrastructure without any network-level restriction.

### Proposed Solution

Deploy AWS PrivateLink VPC endpoints to force all Bedrock traffic through private networking, then add IAM conditions that deny access from outside the VPC endpoint.

**VPC Endpoints Required:**

| Endpoint | Service Name | Purpose |
|----------|-------------|---------|
| Bedrock Runtime | `com.amazonaws.us-east-1.bedrock-runtime` | Model invocation (`InvokeModel`) |
| Bedrock Agent Runtime | `com.amazonaws.us-east-1.bedrock-agent-runtime` | Agent invocation (`InvokeAgent`) |
| Bedrock | `com.amazonaws.us-east-1.bedrock` | Control plane (agent management) |

**Terraform Implementation:**

```hcl
resource "aws_vpc_endpoint" "bedrock_runtime" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.us-east-1.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.bedrock_vpce.id]
}

resource "aws_vpc_endpoint" "bedrock_agent_runtime" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.us-east-1.bedrock-agent-runtime"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.bedrock_vpce.id]
}

resource "aws_security_group" "bedrock_vpce" {
  name_prefix = "bedrock-vpce-"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.ir_lambda.id]
    description     = "Allow HTTPS from IR Lambda security group only"
  }
}
```

**IAM Deny Policy (restricts to VPC endpoint only):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyBedrockOutsideVPCE",
      "Effect": "Deny",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
        "bedrock-agent-runtime:InvokeAgent"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:SourceVpce": "vpce-xxxxxxxxxxxxxxxxx"
        }
      }
    }
  ]
}
```

### Impact on Developer Access (Claude Code)

VPC endpoint restrictions would block developer Claude Code access from laptops (which don't route through the VPC). Two options:

| Option | How It Works | Trade-off |
|--------|-------------|-----------|
| **A: VPN-routed traffic** | Developers connect via GlobalProtect VPN; traffic routes through VPC to Bedrock endpoint | Requires VPN always on; adds latency |
| **B: Separate IAM policies** | Lambda roles get VPC-only restriction; developer SSO roles keep public access with source IP conditions (Layer 3) | Two access paths; developer path less restricted |
| **C: AWS Client VPN** | Dedicated Bedrock Client VPN endpoint for developer access | Additional infrastructure cost |

> **Q for Network Engineering:** Which VPC should host the Bedrock VPC endpoints? Is there an existing shared services VPC, or does the `siq-security` account need its own? What is the subnet availability? See [Section 13, Q3](#q3).

> **Q for Network Engineering:** If Option A (VPN-routed), can GlobalProtect be configured to route `bedrock-runtime.us-east-1.amazonaws.com` traffic through the VPN split tunnel? See [Section 13, Q4](#q4).

> **Q for Cloud/Platform Engineering:** Is there an existing Terraform module or pattern for deploying VPC endpoints at Sleep Number? Should these be added to a shared infrastructure module? See [Section 13, Q5](#q5).

> **Q for DevOps/SRE:** The VPC endpoint IAM deny and Lambda VPC attachment must deploy atomically — if the deny lands first, IR automation breaks. What is the preferred zero-downtime rollout strategy? See [Section 13, Q24](#q24).

---

## 5. Layer 2 — AI Application Security

### Problem

The IR automation system accepts Security Hub findings as input and passes them directly to Bedrock agents. A malicious actor with access to create Security Hub findings (or modify resource tags/descriptions that feed into findings) could craft prompt injection payloads that manipulate agent behavior:

- Instruct the agent to skip evidence collection
- Exfiltrate environment variables or secrets via the Teams notification
- Generate false runbooks that introduce vulnerabilities
- Override the system prompt to change agent behavior

### Proposed Solution: AWS Bedrock Guardrails

Bedrock Guardrails is a native AWS feature that filters inputs and outputs at the model layer — no application code changes needed.

**Guardrail Configuration:**

```hcl
resource "aws_bedrock_guardrail" "ir_safeguard" {
  name                      = "prod-bedrock-guardrail-ir-safeguard"
  blocked_input_messaging   = "Input blocked by security policy."
  blocked_outputs_messaging = "Output blocked by security policy."
  description               = "IR automation prompt injection and data protection"

  # Prompt attack detection
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

  # Sensitive data protection
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
    pii_entities_config {
      type   = "EMAIL_ADDRESS"
      action = "ANONYMIZE"
    }
  }

  # Profanity filter
  word_policy_config {
    managed_word_lists_config {
      type = "PROFANITY"
    }
  }
}
```

**Attach to Each Agent:**

```hcl
resource "aws_bedrockagent_agent" "orchestrator" {
  # ... existing config ...
  guardrail_configuration {
    guardrail_identifier = aws_bedrock_guardrail.ir_safeguard.guardrail_id
    guardrail_version    = aws_bedrock_guardrail.ir_safeguard.version
  }
}
```

### Proposed Solution: Application-Level Input Validation

Defense at the Lambda layer, before content reaches Bedrock:

```python
import re
from loguru import logger

INJECTION_PATTERNS = [
    r"ignore\s+(previous|above|all)\s+instructions",
    r"you\s+are\s+now\s+a",
    r"system\s*:\s*",
    r"<\s*system\s*>",
    r"ADMIN\s*OVERRIDE",
    r"reveal\s+(your|the)\s+(system|instructions|prompt)",
    r"forget\s+(everything|all|your)",
    r"new\s+instructions?\s*:",
    r"act\s+as\s+(if|though)",
]

def sanitize_finding_input(finding: dict) -> dict:
    """Detect and redact prompt injection patterns in Security Hub finding fields."""
    text_fields = ["Description", "Title", "Remediation.Recommendation.Text"]
    for field in text_fields:
        value = finding.get(field, "")
        if isinstance(value, str):
            for pattern in INJECTION_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    logger.warning(f"Prompt injection pattern detected in {field}: {pattern}")
                    finding[field] = re.sub(
                        pattern, "[REDACTED-INJECTION]", value, flags=re.IGNORECASE
                    )
    return finding
```

### Proposed Solution: Output Validation

Validate agent responses before acting on them:

```python
SENSITIVE_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"(?i)aws_secret_access_key\s*=\s*\S+", "AWS secret key assignment"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub PAT"),
    (r"xoxb-[0-9]+-[a-zA-Z0-9]+", "Slack bot token"),
    (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "Private key"),
]

def validate_agent_output(output: str) -> tuple[bool, list[str]]:
    """Check agent output for leaked credentials. Returns (safe, violations)."""
    violations = []
    for pattern, label in SENSITIVE_PATTERNS:
        if re.search(pattern, output):
            violations.append(label)
    return len(violations) == 0, violations
```

> **Q for AI CoE:** What prompt injection detection capabilities exist in the current Azure OpenAI content safety configuration? Can those patterns be reused for Bedrock Guardrails? See [Section 13, Q6](#q6).

> **Q for Security Engineering:** Should blocked/flagged inputs trigger a security incident, or just log and continue with redacted content? What is the escalation path? See [Section 13, Q7](#q7).

> **Q for AI CoE:** Are there additional PII categories beyond AWS keys, IPs, and emails that should be filtered for IR automation specifically (e.g., employee names, internal hostnames, CIDR ranges)? See [Section 13, Q8](#q8).

> **Q for DevOps/SRE:** Is there a staging or test environment for Bedrock agents where Guardrails and input validation can be tested without triggering real IR workflows? See [Section 13, Q23](#q23).

---

## 6. Layer 3 — Credential & Token Abuse Prevention

### Problem

Valid IAM credentials (from SSO or Lambda roles) can invoke Bedrock from any network location. If credentials are exfiltrated via a supply chain attack, phishing, or compromised CI/CD pipeline, the attacker has full model access with no geographic or organizational restriction.

### Proposed Solution A: Service Control Policies (SCPs)

Organization-level restrictions that apply to all accounts:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyBedrockOutsideOrg",
      "Effect": "Deny",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
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
      "Sid": "DenyBedrockOutsideApprovedRegions",
      "Effect": "Deny",
      "Action": "bedrock:*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["us-east-1"]
        }
      }
    },
    {
      "Sid": "DenyBedrockInNonApprovedAccounts",
      "Effect": "Deny",
      "Action": "bedrock:*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalAccount": [
            "622711945934",
            "085133881264"
          ]
        }
      }
    }
  ]
}
```

**What This Prevents:**
- Bedrock use from any account not explicitly approved
- Bedrock use in any region other than us-east-1
- Cross-org credential use (credentials from outside Sleep Number's org)

### Proposed Solution B: Source IP Restrictions for Developer Access

For developers using Claude Code via SSO:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyBedrockOutsideCorporateNetwork",
      "Effect": "Deny",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": "*",
      "Condition": {
        "NotIpAddress": {
          "aws:SourceIp": [
            "CORPORATE_EGRESS_CIDR_1",
            "CORPORATE_EGRESS_CIDR_2",
            "VPN_EGRESS_CIDR"
          ]
        },
        "StringNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/prod-*"
        }
      }
    }
  ]
}
```

> **Q for Network Engineering:** What are the corporate egress IP ranges (office + VPN) that should be allowlisted for Bedrock developer access? See [Section 13, Q9](#q9).

> **Q for IAM/Identity:** Can source IP conditions be added to the `bedrock-model-access` IAM role's permission boundary without breaking existing SSO flows? See [Section 13, Q10](#q10).

> **Q for Security Engineering:** Should the SCP restrict Bedrock to specific accounts (`622711945934` for dev tooling, `085133881264` for IR automation), or should all accounts in the org be eligible? See [Section 13, Q11](#q11).

> **Q for Cloud/Platform Engineering:** What is the process for deploying SCPs at Sleep Number? Is there a change management workflow, or can they be applied directly? See [Section 13, Q12](#q12).

---

## 7. Layer 4 — Cross-Account Containment

### Problem

The IR automation system's Lambdas assume `prod-iam-role-ir-evidence-read` into member accounts to collect evidence (EC2 snapshots, CloudTrail logs, resource configs). If an agent is manipulated via prompt injection, it could attempt to instruct Lambdas to perform actions beyond read-only scope — or the role's permissions could be overly broad.

### Proposed Solution A: Explicit Deny on Write Actions

Add an explicit deny to the evidence role that blocks all write/delete/modify actions, regardless of what allow statements exist:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ExplicitDenyAllWriteActions",
      "Effect": "Deny",
      "Action": [
        "ec2:Terminate*", "ec2:Delete*", "ec2:Modify*", "ec2:Create*",
        "iam:*",
        "s3:Delete*", "s3:Put*",
        "dynamodb:Delete*", "dynamodb:Put*", "dynamodb:Update*",
        "lambda:*",
        "sqs:Delete*", "sqs:Send*",
        "sns:*",
        "kms:Disable*", "kms:Delete*", "kms:Schedule*"
      ],
      "Resource": "*"
    }
  ]
}
```

### Proposed Solution B: Session Duration Limits

Reduce the maximum session duration for cross-account roles:

```hcl
resource "aws_iam_role" "ir_evidence_read" {
  name                 = "prod-iam-role-ir-evidence-read"
  max_session_duration = 900   # 15 minutes — enough for evidence, limits exposure
}
```

Current default is 3600 seconds (1 hour). Reducing to 900 seconds (15 minutes) limits the window of exposure if credentials are compromised.

### Proposed Solution C: External ID Requirement

Prevent confused deputy attacks by requiring an external ID for cross-account assume:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::085133881264:role/prod-iam-role-evidence"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "ir-automation-siq-2026"
        }
      }
    }
  ]
}
```

> **Q for Security Engineering:** Is there an existing standard for cross-account role session durations at Sleep Number? What is the current practice for IR/forensics roles? See [Section 13, Q13](#q13).

> **Q for Cloud/Platform Engineering:** How many member accounts currently have `prod-iam-role-ir-evidence-read` deployed? Will adding an external ID require coordinated rollout across all accounts? See [Section 13, Q14](#q14).

---

## 8. Layer 5 — Real-Time Monitoring & Alerting

### Problem

Without Bedrock-specific monitoring, the following events are invisible:

- Unusual invocation volume (credential stuffing, automated abuse)
- Access from anomalous IP addresses or user agents
- Repeated access denied errors (credential probing)
- Off-hours invocations (compromised automation)
- Model version probing (testing which models are available)

### Proposed Solution A: Bedrock Model Invocation Logging

Captures full input/output of every model call — the AI equivalent of database query logging:

```hcl
resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    embedding_data_delivery_enabled = true
    image_data_delivery_enabled     = false
    text_data_delivery_enabled      = true

    s3_config {
      bucket_name = var.bedrock_logging_bucket
      key_prefix  = "bedrock-invocation-logs/"
    }

    cloudwatch_config {
      log_group_name = "/aws/bedrock/model-invocation-logs"

      large_data_delivery_s3_config {
        bucket_name = var.bedrock_logging_bucket
        key_prefix  = "bedrock-large-logs/"
      }
    }
  }
}
```

**What Gets Logged:**

| Field | Example | Use Case |
|-------|---------|----------|
| Input text | Finding description sent to agent | Detect prompt injection attempts |
| Output text | Agent response | Detect data leakage |
| Model ID | `anthropic.claude-sonnet-4-6` | Track model usage |
| Latency | 2.3 seconds | Performance monitoring |
| Token count | Input: 1200, Output: 800 | Cost attribution |
| Error code | `ThrottlingException` | Abuse detection |

### Proposed Solution B: CloudWatch Metric Filters & Alarms

```hcl
# Detect throttling (possible abuse)
resource "aws_cloudwatch_log_metric_filter" "bedrock_throttled" {
  name           = "BedrockThrottled"
  log_group_name = data.aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventSource = \"bedrock.amazonaws.com\") && ($.errorCode = \"ThrottlingException\") }"

  metric_transformation {
    name      = "BedrockThrottledCount"
    namespace = "Custom/BedrockSecurity"
    value     = "1"
  }
}

# Detect access denied (credential probing)
resource "aws_cloudwatch_log_metric_filter" "bedrock_access_denied" {
  name           = "BedrockAccessDenied"
  log_group_name = data.aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.eventSource = \"bedrock.amazonaws.com\") && ($.errorCode = \"AccessDenied*\") }"

  metric_transformation {
    name      = "BedrockAccessDeniedCount"
    namespace = "Custom/BedrockSecurity"
    value     = "1"
  }
}

# Alarm: >5 access denied in 5 minutes
resource "aws_cloudwatch_metric_alarm" "bedrock_access_denied_alarm" {
  alarm_name          = "prod-use1-cw-alarm-bedrock-access-denied-001"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BedrockAccessDeniedCount"
  namespace           = "Custom/BedrockSecurity"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Multiple Bedrock access denied events — possible credential probing"
  alarm_actions       = [var.security_sns_topic_arn]
}

# Alarm: >200 invocations in 5 minutes (anomalous volume)
resource "aws_cloudwatch_metric_alarm" "bedrock_volume_anomaly" {
  alarm_name          = "prod-use1-cw-alarm-bedrock-volume-anomaly-001"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BedrockInvocationCount"
  namespace           = "Custom/BedrockSecurity"
  period              = 300
  statistic           = "Sum"
  threshold           = 200
  alarm_description   = "Unusual Bedrock invocation volume — possible automated abuse"
  alarm_actions       = [var.security_sns_topic_arn]
}
```

### Proposed Solution C: GuardDuty Integration

AWS GuardDuty detects anomalous API behavior including unusual Bedrock invocation patterns:

```hcl
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs { enable = true }
  }
}
```

GuardDuty findings for Bedrock abuse (unusual invocation volume, access from anomalous IP, credential exfiltration) feed back into Security Hub — creating a feedback loop with the IR automation.

### Proposed Solution D: Automated Response via EventBridge

Auto-revoke compromised credentials on HIGH-severity GuardDuty findings:

```hcl
resource "aws_cloudwatch_event_rule" "guardduty_bedrock_abuse" {
  name        = "prod-use1-eb-rule-guardduty-bedrock-001"
  description = "Auto-respond to GuardDuty Bedrock abuse findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
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

> **Q for DevOps/SRE:** What SNS topics or PagerDuty integrations should Bedrock security alarms route to? Is there an existing security alerting pipeline? See [Section 13, Q15](#q15).

> **Q for Security Engineering:** What invocation volume thresholds are appropriate? The IR system processes findings on-demand, but Claude Code usage varies by developer count. What is a reasonable baseline? See [Section 13, Q16](#q16).

> **Q for DevOps/SRE:** Is GuardDuty already enabled in the `siq-security` account (`085133881264`) and the Bedrock developer account (`622711945934`)? See [Section 13, Q17](#q17).

> **Q for Security Engineering:** Should the automated EventBridge response revoke credentials immediately, or just alert? What is the risk tolerance for false positives disrupting legitimate IR automation? See [Section 13, Q18](#q18).

---

## 9. Layer 6 — Data Loss Prevention

### Problem

Bedrock agent responses may contain sensitive information:

- AWS account IDs (12-digit numbers)
- IP addresses (from evidence collection)
- Resource ARNs (full account + region + resource identifiers)
- Security group IDs, instance IDs
- Vulnerability details (from Security Hub findings)

These responses are sent to Microsoft Teams via webhook and stored in DynamoDB. Teams channels may have broader access than the security team, and DynamoDB data may be retained longer than intended.

### Proposed Solution A: Content Redaction Before External Delivery

Add redaction in the `post_to_teams` Lambda before sending to Teams:

```python
import re

REDACT_PATTERNS = {
    r"\b\d{12}\b": "[ACCOUNT_ID]",
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b": "[IP_ADDRESS]",
    r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:": "arn:aws:***:***:***:",
    r"AKIA[0-9A-Z]{16}": "[AWS_ACCESS_KEY]",
    r"sg-[0-9a-f]{8,17}": "[SG_ID]",
    r"i-[0-9a-f]{8,17}": "[INSTANCE_ID]",
    r"vpc-[0-9a-f]{8,17}": "[VPC_ID]",
    r"subnet-[0-9a-f]{8,17}": "[SUBNET_ID]",
}

def redact_for_external_delivery(text: str) -> str:
    """Strip sensitive AWS identifiers before sending to Teams/external channels."""
    for pattern, replacement in REDACT_PATTERNS.items():
        text = re.sub(pattern, replacement, text)
    return text
```

### Proposed Solution B: S3 Bucket Policy for Invocation Logs

Restrict access to Bedrock invocation logs to the security account only:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyExternalAccess",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::bedrock-invocation-logs/*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-xxxxxxxxxx"
        }
      }
    },
    {
      "Sid": "RestrictToSecurityTeam",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::bedrock-invocation-logs/*",
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::085133881264:role/prod-iam-role-*",
            "arn:aws:iam::085133881264:role/security-*"
          ]
        }
      }
    }
  ]
}
```

### Proposed Solution C: DynamoDB TTL for IR Case Data

Limit retention of IR case data (which includes agent outputs):

```hcl
resource "aws_dynamodb_table" "ir_cases" {
  # ... existing config ...

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}
```

Set TTL to 90 days in the Worker Lambda:

```python
import time
TTL_DAYS = 90
item["expires_at"] = int(time.time()) + (TTL_DAYS * 86400)
```

> **Q for Security Engineering:** What is the data retention requirement for IR case data? Is 90 days sufficient, or do compliance requirements mandate longer retention? See [Section 13, Q19](#q19).

> **Q for Compliance/GRC:** Does sending Security Hub finding summaries to Microsoft Teams require DLP classification? Are there existing policies for what can be shared in Teams channels? See [Section 13, Q20](#q20).

> **Q for Security Engineering:** Should full account IDs be redacted in Teams notifications, or do responders need them for triage? What level of detail is appropriate for the notification vs. the DynamoDB case record? See [Section 13, Q21](#q21).

---

## 10. Implementation Priority Matrix

> **Note:** Priorities aligned with the [EA Design Pattern](./EA_Design_Pattern_AWS_Bedrock.md). VPC Endpoints elevated to P0 per EA guidance — network isolation is a prerequisite for credential abuse controls.

| Priority | Layer | Control | Effort | Impact | Timeline | Owner |
|----------|-------|---------|--------|--------|----------|-------|
| **P0** | 1 | VPC Endpoints for Bedrock | Medium | Eliminates public internet traversal for Lambdas | Week 1 | Network + Cloud/Platform |
| **P0** | 3 | SCPs — org + region lock | Low | Blocks cross-region, cross-org Bedrock abuse | Week 1 | Security + Cloud/Platform |
| **P0** | 5 | Bedrock invocation logging | Low | Full audit trail for all model calls | Week 1 | DevOps/SRE |
| **P1** | 2 | Bedrock Guardrails | Medium | Native prompt injection + PII blocking | Week 2 | AI CoE + Security |
| **P1** | 3 | Source IP conditions on SSO | Low | Restricts developer access to corporate network | Week 2 | IAM/Identity + Network |
| **P1** | 5 | CloudWatch metric filters + alarms | Low | Real-time alerting on abuse patterns | Week 2 | DevOps/SRE + Security |
| **P2** | 4 | Session limits + external ID | Low | Reduces cross-account blast radius | Week 3 | Cloud/Platform + Security |
| **P2** | 2 | Input/output validation in Lambda | Medium | Application-layer injection defense | Weeks 3-4 | AI CoE + DevOps/SRE |
| **P2** | 4 | Explicit deny on write actions | Low | Hardens cross-account evidence roles | Week 3 | Security + Cloud/Platform |
| **P3** | 6 | Content redaction for Teams | Medium | Prevents data leakage to broad channels | Week 4 | Security + DevOps/SRE |
| **P3** | 5 | GuardDuty + auto-response | Medium | Automated threat detection for Bedrock | Weeks 4-5 | Security + DevOps/SRE |
| **P3** | 6 | DynamoDB TTL + log retention | Low | Controls data lifecycle | Week 5 | DevOps/SRE + Compliance |

### Cost Estimate

| Component | Monthly Cost (estimated) |
|-----------|------------------------|
| VPC Endpoints (3x Interface) | ~$22/endpoint = ~$66/month |
| Bedrock Guardrails | Per-policy pricing, ~$1/1000 text units assessed |
| Bedrock Invocation Logging (S3) | Depends on volume; ~$5-20/month for IR workload |
| CloudWatch Alarms (5x) | ~$0.50/alarm = ~$2.50/month |
| GuardDuty | Per-event pricing; ~$10-30/month for security account |
| **Total incremental** | **~$100-150/month** |

---

## 11. Compliance Mapping

| Framework | Control ID | Control Name | Current Status | After Implementation |
|-----------|-----------|-------------|----------------|---------------------|
| **SOC 2** | CC6.1 | Logical Access | Covered | Enhanced |
| **SOC 2** | CC6.6 | External Threats | **Gap** | Covered (Layers 1, 3) |
| **SOC 2** | CC6.7 | Restrict System Access | **Gap** | Covered (Layer 1) |
| **SOC 2** | CC7.2 | Monitor for Anomalies | **Gap** | Covered (Layer 5) |
| **SOC 2** | CC7.3 | Evaluate Anomalies | **Gap** | Covered (Layer 5) |
| **NIST 800-53** | AC-3 | Access Enforcement | Covered | Enhanced |
| **NIST 800-53** | AC-4 | Information Flow | **Gap** | Covered (Layer 6) |
| **NIST 800-53** | SC-7 | Boundary Protection | **Gap** | Covered (Layer 1) |
| **NIST 800-53** | SC-13 | Cryptographic Protection | Covered | Covered |
| **NIST 800-53** | SI-4 | System Monitoring | **Gap** | Covered (Layer 5) |
| **NIST 800-53** | SI-10 | Input Validation | **Gap** | Covered (Layer 2) |
| **CIS AWS** | 2.1 | Encryption in Transit | Covered | Covered |
| **CIS AWS** | 3.1 | CloudTrail Enabled | Covered | Enhanced |
| **OWASP LLM** | LLM01 | Prompt Injection | **Gap** | Covered (Layer 2) |
| **OWASP LLM** | LLM02 | Insecure Output | **Gap** | Covered (Layers 2, 6) |
| **OWASP LLM** | LLM06 | Sensitive Info Disclosure | **Gap** | Covered (Layers 2, 6) |
| **OWASP LLM** | LLM08 | Excessive Agency | **Gap** | Covered (Layer 4) |

---

## 11a. Multi-Cloud Applicability

This RFC is the **AWS Bedrock instantiation** of the cloud-agnostic [EA Design Pattern: Defense-in-Depth for Managed AI Services](./EA_Design_Pattern_AWS_Bedrock.md). The same 6-layer model applies to Azure OpenAI, GCP Vertex AI, and future managed AI services. Teams consuming Azure OpenAI should reference the EA pattern and produce an equivalent RFC with Azure-specific implementations (Private Endpoints, Azure Policy, Content Safety API, Sentinel).

| Layer | This RFC (AWS Bedrock) | Azure OpenAI Equivalent |
|-------|----------------------|------------------------|
| L0 — Identity | IAM + Okta SSO | Entra ID + Azure RBAC |
| L1 — Network | VPC Endpoints | Private Endpoints |
| L2 — AI Safety | Bedrock Guardrails | Content Safety API |
| L3 — Credential | SCPs + Source IP | Azure Policy + Conditional Access |
| L4 — Containment | Cross-account role limits | Subscription boundaries |
| L5 — Monitoring | CloudWatch + GuardDuty | Azure Monitor + Sentinel |
| L6 — DLP | Guardrails PII + Lambda redaction | Azure DLP + Content Safety |

---

## 11b. Deliverables Checklist

Per the [EA Design Pattern](./EA_Design_Pattern_AWS_Bedrock.md), this RFC must produce:

- [ ] **Access Control Matrix** — principal x path x scope for every Bedrock consumer (Layer 0)
- [ ] **Network Flow Diagram** — VPC endpoints, security groups, traffic paths (Layer 1)
- [ ] **Guardrail Configuration** — prompt injection + PII rules as Terraform (Layer 2)
- [ ] **SCP / Org Policy Template** — region + account lock as JSON (Layer 3)
- [ ] **Cross-Account Role Template** — deny writes, session limits, external ID (Layer 4)
- [ ] **Monitoring Runbook** — alerts, thresholds, escalation paths, response procedures (Layer 5)
- [ ] **Redaction Rules** — per external channel (Teams, DynamoDB, S3) (Layer 6)
- [ ] **Compliance Mapping** — control x layer x status (Section 11 above)
- [ ] **Priority Matrix** — effort x impact x timeline (Section 10 above)

---

## 12. Rollout Plan

### Phase 1 — Foundation + Network Isolation (Weeks 1-2)

**Goal:** Establish visibility, org-level boundaries, and network isolation. Per [EA Design Pattern](./EA_Design_Pattern_AWS_Bedrock.md), network isolation (L1) and SCPs (L3) are co-equal P0 priorities.

| Action | Owner | Dependencies | Risk |
|--------|-------|-------------|------|
| Deploy VPC endpoints for Bedrock | Network + Cloud/Platform | VPC, subnet allocation | Medium — Lambda config changes |
| Add IAM VPC-only deny for Lambda roles | Security | VPC endpoints operational | Medium — verify Lambda connectivity first |
| Deploy SCPs (region + account lock) | Security + Cloud/Platform | AWS Organizations admin access | Low — deny-by-default for unused regions/accounts |
| Enable Bedrock invocation logging | DevOps/SRE | S3 bucket + CloudWatch log group | None — read-only observability |
| Create CloudWatch metric filters | DevOps/SRE | CloudTrail log group access | None — monitoring only |
| Baseline normal invocation volume | Security | 2 weeks of invocation data | None — data collection |

### Phase 2 — AI Safety & Credential Hardening (Weeks 3-4)

**Goal:** Add AI-layer defenses and restrict credential use by network location.

| Action | Owner | Dependencies | Risk |
|--------|-------|-------------|------|
| Deploy Bedrock Guardrails | AI CoE + Security | Guardrail content policy approved | Low — can test in DRAFT before attaching |
| Add source IP conditions for developer access | IAM/Identity + Network | Corporate IP range list | Medium — could block legitimate remote work |
| Add input validation to Worker Lambda | DevOps/SRE | Code review + deploy | Low — redacts, doesn't block |
| Deploy CloudWatch alarms for Bedrock | DevOps/SRE + Security | Baseline data from Phase 1 | Low — alerting only |

### Phase 3 — Hardening & Automation (Weeks 5-6)

**Goal:** Tighten cross-account boundaries, add automated response, implement DLP.

| Action | Owner | Dependencies | Risk |
|--------|-------|-------------|------|
| Reduce cross-account session duration | Cloud/Platform | Coordinated member account rollout | Low — test with IR automation first |
| Add external ID to cross-account roles | Cloud/Platform + Security | Member account Terraform updates | Medium — requires coordinated deploy |
| Add explicit deny on write actions | Security | Member account role updates | Low — should deny already-unused permissions |
| Deploy content redaction to Teams Lambda | DevOps/SRE | Redaction patterns approved | Low — additive |
| Enable GuardDuty in Bedrock accounts | Security | GuardDuty subscription | Low — monitoring only |
| Deploy EventBridge auto-response | Security + DevOps/SRE | GuardDuty enabled, SNS configured | Medium — false positives could disrupt IR |
| Set DynamoDB TTL on IR case data | DevOps/SRE | Retention policy approved | Low — future data only |

> **Q for DevOps/SRE:** What is the CI/CD pipeline for IR automation Terraform and Lambda code? Manual `task apply` or automated? See [Section 13, Q22](#q22).

> **Q for DevOps/SRE:** When Bedrock security alarms fire, who gets paged and what is the response procedure? Does this RFC need to produce a runbook? See [Section 13, Q25](#q25).

> **Q for DevOps/SRE:** DevOps/SRE owns or co-owns 8 of 12 implementation items across 6 weeks. Does the team have capacity, or should the timeline extend? See [Section 13, Q26](#q26).

### Rollback Plan

Each layer is independently deployable and reversible:

| Layer | Rollback Method | Time to Rollback |
|-------|----------------|-----------------|
| SCPs | Remove SCP from OU | < 5 minutes |
| VPC Endpoints | Remove VPCE deny from IAM; delete endpoints | < 15 minutes |
| Bedrock Guardrails | Detach from agent config | < 5 minutes (Terraform apply) |
| Source IP conditions | Remove condition from IAM policy | < 5 minutes |
| Input/output validation | Revert Lambda code | < 10 minutes (deploy) |
| Cross-account hardening | Revert role Terraform | < 15 minutes per account |
| Monitoring/alerting | Delete alarms | < 5 minutes |

---

## 13. Open Questions for Reviewers

### Security Engineering

<a id="q1"></a>**Q1:** Is the current IAM-only configuration sufficient for a compliance audit, or have auditors already flagged the absence of network-level controls for AI services?

<a id="q7"></a>**Q7:** Should blocked/flagged prompt injection inputs trigger a security incident, or just log and continue with redacted content? What is the escalation path?

<a id="q11"></a>**Q11:** Should the SCP restrict Bedrock to specific accounts (`622711945934` for dev tooling, `085133881264` for IR automation), or should all accounts in the org be eligible?

<a id="q13"></a>**Q13:** Is there an existing standard for cross-account role session durations at Sleep Number? What is the current practice for IR/forensics roles?

<a id="q16"></a>**Q16:** What invocation volume thresholds are appropriate for CloudWatch alarms? The IR system processes findings on-demand, but Claude Code usage varies by developer count. What is a reasonable baseline?

<a id="q18"></a>**Q18:** Should the automated EventBridge response revoke credentials immediately, or just alert? What is the risk tolerance for false positives disrupting legitimate IR automation?

<a id="q19"></a>**Q19:** What is the data retention requirement for IR case data? Is 90 days sufficient, or do compliance requirements mandate longer retention?

<a id="q21"></a>**Q21:** Should full account IDs be redacted in Teams notifications, or do responders need them for triage? What level of detail is appropriate for the notification vs. the DynamoDB case record?

### Compliance/GRC

<a id="q2"></a>**Q2:** Does Sleep Number's risk framework require defense-in-depth for AI/ML workloads specifically, or are they governed by the same controls as general compute?

<a id="q20"></a>**Q20:** Does sending Security Hub finding summaries to Microsoft Teams require DLP classification? Are there existing policies for what can be shared in Teams channels?

### Network Engineering

<a id="q3"></a>**Q3:** Which VPC should host the Bedrock VPC endpoints? Is there an existing shared services VPC, or does the `siq-security` account need its own? What is the subnet availability?

<a id="q4"></a>**Q4:** If using VPN-routed developer access (Option A), can GlobalProtect be configured to route `bedrock-runtime.us-east-1.amazonaws.com` traffic through the VPN split tunnel?

<a id="q9"></a>**Q9:** What are the corporate egress IP ranges (office + VPN) that should be allowlisted for Bedrock developer access?

### Cloud/Platform Engineering

<a id="q5"></a>**Q5:** Is there an existing Terraform module or pattern for deploying VPC endpoints at Sleep Number? Should these be added to a shared infrastructure module?

<a id="q12"></a>**Q12:** What is the process for deploying SCPs at Sleep Number? Is there a change management workflow, or can they be applied directly?

<a id="q14"></a>**Q14:** How many member accounts currently have `prod-iam-role-ir-evidence-read` deployed? Will adding an external ID require coordinated rollout across all accounts?

### AI CoE

<a id="q6"></a>**Q6:** What prompt injection detection capabilities exist in the current Azure OpenAI content safety configuration? Can those patterns be reused for Bedrock Guardrails?

<a id="q8"></a>**Q8:** Are there additional PII categories beyond AWS keys, IPs, and emails that should be filtered for IR automation specifically (e.g., employee names, internal hostnames, CIDR ranges)?

### IAM/Identity

<a id="q10"></a>**Q10:** Can source IP conditions be added to the `bedrock-model-access` IAM role's permission boundary without breaking existing SSO flows?

### DevOps/SRE

<a id="q15"></a>**Q15:** What SNS topics or PagerDuty integrations should Bedrock security alarms route to? Is there an existing security alerting pipeline?

<a id="q17"></a>**Q17:** Is GuardDuty already enabled in the `siq-security` account (`085133881264`) and the Bedrock developer account (`622711945934`)?

<a id="q22"></a>**Q22:** What is the CI/CD pipeline for the IR automation Terraform and Lambda code? Is deployment currently manual (`task apply`), or is there an automated pipeline? If manual, should this RFC include standing up a pipeline as a prerequisite?

<a id="q23"></a>**Q23:** Is there a staging or test environment for Bedrock agents where Guardrails and input validation can be tested without triggering real IR workflows? If not, what is the safest way to validate these changes — DRAFT agent aliases, a dedicated test agent, or synthetic findings?

<a id="q24"></a>**Q24:** The VPC endpoint IAM deny policy and Lambda VPC configuration must deploy atomically — if the deny lands before Lambdas are VPC-attached, IR automation breaks. What is the preferred zero-downtime rollout strategy? Blue/green Lambda aliases, feature flags, or a maintenance window?

<a id="q25"></a>**Q25:** When Bedrock security alarms fire (access denied spike, volume anomaly, GuardDuty finding), who gets paged and what is the response procedure? Is there an existing IR runbook template, or does this RFC need to produce one?

<a id="q26"></a>**Q26:** DevOps/SRE is owner or co-owner on 8 of 12 implementation items across the 6-week rollout. Does the team have capacity for this alongside current work, or should the timeline be extended? Are there specific sprint boundaries or freeze periods to account for?

---

## 14. How to Review / Comment

1. **Read the sections relevant to your team** — use the "Where Each Team Is Involved" matrix in Section 3 to identify which layers need your input.

2. **Answer the questions tagged to your team** — each question in Section 13 is addressed to a specific team. Your answers will directly shape the implementation.

3. **Flag concerns or constraints** — if a proposed control conflicts with existing infrastructure, operational procedures, or compliance requirements, note it with context.

4. **Suggest alternatives** — if you know a better approach (existing tooling, established patterns, different AWS service), propose it.

**How to submit comments:**

- **GitHub:** Open an issue or PR comment on this file in the repository
- **Teams:** Reply in the RFC review channel with the question number (e.g., "Re: Q3 — the shared services VPC in us-east-1 is...")
- **Direct:** Tag the author with inline feedback

**Review deadline:** 2026-05-19 (two weeks from publication)

**Decision meeting:** Scheduled after comment period closes. All teams with open questions will be invited.

---

## References

- [EA Design Pattern: Defense-in-Depth for Managed AI Services](./EA_Design_Pattern_AWS_Bedrock.md) — Governing architectural pattern (cloud-agnostic)
- [AWS Bedrock Security Analysis](./AWS_Bedrock_Security.md) — Detailed security posture assessment
- [AWS Bedrock Setup Guide](./AWS_BEDROCK_SETUP.md) — Developer + IR automation setup documentation
- [SLA: Claude Code Setup for AWS Bedrock](../docs/AWS_BEDROCK_SETUP.md) — SSO + settings.json configuration
- [devops-security-hub-ai README](../vulnerability_reports/devops-security-hub-ai/README.md) — IR automation architecture
- [AWS Bedrock Security Documentation](https://docs.aws.amazon.com/bedrock/latest/userguide/security.html)
- [AWS Bedrock Guardrails](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html)
- [AWS Bedrock VPC Endpoints](https://docs.aws.amazon.com/bedrock/latest/userguide/vpc-interface-endpoints.html)
- [AWS Bedrock Model Invocation Logging](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [AWS Service Control Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [NIST 800-53 Security Controls](https://csf.tools/reference/nist-sp-800-53/r5/)
