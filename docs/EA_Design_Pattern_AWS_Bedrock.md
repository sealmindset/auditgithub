# Design Pattern: AWS Bedrock Security — Defense-in-Depth

> **Confluence Wiki Format** — Enterprise Architecture Design Pattern
> Follows the [refactoring.guru](https://refactoring.guru/design-patterns/) pattern documentation structure adapted for Enterprise Architecture deliverables.

---

## Pattern Metadata

| Field | Value |
|-------|-------|
| **Pattern Name** | Defense-in-Depth for Managed AI Services |
| **Category** | Structural — Decorator + Proxy (layered security wrapping) |
| **Domain** | Cloud Security, AI/ML Platform Governance |
| **Status** | Proposed |
| **Owner** | Enterprise Architecture — Security |
| **Last Updated** | 2026-05-05 |
| **Reference Implementation** | AWS Bedrock (IR Automation + Developer Access) |

---

## Intent

Establish a repeatable, layered security model for enterprise consumption of managed AI services — ensuring that no single control (identity, network, application) is the sole line of defense.

**One-liner:** Wrap every managed AI service in concentric security layers so that failure of any single layer does not result in unauthorized access, data leakage, or model abuse.

---

## Problem

The enterprise adopts managed AI services (AWS Bedrock, Azure OpenAI, GCP Vertex AI). Teams default to IAM-only security. IAM is necessary but brittle:

- **Stolen tokens** — SSO session hijacked or credential exfiltrated → attacker invokes models from any network
- **Prompt injection** — crafted input manipulates agent behavior → data exfiltration, false outputs, unauthorized actions
- **Blast radius** — cross-account roles without containment → lateral movement from compromised agent
- **Shadow usage** — no invocation logging → abuse goes undetected for weeks
- **Data leakage** — agent responses containing PII, credentials, or internal details sent to external channels

IAM alone cannot address network, application, or data-layer threats. Each gap requires its own control.

---

## Motivation (When to Apply)

Apply this pattern when:

- Enterprise consumes **any managed AI/ML service** (Bedrock, Azure OpenAI, Vertex AI, SageMaker endpoints)
- AI agents **process sensitive data** (security findings, customer data, financial records)
- AI agents **take actions** (create PRs, send notifications, modify infrastructure)
- **Compliance frameworks** require defense-in-depth (SOC 2 CC6.6, NIST SC-7, OWASP LLM Top 10)
- **Multiple access paths** exist (developer CLI, automated pipelines, cross-account roles)

Do **not** apply full pattern for:

- Read-only, non-sensitive AI experimentation in sandbox accounts
- Internal chatbots with no action capabilities and no PII exposure

---

## Structure

```
┌──────────────────────────────────────────────────────────────────────┐
│                    DEFENSE-IN-DEPTH LAYERS                           │
│                                                                      │
│  ┌─── Layer 6: Data Loss Prevention (DLP) ──────────────────────┐   │
│  │  PII filtering · Content redaction · Log bucket policies      │   │
│  │                                                               │   │
│  │  ┌─── Layer 5: Real-Time Monitoring ─────────────────────┐   │   │
│  │  │  Invocation logging · Metric filters · GuardDuty ·     │   │   │
│  │  │  EventBridge auto-response                             │   │   │
│  │  │                                                        │   │   │
│  │  │  ┌─── Layer 4: Cross-Account Containment ─────────┐   │   │   │
│  │  │  │  Explicit deny writes · Session limits ·        │   │   │   │
│  │  │  │  External ID                                    │   │   │   │
│  │  │  │                                                 │   │   │   │
│  │  │  │  ┌─── Layer 3: Credential Abuse Prevention ─┐   │   │   │   │
│  │  │  │  │  SCPs · Source IP · Anomaly alarms        │   │   │   │   │
│  │  │  │  │                                           │   │   │   │   │
│  │  │  │  │  ┌─── Layer 2: AI Application Security ┐ │   │   │   │   │
│  │  │  │  │  │  Guardrails · Input sanitization ·   │ │   │   │   │   │
│  │  │  │  │  │  Output validation                   │ │   │   │   │   │
│  │  │  │  │  │                                      │ │   │   │   │   │
│  │  │  │  │  │  ┌─── Layer 1: Network Isolation ─┐  │ │   │   │   │   │
│  │  │  │  │  │  │  VPC Endpoints · SG lockdown · │  │ │   │   │   │   │
│  │  │  │  │  │  │  IAM VPC conditions            │  │ │   │   │   │   │
│  │  │  │  │  │  │                                │  │ │   │   │   │   │
│  │  │  │  │  │  │  ┌── Layer 0: Identity ──────┐ │  │ │   │   │   │   │
│  │  │  │  │  │  │  │  Okta · SSO · IAM Roles · │ │  │ │   │   │   │   │
│  │  │  │  │  │  │  │  Least-privilege policies  │ │  │ │   │   │   │   │
│  │  │  │  │  │  │  └────────────────────────────┘ │  │ │   │   │   │   │
│  │  │  │  │  │  └────────────────────────────────┘  │ │   │   │   │   │
│  │  │  │  │  └──────────────────────────────────────┘ │   │   │   │   │
│  │  │  │  └──────────────────────────────────────────-┘   │   │   │   │
│  │  │  └──────────────────────────────────────────────────┘   │   │   │
│  │  └─────────────────────────────────────────────────────────┘   │   │
│  └────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Participants (Roles & Responsibilities)

| Participant | Role | Owns |
|-------------|------|------|
| **Enterprise Architect** | Pattern owner. Defines layers, governance, compliance mapping | Pattern template, compliance matrix, priority framework |
| **Cloud Platform Team** | Implements Layers 0, 1, 3. Manages VPC, IAM, SCPs | Terraform modules, network config, SCP policies |
| **Application/AI Team** | Implements Layer 2. Builds input/output validation | Lambda code, guardrail config, agent definitions |
| **Security Operations** | Implements Layers 4, 5, 6. Monitors, responds, audits | CloudWatch rules, GuardDuty config, DLP policies, runbooks |
| **Compliance/GRC** | Validates pattern against frameworks. Accepts risk for gaps | Compliance mapping table, exception approvals |

---

## Layer Specifications

### Layer 0 — Identity & Access (Baseline)

**Design Pattern Analog:** Proxy — controls access to protected resource

| Control | Implementation | Evidence Source |
|---------|---------------|----------------|
| Okta group gating | `aws-bedrock-model-access` membership required | SSO config |
| Temporary credentials | IAM Identity Center issues auto-expiring tokens | SSO session policy |
| Model-scoped IAM | `bedrock:InvokeModel` on specific ARNs only | Terraform IAM policy |
| Resource-based Lambda policies | `bedrock.amazonaws.com` with `ArnLike` condition | Terraform modules |

**Deliverable:** Access control matrix showing principal → path → scope for every consumer.

---

### Layer 1 — Network Isolation

**Design Pattern Analog:** Proxy — intermediary controlling network path to resource

| Control | Implementation | Evidence Source |
|---------|---------------|----------------|
| VPC Endpoints | `com.amazonaws.us-east-1.bedrock-runtime` + `bedrock-agent-runtime` | Terraform `aws_vpc_endpoint` |
| Security Group lockdown | HTTPS 443 from Lambda SG only | Terraform `aws_security_group` |
| IAM VPC condition | `Deny bedrock:*` when `aws:SourceVpce` doesn't match | IAM policy condition |

**Deliverable:** Network flow diagram + Terraform module for VPC endpoint provisioning.

---

### Layer 2 — AI Application Security

**Design Pattern Analog:** Decorator — wraps AI invocation with pre/post processing without modifying core agent logic

| Control | Implementation | Evidence Source |
|---------|---------------|----------------|
| Bedrock Guardrails | Prompt attack blocking, PII detection, profanity filter | Terraform `aws_bedrock_guardrail` |
| Input sanitization | Regex-based injection pattern detection pre-Bedrock | Lambda code |
| Output validation | Credential/secret pattern detection post-Bedrock | Lambda code |

**Deliverable:** Guardrail configuration template + input/output validation library.

---

### Layer 3 — Credential Abuse Prevention

**Design Pattern Analog:** Chain of Responsibility — multiple handlers evaluate credential legitimacy

| Control | Implementation | Evidence Source |
|---------|---------------|----------------|
| SCPs | Deny Bedrock outside org + allowed regions | AWS Organizations SCP |
| Source IP restriction | Corporate IP ranges on SSO developer roles | IAM session policy |
| Anomaly alarms | CloudWatch alarm on invocation volume > threshold | Terraform `aws_cloudwatch_metric_alarm` |

**Deliverable:** SCP template + IP allowlist governance process + alarm threshold baseline.

---

### Layer 4 — Cross-Account Containment

**Design Pattern Analog:** Proxy + Memento — controlled access with time-bounded sessions and rollback capability

| Control | Implementation | Evidence Source |
|---------|---------------|----------------|
| Explicit deny writes | Deny `Terminate*`, `Delete*`, `Modify*`, `Put*` on evidence role | IAM policy |
| Session limits | `max_session_duration = 900` (15 min) | Terraform IAM role |
| External ID | Required for `sts:AssumeRole` cross-account | IAM trust policy condition |

**Deliverable:** Cross-account role template with hardened defaults.

---

### Layer 5 — Real-Time Monitoring

**Design Pattern Analog:** Observer — event-driven notification of security-relevant state changes

| Control | Implementation | Evidence Source |
|---------|---------------|----------------|
| Invocation logging | Full prompt/response to S3 + CloudWatch | Terraform `aws_bedrock_model_invocation_logging_configuration` |
| Metric filters | Throttling, access denied, invocation volume | Terraform `aws_cloudwatch_log_metric_filter` |
| GuardDuty | Anomalous API behavior detection | Terraform `aws_guardduty_detector` |
| Auto-response | EventBridge triggers on HIGH severity GuardDuty findings | Terraform `aws_cloudwatch_event_rule` |

**Deliverable:** Monitoring runbook + alert routing matrix + auto-response playbook.

---

### Layer 6 — Data Loss Prevention

**Design Pattern Analog:** Decorator — wraps outbound data with redaction before delivery to external channels

| Control | Implementation | Evidence Source |
|---------|---------------|----------------|
| PII filtering | Bedrock Guardrails `ANONYMIZE` for IP, `BLOCK` for keys | Guardrail config |
| Content redaction | Regex replacement of account IDs, ARNs, IPs before Teams | Lambda `post_to_teams` |
| Log bucket policies | Deny `s3:GetObject` outside org | S3 bucket policy |

**Deliverable:** Redaction rules library + bucket policy template.

---

## Implementation Priority

| Priority | Layer | Effort | Impact | Timeline |
|----------|-------|--------|--------|----------|
| **P0** | L1 — VPC Endpoints | Medium | Eliminates public internet traversal | Week 1 |
| **P0** | L3 — SCPs | Low | Org-wide region + account lock | Week 1 |
| **P1** | L2 — Bedrock Guardrails | Medium | Native prompt injection + PII blocking | Week 2 |
| **P1** | L5 — Invocation Logging | Low | Full audit trail | Week 2 |
| **P2** | L2 — Input/Output validation | Medium | Crafted-input defense | Week 3 |
| **P2** | L4 — Session limits + external ID | Low | Blast radius reduction | Week 3 |
| **P3** | L6 — Content redaction | Medium | External data leakage prevention | Week 4 |
| **P3** | L5 — GuardDuty + auto-response | Medium | Automated abuse response | Week 4 |

---

## Compliance Mapping

| Framework | Control | Layer | Status |
|-----------|---------|-------|--------|
| SOC 2 CC6.1 | Logical Access | L0 | **Covered** |
| SOC 2 CC6.6 | External Threats | L1, L2 | Gap → P0/P1 |
| SOC 2 CC6.7 | Restrict System Access | L1 | Gap → P0 |
| SOC 2 CC7.2 | Anomaly Monitoring | L5 | Gap → P1 |
| NIST AC-3 | Access Enforcement | L0 | **Covered** |
| NIST AC-4 | Information Flow | L6 | Gap → P3 |
| NIST SC-7 | Boundary Protection | L1 | Gap → P0 |
| NIST SC-13 | Cryptographic Protection | L0 | **Covered** |
| NIST SI-4 | System Monitoring | L5 | Gap → P1 |
| NIST SI-10 | Input Validation | L2 | Gap → P1 |
| OWASP LLM01 | Prompt Injection | L2 | Gap → P1 |
| OWASP LLM02 | Insecure Output | L2 | Gap → P2 |
| OWASP LLM06 | Sensitive Info Disclosure | L6 | Gap → P3 |

---

## Applicability to Other Enterprise Services

This pattern is **not specific to AWS Bedrock**. The layered structure applies to any managed AI service:

| Layer | AWS Bedrock | Azure OpenAI | GCP Vertex AI |
|-------|-------------|--------------|---------------|
| L0 — Identity | IAM + Okta SSO | Entra ID + RBAC | IAM + Workforce Identity |
| L1 — Network | VPC Endpoints | Private Endpoints | VPC Service Controls |
| L2 — AI Safety | Bedrock Guardrails | Content Safety API | Model Armor |
| L3 — Credential | SCPs + Source IP | Azure Policy + Conditional Access | Org Policies + VPC-SC |
| L4 — Containment | Cross-account role limits | Subscription boundaries | Project-level isolation |
| L5 — Monitoring | CloudWatch + GuardDuty | Azure Monitor + Sentinel | Cloud Logging + SCC |
| L6 — DLP | Guardrails PII + Lambda redaction | Azure DLP + Content Safety | Cloud DLP + Model Armor |

**Enterprise Architecture value:** Build once as a pattern, instantiate per cloud provider. Teams consume the layer template, not the vendor-specific implementation.

---

## Related Patterns

| Pattern | Relationship |
|---------|-------------|
| **Decorator** | Core structural concept — each layer wraps the service without modifying it |
| **Proxy** | Network and access layers act as controlled intermediaries |
| **Chain of Responsibility** | Credential validation flows through multiple handlers |
| **Observer** | Monitoring layers subscribe to security events |
| **Template Method** | Fixed layer sequence with customizable implementation per layer |
| **Strategy** | Each layer supports swappable implementations (e.g., Bedrock Guardrails vs custom Lambda validation) |

---

## Repeatable Deliverable Checklist

Every architect applying this pattern produces:

- [ ] **Access Control Matrix** — principal × path × scope (Layer 0)
- [ ] **Network Flow Diagram** — with VPC endpoints and SG rules (Layer 1)
- [ ] **Guardrail Configuration** — prompt injection + PII rules (Layer 2)
- [ ] **SCP / Org Policy Template** — region + account lock (Layer 3)
- [ ] **Cross-Account Role Template** — deny writes, session limits, external ID (Layer 4)
- [ ] **Monitoring Runbook** — alerts, thresholds, escalation paths (Layer 5)
- [ ] **Redaction Rules** — per external channel (Layer 6)
- [ ] **Compliance Mapping** — control → layer → status (All)
- [ ] **Priority Matrix** — effort × impact × timeline (All)

---

## References

- [refactoring.guru — Design Patterns](https://refactoring.guru/design-patterns/) — Pattern documentation structure
- [AWS Bedrock Security Documentation](https://docs.aws.amazon.com/bedrock/latest/userguide/security.html)
- [AWS Bedrock VPC Endpoints](https://docs.aws.amazon.com/bedrock/latest/userguide/vpc-interface-endpoints.html)
- [AWS Bedrock Guardrails](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST 800-53 Security Controls](https://csf.tools/reference/nist-sp-800-53/r5/)
- Source analysis: [AWS_Bedrock_Security.md](./AWS_Bedrock_Security.md)
