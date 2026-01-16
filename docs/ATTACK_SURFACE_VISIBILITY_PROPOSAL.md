# Attack Surface Visibility Enhancement Proposal

**Document Version:** 1.0  
**Date:** December 7, 2025  
**Author:** Security Engineering Team

---

## Executive Summary

This proposal outlines enhancements to transform AuditGH from a vulnerability scanner into a comprehensive **Attack Surface Management (ASM)** platform. The goal is to provide security analysts with real-world visibility into what attackers see and target, powered by AI agents for automated analysis and enrichment.

---

## Current State Analysis

### What We Have Today

| Capability | Data Source | Current Coverage |
|------------|-------------|------------------|
| **Repositories** | GitHub API | 1,855 repos (100% synced) |
| **Vulnerability Scanning** | 7 scanners (Trivy, Grype, Semgrep, etc.) | 5,455 findings |
| **Contributor Tracking** | Git log analysis | Basic commits, email |
| **Dependencies** | SBOM/Syft | Package inventory |
| **Languages** | LOC analysis | Lines of code per language |
| **Architecture** | AI-generated | Diagrams & reports |
| **File Commit History** | GitHub API | 73% of findings have file-level data |

### Current Scanner Distribution
- trivy-fs: 1,542 (OSS vulnerabilities)
- grype: 1,095 (OSS vulnerabilities)
- nuclei: 908 (Infrastructure scanning)
- trufflehog: 888 (Secrets detection)
- retirejs: 545 (JS library vulnerabilities)
- semgrep: 456 (SAST)
- checkov: 21 (IaC security)

---

## Proposed Enhancements

### 1. 🎯 Systems & Services of Interest to Attackers

#### 1.1 API Target Discovery
**Goal:** Automatically identify and map high-value API targets.

| Asset Type | Detection Method | Risk Indicators |
|------------|------------------|-----------------|
| REST APIs | OpenAPI/Swagger specs, route definitions | Public exposure, auth bypass vulns |
| GraphQL APIs | Schema introspection, `*.graphql` files | Overly permissive queries |
| gRPC Services | `.proto` files, service definitions | Unencrypted channels |
| Webhooks | Webhook configs, callback URLs | Secret leakage in URLs |
| API Keys | TruffleHog, regex patterns | Hardcoded, exposed keys |

**New Scanner Integration:**
```python
class APIDiscoveryScanner:
    """Scan for API specifications and endpoints."""
    
    patterns = {
        'openapi': ['swagger.json', 'openapi.yaml', 'api-docs/*'],
        'graphql': ['schema.graphql', '*.gql', 'graphql/*'],
        'grpc': ['*.proto'],
        'rest_routes': ['routes.py', 'urls.py', 'router.ts', 'controllers/*']
    }
    
    def analyze_api_spec(self, spec_content: str) -> dict:
        """Extract endpoints, auth requirements, parameters."""
        # Returns structured API surface data
```

**New Data Model:**
```sql
CREATE TABLE api_endpoints (
    id UUID PRIMARY KEY,
    repository_id UUID REFERENCES repositories(id),
    endpoint_path TEXT NOT NULL,
    http_method VARCHAR(10),
    spec_source TEXT,  -- 'openapi', 'graphql', 'code_analysis'
    auth_required BOOLEAN,
    auth_type VARCHAR(50),  -- 'oauth2', 'api_key', 'jwt', 'none'
    parameters JSONB,
    is_public BOOLEAN,
    risk_score INTEGER,  -- AI-calculated
    last_analyzed_at TIMESTAMP
);

CREATE TABLE api_specs (
    id UUID PRIMARY KEY,
    repository_id UUID REFERENCES repositories(id),
    spec_type VARCHAR(20),  -- 'openapi', 'graphql', 'asyncapi'
    file_path TEXT,
    spec_version VARCHAR(10),
    spec_content TEXT,
    parsed_data JSONB,
    created_at TIMESTAMP
);
```

#### 1.2 Infrastructure Mapping
**Goal:** Map exposed infrastructure and service dependencies.

| Asset Type | Detection Source | Enrichment Source |
|------------|------------------|-------------------|
| Hostnames | Code, configs, env files | DNS, Shodan |
| IP Addresses | Hardcoded IPs scanner | IP reputation, geolocation |
| Cloud Resources | IaC (Terraform, CloudFormation) | Cloud APIs |
| Databases | Connection strings | Version fingerprinting |
| Message Queues | Kafka, RabbitMQ configs | Exposure checks |

**New Data Model:**
```sql
CREATE TABLE infrastructure_assets (
    id UUID PRIMARY KEY,
    repository_id UUID REFERENCES repositories(id),
    asset_type VARCHAR(50),  -- 'hostname', 'ip', 'cloud_resource', 'database'
    asset_value TEXT NOT NULL,  -- The actual hostname, IP, resource ID
    environment VARCHAR(20),  -- 'production', 'staging', 'development'
    source_file TEXT,
    source_line INTEGER,
    is_exposed BOOLEAN,
    exposure_reason TEXT,
    cloud_provider VARCHAR(20),  -- 'aws', 'azure', 'gcp'
    enrichment_data JSONB,  -- DNS records, IP rep, etc.
    risk_score INTEGER,
    first_seen_at TIMESTAMP,
    last_seen_at TIMESTAMP
);
```

---

### 2. 🏚️ Abandoned & Legacy System Detection

**Goal:** Identify repos and code that attackers love: unmaintained, legacy, forgotten systems.

#### 2.1 Abandonment Risk Indicators

| Indicator | Weight | Data Source |
|-----------|--------|-------------|
| No commits in 2+ years | High | GitHub API (pushed_at) |
| Archived repository | High | GitHub API (is_archived) |
| Single contributor (left company) | High | Contributor + Entra ID |
| Outdated dependencies (2+ major versions) | Medium | SBOM analysis |
| Deprecated language versions | Medium | Language detection |
| No recent PR activity | Medium | GitHub API |
| CI/CD pipeline inactive | Medium | GitHub Actions analysis |
| README mentions "deprecated" | Low | Text analysis |

**New Fields on Repository Model:**
```python
class Repository(Base):
    # Existing fields...
    
    # Abandonment Risk Analysis
    abandonment_score = Column(Integer, default=0)  # 0-100
    abandonment_reasons = Column(JSONB)  # Array of risk factors
    last_pr_at = Column(DateTime)
    last_release_at = Column(DateTime)
    active_contributors_30d = Column(Integer, default=0)
    active_contributors_365d = Column(Integer, default=0)
    ci_last_run_at = Column(DateTime)
    is_deprecated = Column(Boolean, default=False)
    deprecated_reason = Column(Text)
    
    # Legacy Tech Detection
    legacy_technologies = Column(JSONB)  # [{"tech": "Python 2.7", "risk": "high"}]
    tech_debt_score = Column(Integer, default=0)
```

**AI Agent Task:**
```yaml
Task: Abandonment Analysis Agent
Inputs:
  - Repository metadata (pushed_at, is_archived, contributors)
  - Commit history patterns
  - Dependency versions vs latest
  - CI/CD activity
  
Outputs:
  - abandonment_score (0-100)
  - abandonment_reasons (structured list)
  - recommended_action (archive, transfer, remediate, maintain)
  - security_risk_summary (what an attacker could exploit)
```

---

### 3. 👥 Business Unit Mapping & Contributor Attribution

**Goal:** Map attack surface to organizational structure, identify ownership gaps.

#### 3.1 Business Unit Attribution

| Data Point | Source | Use Case |
|------------|--------|----------|
| Team ownership | GitHub Teams API, CODEOWNERS | Route findings to right team |
| Cost center | Entra ID (department) | Budget allocation for fixes |
| Application tier | Business criticality tags | Prioritize critical apps |
| Regulatory scope | Repo topics, metadata | Compliance filtering |

**New Data Models:**
```sql
CREATE TABLE business_units (
    id UUID PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    parent_id UUID REFERENCES business_units(id),
    cost_center VARCHAR(50),
    entra_group_id VARCHAR(100),  -- Azure AD group
    owner_email VARCHAR(200),
    security_contact_email VARCHAR(200),
    criticality_tier VARCHAR(20),  -- 'tier1', 'tier2', 'tier3'
    regulatory_requirements JSONB,  -- ['pci-dss', 'hipaa', 'soc2']
    created_at TIMESTAMP
);

CREATE TABLE repository_ownership (
    id UUID PRIMARY KEY,
    repository_id UUID REFERENCES repositories(id),
    business_unit_id UUID REFERENCES business_units(id),
    ownership_type VARCHAR(50),  -- 'primary', 'contributing', 'legacy'
    codeowners_path TEXT,
    github_team_slug VARCHAR(200),
    last_verified_at TIMESTAMP
);
```

#### 3.2 Contributor Identity Mapping

**Goal:** Map contributors to corporate identity, detect access risks.

| Scenario | Risk Level | Detection Method |
|----------|------------|------------------|
| Contributor left company | 🔴 Critical | Entra ID status check |
| Using personal email | 🟡 Medium | Email domain analysis |
| Multiple GitHub accounts | 🟡 Medium | Commit email analysis |
| No MFA on GitHub | 🔴 Critical | GitHub API (if available) |
| External contractor | 🟡 Medium | Email/Entra ID flags |
| Admin with no recent commits | 🟡 Medium | Permission vs activity |

**Enhanced Contributor Model:**
```python
class Contributor(Base):
    # Existing fields...
    
    # Identity Mapping
    entra_id = Column(String)  # Azure AD Object ID
    entra_upn = Column(String)  # user@company.com
    entra_status = Column(String)  # 'active', 'disabled', 'deleted'
    entra_department = Column(String)
    entra_job_title = Column(String)
    entra_manager_upn = Column(String)
    entra_last_sync = Column(DateTime)
    
    # Access Risk Analysis
    is_external = Column(Boolean, default=False)
    using_personal_email = Column(Boolean, default=False)
    alternate_emails = Column(JSONB)  # Other emails seen in commits
    github_accounts = Column(JSONB)  # Multiple accounts detected
    access_risk_score = Column(Integer, default=0)
    access_risk_reasons = Column(JSONB)
    
    # Still with company?
    is_active_employee = Column(Boolean)
    employment_verified_at = Column(DateTime)
    
class ContributorAccess(Base):
    """Track what repos each contributor can access."""
    __tablename__ = "contributor_access"
    
    id = Column(UUID)
    contributor_id = Column(UUID, ForeignKey("contributors.id"))
    repository_id = Column(UUID, ForeignKey("repositories.id"))
    permission_level = Column(String)  # 'admin', 'write', 'read'
    granted_via = Column(String)  # 'direct', 'team', 'org_default'
    last_activity_at = Column(DateTime)
    is_current = Column(Boolean)  # Still has access?
```

---

### 4. 📊 Full Asset Spectrum Discovery

**Goal:** Discover 100+ asset types that attackers target.

#### 4.1 Asset Type Taxonomy

| Category | Asset Types | Detection Method |
|----------|-------------|------------------|
| **Network** | IPs, hostnames, domains, subdomains | Code/config analysis, DNS |
| **Cloud** | S3 buckets, Azure blobs, VMs, functions | IaC scanning, cloud APIs |
| **Identity** | Service accounts, API keys, certificates | Secrets scanning |
| **Data** | Databases, data lakes, PII locations | Connection strings, schema files |
| **API** | REST, GraphQL, gRPC, webhooks | Spec files, code analysis |
| **Infrastructure** | Kubernetes, Docker, VMs | IaC, container analysis |
| **Third-Party** | SaaS integrations, OAuth apps | Config files, API calls |
| **Code** | Packages, libraries, frameworks | SBOM, dependency analysis |
| **Documentation** | README, wiki, API docs | Text analysis for secrets |
| **CI/CD** | Pipelines, secrets, artifacts | GitHub Actions analysis |

**Universal Asset Model:**
```sql
CREATE TABLE assets (
    id UUID PRIMARY KEY,
    repository_id UUID REFERENCES repositories(id),
    
    -- Asset Classification
    asset_category VARCHAR(50) NOT NULL,  -- 'network', 'cloud', 'identity', etc.
    asset_type VARCHAR(100) NOT NULL,  -- 'ip_address', 's3_bucket', 'api_key'
    asset_subtype VARCHAR(100),  -- More specific classification
    
    -- Asset Details
    asset_value TEXT NOT NULL,  -- The actual value (IP, hostname, key prefix)
    asset_name VARCHAR(200),  -- Human-readable name
    asset_description TEXT,
    
    -- Source Information
    source_scanner VARCHAR(50),
    source_file TEXT,
    source_line INTEGER,
    discovery_method VARCHAR(50),  -- 'static_scan', 'api_enrichment', 'manual'
    
    -- Context
    environment VARCHAR(20),
    business_unit_id UUID REFERENCES business_units(id),
    owner_email VARCHAR(200),
    
    -- Risk Assessment
    exposure_level VARCHAR(20),  -- 'public', 'internal', 'private'
    risk_score INTEGER,
    risk_factors JSONB,
    
    -- Enrichment Data
    enrichment_data JSONB,  -- Data from external sources
    enrichment_sources JSONB,  -- ['shodan', 'dns', 'virustotal']
    last_enriched_at TIMESTAMP,
    
    -- Lifecycle
    first_seen_at TIMESTAMP,
    last_seen_at TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    remediation_status VARCHAR(20),
    
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE INDEX idx_assets_category ON assets(asset_category);
CREATE INDEX idx_assets_type ON assets(asset_type);
CREATE INDEX idx_assets_risk ON assets(risk_score DESC);
CREATE INDEX idx_assets_repo ON assets(repository_id);
```

---

### 5. 🤖 AI Agent Architecture

**Goal:** Leverage AI agents for automated analysis, enrichment, and risk scoring.

#### 5.1 Agent Definitions

```yaml
agents:
  
  # Asset Discovery Agent
  - name: AssetDiscoveryAgent
    trigger: on_scan_complete
    capabilities:
      - Parse scan results for asset indicators
      - Classify assets by type and category
      - Deduplicate and normalize asset data
      - Calculate initial risk scores
    tools:
      - code_parser
      - regex_extractor
      - asset_classifier
    output: assets table entries
    
  # Abandonment Analyst Agent
  - name: AbandonmentAnalystAgent
    trigger: weekly_schedule
    capabilities:
      - Analyze repository activity patterns
      - Compare dependency versions to latest
      - Identify legacy technologies
      - Score abandonment risk
    tools:
      - github_api
      - dependency_version_checker
      - language_version_detector
    output:
      - abandonment_score
      - abandonment_reasons
      - recommended_actions
      
  # Contributor Risk Agent
  - name: ContributorRiskAgent
    trigger: on_entra_sync
    capabilities:
      - Map GitHub contributors to Entra ID identities
      - Detect departed employees with repo access
      - Identify external/contractor contributors
      - Analyze access patterns
    tools:
      - entra_id_client
      - github_team_api
      - email_domain_checker
    output:
      - contributor enrichment
      - access risk alerts
      
  # Attack Surface Prioritization Agent
  - name: AttackSurfacePrioritizer
    trigger: on_demand, daily_schedule
    capabilities:
      - Aggregate risk scores across all dimensions
      - Identify highest-risk attack paths
      - Generate executive summaries
      - Recommend remediation priorities
    tools:
      - database_query
      - risk_calculator
      - report_generator
    output:
      - Attack Surface Report
      - Priority remediation list
      - Risk trend analysis
      
  # API Security Analyst Agent
  - name: APISecurityAnalyst
    trigger: on_api_spec_discovered
    capabilities:
      - Parse OpenAPI/GraphQL specs
      - Identify missing auth requirements
      - Detect overly permissive endpoints
      - Check for sensitive data exposure
    tools:
      - openapi_parser
      - graphql_analyzer
      - auth_pattern_detector
    output:
      - API endpoint inventory
      - Auth gap analysis
      - Sensitive data exposure risks
```

#### 5.2 Enrichment Sources Integration

```yaml
enrichment_sources:

  # Identity Provider (Entra ID / Azure AD)
  entra_id:
    endpoint: Microsoft Graph API
    data_points:
      - User status (active/disabled)
      - Department, job title, manager
      - Group memberships
      - Last sign-in date
      - MFA status
    sync_frequency: daily
    
  # DNS/Domain Intelligence
  dns:
    providers: [builtin, securitytrails]
    data_points:
      - A/AAAA records
      - MX, TXT records
      - Subdomain enumeration
      - Historical DNS
    
  # IP Intelligence
  ip_reputation:
    providers: [shodan, virustotal, abuseipdb]
    data_points:
      - Open ports
      - Services running
      - Known vulnerabilities
      - Reputation score
      - Geolocation
      
  # Package Intelligence
  package_intel:
    providers: [osv, snyk, github_advisory]
    data_points:
      - Known vulnerabilities
      - Maintainer status
      - Popularity metrics
      - Supply chain risks
      
  # Cloud Intelligence
  cloud:
    providers: [aws_sdk, azure_sdk, gcp_sdk]
    data_points:
      - Resource exposure (public buckets)
      - IAM misconfigurations
      - Network security groups
      - Encryption status
```

---

### 6. 📈 Attack Surface Dashboard

**Goal:** Provide intuitive visibility into attack surface for security analysts.

#### 6.1 Dashboard Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  🎯 ATTACK SURFACE OVERVIEW                                    [Last 24h] ▼ │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   1,855     │  │    5,455    │  │   12,847    │  │     847     │    │
│  │ Repositories │  │  Findings   │  │   Assets    │  │ Contributors│    │
│  │  ▲ 12 new   │  │  ▼ 45 fixed │  │  ▲ 234 new  │  │  ⚠ 23 risk  │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  🔴 HIGH PRIORITY ATTACK SURFACE                                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 🏚️ ABANDONED SYSTEMS (23 repos)                                      │   │
│  │ ├─ legacy-payment-api    │ Score: 95 │ Last commit: 3y │ 12 vulns │   │
│  │ ├─ old-customer-portal   │ Score: 88 │ Archived       │ 8 vulns  │   │
│  │ └─ deprecated-auth-svc   │ Score: 82 │ Single contrib │ 15 vulns │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 👤 DEPARTED CONTRIBUTORS WITH ACCESS (8 people)                      │   │
│  │ ├─ john.doe@company.com  │ Left: 6mo ago │ 12 repos │ Admin access │   │
│  │ ├─ jane.smith@...        │ Left: 2mo ago │ 5 repos  │ Write access │   │
│  │ └─ contractor@external   │ Contract end  │ 3 repos  │ Write access │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 🌐 PUBLIC EXPOSURE RISKS (15 findings)                               │   │
│  │ ├─ api-gateway          │ Public API │ No auth on /health endpoint  │   │
│  │ ├─ cdn-assets           │ S3 bucket  │ Public read enabled          │   │
│  │ └─ docs-portal          │ Hostname   │ Exposed internal docs        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  📊 ASSET DISTRIBUTION                    │  📈 RISK TREND (30 days)       │
│  ┌─────────────────────────────────────┐  │  ┌────────────────────────────┐ │
│  │ Network Assets    ████████░░ 2,340 │  │  │     ╭──╮                   │ │
│  │ Cloud Resources   ██████░░░░ 1,567 │  │  │    ╭╯  ╰╮   ╭──╮          │ │
│  │ API Endpoints     █████░░░░░ 1,234 │  │  │ ──╯      ╰──╯   ╰─────    │ │
│  │ Secrets/Keys      ████░░░░░░   888 │  │  │ Nov 7        Nov 22  Dec 7 │ │
│  │ Dependencies      ████████████ 5.2k│  │  └────────────────────────────┘ │
│  └─────────────────────────────────────┘  │                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### 7. 🔌 API Enhancements

**Goal:** Expose attack surface data via API for integration and automation.

#### 7.1 New API Endpoints

```yaml
# Attack Surface Summary
GET /api/attack-surface/summary
  - Total assets by category
  - Risk distribution
  - Trend data

# Abandoned Systems
GET /api/attack-surface/abandoned
  - List of repos with high abandonment scores
  - Filtering by score threshold, age
  - Includes contributors and findings

# Contributor Risk
GET /api/attack-surface/contributor-risks
  - Departed employees with access
  - External contractors
  - Access risk scores

# Asset Inventory
GET /api/assets
GET /api/assets/{asset_id}
GET /api/assets/by-type/{asset_type}
GET /api/assets/by-repo/{repo_id}
  - Full asset inventory
  - Filtering, pagination, enrichment data

# Business Unit View
GET /api/business-units
GET /api/business-units/{id}/attack-surface
  - Attack surface scoped to business unit
  - Ownership data

# AI Agent Endpoints
POST /api/agents/abandonment-analysis/run
POST /api/agents/contributor-sync/run
POST /api/agents/asset-discovery/run
GET /api/agents/runs/{run_id}/status
```

---

### 8. 📋 Implementation Phases

#### Phase 1: Foundation (Weeks 1-2)
- [ ] Create new database tables (assets, business_units, repository_ownership)
- [ ] Extend contributor model with Entra ID fields
- [ ] Add abandonment scoring fields to repository model
- [ ] Create basic API endpoints

#### Phase 2: Asset Discovery (Weeks 3-4)
- [ ] Implement API spec discovery scanner
- [ ] Implement infrastructure asset extraction
- [ ] Build asset classification system
- [ ] Create asset inventory API

#### Phase 3: Identity Integration (Weeks 5-6)
- [ ] Integrate Entra ID sync
- [ ] Implement contributor → identity mapping
- [ ] Build access risk scoring
- [ ] Create departed employee detection

#### Phase 4: AI Agents (Weeks 7-8)
- [ ] Implement AbandonmentAnalystAgent
- [ ] Implement ContributorRiskAgent
- [ ] Implement APISecurityAnalyst
- [ ] Create agent orchestration framework

#### Phase 5: Dashboard & Reporting (Weeks 9-10)
- [ ] Build Attack Surface Dashboard
- [ ] Create executive reporting
- [ ] Implement trend analysis
- [ ] Add alerting for high-risk changes

---

### 9. 🚀 Quick Wins (Implementable Now)

These can be implemented with existing data:

| Enhancement | Data Available | Effort |
|-------------|----------------|--------|
| Abandoned repo detection | pushed_at, is_archived, contributors | Low |
| Public repo exposure alert | visibility field | Low |
| Stale contributor identification | last_commit_at from contributors | Low |
| Dependency age analysis | SBOM + package registry APIs | Medium |
| API spec extraction | File pattern scanning | Medium |
| Hardcoded IP/hostname report | Existing semgrep rules | Low |

---

## Summary

This proposal transforms AuditGH from a vulnerability scanner into a comprehensive Attack Surface Management platform by:

1. **Expanding asset discovery** beyond code vulnerabilities to 100+ asset types
2. **Mapping to organization structure** via business units and contributor attribution
3. **Detecting abandoned systems** that attackers love to target
4. **Integrating identity context** from Entra ID for access risk analysis
5. **Powering everything with AI agents** for automated analysis and enrichment

The result: Security analysts gain real-world visibility into what attackers see and can prioritize remediation based on actual exposure risk.
