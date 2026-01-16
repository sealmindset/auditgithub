# AI Credential-URL Testing Implementation Spec

## Overview

This feature enables AI-powered automatic testing of discovered credentials against their mapped target URLs/API endpoints to determine if the credentials are valid and what access they provide.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Credential Testing Flow                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. Discovery Phase (Existing)                                       │
│     ├── Whispers/TruffleHog → Find credentials in code               │
│     ├── API Endpoint Scanner → Find URLs/endpoints                   │
│     └── AI Credential Matcher → Correlate credentials to URLs        │
│                                                                      │
│  2. Testing Phase (NEW)                                              │
│     ├── Test Request Generator → AI generates auth test requests     │
│     ├── Safe Executor → Rate-limited, sandboxed HTTP client          │
│     ├── Response Analyzer → AI analyzes responses for auth status    │
│     └── Path Discovery → Enumerate accessible paths with credential  │
│                                                                      │
│  3. Reporting Phase (NEW)                                            │
│     ├── Store results in credential_url_test_results table           │
│     ├── AI Risk Assessment → Evaluate exposure severity              │
│     └── UI Display → Show test results with recommendations          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Credential Test Engine (`execution/credential_tester.py`)

```python
class CredentialTester:
    """
    Safe credential testing engine with rate limiting and sandboxing.
    """
    
    def __init__(self, config: TestConfig):
        self.rate_limiter = RateLimiter(max_requests_per_minute=10)
        self.timeout = 10  # seconds
        self.max_redirects = 3
        self.user_agent = "AuditGH-Security-Scanner/1.0"
    
    async def test_credential(
        self,
        credential: DiscoveredCredential,
        target_url: str,
        test_mode: str = "passive"  # passive, active, aggressive
    ) -> TestResult:
        """
        Test a credential against a target URL.
        
        Modes:
        - passive: Only test authentication, no data access
        - active: Test auth + enumerate accessible paths
        - aggressive: Full path discovery + sample data retrieval
        """
        pass
```

### 2. AI Test Generator (`execution/ai_test_generator.py`)

```python
class AITestGenerator:
    """
    Uses LLM to generate appropriate authentication test requests.
    """
    
    async def generate_test_request(
        self,
        credential_type: str,
        credential_value: str,
        target_url: str,
        context: dict
    ) -> TestRequest:
        """
        Generate an appropriate test request based on credential type.
        
        Examples:
        - API Key → Header: X-API-Key or Authorization: ApiKey
        - Bearer Token → Header: Authorization: Bearer
        - Basic Auth → Header: Authorization: Basic base64(user:pass)
        - OAuth → Token endpoint + Bearer
        """
        pass
```

### 3. Response Analyzer (`execution/response_analyzer.py`)

```python
class ResponseAnalyzer:
    """
    AI-powered analysis of HTTP responses to determine auth status.
    """
    
    async def analyze_response(
        self,
        response: HTTPResponse,
        credential_type: str
    ) -> AuthAnalysis:
        """
        Analyze response to determine:
        - auth_status: authenticated, denied, expired, invalid, rate_limited
        - confidence: 0-100
        - discovered_permissions: list of accessible resources
        - data_sensitivity: low, medium, high, critical
        """
        pass
```

## Database Schema (Existing)

The `credential_url_test_results` table already exists with appropriate columns:

| Column | Type | Description |
|--------|------|-------------|
| id | uuid | Primary key |
| organization_id | uuid | FK to organizations |
| repository_id | uuid | FK to repositories |
| target_url | text | URL that was tested |
| credential_type | varchar | Type of credential (api_key, bearer, etc.) |
| credential_value | text | Masked credential value |
| auth_status | varchar | authenticated, denied, expired, etc. |
| auth_status_code | int | HTTP status code |
| discovered_paths | jsonb | Accessible paths found |
| ai_risk_assessment | text | AI-generated risk analysis |
| threat_level | varchar | low, medium, high, critical |
| tested_at | timestamp | When test was performed |

## API Endpoints

### New Endpoints

```
POST /projects/{id}/api-audit/test-credential
  - Trigger credential test for a specific credential-URL pair
  - Body: { credential_id, target_url, test_mode }
  - Returns: TestResult

POST /projects/{id}/api-audit/test-all-credentials
  - Trigger batch testing of all high-confidence correlations
  - Body: { test_mode, min_confidence }
  - Returns: BatchTestResult

GET /projects/{id}/api-audit/test-results
  - Get all test results for a project
  - Query: ?status=authenticated&threat_level=high

GET /projects/{id}/api-audit/test-results/{test_id}
  - Get detailed test result

DELETE /projects/{id}/api-audit/test-results/{test_id}
  - Delete a test result
```

## UI Components

### 1. Credential Test Panel (in projects/{id} page)

- List of credential-URL correlations with "Test" button
- Test status indicators (untested, testing, passed, failed)
- Batch test button for all correlations

### 2. Test Results View

- Table of test results with filtering
- Columns: URL, Credential Type, Status, Threat Level, Tested At
- Expandable rows showing full details

### 3. Test Result Detail Modal

- Full AI analysis
- Discovered paths
- Risk assessment
- Recommendations

## Safety Measures

1. **Rate Limiting**: Max 10 requests/minute per target domain
2. **Timeout**: 10 second timeout per request
3. **No Data Modification**: Only GET/HEAD requests in passive mode
4. **Credential Masking**: Never log full credential values
5. **User Consent**: Require explicit user action to trigger tests
6. **Audit Trail**: Log all test attempts

## Implementation Order

1. **Phase 3a**: Core test engine + passive testing
2. **Phase 3b**: AI test generator + response analyzer
3. **Phase 3c**: API endpoints + database integration
4. **Phase 3d**: UI components
5. **Phase 3e**: Active/aggressive modes + path discovery

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `execution/credential_tester.py` | CREATE | Core test engine |
| `execution/ai_test_generator.py` | CREATE | AI request generator |
| `execution/response_analyzer.py` | CREATE | AI response analyzer |
| `src/api/routers/api_audit.py` | MODIFY | Add test endpoints |
| `src/api/models.py` | VERIFY | Ensure model exists |
| `src/web-ui/app/projects/[id]/page.tsx` | MODIFY | Add test UI |
| `src/web-ui/components/CredentialTestPanel.tsx` | CREATE | Test panel component |
| `src/web-ui/components/TestResultsTable.tsx` | CREATE | Results table |
