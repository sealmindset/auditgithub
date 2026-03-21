# OSINT (Open Source Intelligence) in AuditGH

## Overview

AuditGH's OSINT capability is a critical component of the AI Credential URL Agent that gathers intelligence from public sources to understand how APIs are used and authenticated. The key insight is that by analyzing how **other developers and companies** authenticate to the same services, we can learn the correct authentication patterns to use with discovered credentials.

## Why OSINT Matters for Credential Testing

When testing discovered credentials against API endpoints, the biggest challenge is knowing **how** to authenticate. Different services use different authentication methods:

- Some use `Authorization: Bearer {token}`
- Some use `X-API-Key: {key}`
- Some use `Ocp-Apim-Subscription-Key: {key}` (Azure)
- Some use Basic Auth with the token as username
- Some require specific headers or request body formats

**OSINT solves this problem** by finding real-world examples of how others authenticate to the same services.

## OSINT Sources

### 1. Public GitHub Code Search

The primary OSINT source is GitHub's code search API, which searches **all public repositories** on GitHub.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PUBLIC GITHUB CODE SEARCH                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Target: https://prod-apps-svc.sleepiq.example-org.com/rest/api/v1          │
│                                                                             │
│  Search Queries Generated:                                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 1. "prod-apps-svc.sleepiq.example-org.com" NOT org:example-orglabs  │   │
│  │ 2. "sleepiq" api NOT org:example-orglabs                            │   │
│  │ 3. "example-org" api NOT org:example-orglabs                        │   │
│  │ 4. "Ocp-Apim-Subscription-Key" NOT org:example-orglabs              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Key: "NOT org:{current_org}" ensures we search EXTERNAL public repos      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Why External Repos Matter

- **Internal repos** show how YOUR organization uses the API (already known)
- **External repos** show how OTHER developers/companies authenticate to the same service
- External patterns are more valuable because they reveal working authentication methods

### 2. API Documentation Search

The agent also searches for official API documentation:

- Swagger/OpenAPI specifications
- Developer documentation pages
- API reference guides
- Authentication guides

### 3. Service-Specific Patterns

Built-in knowledge of common service authentication patterns:

| Service | Auth Header | Format |
|---------|-------------|--------|
| Azure API Management | `Ocp-Apim-Subscription-Key` | Raw key |
| AWS Cognito | `X-Amz-Target` + JSON body | Cognito InitiateAuth |
| Stripe | `Authorization` | `Bearer sk_...` |
| GitHub | `Authorization` | `Bearer ghp_...` |
| OpenAI | `Authorization` | `Bearer sk-...` |
| Mixpanel | `Authorization` | `Basic {base64(token:)}` |
| Firebase/FCM | `Authorization` | `key={server_key}` |
| Slack | `Authorization` | `Bearer xoxb-...` |

## OSINT Workflow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           OSINT WORKFLOW                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐                                                          │
│  │ Target URL   │                                                          │
│  │ + Credential │                                                          │
│  └──────┬───────┘                                                          │
│         │                                                                   │
│         ▼                                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ STEP 1: GATHER OSINT                                                 │  │
│  │                                                                      │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐      │  │
│  │  │ GitHub Search   │  │ Doc Search      │  │ Service Detect  │      │  │
│  │  │ (Public Repos)  │  │ (API Docs)      │  │ (Patterns)      │      │  │
│  │  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘      │  │
│  │           │                    │                    │               │  │
│  │           └────────────────────┼────────────────────┘               │  │
│  │                                │                                    │  │
│  │                                ▼                                    │  │
│  │                    ┌───────────────────────┐                        │  │
│  │                    │ OSINT Findings        │                        │  │
│  │                    │ - External repos      │                        │  │
│  │                    │ - Auth patterns       │                        │  │
│  │                    │ - API endpoints       │                        │  │
│  │                    │ - Code snippets       │                        │  │
│  │                    └───────────┬───────────┘                        │  │
│  └────────────────────────────────┼─────────────────────────────────────┘  │
│                                   │                                        │
│                                   ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ STEP 2: LEARN FROM OSINT                                             │  │
│  │                                                                      │  │
│  │  Extract authentication patterns from discovered code:               │  │
│  │  - Header names (Authorization, X-API-Key, etc.)                    │  │
│  │  - Header formats (Bearer, Basic, raw)                              │  │
│  │  - Request methods (GET, POST)                                      │  │
│  │  - Body formats (JSON, form-encoded)                                │  │
│  │                                                                      │  │
│  └────────────────────────────────┬─────────────────────────────────────┘  │
│                                   │                                        │
│                                   ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ STEP 3: BUILD AUTH REQUESTS                                          │  │
│  │                                                                      │  │
│  │  Use learned patterns to construct authentication requests:          │  │
│  │  - Apply discovered headers                                         │  │
│  │  - Use correct auth format                                          │  │
│  │  - Try discovered API paths                                         │  │
│  │                                                                      │  │
│  └────────────────────────────────┬─────────────────────────────────────┘  │
│                                   │                                        │
│                                   ▼                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ STEP 4: TEST CREDENTIAL                                              │  │
│  │                                                                      │  │
│  │  Test the credential using learned auth patterns                     │  │
│  │  - Primary method from OSINT                                        │  │
│  │  - Fallback to service-specific patterns                            │  │
│  │  - Try intelligent combinations                                     │  │
│  │                                                                      │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Auth Pattern Extraction

When OSINT finds code in external repos, it analyzes the code to extract authentication patterns.

### Detected Header Patterns

```python
# Headers the OSINT engine looks for:
auth_header_patterns = [
    'Authorization: Bearer',    # Bearer token auth
    'Authorization: Basic',     # Basic auth
    'Authorization',            # Generic auth header
    'X-API-Key',               # API key header
    'X-Api-Key',               # Alternative casing
    'api-key',                 # Lowercase variant
    'apikey',                  # No separator
    'Ocp-Apim-Subscription-Key', # Azure APIM
    'X-Auth-Token',            # Auth token
    'X-Access-Token',          # Access token
    'token',                   # Generic token
    'access_token',            # OAuth style
    'X-Subscription-Key',      # Subscription key
]
```

### Detected Auth Methods

```python
# Methods/patterns the OSINT engine recognizes:
method_patterns = [
    'Bearer token',            # Bearer {token}
    'Basic auth',              # Basic {base64}
    'setRequestHeader',        # JavaScript XHR
    'headers dict',            # Python dict style
    'header method',           # Method chaining
    'fetch with headers',      # JavaScript fetch
    'axios with headers',      # Axios library
    'requests with headers',   # Python requests
]
```

### Code Snippet Extraction

The OSINT engine extracts code snippets showing how authentication is performed:

```javascript
// Example snippet extracted from external repo:
fetch('https://api.example.com/v1/data', {
    headers: {
        'Authorization': 'Bearer ' + apiKey,
        'Content-Type': 'application/json'
    }
})
```

## OSINT Findings Structure

### External Auth Patterns (Highest Value)

```json
{
    "type": "External_Auth_Patterns",
    "description": "Auth patterns from 5 external PUBLIC repos",
    "relevance": 99,
    "discovered_headers": [
        "Authorization: Bearer",
        "X-API-Key",
        "Ocp-Apim-Subscription-Key"
    ],
    "discovered_methods": [
        "Bearer token",
        "fetch with headers"
    ],
    "source_repos": [
        "company-a/api-client",
        "developer-b/integration",
        "org-c/sdk"
    ],
    "details": [
        {
            "repo": "company-a/api-client",
            "headers": ["Authorization: Bearer"],
            "methods": ["fetch with headers"],
            "snippets": ["headers: { 'Authorization': 'Bearer ' + token }"]
        }
    ]
}
```

### External API Usage Summary

```json
{
    "type": "External_API_Usage_Summary",
    "description": "3 external PUBLIC repos accessing this API",
    "relevance": 95,
    "repos": [
        {
            "repo_name": "company-a/api-client",
            "file_path": "src/api.js",
            "url": "https://github.com/company-a/api-client/blob/main/src/api.js",
            "api_endpoints": [
                {
                    "url": "https://api.example.com/v1/users",
                    "type": "full_url",
                    "context": "Found in external public repo"
                }
            ]
        }
    ]
}
```

### GitHub Repository Finding

```json
{
    "type": "GitHub_External",
    "description": "Found in company-a/api-client",
    "relevance": 75,
    "url": "https://github.com/company-a/api-client/blob/main/src/api.js",
    "file_path": "src/api.js",
    "repo_name": "company-a/api-client",
    "is_internal": false,
    "api_endpoints_found": [...]
}
```

## Search Query Construction

### Domain-Based Queries

```python
# Extract service identifiers from domain
domain = "prod-apps-svc.sleepiq.example-org.com"
domain_parts = domain.split('.')
# Result: ['prod-apps-svc', 'sleepiq', 'example-org', 'com']

# Filter to meaningful identifiers (>3 chars, not common TLDs)
service_identifiers = ['sleepiq', 'example-org']

# Build queries
queries = [
    '"prod-apps-svc.sleepiq.example-org.com" NOT org:example-orglabs',
    '"sleepiq" api NOT org:example-orglabs',
    '"example-org" api NOT org:example-orglabs'
]
```

### Credential-Type Specific Queries

```python
# Based on credential type, add service-specific searches
if 'azure' in credential_type or 'azure' in domain:
    queries.append('"Ocp-Apim-Subscription-Key" NOT org:{org}')
    queries.append('"azure-api.net" NOT org:{org}')

elif 'cognito' in credential_type:
    queries.append('"cognito-idp" "InitiateAuth" NOT org:{org}')

elif 'stripe' in credential_type:
    queries.append('"api.stripe.com" NOT org:{org}')

elif 'mixpanel' in credential_type:
    queries.append('"mixpanel.com" Authorization NOT org:{org}')
```

## Integration with Credential Testing

### Using OSINT-Learned Patterns

```python
# After gathering OSINT, the agent uses learned patterns:

async def _try_learned_auth(self, learned_patterns):
    """
    Try authentication using patterns learned from OSINT.
    
    This is the OSINT-first approach - we use what we learned
    from analyzing how OTHERS authenticate to this service.
    """
    headers = {}
    
    # Apply discovered headers
    for header in learned_patterns.get('discovered_headers', []):
        if 'Bearer' in header:
            headers['Authorization'] = f'Bearer {self.credential_value}'
        elif 'Basic' in header:
            headers['Authorization'] = f'Basic {base64_encode(self.credential_value)}'
        elif header in ['X-API-Key', 'X-Api-Key', 'api-key']:
            headers[header] = self.credential_value
        elif header == 'Ocp-Apim-Subscription-Key':
            headers[header] = self.credential_value
    
    # Make request with learned auth
    response = await self._make_request(self.target_url, headers=headers)
    
    return response
```

### Fallback Chain

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        AUTH METHOD PRIORITY                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. OSINT-Learned Patterns (highest confidence)                            │
│     └── Auth headers discovered from external public repos                 │
│                                                                             │
│  2. Service-Specific Patterns (high confidence)                            │
│     └── Built-in knowledge of Azure, AWS, Stripe, etc.                     │
│                                                                             │
│  3. Credential-Type Heuristics (medium confidence)                         │
│     └── Infer auth method from credential format                           │
│                                                                             │
│  4. Intelligent Combination Testing (low confidence)                       │
│     └── Try multiple auth methods systematically                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Configuration

### Required Environment Variables

```bash
# GitHub token for code search API
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Optional: Specify organization to exclude from search
# (Auto-detected from token if not specified)
GITHUB_ORG=example-orglabs
```

### Rate Limiting

The OSINT engine respects GitHub API rate limits:

- **Authenticated requests**: 30 requests/minute for code search
- **Sleep between queries**: 1 second between search requests
- **Query limit**: Maximum 4-6 queries per OSINT gathering session

## Viewing OSINT Results

### In the UI

OSINT findings appear in the Credential URL Test Results:

1. Navigate to **API Audit** for a project
2. Run a credential-URL test
3. View the **OSINT Findings** section in the results

### In API Response

```json
{
    "osint_findings": [
        {
            "type": "External_Auth_Patterns",
            "description": "Auth patterns from 3 external PUBLIC repos",
            "relevance": 99,
            "discovered_headers": ["Authorization: Bearer", "X-API-Key"]
        },
        {
            "type": "External_API_Usage_Summary",
            "description": "5 external PUBLIC repos accessing this API",
            "relevance": 95,
            "repos": [...]
        },
        {
            "type": "GitHub_External",
            "description": "Found in company/repo",
            "relevance": 75,
            "url": "https://github.com/..."
        }
    ],
    "github_repos_found": 8,
    "documentation_links_found": 2
}
```

### In Logs

```
INFO - Gathering OSINT for https://api.example.com (searching PUBLIC GitHub)
INFO - OSINT search queries (targeting PUBLIC repos): ['"api.example.com" NOT org:myorg', ...]
INFO - OSINT: Found 5 EXTERNAL public repos, 2 internal repos
INFO - OSINT: Found auth patterns in company/repo: ['Authorization: Bearer', 'X-API-Key']
INFO - OSINT GOLD: Found auth patterns from external repos: ['Authorization: Bearer', 'X-API-Key']
INFO - Found 12 OSINT sources (7 GitHub repos, 5 external)
```

## Security Considerations

### What OSINT Does NOT Do

- **Does not access private repos** - Only searches public GitHub
- **Does not store external code** - Only extracts patterns and snippets
- **Does not leak credentials** - Credentials are only used for testing, not sent to GitHub
- **Does not modify external repos** - Read-only operations

### What OSINT Reveals

- How other developers authenticate to the same services
- API endpoint paths used by others
- Authentication header names and formats
- Code patterns for API integration

### Privacy

- OSINT only searches **public** repositories
- No private or internal code is accessed
- GitHub's code search API enforces access controls

## Troubleshooting

### No OSINT Results

1. **Check GITHUB_TOKEN** - Token must have `public_repo` scope
2. **Check rate limits** - May be rate-limited by GitHub
3. **Check domain** - Domain may be too specific or unique

### Low-Quality Results

1. **Broaden search** - Try service identifiers instead of full domain
2. **Check credential type** - Ensure correct type for service-specific searches
3. **Manual search** - Try searching GitHub directly to verify results exist

### Auth Patterns Not Working

1. **Check OSINT findings** - Review discovered headers
2. **Try alternatives** - Use fallback auth methods
3. **Check service docs** - OSINT may have found outdated patterns

## Related Documentation

- [AI Agents](./AI_AGENTS.md) - Overview of AI agents including Credential URL Agent
- [Getting Started](./GETTING_STARTED.md) - Initial setup including GitHub token
- [Scheduler](./SCHEDULER.md) - Automated scanning that uses OSINT

## Code References

| File | Description |
|------|-------------|
| `execution/ai_credential_url_agent.py` | Main OSINT implementation |
| `gather_osint()` | Entry point for OSINT gathering |
| `_search_github()` | GitHub code search with public repo targeting |
| `_extract_api_endpoints_from_github_file()` | Endpoint and auth pattern extraction |
| `_extract_auth_headers_from_code()` | Auth header pattern detection |
| `_search_documentation()` | API documentation search |
