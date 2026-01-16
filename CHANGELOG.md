# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Cribl Stream Log Management Integration** - Centralized log collection and forwarding
  - **Purpose**: Integrate with Cribl Stream for centralized log management, processing, and routing to SIEM/analytics platforms
  - **Architecture**:
    - Push-based ingestion model for real-time log forwarding
    - MinIO S3-compatible storage as fallback when Cribl is unavailable
    - Next.js API route proxy to keep auth tokens server-side
  - **New Docker Service**: `minio` container for S3-compatible log storage
    - Ports: 9000 (S3 API), 9001 (Console UI)
    - Volume: `minio-data` for persistent storage
    - Acts as collector source for Cribl Stream pull model
  - **Database**: New `cribl_config` table for configuration storage
    - Connection settings: ingest_url, auth_token, verify_ssl
    - Feature toggles: enabled, log_levels, include_app_context, include_security_audit
    - MinIO fallback settings: minio_endpoint, minio_bucket, access/secret keys
    - Test status tracking: last_test_at, last_test_status, last_test_message
  - **API Endpoints** (`/cribl`):
    - `GET /cribl/config` - Get current configuration
    - `POST /cribl/config` - Save/update configuration
    - `POST /cribl/test` - Test Cribl connection
    - `POST /cribl/test-minio` - Test MinIO connection
    - `GET /cribl/status` - Get logging status
    - `POST /cribl/toggle` - Enable/disable forwarding
    - `POST /cribl/forward` - Forward log entry (used by Next.js proxy)
  - **UI**: New "Cribl" tab in Settings > Configuration page
    - Cribl Stream configuration: Ingest URL, Auth Token, Verify SSL toggle
    - Log level selection: DEBUG, INFO, WARNING, ERROR, CRITICAL checkboxes
    - Content options: Include App Context, Include Security Audit toggles
    - MinIO fallback configuration: Endpoint, Bucket, Access/Secret keys
    - Test Configuration buttons for both Cribl and MinIO
    - Status badges and test result display
  - **Logging Implementation**: Loguru-based structured logging with HTTP transport
    - Background thread with queue for non-blocking log forwarding
    - Automatic batching (100 entries or 5 seconds)
    - Request-scoped context for org_id, user_id, request_id
    - Security audit logging with action, resource, outcome fields
    - MinIO fallback storage when Cribl is unreachable
  - **Log Format** (NDJSON):
    ```json
    {
      "timestamp": "2024-12-24T18:30:00.000Z",
      "level": "INFO",
      "message": "User authenticated",
      "source": "api",
      "host": "auditgh_api",
      "app_context": { "org_id": "...", "user_id": "...", "request_id": "..." },
      "security_audit": { "action": "authenticate", "resource": "user", "outcome": "success" }
    }
    ```
  - **Files Added**:
    - `migrations/013_cribl_config.sql` - Database migration
    - `src/api/routers/cribl.py` - API router
    - `src/api/utils/cribl_logger.py` - Loguru sink with HTTP transport
    - `src/web-ui/app/api/log/route.ts` - Next.js log forwarding proxy
    - `docs/CRIBL_INTEGRATION_SPEC.md` - Implementation specification
  - **Files Changed**:
    - `docker-compose.yml` - Added MinIO service and volume
    - `src/api/models.py` - Added CriblConfig model
    - `src/api/main.py` - Registered cribl router, added logger init/shutdown
    - `src/web-ui/app/settings/page.tsx` - Added Cribl configuration tab
    - `requirements.txt` - Added loguru and minio dependencies
  - **Environment Variables**:
    - `MINIO_ROOT_USER` - MinIO admin username (default: auditgh)
    - `MINIO_ROOT_PASSWORD` - MinIO admin password (default: auditgh_logs_2024)
  - **Documentation**: See `docs/CRIBL_INTEGRATION_SPEC.md` for full architecture and configuration details

### Changed

- **Scanner Separated into Dedicated Container** - Improved resource isolation between scanner and API
  - **Problem**: Scanner and API shared resources, causing memory spikes (6+ GB) during scans that affected API performance
  - **Solution**: Created dedicated `Dockerfile.scanner` and separated scanner into its own container
  - **New Architecture**:
    - `scanner` service: Heavy-weight container with all security tools, runs on-demand
    - `api` service: Lightweight container for serving the web API, runs continuously
    - Each service has independent resource limits (scanner: 8GB, API: 4GB)
  - **New Commands**:
    - `docker-compose run --rm scanner --target myorg` (replaces `docker-compose run --rm --entrypoint bash auditgh -c 'python3 scan_repos.py --target myorg'`)
    - `docker-compose run --rm scanner --dry-run` for preview
    - `docker-compose run --rm scanner --list-orgs` to list organizations
  - **Benefits**:
    - API remains responsive during scans
    - Scanner can use full system resources without impacting web users
    - Cleaner separation of concerns
    - Simplified command syntax
  - **Files Changed**:
    - `Dockerfile.scanner`: New dedicated Dockerfile for scanner (copied from original `Dockerfile`)
    - `docker-compose.yml`: Restructured with separate `scanner` and `api` services, added resource limits and healthchecks
    - `README.md`: Updated all scanner commands to use new syntax
  - **Resource Limits**:
    | Service | CPU Limit | Memory Limit | Memory Reserved |
    |---------|-----------|--------------|-----------------|
    | Scanner | 4 cores   | 8 GB         | 2 GB            |
    | API     | 2 cores   | 4 GB         | 512 MB          |
  - **New Volume Caches**: Added `trivy-cache` and `grype-cache` volumes for faster subsequent scans

### Fixed

- **Organization API Endpoints and Selector**
  - **Problem**: Organization selector was not displaying in UI, `/organizations/` returned empty array, and `/organizations/current` returned 500 errors. The `ai_org_agent` dependency was failing to initialize, breaking all organization-related endpoints.
  - **Root Cause**: 
    1. `is_active` and `is_default` columns in organizations table were NULL, causing filter `is_active == True` to exclude all orgs
    2. API endpoints relied on `ai_org_agent` which failed to initialize
    3. `OrganizationResponse` model expected fields (`schema_version`, `scan_status`, etc.) that don't exist in the database
    4. UI `Organization` interface expected fields the API no longer returns
  - **Solution**: 
    1. Refactored organization API endpoints to use direct database queries instead of failing agent
    2. Simplified `OrganizationResponse` model to match actual database schema
    3. Added computed fields (`total_repos`, `total_findings`) via COUNT queries
    4. Updated UI `Organization` interface to match simplified API response
    5. Fixed NULL values in organizations table (`is_active=true`, `is_default` set appropriately)
  - **Files Changed**:
    - `src/api/routers/organizations.py`: Refactored `list_organizations()`, `get_current_organization()`, `get_organization()`, `select_organization()` to use direct DB queries
    - `src/web-ui/components/OrganizationSelector.tsx`: Updated `Organization` interface, removed references to `scan_status` and `schema_sync_status`
    
- **Repository Count Discrepancy in Orchestrator**
  - **Problem**: Orchestrator filtered out forks and archived repositories which significantly reduced repository count (e.g., finding 165 instead of 479 repos).
  - **Solution**: Updated `orchestrate_scans.py` to include forks and archived repositories by default for comprehensive audits. Added `--no-forks` and `--no-archived` flags for optional exclusion.
  - **Files Changed**: `orchestrate_scans.py`

### Added
- **Multi-Org Token Support**: `orchestrate_scans.py` now implements dynamic token switching. It automatically detects and uses organization-specific tokens (e.g., `ORG_sleepnumberlabs_TOKEN` from `.env`) when scanning a target organization, overriding the default `GITHUB_TOKEN`. This ensures correct access permissions in multi-tenant environments.

- **DOE Self-Annealing for AI Model Configuration**
  - **Problem**: Claude API calls were failing with "model: llama3" errors when `AI_MODEL=llama3` was set in `.env` but `AI_PROVIDER=claude`, causing the wrong model to be sent to Anthropic's API.
  - **Solution**: Implemented DOE (Design of Experiments) self-annealing that detects and auto-corrects AI model misconfigurations at multiple levels:
    1. **Startup Validation** (`scan_repos.py`): `AIModelSelfAnnealing` class validates provider/model combinations at Config initialization
    2. **Provider Initialization** (`claude.py`): `ClaudeModelSelfAnnealing` validates model when `ClaudeProvider` is instantiated
    3. **Runtime Error Detection** (`claude.py`): `_call_api_with_retry()` detects model errors from API responses and auto-corrects with retry
  - **Detection Patterns**:
    - Claude provider with non-Claude model (llama3, gpt-4, mistral) → corrects to `claude-sonnet-4-20250514`
    - OpenAI provider with non-OpenAI model → corrects to `gpt-4o`
    - API error containing "model: llama3" or similar → triggers correction and retry
  - **Audit Trail**: All corrections are logged with timestamp, original model, corrected model, and reason
  - **Files Changed**:
    - `scan_repos.py`: Added `AIModelSelfAnnealing` class and integrated into `Config` initialization
    - `src/ai_agent/providers/claude.py`: Added `ClaudeModelSelfAnnealing` class and integrated into provider init and API retry logic

- **DOE Self-Annealing for NUL Character Sanitization**
  - **Problem**: Horusec and other scanners may produce JSON reports containing NUL (0x00) characters when scanning binary files or files with unusual encodings. These NUL characters cause PostgreSQL `ValueError: A string literal cannot contain NUL (0x00) characters` errors during ingestion.
  - **Solution**: Implemented DOE self-annealing at two levels for defense-in-depth:
    1. **Scan-Time Sanitization** (`scan_repos.py`): `sanitize_json_file()` function removes NUL characters from Horusec JSON output immediately after scanning, fixing the root cause
    2. **Ingestion-Time Fallback** (`ingest_scans.py`): `safe_json_load()` function detects and removes NUL characters when reading existing JSON reports, handling legacy reports
  - **Detection & Correction**:
    - Reads file in binary mode to detect NUL bytes
    - Counts and logs number of NUL characters found
    - Removes NUL characters and writes sanitized content back to file
    - Logs warning with file name and NUL count for audit trail
  - **Files Changed**:
    - `scan_repos.py`: Added `sanitize_json_file()` function, integrated into `run_horusec()` after scan completes
    - `ingest_scans.py`: Added `safe_json_load()` function, updated `ingest_horusec()` to use it; added `sanitize_string()` for field-level sanitization

- **DOE Self-Annealing for Organization Filtering in Scans**
  - **Problem**: Repos could be scanned or findings ingested without proper organization context, leading to data going to wrong org or missing org_id
  - **Solution**: Implemented DOE self-annealing for organization filtering at scan and ingestion time:
    1. **Scan Context Validation** (`scan_repos.py`): `OrgFilteringSelfAnnealing` validates target org, GitHub org, and org_id consistency before scanning
    2. **Ingestion Validation** (`ingest_scans.py`): `IngestionOrgSelfAnnealing` validates and corrects org_id for each repo during ingestion
  - **Detection & Correction**:
    - Missing org context → resolves from repo URL or database lookup
    - Org/repo URL mismatch → corrects org_id based on repo's actual GitHub org
    - org_id doesn't match target org → corrects to proper org_id
    - Fallback to default org when resolution fails (logged as anomaly)
  - **Audit Trail**: All corrections and anomalies logged with timestamp, type, and reason
  - **Files Changed**:
    - `scan_repos.py`: Added `OrgFilteringSelfAnnealing` class with `validate_scan_context()`, `correct_org_context()`, `validate_finding_org()`
    - `ingest_scans.py`: Added `IngestionOrgSelfAnnealing` class with `validate_and_correct_org()` integrated into `_ingest_single_project()`

- **Dashboard Organization Filtering**
  - **Problem**: Security Dashboard showed combined data from all organizations regardless of which org was selected
  - **Solution**: Implemented request-scoped organization context via middleware and query parameters
  - **Changes**:
    - `src/api/database.py`: Added `set_request_org_id()` and `get_request_org_id()` for request-scoped org context
    - `src/api/main.py`: Added `OrganizationContextMiddleware` that extracts org from `X-Organization-ID` header, `X-Organization-Name` header, or `org` query parameter
    - `src/api/routers/analytics.py`: Updated `apply_org_filter()` to use request-scoped org ID; added filtering to all dashboard endpoints (`/hero-metrics`, `/threat-radar`, `/ai-insights`, `/recent-findings`, `/executive-summary`)
    - `src/web-ui/app/page.tsx`: Updated dashboard to read `org` from URL params and pass to API calls

- **Removed All Credential Masking/Truncation**
  - **Problem**: Credential values were being masked or truncated (e.g., `3c924...`, `qtG7w...`, `b26ec87efcd44ebf9880...`) in API responses and database, making it impossible for security analysts to validate if credentials are active.
  - **Policy**: Per security policy, credentials should NOT be masked or truncated for security analyst validation.
  - **Files Fixed**:
    - `execution/ai_credential_matcher.py` - Removed `[:50]` and `[:30]` truncation in 4 places
    - `execution/credential_tester.py` - Removed `masked_value()` function, changed `credential_value_masked` to `credential_value`
    - `execution/ai_credential_url_agent.py` - Updated `_mask_credential()` to return full value
    - `summarize_gitleaks.py` - Removed `[:47]` truncation
    - `generate_secrets_report.py` - Removed `[:50]` truncation
    - `detailed_secrets_report.py` - Removed `[:100]` truncation
    - `analyze_secrets.py` - Removed `[:50]` truncation
    - `scan_repos.py` - Removed `[:10]` truncation in TruffleHog report
  - **Database Fix**: Created `fix_truncated_secrets.py` script to repair 681 existing truncated secrets in the database by re-reading from source whispers JSON files
  - **Result**: All credential values now display in full clear text in API responses, database, and reports

- **Multi-Org Report Directory Structure**
  - **Problem**: All vulnerability reports were stored in a flat directory (`vulnerability_reports/{repo_name}/`), mixing repos from different organizations.
  - **Solution**: Reports are now stored in org-specific subdirectories: `vulnerability_reports/{org_name}/{repo_name}/`
  - **Changes**:
    - `scan_repos.py`: When `--target ORG` is used, reports are saved to `vulnerability_reports/{org_name}/`
    - `ingest_scans.py`: Updated to support both flat and org-based directory structures
    - Ingestion auto-detects org directories and processes them with correct organization scoping
  - **Backward Compatible**: Existing flat structure still works; repos are matched to orgs via database lookup

- **Enhanced OSINT to Search PUBLIC GitHub Repos Outside Organization**
  - **Problem**: OSINT was limited to the organization's repos, missing valuable intelligence from public GitHub repos that use the same API services.
  - **Solution**: Enhanced GitHub code search to explicitly target PUBLIC repos OUTSIDE the organization using `NOT org:{current_org}` filter.
  - **Key Changes**:
    - Search queries now explicitly exclude the current org to find external usage patterns
    - Added service identifier extraction from domain (e.g., "sleepiq" from "prod-apps-svc.sleepiq.sleepnumber.com")
    - New `_extract_auth_headers_from_code()` function analyzes external code for auth patterns
    - Captures auth headers (Authorization, X-API-Key, Ocp-Apim-Subscription-Key, etc.)
    - Captures auth methods (Bearer token, Basic auth, fetch with headers, axios, requests)
    - Creates `External_Auth_Patterns` summary with discovered headers from external repos
  - **OSINT Value**: By analyzing how OTHER developers authenticate to the same services, we learn the correct auth patterns to use
  - **Files Changed**: `execution/ai_credential_url_agent.py`

- **URL Pre-Validation to Eliminate False Positives**
  - **Problem**: Credentials were being mapped to URLs like `https://www.sleepnumber.com` that don't require authentication, creating false positives and wasting time testing credentials against public endpoints.
  - **Solution**: Implemented URL pre-validation that tests each URL WITHOUT credentials first:
    1. **PUBLIC (200)**: URL returns success without auth → Skip, no credential needed
    2. **AUTH_REQUIRED (401/403)**: URL requires auth → Include in correlation
    3. **NOT_FOUND (404)**: Endpoint doesn't exist → Skip
    4. **ERROR**: Connection failed → Include for safety
  - **New Functions**:
    - `pre_validate_url()` - Tests single URL without credentials
    - `pre_validate_urls()` - Concurrent validation of multiple URLs
    - `correlate_credentials_to_urls_v2()` - New correlation with pre-validation
  - **Auth Hints**: Extracts hints from 401/403 responses:
    - `WWW-Authenticate` header
    - Response body keywords (api-key, bearer, subscription)
  - **Files Changed**: 
    - `execution/ai_credential_matcher.py`
    - `src/api/routers/api_audit.py`

- **OSINT-First Authentication Learning**
  - **Problem**: The agent was blindly trying predefined auth patterns without understanding how the API is actually used. For example, the SleepIQ API uses `access_token` as a query parameter, not a header.
  - **Solution**: Implemented an OSINT-first workflow that learns authentication patterns from discovered code:
    1. **Step 1: OSINT First** - Search GitHub for code using the target API
    2. **Step 2: Learn Auth Patterns** - Extract authentication patterns from discovered code:
       - Query parameter auth (e.g., `?access_token={{token}}`)
       - Header-based auth (Bearer, Basic, X-API-Key, Ocp-Apim-Subscription-Key)
       - Cookie-based auth
       - Body-based auth (username/password, client_id/secret)
    3. **Step 3: Build Request** - Construct HTTP request using learned patterns
    4. **Step 4: Test** - Execute request with learned auth method
    5. **Step 5: Fallback** - Try canonical endpoints if learned auth fails
  - **Example**: For `https://sleepiqapi.azure-api.net/prod/activities`:
    ```
    OSINT Found: danpenn/SleepIQ/insights.go
    Learned Pattern: query_param auth with access_token
    Code Example: url = "...?access_token={{token}}"
    Built Request: GET /prod/activities?access_token=<credential_value>
    ```
  - **New Methods Added**:
    - `_extract_auth_patterns_from_code()` - Analyzes code to find auth patterns
    - `learn_auth_from_osint()` - Aggregates patterns from all discovered repos
    - `build_request_from_learned_patterns()` - Constructs request using learned auth
  - **Files Changed**: `execution/ai_credential_url_agent.py`

- **Frontend Timeout Extended to 5 Minutes**
  - **Problem**: Frontend was timing out after 2 minutes while backend tests take 3+ minutes due to OSINT gathering and path discovery.
  - **Solution**: Increased `AbortController` timeout from 120000ms to 300000ms (5 minutes).
  - **Files Changed**: `src/web-ui/components/APIAuditView.tsx`

- **Credential Values Now Stored Unmasked in Test Results**
  - **Problem**: `[No credential stored]` was showing in request headers because credential values were being masked before storage.
  - **Solution**: Store actual credential value in `TestResult` instead of masked value. Security analysts need full unmasked values to validate findings.
  - **Files Changed**: `execution/ai_credential_url_agent.py`

- **AWS Cognito Auth Method Support**
  - **Problem**: `cognito_api` auth method was unknown, causing fallback to generic auth.
  - **Solution**: Added `cognito_api` case to `_get_headers()` with proper `X-Amz-Target` header for Cognito API calls.
  - **Files Changed**: `execution/ai_credential_url_agent.py`

- **Optimized Test Speed (3+ min → ~30 sec)**
  - **Problem**: Tests were taking 3+ minutes due to extensive path discovery (100 paths × 0.5-2s delays).
  - **Solution**: 
    - Reduced `COMMON_API_PATHS` from 60+ to 20 high-value security-relevant paths
    - Reduced max paths: cautious mode from 100 → 25
    - Reduced delays: cautious mode from 0.5-2.0s → 0.1-0.3s
  - **Files Changed**: `execution/ai_credential_url_agent.py`

- **Fixed API Endpoint Missing Credential Data**
  - **Problem**: The `credential-url-results/{id}` endpoint was missing `credential_value`, `auth_request_headers`, and other critical fields, causing `[No credential stored]` in the UI.
  - **Solution**: Added missing fields to the API response including `credential_value`, `auth_request_headers`, `auth_request_body`, `detected_service`, etc.
  - **Files Changed**: `src/api/routers/api_audit.py`

- **Enhanced OSINT Search with Credential-Type Patterns**
  - **Problem**: OSINT was only searching for the exact domain, which often returned 0 results for private APIs.
  - **Solution**: Added credential-type specific search patterns:
    - Azure: `"Ocp-Apim-Subscription-Key"`, `"azure-api.net"`
    - AWS Cognito: `"cognito-idp" "InitiateAuth"`
    - Stripe: `"api.stripe.com"`
    - GitHub: `"api.github.com" Authorization`
    - OpenAI: `"api.openai.com" Authorization`
    - Slack: `"slack.com/api" token`
  - **Files Changed**: `execution/ai_credential_url_agent.py`

- **Intelligent Auth Combination Testing**
  - **Feature**: New `try_intelligent_auth_combinations()` method that combines:
    1. **OSINT-learned patterns** - Headers/params discovered from code analysis
    2. **Discovered paths from fuzzing** - Non-404 endpoints found during path discovery
    3. **Service-specific auth methods** - Azure subscription keys, Bearer tokens, Basic auth, etc.
    4. **All available credentials** - Tests multiple credentials against multiple endpoints
  - **Flow**: After path discovery, if auth still fails, the agent tries all combinations:
    - Tests each credential against each discovered path
    - Uses service-specific header combinations (e.g., Azure uses `Ocp-Apim-Subscription-Key`)
    - Falls back to common auth patterns (Bearer, API-Key, Basic)
    - Stores all attempts for debugging and audit trail
  - **Files Changed**: `execution/ai_credential_url_agent.py`
  - **New Methods**:
    - `try_intelligent_auth_combinations()` - Main orchestration method
    - `_get_service_header_combinations()` - Service-specific header templates

### Fixed

- **CRITICAL: AI Credential-URL Matcher Now Uses Correct API Endpoints**
  - **Problem**: The AI matcher was incorrectly correlating credentials with unrelated URLs. For example, a `mixpanel_token` was being tested against `sleepnumber.com` instead of `api.mixpanel.com`.
  - **Root Cause**: When no matching URL was found in the codebase, the matcher defaulted to the first URL in the list (which could be completely unrelated).
  - **Solution**: Added `SERVICE_API_ENDPOINTS` mapping with canonical API URLs for each service type (Mixpanel, Stripe, Firebase, GitHub, OpenAI, etc.). The matcher now:
    1. Detects the service from the credential type
    2. Uses the canonical API endpoint for that service
    3. Only falls back to codebase URLs if they actually match the service
    4. Skips credentials that have no matching URL and no canonical endpoint
  - **Files Changed**: `execution/ai_credential_matcher.py`

- **AI Agent Now Tests Multiple Auth Combinations Against Canonical Endpoints**
  - **Problem**: The agent was only trying one authentication method, missing valid credentials that required different auth patterns (e.g., Mixpanel Service Account API uses Basic auth with specific username:password formats).
  - **Solution**: Enhanced `execution/ai_credential_url_agent.py` with:
    1. **Canonical Endpoints**: Each service now has known API endpoints with documentation URLs
    2. **Multiple Auth Combinations**: Each endpoint defines multiple auth patterns to try:
       - Basic auth with different username:password formats
       - Bearer tokens
       - Custom headers
       - Query parameters
    3. **Smart Detection**: If target URL doesn't match service domain, automatically tests canonical endpoints
    4. **Full Proof**: On success, captures complete request/response as proof of working combination
  - **Services with Canonical Endpoints**:
    - **Mixpanel**: `/api/app/me`, `/api/app/workspaces`, `/track`, `/export` (Service Account API)
    - **Stripe**: `/v1/balance`, `/v1/customers`
    - **GitHub**: `/user`, `/rate_limit`
    - **OpenAI**: `/v1/models`
    - **Slack**: `/api/auth.test`, `/api/users.list`
  - **Example**: For `mixpanel_token`, the agent now:
    1. Detects service as "Mixpanel"
    2. Tests `https://mixpanel.com/api/app/me` with multiple Basic auth combinations
    3. Reports success/failure with full HTTP request/response proof
  - **Files Changed**: `execution/ai_credential_url_agent.py`

- **Enhanced OSINT: External Repos Now Show Specific API Endpoints**
  - **Problem**: OSINT section showed repos referencing the domain but didn't show which specific API endpoints those repos were accessing. Hard to tell if findings were relevant to the target URL.
  - **Solution**: Enhanced `_search_github` and added `_extract_api_endpoints_from_github_file`:
    1. **Internal vs External Separation**: Repos are now categorized as `GitHub_Internal` or `GitHub_External`
    2. **API Endpoint Extraction**: For external repos, the agent fetches the file content and extracts actual API endpoint URLs
    3. **Summary Card**: Creates an `External_API_Usage_Summary` card listing all external repos with their specific API endpoints
    4. **URL Pattern Matching**: Extracts full URLs and API path patterns (`/api/v1/...`, `/rest/...`, `/graphql`)
  - **Example Output**:
    ```json
    {
      "type": "External_API_Usage_Summary",
      "description": "3 external repos accessing this API",
      "repos": [
        {
          "repo_name": "external-org/their-app",
          "api_endpoints": [
            {"url": "https://api.example.com/v1/users", "type": "full_url"},
            {"url": "/api/v1/orders", "type": "api_path"}
          ]
        }
      ]
    }
    ```
  - **Files Changed**: `execution/ai_credential_url_agent.py`

- **AWS Cognito client_id Now Tested Against Correct Endpoints**
  - **Problem**: `cognito_client_id` was being tested against arbitrary URLs (like `qa.sleepnumber.com`) which always return 200 because they're public websites. The credential wasn't even being used in the request.
  - **Root Cause**: The agent didn't understand that `cognito_client_id` is NOT a bearer token - it's used in the request body with AWS Cognito's specific API.
  - **Solution**: Added `AWS_Cognito` as a separate service with:
    1. **Correct Endpoints**: `https://cognito-idp.{region}.amazonaws.com`
    2. **Correct API Format**: POST with `X-Amz-Target` header and JSON body containing the client_id
    3. **Multiple Regions**: Tests us-east-1 and us-east-2 (can be extended)
    4. **Smart Validation**: Recognizes Cognito-specific error responses:
       - `NotAuthorizedException` = client_id valid, wrong credentials
       - `UserNotFoundException` = client_id valid, user doesn't exist
       - `ResourceNotFoundException` = wrong region
    5. **Body-Based Auth**: Sends `ClientId` in request body, not headers
  - **Example Request**:
    ```
    POST https://cognito-idp.us-east-1.amazonaws.com HTTP/1.1
    Content-Type: application/x-amz-json-1.1
    X-Amz-Target: AWSCognitoIdentityProviderService.InitiateAuth
    
    {"AuthFlow": "USER_PASSWORD_AUTH", "ClientId": "58seuj8tmopc2vbm1pevhcq6sp", ...}
    ```
  - **Files Changed**: `execution/ai_credential_url_agent.py`

- **Credential Values Now Displayed in Reports (No Masking)**
  - **Problem**: HTTP request headers in reports showed `[MASKED]` instead of actual credential values, preventing security analysts from validating findings.
  - **Solution**: 
    1. Removed hardcoded `[MASKED]` placeholder from `APIAuditView.tsx`
    2. Added `credential_value` and `auth_request_headers` to API responses
    3. Display actual credential values with proper formatting (Bearer, Basic, etc.)
  - **Files Changed**: 
    - `src/web-ui/components/APIAuditView.tsx` - Display actual values instead of `[MASKED]`
    - `src/api/routers/api_audit.py` - Include `credential_value` and `auth_request_headers` in API responses
  - **Policy**: Per security analyst requirements, credentials are never masked/redacted to enable validation of findings

### Added

- **Export Filename Dialog** - Prompt for filename when exporting PDF/DOCX reports
  - Shows dialog with editable filename field for PDF and DOCX exports
  - Pre-populates with default filename (security-report-{project}-{date})
  - Displays file extension next to input field
  - Supports Enter key to confirm export
  - Cancel button to abort export

- **Include in Report Checkbox** - Manual inclusion of findings in Critical Insights section
  - **Database**: Added `include_in_report` boolean column to `findings` table (default: false)
  - **Migration**: `migrations/012_include_in_report.sql`
  - **API Endpoint**: `PATCH /findings/{id}/include-in-report` to toggle inclusion status
  - **UI**: Checkbox labeled "Include in Report" on findings detail page (left of Journal button)
  - **Critical Insights**: Manually included findings appear as "Analyst Highlighted" type
  - **Severity Handling**: Uses finding's own severity for manually included items
  - **History Tracking**: Changes logged to finding_history table
  - **Purpose**: Allows Security Analysts to manually highlight important findings for executive attention

- **Self-Annealing Data Integrity Agent** - AI agent for detecting and repairing data quality issues
  - **Script**: `scripts/self_annealing_agent.py`
  - **DOE Approach**: Systematic detection, diagnosis, repair, and reporting
  - **Auto-Repair**: Contributors, Languages, SBOM, Finding Types
  - **Data Quality Score**: Calculates overall data integrity percentage
  - **Reports**: JSON reports saved to `logs/annealing_report_*.json`
  - **Documentation**: Updated `docs/SELF_ANNEALING.md`

- **Built-in Scheduler Service** - Configurable cron-based task scheduler
  - **Service**: `src/api/scheduler.py`
  - **API Router**: `src/api/routers/scheduler.py`
  - **Configuration via `.env`**:
    - `SCHEDULER_ENABLED` - Master switch for scheduler
    - `ANNEALING_CRON/ENABLED` - Data integrity checks (default: daily 3 AM)
    - `SCAN_CRON/ENABLED` - Repository scanning (default: disabled)
    - `BACKUP_CRON/ENABLED` - Organization backups (default: weekly Sunday 2 AM)
  - **API Endpoints**:
    - `GET /scheduler/status` - View scheduler and job status
    - `GET /scheduler/jobs` - List all configured jobs
    - `POST /scheduler/jobs/{name}/trigger` - Manually trigger a job
    - `GET /scheduler/next-runs` - View next scheduled run times
  - **Dependency**: Added `apscheduler>=3.10.0` to requirements.txt

- **Organization Backup & Restore Scripts** - Complete backup/restore solution for multi-tenant data
  - **Backup Script** (`scripts/backup_organization.py`):
    - `--list` - List all organizations with repo/finding counts
    - `--org NAME` - Backup single organization to JSON
    - `--all` - Backup all organizations
    - `--output DIR` - Custom output directory
  - **Restore Script** (`scripts/restore_organization.py`):
    - `--file PATH` - Restore from backup file
    - `--as-new NAME` - Create as new organization with different name
    - `--dry-run` - Preview without making changes
    - `--force` - Skip confirmation prompts
  - **Backup Contents**: Repositories, Findings, Credentials, API Endpoints, Credential-URL Correlations, Test Results, Scan Runs, Contributors
  - **Documentation**: `docs/BACKUP.md` and `docs/RESTORE.md`

- **Raw HTTP Request/Response Capture** - Credential-URL tests now capture and display full HTTP details
  - **Request Capture**: Method, URL, headers (with credentials masked), and body
  - **Response Capture**: Status code, headers, and body (truncated at 10KB)
  - **UI Modal Enhancement**: New "Raw HTTP Request & Response" section in the Report modal
    - Terminal-style display with syntax highlighting
    - Request headers shown with credential values masked
    - Response body auto-formatted as JSON when applicable
    - Truncation indicator for large responses
  - **Download Reports**: JSON, Markdown, and other formats now include raw request/response data
  - **Service Detection**: Shows detected service type and confidence score
  - **Files Updated**:
    - `execution/ai_credential_url_agent.py` - Added request/response capture in `TestResult` dataclass
    - `src/api/models.py` - Added database columns for request/response storage
    - `src/api/routers/api_audit.py` - Updated API endpoints and download formats
    - `src/web-ui/components/APIAuditView.tsx` - Enhanced modal with request/response display
  - **Migration**: `migrations/007_add_request_response_capture.sql`

### Fixed

- **Request Headers No Longer Masked** - Credential values in request headers are now preserved for audit validation
  - Security auditors need to see actual token values to validate if credentials are real/active
  - Changed `_mask_headers_for_storage()` to `_preserve_headers_for_storage()` in `ai_credential_url_agent.py`
  - Rerun credential-URL tests to see unmasked values

- **Contributors/Languages/SBOM Data Ingestion** - Fixed missing data for scanned repositories
  - Data was being generated in `_intel.json` and `_syft_repo.json` files but not ingested
  - Re-ingested all existing repos: 2,688 contributors, 1,544 language stats, 25,996 SBOM dependencies

- **Horusec Finding Type Correction** - Fixed SAST findings not appearing in SAST tab
  - Horusec findings were incorrectly categorized as `vulnerability` instead of `sast`
  - Updated `ingest_scans.py` to use correct `finding_type='sast'`
  - Fixed 3,209 existing horusec findings in database

- **Findings Data Ingestion Field Mapping** - Fixed incorrect field mapping in scanner ingestion
  - **Problem**: Horusec findings had title+description concatenated in `title`, evidence in `description`
  - **Solution**: Properly parse Horusec `details` field to extract title and description separately
  - **New Mapping**:
    - `title`: Short vulnerability name (first line of details)
    - `description`: Explanation of what the vulnerability is (rest of details)
    - `code_snippet`: Evidence/code found by scanner
  - **Files Updated**: `ingest_scans.py` (`ingest_horusec()`, `ingest_whispers()`)

- **Terrascan Null Violations Fix** - Fixed `'NoneType' object is not iterable` error
  - **Problem**: Terrascan reports with `"violations": null` caused ingestion crash
  - **Solution**: Handle null violations with `violations = results.get('violations') or []`
  - **Files Updated**: `ingest_scans.py` (`ingest_terrascan()`)

- **DataTable Reset Button Always Visible** - Users can now reset stale filters
  - **Problem**: Persisted localStorage filters could cause "No results found" even with data
  - **Solution**: Reset button is now always visible, highlighted orange when filters are active
  - **Files Updated**: `src/web-ui/components/data-table-toolbar.tsx`

- **Credential-URL Test Results API** - Added missing endpoints for test results
  - **Problem**: No API endpoints to retrieve/delete credential-URL test results
  - **Solution**: Added GET/DELETE endpoints for test results with org filtering
  - **New Endpoints**:
    - `GET /projects/{id}/api-audit/credential-url-test-results` - List all test results
    - `GET /projects/{id}/api-audit/credential-url-test-results/{result_id}` - Get detailed result
    - `DELETE /projects/{id}/api-audit/credential-url-test-results/{result_id}` - Delete result
  - **Files Updated**: `src/api/routers/api_audit.py`

- **Fixed Organization Context Query** - Fixed failed SQL transaction error
  - **Problem**: `_get_current_organization_id()` queried non-existent `is_current` column
  - **Solution**: Use `get_current_org_id()` from `database.py` instead
  - **Files Updated**: `src/api/routers/api_audit.py`

### Added

- **Multi-Tenant Organization Scanning** - Successfully scanned sleepnumberlabs/android-consumer-app
  - **Scan Results**: 121 findings including Azure API keys, secrets, and vulnerabilities
  - **Data Migration**: Migrated org-specific database data to master database with organization_id
  - **Organization Stats**: Updated organization stats to reflect actual repo/finding counts
  - **Test Coverage**: Validates multi-tenant scanning, data isolation, and organization switching

### Fixed

- **Credential-URL Test Results Display** - Fixed report modal not showing results
  - **Problem**: Multiple credentials testing against the same URL overwrote each other's results
  - **Solution**: Use composite key `url::credential_type` for result storage and lookup
  - **Files Updated**: `src/web-ui/components/APIAuditView.tsx`

- **Download Controls for All Cards** - Added download functionality to all AI correlation cards
  - **Inbound API Target URLs**: Download method, path, target URL, confidence
  - **Outbound API Target URLs**: Download code snippet, target URL, confidence
  - **Server-Credential Mapping**: Download server URL, environment, credential type/value, confidence
  - **Credential-URL Mapping**: Already had download control (enhanced with composite key support)
  - **Formats Supported**: CSV, JSON, YAML, Markdown, DOCX (Word)
  - **Files Updated**: `src/web-ui/components/APIAuditView.tsx`, `src/web-ui/components/DownloadControl.tsx`

### Enhanced

- **AI Credential-URL Testing Agent** - Improved authentication header selection using service detection
  - **Problem**: Tests failed despite high confidence because generic auth headers were used
  - **Solution**: Integrated sophisticated service detection patterns from `ai_credential_matcher.py`
  - **Service Detection**: Matches URL domain, credential type, keywords, and environment
  - **Supported Services**: Azure, AWS/Cognito, Firebase, Stripe, Twilio, SendGrid, Mixpanel, Instabug, Slack, GitHub, OpenAI, SleepIQ
  - **Auth Methods**: Header (X-API-Key), Bearer, Basic, Basic-Token, Key-Prefix
  - **Scoring**: Domain match (40pts), Secret type (35pts), Keyword (20pts), Environment (5pts)
  - **New Fields**: `detected_service`, `service_detection_score` in test results
  - **Files Updated**: `execution/ai_credential_url_agent.py`

- **Removed Hardcoded Organizations from Migrations** - Organizations are now created dynamically
  - **Problem**: `sealmindset` and `sleepnumberlabs` were hardcoded in SQL migrations, appearing in fresh databases
  - **Solution**: Removed all hardcoded organization inserts from migrations
  - **New Behavior**: Organizations are created when:
    1. User runs `--create-org NAME --github-org ORG --token TOKEN`
    2. Auto-registered from `ORG_{NAME}_TOKEN` environment variables on first scan
  - **Files Updated**: `migrations/002_organizations.sql`, `migrations/004_fix_multi_tenant_repositories.sql`

- **Database Name Consistency** - Standardized on `auditgh_kb` database with `postgres` user
  - **Problem**: Code defaults to `auditgh_kb` but `.env` had `security_portal`, causing drift
  - **Solution**: Standardized everything on `auditgh_kb` with `postgres:postgres` credentials
  - **Configuration Reference**:
    - Database: `auditgh_kb`
    - User: `postgres`
    - Password: `postgres`
    - Host: `db` (container) / `localhost` (host)
  - **New File**: `.env.example` - Template with placeholder values (no real credentials)
  - **Files Updated**: `.env`, `.env.example`, `docker-compose.yml`, all docs, `scripts/setup_database.sh`

- **API Multi-Tenant Database Routing Fix** - Fixed API querying wrong database
  - **Problem**: API was routing to org-specific databases (`auditgh_sealmindset`) but data was stored in master DB (`auditgh_kb`)
  - **Solution**: Changed `get_db()` to always use master DB with `organization_id` filtering
  - **Files Updated**: `src/api/database.py`, `src/api/routers/analytics.py`, `src/api/routers/organizations.py`
  - **New Functions**: `get_current_org_id()`, `apply_org_filter()` for query filtering

- **Organizations Table Schema Fix** - Added missing columns to `organizations` table
  - **Symptom**: `column "schema_version" does not exist` error when running `--list-orgs`
  - **Cause**: Migration `002_organizations.sql` wasn't fully applied or table was created with minimal columns
  - **Fix**: Added 16 missing columns: `database_schema`, `schema_version`, `schema_version_name`, `last_schema_sync`, `schema_sync_status`, `schema_sync_error`, `last_scan_at`, `scan_status`, `scan_progress`, `current_scan_id`, `total_scans`, `total_repos`, `total_findings`, `description`, `settings`, `created_by`
  - **New Migration** (`migrations/006_ensure_all_tables.sql`): Comprehensive catch-all migration that ensures all tables and columns exist - safe to run multiple times
  - **New Script** (`scripts/setup_database.sh`): Automated database setup script that applies all migrations in order
  - **Documentation**: Updated `DATABASE_SETUP.md`, `DATABASE_RESET.md`, `TROUBLESHOOTING.md` with fix instructions

- **CRITICAL: Multi-Tenant Framework Fix** - Complete overhaul of organization scoping for all data
  - **Root Cause**: `repositories` table and related tables were missing `organization_id` column, causing all scans to be stored without organization context
  - **Migration** (`migrations/004_fix_multi_tenant_repositories.sql`):
    - Added `organization_id` column to: `repositories`, `scan_runs`, `findings`, `contributors`, `language_stats`, `dependencies`, `api_endpoints`, `openapi_specs`, `file_commits`
    - Created indexes for organization-scoped queries
    - Migrates orphaned data to default organization (if one exists)
    - Updated unique constraint: repo names now unique per organization (not globally)
  - **SQLAlchemy Models** (`src/api/models.py`):
    - Added `organization_id` and `organization` relationship to all affected models
    - Added `UniqueConstraint('organization_id', 'name')` to Repository
  - **Scan Pipeline** (`scan_repos.py`):
    - Added `ORGANIZATION_ID` and `ORGANIZATION_NAME` to Config class
    - `--target` flag now sets organization ID for database scoping
    - `ensure_repo_in_database()` now scopes repos to correct organization
    - Repos with same name in different orgs are now properly separated
  - **Ingestion Pipeline** (`ingest_scans.py`):
    - `ingest_single_repo()` and `ingest_reports()` now accept `organization_id` parameter
    - All created records (repos, scan_runs, findings) are scoped to organization
  - **Impact**: Scans for `sleepnumberlabs` will now be stored separately from `sealmindset`

- **Organization Data Reset with Backup** - Safe reset process for clean slate scans
  - **Reset Script** (`scripts/reset_organization_data.py`):
    - Creates timestamped backup before any deletion
    - 30-day retention policy for backups (configurable via `BACKUP_RETENTION_DAYS`)
    - Deletes all organization data in correct FK order
    - Resets organization stats (total_repos, total_findings, etc.)
    - Automatic cleanup of expired backups
  - **CLI Flags** (in `scan_repos.py`):
    - `--reset-org --target ORG`: Reset organization data with backup
    - `--reset-force`: Skip confirmation prompt
    - `--list-backups`: List all organization backups
    - `--cleanup-backups`: Remove backups older than 30 days
  - **Backup Features**:
    - CSV export of all organization data per table
    - JSON metadata with stats and retention info
    - Restore capability from backup files

- **Documentation Restructure** - Comprehensive topic-based documentation
  - **Main README.md**: High-level overview, quick start, feature summary
  - **docs/GETTING_STARTED.md**: Installation and first scan walkthrough
  - **docs/RUNNING_MODES.md**: Docker vs CLI comparison, when to use each
  - **docs/MULTI_TENANT.md**: Multi-organization setup and management
  - **docs/DATABASE_RESET.md**: Backup, reset, and restore procedures
  - **docs/AI_AGENTS.md**: AI agent inventory, LLM configuration, hallucination mitigation
  - **docs/DEPENDENCIES.md**: System requirements, external services, version compatibility
  - **docs/CONFIGURATION.md**: Complete environment variable reference
  - **docs/TROUBLESHOOTING.md**: Common issues and solutions
  - **docs/CHEATSHEET.md**: Quick reference for startup, scanning, restart, shutdown
  - **docs/SECURITY_TOOLS.md**: All 15+ security tools with purposes, commands, and future roadmap

### Added

- **Phase 1 Security Tools Integration** - 5 new security scanners integrated into the scanning pipeline
  - **Horusec** (`scan_repos.py` → `run_horusec()`):
    - Multi-language SAST aggregating 15+ security tools
    - Supports: Go, C#, Java, Kotlin, Python, Ruby, JavaScript, TypeScript, Terraform, HCL, Dart, Elixir, Shell, PHP, C, HTML, JSON, Nginx
    - Output: `{repo}_horusec.json`, `{repo}_horusec.md`
    - Install: `brew install horusec`
  - **Whispers** (`scan_repos.py` → `run_whispers()`):
    - Hardcoded secrets detection in config files
    - Parses: YAML, JSON, XML, .npmrc, .pypirc, .htpasswd, .properties, pip.conf, Dockerfile, Shell scripts
    - Output: `{repo}_whispers.json`, `{repo}_whispers.md`
    - Install: `pip install whispers`
  - **Bearer** (`scan_repos.py` → `run_bearer()`):
    - Data flow analysis for sensitive data exposure (PII/PHI)
    - GDPR/CCPA compliance detection
    - Output: `{repo}_bearer.json`, `{repo}_bearer.md`
    - Install: `brew install bearer/tap/bearer`
  - **Dockle** (`scan_repos.py` → `run_dockle()`):
    - Container image linter for CIS Docker Benchmark compliance
    - Detects Dockerfiles and provides scan instructions
    - Output: `{repo}_dockle.json`, `{repo}_dockle.md`
    - Install: `brew install goodwithtech/r/dockle`
  - **Terrascan** (`scan_repos.py` → `run_terrascan()`):
    - IaC security scanner with 500+ policies
    - Supports: Terraform, Kubernetes, Helm, Dockerfiles, CloudFormation, Azure ARM
    - Output: `{repo}_terrascan.json`, `{repo}_terrascan.md`
    - Install: `brew install terrascan`
  - **Ingestion** (`ingest_scans.py`):
    - `ingest_horusec()`: Ingests multi-tool SAST findings
    - `ingest_whispers()`: Ingests config file secrets
    - `ingest_bearer()`: Ingests data flow findings with data type context
    - `ingest_terrascan()`: Ingests IaC policy violations
    - All findings stored in existing `findings` table with appropriate `scanner_name` and `finding_type`
  - **Risk Metrics** (`calculate_risk_metrics()`):
    - Updated to include findings from all 5 new scanners in security score calculation
  - **Dockerfile** (`Dockerfile`):
    - Added Horusec v2.8.0 binary installation
    - Added Whispers in isolated Python venv (avoids dependency conflicts)
    - Added Bearer via official install script
    - Added Terrascan v1.19.1 binary
    - Added Dockle v0.4.14 binary
    - All tools run inside `auditgh` container, not on host
  - **Skipped**: Snyk CLI (requires API key registration, even for free tier)
    - Alternative: Use Grype + Trivy for similar coverage

- **Phase 3 Security Tools Integration** - Go and Mobile security scanners
  - **gosec** (`scan_repos.py` → `run_gosec()`):
    - Go source code security analyzer (AST-based)
    - Detects: SQL injection, command injection, hardcoded credentials, weak crypto, path traversal
    - CWE mapping for all findings
    - Output: `{repo}_gosec.json`, `{repo}_gosec.md`
    - Install: `go install github.com/securego/gosec/v2/cmd/gosec@latest`
  - **GolangCI-Lint** (`scan_repos.py` → `run_golangci_lint()`):
    - Go linter aggregator with security linters enabled
    - Includes: gosec, staticcheck, govet, errcheck, ineffassign, typecheck
    - Deduplicates gosec findings to avoid double-counting
    - Output: `{repo}_golangci.json`, `{repo}_golangci.md`
    - Install: `brew install golangci-lint`
  - **MobSF** (`scan_repos.py` → `run_mobsf_static()`):
    - Mobile Security Framework for Android/iOS source code analysis
    - Android checks: hardcoded secrets, insecure HTTP, WebView JS, SQL injection, debuggable flag, backup enabled, exported components, weak crypto
    - iOS checks: hardcoded secrets, ATS disabled, keychain security, weak crypto, jailbreak detection, clipboard leakage
    - Output: `{repo}_mobsf.json`, `{repo}_mobsf.md`
    - Full MobSF: `docker pull opensecurity/mobile-security-framework-mobsf`
  - **Database Migration** (`migrations/005_mobile_go_scanners.sql`):
    - `mobile_apps` table: Mobile app metadata (package name, permissions, signing info, security flags)
    - `mobile_security_findings` table: MobSF-specific finding details
    - `go_security_findings` table: gosec rule IDs, CWE mappings, vulnerability types
    - `scanner_configs` table: Per-organization scanner configuration
    - Added `is_mobile_finding`, `is_go_finding`, `gosec_rule_id` columns to `findings`
    - Added `has_go_code`, `has_android_code`, `has_ios_code`, `has_mobile_app` columns to `repositories`
  - **Ingestion** (`ingest_scans.py`):
    - `ingest_gosec()`: Parses gosec JSON, extracts CWE, maps severity
    - `ingest_golangci()`: Parses GolangCI-Lint JSON, skips gosec duplicates
    - `ingest_mobsf()`: Parses MobSF JSON, categorizes by platform
  - **Risk Metrics** (`calculate_risk_metrics()`):
    - Added gosec, GolangCI-Lint, and MobSF to security score calculation
  - **Dockerfile**:
    - Added Go 1.21.5 installation
    - Added gosec via `go install`
    - Added GolangCI-Lint v1.55.2 via official install script

- **AI Credential-URL Testing Agent** - Intelligent agent for testing credential authentication against discovered API endpoints
  - **AI Agent** (`execution/ai_credential_url_agent.py`): Core testing engine
    - Tests authentication and authorization of credentials against target URLs
    - Performs API path discovery (fuzzing) with common API wordlist
    - Retrieves and analyzes sample data from accessible endpoints
    - Performs OSINT searches on GitHub and documentation URLs
    - Generates AI-powered executive summaries, risk assessments, and recommendations
    - Supports multiple rate limiting modes: None, Cautious (evasion), Insane (all off)
    - Uses Anthropic Claude or OpenAI GPT for AI analysis
    - Rotates user agents and implements intelligent request delays
  - **Database Migration** (`migrations/003_credential_url_test_results.sql`):
    - `credential_url_test_results` table with comprehensive fields
    - **Multi-tenant**: `organization_id` column for organization scoping
    - Authentication status, response codes, timing metrics
    - Discovered paths with method, status, and sample data
    - OSINT findings with source URLs and relevance scores
    - AI-generated overview, risk assessment, and recommendations
    - Threat level classification (critical, high, medium, low, info)
    - Test metadata including duration, mode, and LLM provider
    - `credential_url_test_status` table for tracking auto-test initialization per project
    - Prevents re-testing on every page load (only tests on first load)
  - **SQLAlchemy Model** (`src/api/models.py`): `CredentialUrlTestResult` model
    - JSONB fields for discovered paths, sample data, OSINT findings
    - Relationships to project and audit data
    - Timestamps for created/updated tracking
  - **API Endpoints** (`src/api/routers/api_audit.py`):
    - `POST /{project_id}/api-audit/credential-url-test`: Test single credential-URL pair
    - `POST /{project_id}/api-audit/credential-url-test-all`: Test all credential-URL pairs
    - `GET /{project_id}/api-audit/credential-url-results`: List all test results
    - `GET /{project_id}/api-audit/credential-url-results/{result_id}`: Get detailed result
    - `GET /{project_id}/api-audit/credential-url-results/{result_id}/download`: Download report
    - `GET /{project_id}/api-audit/credential-url-test-status`: Check if initial auto-test completed
    - `POST /{project_id}/api-audit/credential-url-test-status/mark-complete`: Mark initial test done
    - All endpoints scoped to current organization (multi-tenant)
  - **Report Generation**: Multiple export formats
    - PDF (via reportlab)
    - JSON
    - DOCX (via python-docx)
    - CSV
    - Markdown
  - **UI Updates** (`src/web-ui/components/APIAuditView.tsx`):
    - New "AuthN/Z" column showing Yes, Failed, or Not Tested status
    - New "Action" column with Test/Re-test and Report buttons
    - Rate limit mode selector (Cautious, None, Insane)
    - "Test All" button for batch testing
    - Automatic testing on page load for untested correlations
    - Live testing status with animated indicators
    - Comprehensive Report Modal (75% screen size, scrollable):
      - AI Overview with threat level badge
      - Authentication status with HTTP code and response time
      - Discovered paths table with method, path, status, and result
      - OSINT findings table with source URLs and relevance
      - AI Recommendations list
      - Test metadata (timestamp, duration, mode, LLM)
    - Download Modal with format and filename selection
  - **Environment Variables**:
    - `GITHUB_TOKEN`: For GitHub OSINT searches
    - `ANTHROPIC_API_KEY`: For Claude AI analysis
    - `OPENAI_API_KEY`: For GPT AI analysis (fallback)

## [2.0.0] - 2025-12-12

### Added

- **Multi-Organization AI Agent System** - Intelligent orchestration for scanning multiple GitHub organizations
  - **Organization Registry**: Database-backed registry for managing multiple organizations
    - Each organization has isolated database (same PostgreSQL instance, securely segmented)
    - Tracks schema version, sync status, scan progress, and statistics
    - Supports default organization selection
  - **AI Organization Agent** (`execution/ai_org_agent.py`): Core orchestration engine
    - Automatic schema synchronization on startup
    - Schema drift detection across all organization databases
    - Credential management via secrets manager abstraction
    - Context switching for scans (loads org-specific credentials)
    - Database provisioning from master schema
  - **Secrets Manager Abstraction** (`execution/secrets_manager.py`): Secure credential storage
    - MockSecretsManager for development (encrypted in-memory with file persistence)
    - VaultSecretsManager interface for production (HashiCorp Vault)
    - Fernet/AES-128 encryption at rest
    - Version tracking and rotation support
    - Credential format: `{org_name}/github_token`, `{org_name}/github_org`
  - **CLI Arguments** for `scan_repos.py`:
    - `--target ORG`: Select organization for scanning (e.g., `--target sealmindset`)
    - `--list-orgs`: List all registered organizations
    - `--create-org NAME`: Create new organization with database
    - `--sync-schemas`: Sync all organization schemas with master
    - `--check-drift`: Check for schema drift across organizations
  - **REST API Endpoints** (`src/api/routers/organizations.py`):
    - `GET /organizations/`: List all organizations
    - `GET /organizations/current`: Get currently selected organization
    - `GET /organizations/{name}`: Get organization details
    - `POST /organizations/`: Create new organization
    - `POST /organizations/{name}/select`: Select organization context
    - `POST /organizations/{name}/sync-schema`: Sync schema with master
    - `GET /organizations/schema/drift`: Check schema drift
    - `POST /organizations/{name}/scan`: Start scan for organization
  - **OrganizationSelector UI Component** (`src/web-ui/components/OrganizationSelector.tsx`):
    - Top navigation dropdown for quick organization switching
    - Shows scan status indicators (scanning, queued, error)
    - Schema sync status badges (synced, drift, error)
    - Repository and findings counts per organization
    - Quick access to organization management
  - **Database Migration** (`migrations/002_organizations.sql`):
    - `organizations` table with UUID id, api_id, schema tracking
    - `organization_audit_log` for compliance tracking
    - `organization_schema_versions` for migration history
    - `organization_context` for session-based selection
    - Triggers for timestamp updates and audit logging
    - Initial data: sealmindset as first/default organization
  - **Configuration**:
    - `SECRETS_MASTER_KEY`: Environment variable for consistent encryption across containers
    - `POSTGRES_*` variables take precedence over `DATABASE_URL` for container compatibility
    - Automatic fallback to psycopg2 when psql is not available in container

- **AI Agent-Powered API Audit Cards** - Intelligent correlation agents for the API Audit feature
  - **Credential-URL Correlation**: AI-powered matching of discovered credentials to their target URLs
    - File proximity analysis (credentials and URLs in same file)
    - Code context analysis (credentials used with specific URLs)
    - Environment matching (dev credentials → dev URLs, prod → prod)
    - Service type matching (Azure keys → Azure URLs, AWS → AWS)
    - Optional LLM enhancement via Anthropic Claude for refined confidence scores
  - **Inbound Endpoint-Server Correlation**: Maps inbound API routes to discovered servers
    - Framework detection (Express routes → Node servers)
    - Path prefix matching
    - Environment indicators in file paths
  - **Outbound Endpoint-Server Correlation**: Maps outbound API calls to target servers
    - Direct URL extraction from code (highest confidence)
    - Environment variable references
    - Service type hints
  - **Server-Credential Mapping**: Groups credentials by their associated servers
    - Environment matching (prod servers → prod credentials)
    - Domain patterns in credential code
    - Service type matching
  - **Scoring Algorithm**: Confidence-scored correlations with weighted signals
    - Same file proximity: +40 points
    - Close line numbers (<10 lines): +20 points
    - Environment match: +25-35 points
    - Service type match: +30 points
    - Direct URL extraction: +90-95 points
    - Maximum confidence capped at 99%
  - **UI Components**: Color-coded AI correlation cards in API Audit view
    - Inbound APIs: Cyan theme with endpoint-server pairs
    - Outbound APIs: Purple theme with code-URL pairs
    - API Servers: Green theme with server-credential groups
    - Credentials: Collapsible card with export functionality
    - Confidence indicators: Green (≥70%), Yellow (40-69%), Red (<40%)
  - **Backend**: New correlation functions in `execution/ai_credential_matcher.py`
  - **API Endpoints**: Four new REST endpoints in `src/api/routers/api_audit.py`
    - `GET /{project_id}/api-audit/credential-url-correlations`
    - `GET /{project_id}/api-audit/inbound-url-correlations`
    - `GET /{project_id}/api-audit/outbound-url-correlations`
    - `GET /{project_id}/api-audit/server-credential-correlations`

- **AI Security Analysis Enhancements** - Major improvements to the Ask AI feature for findings
  - **Update Description Button**: Save AI analysis directly to the finding's description in the database
  - **Beautified Description Display**: ReactMarkdown rendering with gradient styling for AI-enhanced descriptions
  - **Conversation Separation**: Initial AI analysis displayed in a distinct card, follow-up conversation in a separate chat area
  - **Auto-Start Analysis**: AI analysis automatically begins when the dialog opens
  - **NLP Revision Detection**: Automatically detects when follow-up questions request description revisions (e.g., "update the description", "add more detail")
  - **Description Version History**: Full versioning system with restore capability
    - View previous versions with timestamps via history popover
    - One-click restore to any previous version
    - Tracks all changes with `description_change` type in finding_history table
  - **Pro Tips Popover**: Helpful tips for analysts via lightbulb icon

- **Repository Navigation Links** - Added repository links throughout the UI
  - Finding details page: Repository name links to project details page
  - All Findings table: Repository column now links to project details page

- **Last Commit Column** - Added "Last Commit" column to All Findings table
  - Shows the repository's last commit date (from contributor commit history)
  - Helps analysts prioritize findings in actively maintained vs. dormant repositories
  - Efficient batch query fetches commit dates for all repositories in one database call

### Changed

- **Finding Response Model**: Added `repo_last_commit_at` field derived from max contributor `last_commit_at`
- **AskAIDialog Component**: Complete rewrite with improved UX and state management
- **Finding Details Page**: Moved Ask AI button to Details card, added ReactMarkdown for description rendering

### Fixed

- Fixed useEffect ordering issue where `handleAnalyze` was called before it was defined

---

- **Intelligent Progress Monitoring System** - Adaptive timeout system that monitors subprocess progress
  - Replaces fixed 30-minute timeout with 5-minute initial timeout
  - Monitors CPU usage, file I/O, and output in real-time
  - Automatically extends timeout if scan is making progress
  - Only times out after 3 minutes of no progress detected
  - Integrated with Semgrep and Dependency-Check scanners
  - Progress metrics included in AI analysis for better diagnostics
  - New CLI arguments: `--progress-check-interval`, `--max-idle-time`, `--min-cpu-threshold`
  - Requires `psutil>=5.9.0` (already in requirements.txt)
- **OpenAI GPT-5 Support** - Updated AI provider to support GPT-5 models
  - Uses `max_completion_tokens` parameter for GPT-5 compatibility
  - Backward compatible with GPT-4 models
- **Self-Annealing Scanner with DOE (Design of Experiments) Recovery:**
  - Per-repository timeout (default: 30 minutes, configurable via `--repo-timeout`)
  - Automatic recovery from stuck scans: generates partial reports and continues to next repository
  - Proper Ctrl-C signal handling: immediately cancels pending scans and exits cleanly
  - Stuck repository tracking: creates `stuck_repos.log` and `stuck_repos_summary.md` for post-mortem analysis
  - New CLI arguments:
    - `--repo-timeout N`: Set timeout in minutes per repository (0 = no timeout)
    - `--scanner-timeout N`: Set timeout in minutes per individual scanner (default: 10)
    - `--continue-on-timeout`: Continue scanning after timeout (default: True)
  - Enhanced logging with scan statistics (success/timeout/error/skipped counts)
  - Partial report generation for timed-out repositories showing what was attempted
  - Global shutdown event for coordinated worker termination
  - Self-annealing recovery functions: `process_repo_with_timeout()`, `log_stuck_repo()`, `generate_partial_report()`

- **AI-Enhanced Scanning Agent:**
  - Integration with OpenAI (GPT-4) and Anthropic (Claude) APIs
  - Intelligent diagnosis of stuck scans (Root Cause Analysis)
  - Remediation suggestions (increase timeout, exclude patterns, etc.)
  - Auto-remediation engine (opt-in via `--ai-auto-remediate`)
  - Learning system to track suggestion effectiveness over time
  - Cost tracking and budget controls
  - New CLI arguments: `--ai-agent`, `--ai-provider`, `--ai-auto-remediate`

- Web app scaffolding and DX improvements:
  - `web/vite.config.ts` with React plugin and dev server bind to `0.0.0.0:3000`.
  - `docker-compose.dev.yml` for hot-reload dev stack (`web`, `server`, `db`, `postgrest`).
  - Husky pre-commit hook `.husky/pre-commit` to run `web` typecheck and build.
  - `web/src/pages/AITokens.tsx` and top-nav link to surface AI tokens across orgs.

- GenAI tokens detection and persistence:
  - DB migration `db/portal_init/014_ai_tokens.sql`:
    - Tables: `public.ai_tokens`, `public.ai_tokens_validations` (RLS enabled).
    - Views: `api.ai_tokens` (includes token), `api.ai_tokens_admin`.
    - RPCs: `api.upsert_ai_tokens(p_project_id int, p_payload jsonb)`, `api.record_ai_token_validation(...)`.
  - Server:
    - Route: `server/src/api/routes/ai_tokens.ts` as PostgREST proxy (`/api/ai-tokens`).
    - Services: `genai_ingest.ts` to upsert tokens from artifacts; `genai_validate.ts` to validate (OpenAI, Anthropic, Cohere).
  - Scanner + Orchestrator:
    - New `scan_genai_tokens.py` (providers: openai/anthropic/cohere initial).
    - `orchestrate_scans.py` now supports `genai_tokens` step (persists via PostgREST).
  - UI:
    - Project page (`web/src/pages/ProjectDetail.tsx`) now shows a "Published Secrets / Tokens" section filtered to the current project.
    - Org-level page `AITokens` lists tokens with filters (provider/validation).
  - DataTable: Excel-style header filter menus (`web/src/components/DataTable.tsx`)
    - Per-column menu with two modes:
      - enum: checkbox multi-select with in-menu search and Select All
      - text: case-insensitive "contains"
    - Default behavior for enum filters: all values pre-selected; unchecking dynamically filters rows out; full selection is treated as no filter; empty selection yields zero matches.
    - Column filters compose with global search, sorting, and pagination.
  - Enabled Excel-style filters across tables:
    - Project Detail → Published Secrets
    - Project Detail → CodeQL Findings (Severity/Rule/File/Message)
    - Project Detail → Contributors (Login/Email) and Commit History (Message/Author/Email/SHA)
    - OSS Vulnerabilities (`OssVulnTables`): Summary/Multiple/Vulnerabilities tables
    - AI Tokens page: Provider/Validation/Project/Repo/Token/File
    - Projects List: Name/Description/Primary Language/Status
  - Terraform persistence: new DB table and API view
    - DB: `db/portal_init/016_terraform.sql` adds `public.terraform_findings` (UUID id, bigserial api_id), RLS, and `api.terraform_findings` view.
    - Server: `server/src/services/terraform_ingest.ts` ingests Checkov/Trivy FS outputs after scans and upserts into `public.terraform_findings`.
    - UI: `TerraformFindings.tsx` now prefers PostgREST (`/db/terraform_findings?project_id=...&repo_short=...`) and falls back to static `/terraform_reports` JSON when DB is empty.
    - Project Detail: Terraform findings table (Checkov/Trivy) with Excel-style filters.

 - Project Detail: Binaries table
   - Scanning: `scan_binaries.py` writes per-repo JSON/Markdown into `binaries_reports/<repo>/`.
   - Web: `docker-compose.portal.yml` mounts `./binaries_reports` into the web container at `/usr/share/nginx/html/binaries_reports` for static access.
   - UI: `web/src/components/BinariesTable.tsx` loads `/binaries_reports/<repo>/<repo>_binaries.json` and renders a DataTable with filters (Filename/Path/Ext/Size/Executable/Type/SHA256/Mode). Links to Markdown/JSON in header.
   - Integrated in `web/src/pages/ProjectDetail.tsx` below Terraform Findings.

- Environment
  - `.env.sample` adds `VALIDATE_GENAI_TOKENS=true` and per-provider flags (all default `true`).

- AI Assist (provider-selectable):
  - DB: `db/portal_init/017_ai_assist.sql` adds `public.ai_assist_analyses` (UUID id, bigserial api_id), RLS, and API view `api.ai_assist_analyses`.
  - Server: `/api/ai/assist` endpoint performs analysis using Ollama (default gpt-oss) or OpenAI and persists the result and reference extracts.
  - Providers: `server/src/services/ai_providers/ollama.ts`, `server/src/services/ai_providers/openai.ts`; orchestration in `server/src/services/ai_assist.ts`.
  - UI: `web/src/components/AiAssistantPanel.tsx` with provider/model selection, response display; integrated as "Ask AI" per-row actions in:
    - Terraform Findings (`TerraformFindings.tsx`)
    - OSS Vulnerabilities (`OssVulnTables.tsx`)
    - CodeQL Findings and Published Secrets (`ProjectDetail.tsx`)
  - Compose: optional `ollama` service (ports 11434) with local model cache volume.

- Exploitability statuses and Agent AI citations:
  - DB: `db/portal_init/018_exploitability.sql` adds `public.exploitability_statuses` (UUID id, bigserial api_id), RLS, and API view `api.exploitability_statuses`.
  - Server:
    - Discovery service `server/src/services/discovery.ts` queries OSV, KEV (CISA), EPSS, GitHub Search, and DuckDuckGo; returns ranked, de-duped citations.
    - New route `server/src/api/routes/exploitability.ts`:
      - GET `/api/exploitability?type=<cve|ghsa>&keys=KEY1,KEY2` to batch fetch statuses.
      - POST `/api/exploitability` to upsert manual status + citations.
    - AI Assist (`server/src/services/ai_assist.ts`):
      - `auto_discovery` to enrich references automatically.
      - `mode`: `citations_only` (default) or `analysis_with_citations`.
      - Optional `set_exploit_from_citations` to set `exploit_available=true` only when substantiated by credible PoCs (KEV, Exploit-DB/Metasploit, multiple GitHub PoCs). Otherwise remains Unknown.
  - UI:
    - `web/src/components/AiAssistantPanel.tsx` now includes Auto-discover toggle, Mode selector, and “Apply Exploit Available from citations” checkbox.
    - `web/src/components/OssVulnTables.tsx` adds an Exploit pill per row and a Manage dialog for manual override and citations entry.

### Changed
- Web Dockerfile: prefer `npm ci`; if lock is out-of-sync, fall back to `npm install` to avoid build failures in CI/containers.
- `.gitignore`: avoid ignoring `web/src/lib/` by scoping `/lib/` and `/lib64/` to repo root.
- `docker-compose.portal.yml`: clarified `seeder_langloc` purpose and ensured local build (no registry pull) for seeders.
- `docker-compose.portal.yml`: mounted `terraform_reports` into web container for static serving.
 - AI Assist defaults: Ollama default model is now `qwen2.5:3b` (fallback remains configurable via env `AI_ASSIST_DEFAULT_MODEL_OLLAMA`).
 - Initial seeding flow: remove OSS from `seeder_langloc` entrypoint (now runs only `scan_linecount.py` to persist LOC/files). CodeQL was not part of seeding and remains disabled during initial seed.
 - Projects page: removed 'Scan' link from page header.
 - Top header: renamed brand title from 'Security Portal' to 'GitHub Auditor'.
 - Terraform Findings UI: added severity totals chips and clickable severity toggles (Critical/High/Medium/Low/Unknown).
 - Scans page: renamed section header from 'Run Shai-Hulud Scan' to 'Repo Scanner'.
 - Scans page: removed the 'CodeQL Findings' panel.
 - Projects page: removed the 'CodeQL Severity Totals' section.
 - Project Detail UI enhancements:
   - Added an `Ask AI` column to CI/CD workflow runs, Contributors, and Commit History tables (opens `AiAssistantPanel` with provider/model selection).
   - Confirmed `Ask AI` and `Exploit` columns for CodeQL and Terraform findings; Exploit includes Manage dialog with citations and persists via `/api/exploitability`.
   - Confirmed OSS Vulnerabilities tables retain `Ask AI` and `Exploit` integration.
   - Increased nginx proxy timeouts for `/api/ai/` to accommodate longer first responses.

### Fixed
- PostgREST permissions for AI tokens RPCs:
  - Set `SECURITY DEFINER` and granted `EXECUTE` to `postgrest_anon` for `api.upsert_ai_tokens` and `api.record_ai_token_validation`.
- PostgREST schema cache refresh after adding new RPCs via `NOTIFY pgrst, 'reload schema'`.
- `README.md` with setup and usage instructions.
- `requirements.txt` for Python dependencies.
- `.gitignore` to exclude sensitive files and development artifacts.
- `--repo` CLI argument to scan a single repository (e.g., `--repo owner/repo` or `--repo repo` defaulting to `--org`). If omitted, all repositories in `--org` are scanned.
- Optional Dagda integration for container image analysis:
  - Flags: `--dagda-url`, `--docker-image`
  - Outputs: `{repo}_dagda.json`, `{repo}_dagda.md`
- Optional Syft integration for SBOM generation:
  - Runs on cloned repo directory; if `--docker-image` is provided, also runs on the image
  - Flag: `--syft-format` (default: `cyclonedx-json`)
  - Outputs: `{repo}_syft_repo.json`/`.md` and (if image) `{repo}_syft_image.json`/`.md`

- OSS scanner: integrated Semgrep Struts2 rules (`semgrep-rules/java-struts2.yaml`, `java-struts2-heuristics.yaml`) to detect RCE patterns in Java code.
- OSS scanner: added naive POM-based detector for known Struts2 CVEs (e.g., CVE-2017-5638), including property resolution from the same pom `<properties>`.
- OSS scanner: unified JSON parsing across `pip-audit`, `osv-scanner`, `npm audit`, and `semgrep` into a consolidated vulnerability table in per-repo markdown reports.
- OSS scanner: helper to optionally generate `package-lock.json` in temp clones (`npm install --ignore-scripts --package-lock-only`) when only `package.json` exists to improve OSV coverage.
- OSS scanner: optional flag `--parse-osv-cvss` to compute CVSS base scores from OSV severity vectors (uses `cvss`/`cvsslib` if available).
- Dependencies: added `cvss` to `requirements.txt` for CVSS vector parsing.

- CodeQL scanner: revamped orchestration modeled after `scan_oss.py`.
  - Retries on GitHub API, org→user fallback, and improved logging.
  - Concurrency with `--max-workers` for repo-level parallelism.
  - Enhanced CLI: `--fail-fast`, `--fail-on-severity`, `--sarif-only`, `--json-only`, `--top-n`, `--timeout-seconds`, `--skip-autobuild`, `--build-command`.
  - Language detection improvements (Java/Kotlin, JS/TS, Python, Go, C/C++, C#, Ruby, Swift).
  - CodeQL DB creation supports custom build or autobuild; step timeouts supported.
  - SARIF parsing enriched with rule tags, precision, CWE extraction; severity normalized from security-severity.
  - Rule-specific mitigation text extracted from CodeQL rule metadata (`help`, `fullDescription`) and surfaced in Markdown reports; `helpUri` captured as `rule_doc_url` in JSON.
  - Deduplication and ranking (CVSS then severity rank).
  - Per-repo JSON/Markdown outputs and org-level `codeql_summary.md`.
 - Orchestrator script `orchestrate_scans.py` to run all scanners with profiles (fast/balanced/deep) and generate `markdown/orchestration_summary.md`.
- README: new Orchestrator section with usage examples and summary/output locations.
- Docker: comprehensive toolchain in image (Semgrep, Gitleaks, Trivy, Syft, Grype, OSV-Scanner, CodeQL CLI, govulncheck, bundler-audit, Dependency-Check) with per-scanner report volumes.
- Docker Compose: macOS-friendly defaults (platform linux/amd64), report/cache volumes, and balanced-profile entrypoint via orchestrator.
- Orchestrator: preflight `logs/versions.log` capturing installed tool versions for diagnostics.
- Compose: fixed invalid `.git-credentials` file mount; all mounts now target directories only. Added guidance to ensure host bind paths exist.
- Docs: added `Docker.md` with comprehensive Docker/Compose usage, single/multi-scanner runs, arguments, and troubleshooting.

- CLI: added `--max-workers` to scanners for configurable concurrency with env fallbacks.
  - `scan_contributor.py` (env: `CONTRIB_MAX_WORKERS` or `SCAN_MAX_WORKERS`)
  - `scan_oss.py` (env: `OSS_MAX_WORKERS` or `SCAN_MAX_WORKERS`)
  - `scan_terraform.py` (env: `TF_MAX_WORKERS` or `SCAN_MAX_WORKERS`)
  - `scan_cicd.py` (env: `CICD_MAX_WORKERS` or `SCAN_MAX_WORKERS`)
  - `scan_binaries.py` (env: `BINARIES_MAX_WORKERS` or `SCAN_MAX_WORKERS`)
  - `scan_linecount.py` (env: `LINECOUNT_MAX_WORKERS` or `SCAN_MAX_WORKERS`)
  - `scan_gitleaks.py` (env: `GITLEAKS_MAX_WORKERS` or `SCAN_MAX_WORKERS`)
  - Note: `scan_codeql.py` and `scan_insights.py` already supported `--max-workers`.

- CodeQL scanner: resource tuning flags and env fallbacks.
  - `scan_codeql.py` now supports `--ram-mib` and `--threads` (defaults from env `CODEQL_RAM_MIB`, `CODEQL_THREADS`).
  - These are passed through to CodeQL `database create`/`analyze` as `--ram` and `--threads`.
  - Server runner forwards `CODEQL_RAM_MIB` and `CODEQL_THREADS` into the scanner container so UI scans honor limits.
  - `.env.sample` updated with safe defaults `CODEQL_RAM_MIB=8192`, `CODEQL_THREADS=1`.

- Orchestrator (CodeQL): profile-based query suite and timeout with overrides
  - Default mapping by profile:
    - fast → suite: `code-scanning`, timeout: `1200` seconds
    - balanced → suite: `security-extended`, timeout: `1800` seconds
    - deep → suite: `security-and-quality`, timeout: `3600` seconds
  - New CLI flags in `orchestrate_scans.py`:
    - `--codeql-query-suite` to override the query suite
    - `--codeql-timeout-seconds` to override the analyze timeout
    - `--codeql-languages` to target specific CodeQL languages (comma-separated, e.g., `python,java`)
  - Env overrides (optional):
    - `ORCHESTRATOR_CODEQL_QUERY_SUITE`
    - `ORCHESTRATOR_CODEQL_TIMEOUT`
    - `ORCHESTRATOR_CODEQL_LANGUAGES`
  - Precedence: CLI > Env > Profile defaults

- CodeQL DB recreation toggle
  - Orchestrator: new CLI flag `--codeql-recreate-db` to force DB recreation on any profile (deep still recreates by default unless `--no-deep-codeql`).
  - Server API & Runner: accept `codeql_recreate_db: boolean` and forward `--codeql-recreate-db` to the orchestrator.
  - Web UI: added a "Recreate CodeQL DB" checkbox in CodeQL Options to avoid cached DB issues on non-deep runs (e.g., balanced profile).

- Server API & Runner: pass targeted CodeQL languages through to orchestrator
  - API `POST /api/scans` now accepts optional `codeql_languages: string[]`
  - Server runner forwards `--codeql-languages` to orchestrator when provided
  - `.env.sample` documents `ORCHESTRATOR_CODEQL_LANGUAGES` for env-based override

- Adaptive GitHub rate-limit defaults added to `.env.sample` and generated `.env` by `bootstrap.sh`:
  - `GITHUB_TARGET_UTILIZATION=0.5`
  - `GITHUB_MIN_INTERVAL=0.5`

- Database (portal_init): added CodeQL persistence schema and API views
  - New tables: `public.codeql_findings`, `public.codeql_scan_repos` with UUID `id` and numeric `api_id` per row.
  - RLS enabled on both tables; `postgrest_anon` granted SELECT via policies; `app` has ALL for server-side writes.
  - API views created: `api.codeql_findings`, `api.codeql_scan_repos`, `api.codeql_org_severity_totals`, `api.codeql_org_top_repos`, `api.codeql_recent_scans`.
  - Implemented migration file `db/portal_init/012_codeql.sql` so fresh setups initialize correctly without manual SQL.

- Server: CodeQL ingestion now persists per-scan, per-repo summary rows
  - `server/src/services/codeql_ingest.ts` stages and upserts rows into `codeql_scan_repos` via new repository `server/src/db/repositories/codeql_scan_repos.ts`.
  - Summary rows include `has_sarif` and `findings_count` aggregated by language.

### Fixed
- Resolved Semgrep rules path to use absolute `semgrep-rules/` directory relative to the project, avoiding CWD issues.
- Prevented OSV extractor errors by avoiding direct scans of `package.json`; scanning is restricted to lockfiles, with `npm audit` as fallback.
- Eliminated false "pip-audit not installed" failures by correcting flags and adding a module fallback when PATH resolution fails.

- CodeQL CLI detection inside scanner container:
  - Fixed PATH to include `/opt/codeql` so `codeql` binary is found.
  - Built scanner image for `linux/amd64` to match the CodeQL CLI binary architecture; Docker Compose updated to run `scanner`/`seeder` with `platform: linux/amd64` to avoid architecture mismatch (Rosetta/QEMU errors).

- Server GenAI token validation service fixes:
  - Implemented missing validators: Gemini and Mistral
  - Corrected Cohere endpoint to `https://api.cohere.ai/v1/models`
  - Unified return types to narrow `status` to `'valid'|'invalid'|'error'` and resolve TypeScript build errors

- Dashboard severity totals: `api.codeql_org_severity_totals` now `COALESCE`s null sums to `0` so empty datasets return numeric zeros instead of nulls.
- Scanner: added `scan_engagement.py` to fetch stars/forks/watchers/open_issues (and best-effort counts for contributors) and persist via PostgREST.
  - Flags: `--org/--repo --token --postgrest-url --persist --max-workers`.
- Web UI: projects list and project detail now display `primary_language`, `total_loc`, and `stars/forks`.

### Changed
- OSS scanner: corrected `pip-audit` usage to `-r <requirements*.txt> -f json`, tolerate non-zero exits when vulns are found, and fallback to `python -m pip_audit` when the CLI is not in PATH.
- OSS scanner: for Node/Python, OSV scanning now targets lockfiles only; for Java manifests (`pom.xml`, Gradle), OSV scans the repository recursively (`osv-scanner -r`) for better resolution.
- OSS scanner: when only `package.json` is present, fallback to `npm audit --json` with robust parsing and aggregation.
- OSS scanner: improved error handling, logging, and multi-JSON chunk parsing across all tool integrations.
- OSS scanner: deduplication now preserves `cvss_score` from any source when the current record lacks it, improving severity ranking consistency.

- CodeQL scanner: reporting now shows top findings sorted by CVSS/severity and includes SARIF artifact paths (unless `--json-only`).
  - Added `Mitigation` column to per-repo Markdown Top Findings tables.

- Dockerfile: Made `bundler-audit` installation resilient to corporate SSL interception.
  - Option B: automatic HTTP RubyGems fallback if HTTPS install fails (last resort, insecure).
  - Option A (alternative): support `--build-arg CORP_CA_B64=<base64 PEM>` to trust a corporate root CA during build.

- Docker build base images:
  - Switched Node and Nginx bases to Amazon ECR Public mirror to avoid Docker Hub auth/rate limits in dev/CI
    - `web/Dockerfile`: `public.ecr.aws/docker/library/node:20-alpine`, `public.ecr.aws/docker/library/nginx:alpine`
    - `server/Dockerfile`: `public.ecr.aws/docker/library/node:20-alpine` (build and runtime)

- Orchestrator: switched to streaming child process output (stdout+stderr) live to stdout and log files, so UI SSE shows real-time logs during scans. Logs are now written under `REPORT_DIR/logs` when `REPORT_DIR` is provided (e.g., by the server), otherwise under repo `logs/`.
- Orchestrator: summary now writes to `REPORT_DIR/markdown/orchestration_summary.md` when `REPORT_DIR` is provided, preserving artifacts in the server-mounted runs directory.
- Server runner: after container completion, prefers persisting `markdown/orchestration_summary.md` when present, falling back to `shaihulu_summary.md`. Scan status now reflects presence of the orchestrator summary.

- Server runner: force scanner container platform to `linux/amd64` when creating the container to match CodeQL CLI binary architecture and avoid Rosetta/loader errors on Apple Silicon hosts.

### Planned
- Add structured, parseable output (e.g., SARIF/JSON) and a consolidated summary report.
- Add CI workflow and containerized execution (Docker) with pinned tool versions.
- Add `--dry-run` mode and additional dependency discovery (Pipenv, setup.cfg/py, requirements.in).
- Add a minimal fixtures test suite covering JSON parsing normalization and the Struts2 POM detection helper (including property resolution).

### Fixed
- Resolved Semgrep rules path to use absolute `semgrep-rules/` directory relative to the project, avoiding CWD issues.
- Prevented OSV extractor errors by avoiding direct scans of `package.json`; scanning is restricted to lockfiles, with `npm audit` as fallback.
- Eliminated false "pip-audit not installed" failures by correcting flags and adding a module fallback when PATH resolution fails.

- CodeQL CLI detection inside scanner container:
  - Fixed PATH to include `/opt/codeql` so `codeql` binary is found.
  - Built scanner image for `linux/amd64` to match the CodeQL CLI binary architecture; Docker Compose updated to run `scanner`/`seeder` with `platform: linux/amd64` to avoid architecture mismatch (Rosetta/QEMU errors).

- Dashboard severity totals: `api.codeql_org_severity_totals` now `COALESCE`s null sums to `0` so empty datasets return numeric zeros instead of nulls.

### Changed
- CodeQL scanner: dynamic language detection and normalization to CodeQL-supported languages.
  - Normalizes common synonyms (e.g., `typescript` → `javascript`, `kotlin` → `java`, `c`/`c++`/`cc`/`cxx` → `cpp`).
  - Ignores unsupported languages with a diagnostic note.
  - Adds diagnostics in per-repo markdown: detected languages and any explicit normalization.
  - Honors `--skip-autobuild` by passing `--no-autobuild` to CodeQL database create for compiled languages (or when a custom `--build-command` is provided).

## [0.3.1] - 2025-09-12

### Added
- Hardcoded IPs/Hostnames report now includes proof fields:
  - JSON: adds `key` and `value` per finding.
  - Markdown: new columns Key and Value in Detailed Findings.
- Logging controls added to `scan_hardcoded_ips.py` (mirrors gitleaks script):
  - `-v/--verbose` (repeatable), `-q/--quiet`, `--loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}`.

### Changed
- `scan_gitleaks_fixed.py` and `scan_hardcoded_ips.py` now fall back from org to user on 404 for repo listing.
- `install_dependencies.sh` expanded with optional flags and post-install sanity check (documented in 0.3.0), minor refinements.

### Fixed
- Replaced deprecated `datetime.utcnow()` with `datetime.now(timezone.utc)` in `scan_hardcoded_ips.py`.
- Summary aggregation for hardcoded IPs: robust regex parsing prevents `ValueError` when reading markdown counts.
- Created missing Semgrep rules file `semgrep-rules/hardcoded-ips-hostnames.yaml` used by hardcoded IP scanner.

### Notes
- Consider adding a timeout to the Semgrep subprocess and SIGINT handling if long scans are interrupted.

## [0.3.0] - 2025-09-11

### Added
- Bandit and Trivy FS scanners integrated:
  - Bandit: writes `<repo>_bandit.json` and `<repo>_bandit.md` with summaries and sample findings.
  - Trivy (fs): writes `<repo>_trivy_fs.json` and `<repo>_trivy_fs.md` with severity summaries.
- Semgrep taint-mode optional pass (`--semgrep-taint`) and exploitable flows section.
- Gitleaks integration with secrets findings section.
- Policy gate and `policy.yaml` link surfaced in summary.
- Threat intel enrichment (KEV/EPSS) for Grype and Top 5 ranking:
  - Added KEV/EPSS badges and an explicit `Exploitability` column to "Top 5 Vulnerabilities".
  - New "Threat Intel" counts block and a "Threat Intel Diagnostics" subsection.
- VEX support passthrough for Grype (`--vex <file>`) and sample VEX file `struts2_exploitable.vex.json` (CVE-2017-5638 set to exploitable for Struts2).
- Summary now lists Bandit and Trivy report links in "Detailed Reports" when present.
- `install_dependencies.sh` expanded to install all scanners on macOS/Linux/Windows.
  - Optional flags: `--no-java`, `--no-go`, `--sanity-only`.
  - Post-install sanity check prints versions for all tools.

### Changed
- Summary table status for Bandit/Trivy is derived from JSON results rather than exit codes (avoids "success" when findings exist).
- Top 5 now considers Trivy FS vulnerabilities in addition to Grype to avoid empty results when VEX suppresses Grype findings.
- Improved repository information with contributors, languages, activity, and enhanced Top 5 ranking (KEV > EPSS > severity).

### Fixed
- Resolved `IndentationError` in `run_pip_audit_scan()` and removed placeholder lines.
- Hardened summary generation with additional try/except blocks around sections to ensure the summary always writes.

### Notes
- For Grype + VEX, best results occur when scanning an SBOM with bom-refs matching the VEX `affects` entries.

## [0.2.0] - 2025-09-10

### Added
- CLI options via `argparse` for org, API base, report directory, inclusion flags, worker count, and verbosity (`-v`, `-vv`).
- Logging with levels and timestamps; scanner outputs are captured and written to files.
- Parallel processing using `ThreadPoolExecutor` with configurable `--max-workers`.

### Changed
- GitHub authentication now uses `Authorization: Bearer <token>` and validates token presence at startup.
- HTTP calls use a `requests.Session` with retries/backoff and timeouts.
- Repository cloning is shallow (`--depth=1 --filter=blob:none`) and prefers `ssh_url` when available.
- Repositories that are forked or archived are skipped by default (override with `--include-forks` and `--include-archived`).
- Dependency discovery expanded to PEP 621 (`project.dependencies`) and Poetry (`tool.poetry.dependencies`).
- Temporary requirement files created from `pyproject.toml` are cleaned up after scanning.
- `safety` and `pip-audit` invocations now capture stdout/stderr and return codes; results saved to per-repo files.

## [0.1.0] - 2025-09-10

### Added
- Initial Python script `scan_repos.py` that:
  - Fetches repositories from a GitHub organization via the REST v3 API with pagination.
  - Clones repositories into a temporary working directory.
  - Detects Python dependencies via `requirements.txt` or PEP 621 `pyproject.toml` (`project.dependencies`).
  - Runs `safety` and `pip-audit` against discovered dependencies.
  - Writes per-repo vulnerability reports into `vulnerability_reports/`.
  - Cleans up temporary clone directories on completion.

### Known Issues
- `GITHUB_TOKEN` may be `None`, resulting in an invalid `Authorization` header. Token should be required and validated at startup.
- `clone_url` often requires credentials for private repos; support for `ssh_url` or embedded token over HTTPS is needed.
- `requests.get` calls lack timeouts and retry/backoff; risk of hangs and rate-limit failures.
- `safety` flags may not be correct for current versions (`--save-html` with `--output text` mismatch). Pin `safety` version and adjust CLI accordingly.
- Only PEP 621 dependencies are parsed from `pyproject.toml`; Poetry (`tool.poetry.dependencies`) and other ecosystems are not handled.
- Temporary requirements file created from `pyproject.toml` is not explicitly cleaned per repo.
- No aggregated summary across repos; reports are individual text/markdown files.
- Limited error handling: subprocess failures for scanners are ignored (`check=False`) without surfacing status.

### Security Notes
- Avoid echoing tokens. Consider using `Bearer` scheme for the header and validate presence.
- Prefer least-privilege tokens; document required scopes.

[Unreleased]: https://example.com/compare/v0.3.1...HEAD
[0.3.1]: https://example.com/compare/v0.3.0...v0.3.1
[0.3.0]: https://example.com/compare/v0.2.0...v0.3.0
[0.2.0]: https://example.com/compare/v0.1.0...v0.2.0
[0.1.0]: https://example.com/releases/tag/v0.1.0
