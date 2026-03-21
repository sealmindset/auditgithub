"""
AI-Powered Credential Matcher

Intelligently matches discovered credentials to target API services
using file proximity, naming conventions, domain matching, and LLM inference.

Also provides AI-powered correlation functions for:
- Credentials to URLs
- Inbound endpoints to servers
- Outbound endpoints to servers
- Servers to credentials

NEW OSINT-FIRST APPROACH (v2):
1. Pre-validate URLs to check if they require authentication
2. Only map credentials to URLs that actually need auth
3. Use OSINT to understand API requirements before mapping
4. Skip public endpoints that don't need credentials
"""

import json
import os
import re
import asyncio
import httpx
import logging
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# Service detection patterns
SERVICE_PATTERNS = {
    'Azure': {
        'keywords': ['azure', 'ocp-apim', 'subscription', 'microsoft'],
        'domains': ['azure-api.net', 'azure.com', 'microsoft.com', 'windows.net'],
        'secret_types': ['azure_key', 'azure_endpoint', 'subscription_key']
    },
    'AWS': {
        'keywords': ['aws', 'amazon', 's3', 'lambda', 'dynamodb', 'ec2'],
        'domains': ['amazonaws.com', 'aws.amazon.com', 'execute-api'],
        'secret_types': ['aws_access_key', 'aws_secret']
    },
    'AWS_Cognito': {
        'keywords': ['cognito', 'cognito_client', 'user_pool', 'identity_pool'],
        'domains': ['cognito-idp', 'cognito-identity', 'amazonaws.com'],
        'secret_types': ['cognito_client_id', 'cognito_client_secret', 'cognito_user_pool', 'cognito']
    },
    'Mixpanel': {
        'keywords': ['mixpanel'],
        'domains': ['mixpanel.com', 'api.mixpanel.com'],
        'secret_types': ['mixpanel_token', 'mixpanel_key']
    },
    'Instabug': {
        'keywords': ['instabug'],
        'domains': ['instabug.com'],
        'secret_types': ['instabug_key', 'instabug_token']
    },
    'Firebase': {
        'keywords': ['firebase', 'fcm', 'google'],
        'domains': ['firebase.google.com', 'firebaseio.com', 'googleapis.com'],
        'secret_types': ['firebase_key', 'google_api_key']
    },
    'Stripe': {
        'keywords': ['stripe', 'payment'],
        'domains': ['stripe.com', 'api.stripe.com'],
        'secret_types': ['stripe_key', 'stripe_secret']
    },
    'SleepIQ': {
        'keywords': ['sleepiq', 'sleepnumber', 'siq'],
        'domains': ['sleepiq.sleepnumber.com', 'sleepnumber.com'],
        'secret_types': ['api_key', 'x-api-key']
    }
}

# =============================================================================
# Service-Specific API Endpoints
# =============================================================================
# When a credential type is detected but no matching URL is found in the codebase,
# use the canonical API endpoint for that service. This ensures credentials are
# tested against the CORRECT service, not random URLs from the codebase.

SERVICE_API_ENDPOINTS = {
    'Mixpanel': {
        'api_url': 'https://mixpanel.com/api/app/me',  # Service Account API endpoint
        'test_paths': ['/api/app/me', '/api/app/workspaces'],
        'auth_method': 'basic_token',  # Token as username, empty password OR service_account_id:secret
        'description': 'Mixpanel Service Account API',
        'documentation_url': 'https://developer.mixpanel.com/reference/service-accounts'
    },
    'Azure': {
        'api_url': None,  # Requires specific endpoint from code
        'test_paths': ['/'],
        'auth_method': 'header',
        'description': 'Azure API Management'
    },
    'AWS': {
        'api_url': None,  # Requires specific endpoint from code
        'test_paths': ['/'],
        'auth_method': 'aws_sig',
        'description': 'AWS Services'
    },
    'AWS_Cognito': {
        'api_url': 'https://cognito-idp.us-east-1.amazonaws.com',
        'test_paths': ['/'],
        'auth_method': 'cognito_api',
        'description': 'AWS Cognito User Pool API - client_id goes in request body, not headers',
        'notes': 'cognito_client_id is NOT a bearer token - it identifies the app client'
    },
    'Instabug': {
        'api_url': 'https://api.instabug.com',
        'test_paths': ['/v1/applications', '/v1/bugs'],
        'auth_method': 'header',
        'description': 'Instabug Bug Reporting API'
    },
    'Firebase': {
        'api_url': 'https://fcm.googleapis.com',
        'test_paths': ['/fcm/send', '/v1/projects'],
        'auth_method': 'key_prefix',
        'description': 'Firebase Cloud Messaging'
    },
    'Stripe': {
        'api_url': 'https://api.stripe.com',
        'test_paths': ['/v1/charges', '/v1/customers', '/v1/balance'],
        'auth_method': 'basic',
        'description': 'Stripe Payment API'
    },
    'SleepIQ': {
        'api_url': 'https://prod-api.sleepiq.sleepnumber.com',
        'test_paths': ['/rest/login', '/rest/bed'],
        'auth_method': 'header',
        'description': 'SleepIQ Smart Bed API'
    },
    'Twilio': {
        'api_url': 'https://api.twilio.com',
        'test_paths': ['/2010-04-01/Accounts'],
        'auth_method': 'basic',
        'description': 'Twilio Communications API'
    },
    'SendGrid': {
        'api_url': 'https://api.sendgrid.com',
        'test_paths': ['/v3/mail/send', '/v3/user/profile'],
        'auth_method': 'bearer',
        'description': 'SendGrid Email API'
    },
    'Slack': {
        'api_url': 'https://slack.com/api',
        'test_paths': ['/auth.test', '/users.list'],
        'auth_method': 'bearer',
        'description': 'Slack API'
    },
    'GitHub': {
        'api_url': 'https://api.github.com',
        'test_paths': ['/user', '/rate_limit'],
        'auth_method': 'bearer',
        'description': 'GitHub API'
    },
    'OpenAI': {
        'api_url': 'https://api.openai.com',
        'test_paths': ['/v1/models', '/v1/chat/completions'],
        'auth_method': 'bearer',
        'description': 'OpenAI API'
    },
    'Anthropic': {
        'api_url': 'https://api.anthropic.com',
        'test_paths': ['/v1/messages'],
        'auth_method': 'header',
        'description': 'Anthropic Claude API'
    }
}


def get_service_api_endpoint(service_name: str) -> dict:
    """
    Get the canonical API endpoint for a service.
    Returns endpoint config or None if service requires specific URL from code.
    """
    return SERVICE_API_ENDPOINTS.get(service_name, {})


# Type normalization
TYPE_DISPLAY_NAMES = {
    'api_key': 'API Key',
    'azure_key': 'API Key',
    'azure_endpoint': 'Endpoint',
    'subscription_key': 'Subscription Key',
    'cognito_client_id': 'Client ID',
    'client_secret': 'Client Secret',
    'mixpanel_token': 'API Token',
    'instabug_key': 'App Key',
    'hex_key': 'Hex Key',
    'signature': 'Signature',
    'x-api-key': 'API Key',
    'bearer_token': 'Bearer Token',
    'basic_auth': 'Basic Auth'
}


def detect_service_from_credential(credential: Dict) -> tuple[str, int]:
    """
    Detect the likely service for a credential based on patterns.
    Returns (service_name, base_certainty_score).
    """
    secret_type = credential.get('metadata', {}).get('secret_type', '')
    code = credential.get('code', '')
    path = credential.get('path', '')
    endpoint = credential.get('endpoint_path', '')
    message = credential.get('message', '')
    
    combined_text = f"{secret_type} {code} {path} {endpoint} {message}".lower()
    
    best_match = ('Unknown', 30)
    
    for service, patterns in SERVICE_PATTERNS.items():
        score = 0
        
        # Check secret_type match (strongest signal)
        if secret_type in patterns.get('secret_types', []):
            score += 50
        
        # Check keywords
        for keyword in patterns.get('keywords', []):
            if keyword in combined_text:
                score += 20
                break
        
        # Check domain patterns in endpoint
        for domain in patterns.get('domains', []):
            if domain in endpoint.lower() or domain in code.lower():
                score += 25
                break
        
        if score > best_match[1]:
            best_match = (service, min(score, 98))
    
    return best_match


def match_credential_to_server(credential: Dict, servers: List[str]) -> tuple[str, int]:
    """
    Match a credential to a specific server URL.
    Returns (server_url, certainty_boost).
    """
    code = credential.get('code', '')
    path = credential.get('path', '')
    environment = credential.get('metadata', {}).get('environment', '')
    
    for server in servers:
        parsed = urlparse(server)
        domain = parsed.netloc.lower()
        
        # Direct domain match in code
        if domain in code.lower():
            return (server, 30)
        
        # Environment match (prod/stage/test)
        if environment:
            if 'prod' in environment.lower() and 'prod' in server.lower():
                return (server, 20)
            if 'stage' in environment.lower() and 'stage' in server.lower():
                return (server, 20)
            if 'test' in environment.lower() and 'test' in server.lower():
                return (server, 20)
        
        # Keyword matching
        server_keywords = set(re.findall(r'\w+', domain))
        path_keywords = set(re.findall(r'\w+', path.lower()))
        code_keywords = set(re.findall(r'\w+', code.lower()))
        
        overlap = server_keywords & (path_keywords | code_keywords)
        if len(overlap) >= 2:
            return (server, 15)
    
    return (servers[0] if servers else '', 0)


def extract_credential_value(credential: Dict) -> str:
    """Extract the actual credential value from the code."""
    code = credential.get('code', '')
    
    # Try common patterns
    patterns = [
        r'["\']([A-Za-z0-9+/=_-]{20,})["\']',  # Quoted long strings
        r'=\s*([A-Za-z0-9+/=_-]{20,})',  # After equals
        r':\s*([A-Za-z0-9+/=_-]{20,})',  # After colon
    ]
    
    for pattern in patterns:
        match = re.search(pattern, code)
        if match:
            return match.group(1)
    
    # Fallback: extract from code after = or :
    if '=' in code:
        parts = code.split('=', 1)
        if len(parts) > 1:
            return parts[1].strip().strip('"\'')
    
    return code


def match_credentials(
    project_name: str,
    server_url: Optional[str] = None,
    reports_dir: str = "/app/vulnerability_reports"
) -> List[Dict[str, Any]]:
    """
    Match credentials to services with certainty scores.
    
    Args:
        project_name: Name of the project
        server_url: Optional filter for specific server
        reports_dir: Directory containing vulnerability reports
    
    Returns:
        List of matched credentials with service, type, value, certainty
    """
    project_dir = os.path.join(reports_dir, project_name)
    endpoints_file = os.path.join(project_dir, f"{project_name}_api_endpoints.json")
    openapi_file = os.path.join(project_dir, f"{project_name}_openapi.yaml")
    
    if not os.path.exists(endpoints_file):
        return []
    
    # Load endpoints data
    with open(endpoints_file, 'r') as f:
        data = json.load(f)
    
    # Extract servers from OpenAPI if available
    servers = []
    if os.path.exists(openapi_file):
        try:
            import yaml
            with open(openapi_file, 'r') as f:
                spec = yaml.safe_load(f)
            servers = [s.get('url', '') for s in spec.get('servers', [])]
        except (IOError, yaml.YAMLError, KeyError, AttributeError) as e:
            logger.debug(f"Failed to parse OpenAPI spec from {openapi_file}: {str(e)}")
    
    # Get credentials (non-URL endpoints)
    credentials = []
    for ep in data.get('outbound_endpoints', []):
        secret_type = ep.get('metadata', {}).get('secret_type', '')
        if secret_type and secret_type != 'api_url':
            credentials.append(ep)
    
    # Match each credential
    matched = []
    for cred in credentials:
        service, base_score = detect_service_from_credential(cred)
        
        # Match to server if available
        matched_server = ''
        server_boost = 0
        if servers:
            matched_server, server_boost = match_credential_to_server(cred, servers)
        
        # Calculate final certainty
        certainty = min(base_score + server_boost, 99)
        
        # Get type display name
        secret_type = cred.get('metadata', {}).get('secret_type', 'unknown')
        type_display = TYPE_DISPLAY_NAMES.get(secret_type, secret_type.replace('_', ' ').title())
        
        # Extract value
        value = extract_credential_value(cred)
        
        matched.append({
            'service': service,
            'type': type_display,
            'value': value,
            'certainty': certainty,
            'server_url': matched_server,
            'file_path': cred.get('path', ''),
            'line': cred.get('line', 0),
            'environment': cred.get('metadata', {}).get('environment', ''),
            'raw_type': secret_type
        })
    
    # Sort by certainty descending
    matched.sort(key=lambda x: x['certainty'], reverse=True)
    
    # Filter by server if specified
    if server_url:
        matched = [m for m in matched if server_url in m.get('server_url', '')]
    
    return matched


async def match_credentials_with_llm(
    project_name: str,
    server_url: Optional[str] = None,
    reports_dir: str = "/app/vulnerability_reports"
) -> List[Dict[str, Any]]:
    """
    Enhanced credential matching using Claude LLM for better certainty.
    Falls back to pattern matching if LLM unavailable.
    """
    # First get pattern-based matches
    matched = match_credentials(project_name, server_url, reports_dir)
    
    # Try LLM enhancement
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key or not matched:
        return matched
    
    try:
        import anthropic
        # AI Safety imports
        try:
            from src.services.ai_safety.sanitize import sanitize_prompt_input
            from src.services.ai_safety.pii_masker import mask_pii, unmask_pii
            from src.services.ai_safety.validate import validate_agent_output
            from src.services.ai_safety.errors import sanitize_ai_error
            _safety_available = True
        except ImportError:
            _safety_available = False

        client = anthropic.Anthropic(api_key=api_key)

        # Prepare context for LLM - mask credential values before sending
        cred_summary = []
        for m in matched[:20]:  # Limit to 20 for context
            cred_summary.append({
                'service_guess': m['service'],
                'type': m['type'],
                'value': m['value'][:4] + '****' if len(m.get('value', '')) > 4 else '****',
                'file': m['file_path'],
                'environment': m['environment']
            })

        prompt = f"""Analyze these discovered API credentials and refine the service attribution.

Credentials found:
{json.dumps(cred_summary, indent=2)}

For each credential, confirm or correct the service name and provide a certainty score (0-100).
Consider:
- File location patterns
- Naming conventions
- Credential format/structure
- Environment indicators

Return a JSON array with objects containing:
- index (0-based position in input)
- service (confirmed/corrected service name)
- certainty (0-100 score)

Only return the JSON array, no other text."""

        # AI Safety: sanitize and mask prompt
        if _safety_available:
            prompt = sanitize_prompt_input(prompt)
            prompt, pii_mappings = mask_pii(prompt)
        else:
            pii_mappings = {}

        response = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )

        # Parse LLM response
        result_text = response.content[0].text.strip()

        # AI Safety: validate output
        if _safety_available:
            validation = validate_agent_output(result_text)
            result_text = validation.get("sanitized_text", result_text)
            result_text = unmask_pii(result_text, pii_mappings)
        if result_text.startswith('['):
            llm_results = json.loads(result_text)
            
            # Apply LLM refinements
            for llm_item in llm_results:
                idx = llm_item.get('index', -1)
                if 0 <= idx < len(matched):
                    matched[idx]['service'] = llm_item.get('service', matched[idx]['service'])
                    matched[idx]['certainty'] = llm_item.get('certainty', matched[idx]['certainty'])
            
            # Re-sort after LLM refinement
            matched.sort(key=lambda x: x['certainty'], reverse=True)
    
    except Exception as e:
        # LLM failed, return pattern-based matches
        print(f"LLM credential matching failed: {e}")
    
    return matched


# =============================================================================
# Environment Detection Helpers
# =============================================================================

# Compatible environment groups
ENVIRONMENT_GROUPS = {
    'production': {'prod', 'production', 'prd', 'live'},
    'staging': {'stage', 'staging', 'stg', 'preprod', 'pre-prod'},
    'development': {'dev', 'develop', 'development', 'sandbox', 'local'},
    'test': {'test', 'testing', 'qa', 'uat', 'quality'}
}


def _detect_environment_from_url(url: str) -> str:
    """
    Detect environment from URL patterns.
    
    Returns: 'production', 'staging', 'development', 'test', or 'unknown'
    """
    url_lower = url.lower()
    
    # Production indicators
    if any(x in url_lower for x in ['prod', 'api.', 'www.', 'live']):
        if not any(x in url_lower for x in ['dev', 'stage', 'test', 'qa', 'sandbox']):
            return 'production'
    
    # Staging indicators
    if any(x in url_lower for x in ['stage', 'staging', 'stg', 'preprod']):
        return 'staging'
    
    # Development indicators
    if any(x in url_lower for x in ['dev', 'develop', 'sandbox', 'local']):
        return 'development'
    
    # Test indicators
    if any(x in url_lower for x in ['test', 'qa', 'uat']):
        return 'test'
    
    return 'unknown'


def _detect_environment_from_path(file_path: str) -> str:
    """
    Detect environment from file path patterns.
    
    Returns: 'production', 'staging', 'development', 'test', or 'unknown'
    """
    path_lower = file_path.lower()
    
    # Production indicators
    if any(x in path_lower for x in ['/prod/', 'production', '.prod.', '-prod-', '_prod_']):
        return 'production'
    
    # Staging indicators
    if any(x in path_lower for x in ['/stage/', 'staging', '.stage.', '-stage-', '_stage_']):
        return 'staging'
    
    # Development indicators
    if any(x in path_lower for x in ['/dev/', 'development', '.dev.', '-dev-', '_dev_', 'sandbox']):
        return 'development'
    
    # Test indicators
    if any(x in path_lower for x in ['/test/', 'testing', '.test.', '-test-', '_test_', '/qa/', 'uat']):
        return 'test'
    
    return 'unknown'


def _environments_compatible(env1: str, env2: str) -> Tuple[bool, int]:
    """
    Check if two environments are compatible.
    
    Returns: (is_compatible, confidence_boost)
    - Exact match: +35 points
    - Same group: +25 points
    - Related (dev/test): +15 points
    - Incompatible: 0 points
    """
    env1_lower = env1.lower() if env1 else ''
    env2_lower = env2.lower() if env2 else ''
    
    # Exact match
    if env1_lower == env2_lower and env1_lower:
        return (True, 35)
    
    # Find groups
    env1_group = None
    env2_group = None
    
    for group_name, group_values in ENVIRONMENT_GROUPS.items():
        if any(v in env1_lower for v in group_values):
            env1_group = group_name
        if any(v in env2_lower for v in group_values):
            env2_group = group_name
    
    # Same group
    if env1_group and env1_group == env2_group:
        return (True, 25)
    
    # Related groups (dev and test are often interchangeable)
    related_pairs = [
        ('development', 'test'),
        ('staging', 'test'),
    ]
    if (env1_group, env2_group) in related_pairs or (env2_group, env1_group) in related_pairs:
        return (True, 15)
    
    return (False, 0)


def _extract_domain_keywords(url: str) -> set:
    """Extract meaningful keywords from a URL domain."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # Remove common TLDs and split
        domain = re.sub(r'\.(com|net|org|io|dev|app|co|api)$', '', domain)
        keywords = set(re.findall(r'[a-z]{3,}', domain))
        # Remove common words
        keywords -= {'www', 'api', 'http', 'https', 'azure', 'amazonaws'}
        return keywords
    except (ValueError, AttributeError, TypeError) as e:
        logger.debug(f"Failed to extract domain keywords from URL {url}: {str(e)}")
        return set()


# =============================================================================
# URL Pre-Validation Functions
# =============================================================================

async def pre_validate_url(url: str, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Pre-validate a URL to determine if it requires authentication.
    
    Makes a request WITHOUT credentials to classify the endpoint:
    - PUBLIC: Returns 200-299 without auth (no credential needed)
    - AUTH_REQUIRED: Returns 401/403 (needs credential)
    - NOT_FOUND: Returns 404 (endpoint doesn't exist)
    - ERROR: Connection failed or other error
    
    Returns:
        Dict with 'status', 'status_code', 'requires_auth', 'response_preview'
    """
    result = {
        'url': url,
        'status': 'unknown',
        'status_code': None,
        'requires_auth': None,
        'response_preview': '',
        'headers_hint': []  # Headers that might be required based on response
    }
    
    try:
        ssl_verify = os.getenv("SSL_VERIFY", "true").lower() != "false"
        async with httpx.AsyncClient(timeout=timeout, verify=ssl_verify, follow_redirects=True) as client:
            # Make request without any auth headers
            headers = {
                'User-Agent': 'AuditGH-SecurityScanner/1.0',
                'Accept': 'application/json, text/plain, */*'
            }
            
            response = await client.get(url, headers=headers)
            result['status_code'] = response.status_code
            result['response_preview'] = response.text[:500] if response.text else ''
            
            if response.status_code in (200, 201, 202, 204):
                result['status'] = 'PUBLIC'
                result['requires_auth'] = False
                logger.info(f"[PreValidate] {url} is PUBLIC (no auth required)")
                
            elif response.status_code in (401, 403):
                result['status'] = 'AUTH_REQUIRED'
                result['requires_auth'] = True
                
                # Try to extract auth hints from response
                www_auth = response.headers.get('WWW-Authenticate', '')
                if www_auth:
                    result['headers_hint'].append(f"WWW-Authenticate: {www_auth}")
                
                # Check for common auth header hints in response body
                body_lower = result['response_preview'].lower()
                if 'api-key' in body_lower or 'apikey' in body_lower:
                    result['headers_hint'].append('X-API-Key or Api-Key header likely required')
                if 'bearer' in body_lower or 'token' in body_lower:
                    result['headers_hint'].append('Authorization: Bearer token likely required')
                if 'subscription' in body_lower:
                    result['headers_hint'].append('Ocp-Apim-Subscription-Key likely required (Azure)')
                
                logger.info(f"[PreValidate] {url} requires AUTH (401/403)")
                
            elif response.status_code == 404:
                result['status'] = 'NOT_FOUND'
                result['requires_auth'] = None  # Can't determine
                logger.info(f"[PreValidate] {url} NOT_FOUND (404)")
                
            else:
                result['status'] = 'OTHER'
                result['requires_auth'] = None
                logger.info(f"[PreValidate] {url} returned {response.status_code}")
                
    except httpx.TimeoutException:
        result['status'] = 'TIMEOUT'
        result['requires_auth'] = None
        logger.warning(f"[PreValidate] {url} timed out")
        
    except httpx.ConnectError as e:
        result['status'] = 'CONNECTION_ERROR'
        result['requires_auth'] = None
        logger.warning(f"[PreValidate] {url} connection error: {e}")
        
    except Exception as e:
        result['status'] = 'ERROR'
        result['requires_auth'] = None
        logger.warning(f"[PreValidate] {url} error: {e}")
    
    return result


async def pre_validate_urls(urls: List[str], max_concurrent: int = 5) -> Dict[str, Dict]:
    """
    Pre-validate multiple URLs concurrently.
    
    Returns:
        Dict mapping URL to validation result
    """
    results = {}
    
    # Use semaphore to limit concurrent requests
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def validate_with_limit(url: str):
        async with semaphore:
            return await pre_validate_url(url)
    
    # Run validations concurrently
    tasks = [validate_with_limit(url) for url in urls]
    validation_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for url, result in zip(urls, validation_results):
        if isinstance(result, Exception):
            results[url] = {
                'url': url,
                'status': 'ERROR',
                'status_code': None,
                'requires_auth': None,
                'error': str(result)
            }
        else:
            results[url] = result
    
    return results


# =============================================================================
# Correlation Functions
# =============================================================================

async def correlate_credentials_to_urls_v2(
    project_name: str,
    reports_dir: str = "/app/vulnerability_reports",
    pre_validate: bool = True
) -> List[Dict[str, Any]]:
    """
    IMPROVED AI-powered correlation of credentials to their target URLs.
    
    NEW OSINT-FIRST APPROACH:
    1. Extract all URLs from codebase
    2. Pre-validate URLs to check if they require authentication
    3. Only map credentials to AUTH_REQUIRED URLs
    4. Skip PUBLIC URLs (no credential needed)
    5. Use service detection for proper credential-URL matching
    
    Args:
        project_name: Name of the project
        reports_dir: Directory containing vulnerability reports
        pre_validate: If True, test URLs without auth first to filter public endpoints
    
    Returns:
        List of credential-URL pairs with confidence scores
    """
    project_dir = os.path.join(reports_dir, project_name)
    endpoints_file = os.path.join(project_dir, f"{project_name}_api_endpoints.json")
    openapi_file = os.path.join(project_dir, f"{project_name}_openapi.yaml")
    
    if not os.path.exists(endpoints_file):
        return []
    
    # Load endpoints data
    with open(endpoints_file, 'r') as f:
        data = json.load(f)
    
    # Extract servers from OpenAPI
    servers = []
    if os.path.exists(openapi_file):
        try:
            import yaml
            with open(openapi_file, 'r') as f:
                spec = yaml.safe_load(f)
            servers = spec.get('servers', [])
        except (IOError, yaml.YAMLError, KeyError, AttributeError) as e:
            logger.debug(f"Failed to parse OpenAPI spec from {openapi_file}: {str(e)}")
    
    # Extract URLs from outbound endpoints
    urls = []
    for ep in data.get('outbound_endpoints', []):
        secret_type = ep.get('metadata', {}).get('secret_type', '')
        if secret_type == 'api_url':
            endpoint_path = ep.get('endpoint_path', '')
            if endpoint_path and endpoint_path.startswith('http'):
                urls.append({
                    'url': endpoint_path,
                    'file': ep.get('path', ''),
                    'line': ep.get('line', 0),
                    'environment': _detect_environment_from_url(endpoint_path)
                })
    
    # Add servers as URLs
    for server in servers:
        url = server.get('url', '')
        if url:
            urls.append({
                'url': url,
                'file': 'openapi.yaml',
                'line': 0,
                'environment': _detect_environment_from_url(url)
            })
    
    # Get credentials (non-URL endpoints)
    credentials = []
    for ep in data.get('outbound_endpoints', []):
        secret_type = ep.get('metadata', {}).get('secret_type', '')
        if secret_type and secret_type != 'api_url':
            credentials.append({
                'type': secret_type,
                'value': extract_credential_value(ep),
                'file': ep.get('path', ''),
                'line': ep.get('line', 0),
                'code': ep.get('code', ''),
                'environment': ep.get('metadata', {}).get('environment', ''),
                'raw': ep
            })
    
    if not urls or not credentials:
        return []
    
    # =========================================================================
    # STEP 1: PRE-VALIDATE URLs (NEW)
    # =========================================================================
    url_validation = {}
    auth_required_urls = []
    public_urls = []
    
    if pre_validate:
        logger.info(f"[AI Matcher] Pre-validating {len(urls)} URLs...")
        unique_urls = list(set(u['url'] for u in urls))
        url_validation = await pre_validate_urls(unique_urls)
        
        for url_info in urls:
            url = url_info['url']
            validation = url_validation.get(url, {})
            
            if validation.get('requires_auth') == True:
                auth_required_urls.append(url_info)
            elif validation.get('requires_auth') == False:
                public_urls.append(url_info)
                logger.info(f"[AI Matcher] SKIPPING public URL: {url}")
            else:
                # Unknown - include for safety
                auth_required_urls.append(url_info)
        
        logger.info(f"[AI Matcher] Found {len(auth_required_urls)} AUTH_REQUIRED, {len(public_urls)} PUBLIC URLs")
    else:
        auth_required_urls = urls
    
    # =========================================================================
    # STEP 2: CORRELATE CREDENTIALS TO AUTH_REQUIRED URLs ONLY
    # =========================================================================
    correlations = []
    
    for cred in credentials:
        cred_file = cred['file']
        cred_line = cred['line']
        cred_env = cred['environment'] or _detect_environment_from_path(cred_file)
        cred_code = cred['code'].lower()
        cred_type = cred['type'].lower()
        
        best_url = None
        best_score = 0
        best_reasons = []
        
        # Only consider AUTH_REQUIRED URLs
        for url_info in auth_required_urls:
            url = url_info['url']
            url_file = url_info['file']
            url_line = url_info['line']
            url_env = url_info['environment']
            
            score = 0
            reasons = []
            
            # Same file proximity (+40)
            if cred_file == url_file and cred_file:
                score += 40
                reasons.append("Same file")
                
                # Close line numbers
                line_diff = abs(cred_line - url_line)
                if line_diff < 10:
                    score += 20
                    reasons.append(f"Within {line_diff} lines")
                elif line_diff < 50:
                    score += 10
                    reasons.append(f"Within {line_diff} lines")
            
            # Environment matching
            env_compatible, env_boost = _environments_compatible(cred_env, url_env)
            if env_compatible and env_boost > 0:
                score += env_boost
                reasons.append(f"Environment match ({cred_env}→{url_env})")
            
            # Domain keyword in code (+15)
            url_keywords = _extract_domain_keywords(url)
            for keyword in url_keywords:
                if keyword in cred_code and len(keyword) >= 4:
                    score += 15
                    reasons.append(f"Domain keyword '{keyword}' in code")
                    break
            
            # Service type match (+30) OR mismatch (DISQUALIFY)
            url_lower = url.lower()
            
            # Services that MUST use their own endpoints
            service_specific_creds = {
                'cognito': ['cognito-idp', 'cognito-identity', 'amazonaws.com'],
                'mixpanel': ['mixpanel.com', 'api.mixpanel.com'],
                'stripe': ['stripe.com', 'api.stripe.com'],
                'firebase': ['firebase', 'googleapis.com', 'fcm.googleapis.com'],
                'github': ['github.com', 'api.github.com'],
                'openai': ['openai.com', 'api.openai.com'],
                'slack': ['slack.com', 'api.slack.com'],
                'azure': ['azure-api.net', 'azure.com', 'microsoft.com'],
            }
            
            # Check for service type match
            service_matched = False
            for service_key, url_patterns in service_specific_creds.items():
                if service_key in cred_type:
                    for pattern in url_patterns:
                        if pattern in url_lower:
                            score += 30
                            reasons.append(f"Service type match ({service_key})")
                            service_matched = True
                            break
                    
                    # CRITICAL: If credential is service-specific and URL doesn't match, DISQUALIFY
                    if not service_matched:
                        score = 0
                        reasons = [f"DISQUALIFIED: {cred_type} requires {service_key} endpoint, not {url}"]
                    break
            
            # Direct URL extraction from code (+90)
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain and domain in cred_code:
                score += 90
                reasons.append("Direct URL in code")
            
            # Add auth requirement info from pre-validation
            validation = url_validation.get(url, {})
            if validation.get('headers_hint'):
                reasons.append(f"Auth hints: {', '.join(validation['headers_hint'][:2])}")
            
            score = min(score, 99)
            
            if score > best_score:
                best_score = score
                best_url = url_info
                best_reasons = reasons
        
        # =====================================================================
        # FALLBACK: Use service-specific canonical endpoint
        # =====================================================================
        if not best_url or best_score < 30:
            service_name, service_score = detect_service_from_credential(cred['raw'])
            service_endpoint = get_service_api_endpoint(service_name)
            
            if service_endpoint and service_endpoint.get('api_url'):
                canonical_url = service_endpoint['api_url']
                best_url = {
                    'url': canonical_url,
                    'file': '[Service-specific endpoint]',
                    'environment': 'production'
                }
                best_score = max(service_score, 70)
                best_reasons = [
                    f"Service detected: {service_name}",
                    f"Canonical API endpoint: {canonical_url}",
                    f"Auth method: {service_endpoint.get('auth_method', 'unknown')}"
                ]
                logger.info(f"[AI Matcher] Using canonical endpoint for {service_name}: {canonical_url}")
            elif not best_url:
                logger.info(f"[AI Matcher] SKIPPING {cred['type']}: No matching AUTH_REQUIRED URL")
                continue
        
        if best_url:
            correlations.append({
                'credential': {
                    'type': cred['type'],
                    'value': cred['value'],  # Full value for security analyst validation
                    'file': cred['file'],
                    'line': cred['line'],
                    'environment': cred_env
                },
                'url': best_url['url'],
                'url_file': best_url.get('file', ''),
                'confidence': best_score,
                'match_reasons': best_reasons,
                'requires_auth': url_validation.get(best_url['url'], {}).get('requires_auth', True),
                'auth_hints': url_validation.get(best_url['url'], {}).get('headers_hint', []),
                'llm_enhanced': False
            })
    
    # Sort by confidence descending
    correlations.sort(key=lambda x: x['confidence'], reverse=True)
    
    # Add summary of skipped public URLs
    if public_urls:
        logger.info(f"[AI Matcher] Skipped {len(public_urls)} public URLs that don't require auth:")
        for url_info in public_urls[:5]:
            logger.info(f"  - {url_info['url']}")
    
    return correlations


async def correlate_credentials_to_urls(
    project_name: str,
    reports_dir: str = "/app/vulnerability_reports"
) -> List[Dict[str, Any]]:
    """
    AI-powered correlation of credentials to their target URLs.
    
    Analyzes:
    - File proximity (credentials and URLs in same file)
    - Code context (credentials used with specific URLs)
    - Environment matching (dev credentials with dev URLs)
    - Naming conventions (variable names suggesting target)
    - Service type matching (Azure key → Azure URL)
    
    Returns list of credential-URL pairs with confidence scores.
    """
    project_dir = os.path.join(reports_dir, project_name)
    endpoints_file = os.path.join(project_dir, f"{project_name}_api_endpoints.json")
    openapi_file = os.path.join(project_dir, f"{project_name}_openapi.yaml")
    
    if not os.path.exists(endpoints_file):
        return []
    
    # Load endpoints data
    with open(endpoints_file, 'r') as f:
        data = json.load(f)
    
    # Extract servers from OpenAPI
    servers = []
    if os.path.exists(openapi_file):
        try:
            import yaml
            with open(openapi_file, 'r') as f:
                spec = yaml.safe_load(f)
            servers = spec.get('servers', [])
        except (IOError, yaml.YAMLError, KeyError, AttributeError) as e:
            logger.debug(f"Failed to parse OpenAPI spec from {openapi_file}: {str(e)}")
    
    # Extract URLs from outbound endpoints
    urls = []
    for ep in data.get('outbound_endpoints', []):
        secret_type = ep.get('metadata', {}).get('secret_type', '')
        if secret_type == 'api_url':
            endpoint_path = ep.get('endpoint_path', '')
            if endpoint_path and endpoint_path.startswith('http'):
                urls.append({
                    'url': endpoint_path,
                    'file': ep.get('path', ''),
                    'line': ep.get('line', 0),
                    'environment': _detect_environment_from_url(endpoint_path)
                })
    
    # Add servers as URLs
    for server in servers:
        url = server.get('url', '')
        if url:
            urls.append({
                'url': url,
                'file': 'openapi.yaml',
                'line': 0,
                'environment': _detect_environment_from_url(url)
            })
    
    # Get credentials (non-URL endpoints)
    credentials = []
    for ep in data.get('outbound_endpoints', []):
        secret_type = ep.get('metadata', {}).get('secret_type', '')
        if secret_type and secret_type != 'api_url':
            credentials.append({
                'type': secret_type,
                'value': extract_credential_value(ep),
                'file': ep.get('path', ''),
                'line': ep.get('line', 0),
                'code': ep.get('code', ''),
                'environment': ep.get('metadata', {}).get('environment', ''),
                'raw': ep
            })
    
    if not urls or not credentials:
        return []
    
    # Correlate each credential to URLs
    correlations = []
    
    for cred in credentials:
        cred_file = cred['file']
        cred_line = cred['line']
        cred_env = cred['environment'] or _detect_environment_from_path(cred_file)
        cred_code = cred['code'].lower()
        
        best_url = None
        best_score = 0
        best_reasons = []
        
        for url_info in urls:
            url = url_info['url']
            url_file = url_info['file']
            url_line = url_info['line']
            url_env = url_info['environment']
            
            score = 0
            reasons = []
            
            # Same file proximity (+40)
            if cred_file == url_file and cred_file:
                score += 40
                reasons.append("Same file")
                
                # Close line numbers (+20 for <10 lines, +10 for <50 lines)
                line_diff = abs(cred_line - url_line)
                if line_diff < 10:
                    score += 20
                    reasons.append(f"Within {line_diff} lines")
                elif line_diff < 50:
                    score += 10
                    reasons.append(f"Within {line_diff} lines")
            
            # Environment matching
            env_compatible, env_boost = _environments_compatible(cred_env, url_env)
            if env_compatible and env_boost > 0:
                score += env_boost
                reasons.append(f"Environment match ({cred_env}→{url_env})")
            
            # Domain keyword in code (+15)
            url_keywords = _extract_domain_keywords(url)
            for keyword in url_keywords:
                if keyword in cred_code and len(keyword) >= 4:
                    score += 15
                    reasons.append(f"Domain keyword '{keyword}' in code")
                    break
            
            # Domain in file path (+10)
            for keyword in url_keywords:
                if keyword in cred_file.lower() and len(keyword) >= 4:
                    score += 10
                    reasons.append(f"Domain keyword '{keyword}' in path")
                    break
            
            # Service type match (+30) OR mismatch (DISQUALIFY)
            cred_type = cred['type'].lower()
            url_lower = url.lower()
            
            # Services that MUST use their own endpoints (not generic URLs)
            service_specific_creds = {
                'cognito': ['cognito-idp', 'cognito-identity', 'amazonaws.com'],
                'mixpanel': ['mixpanel.com', 'api.mixpanel.com'],
                'stripe': ['stripe.com', 'api.stripe.com'],
                'firebase': ['firebase', 'googleapis.com', 'fcm.googleapis.com'],
                'github': ['github.com', 'api.github.com'],
                'openai': ['openai.com', 'api.openai.com'],
                'slack': ['slack.com', 'api.slack.com'],
                'twilio': ['twilio.com', 'api.twilio.com'],
                'sendgrid': ['sendgrid.com', 'api.sendgrid.com'],
                'instabug': ['instabug.com', 'api.instabug.com'],
            }
            
            service_matches = [
                ('azure', ['azure-api.net', 'azure.com', 'microsoft.com']),
                ('aws', ['amazonaws.com', 'aws.amazon.com']),
                ('cognito', ['cognito-idp', 'cognito-identity', 'amazonaws.com']),
                ('stripe', ['stripe.com']),
                ('firebase', ['firebase', 'googleapis.com']),
                ('mixpanel', ['mixpanel.com']),
                ('github', ['github.com', 'api.github.com']),
                ('openai', ['openai.com', 'api.openai.com']),
                ('slack', ['slack.com']),
                ('instabug', ['instabug.com']),
            ]
            
            # Check for service type match
            service_matched = False
            for service_key, url_patterns in service_matches:
                if service_key in cred_type:
                    for pattern in url_patterns:
                        if pattern in url_lower:
                            score += 30
                            reasons.append(f"Service type match ({service_key})")
                            service_matched = True
                            break
                    break
            
            # CRITICAL: If credential is service-specific and URL doesn't match, DISQUALIFY
            # This prevents cognito_client_id from being matched to sleepnumber.com
            for service_key, required_domains in service_specific_creds.items():
                if service_key in cred_type:
                    url_matches_service = any(domain in url_lower for domain in required_domains)
                    if not url_matches_service:
                        # This URL is NOT valid for this credential type
                        score = 0  # Disqualify
                        reasons = [f"DISQUALIFIED: {cred_type} requires {service_key} endpoint, not {url}"]
                        break
            
            # Direct URL extraction from code (+90-95)
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain and domain in cred_code:
                score += 90
                reasons.append("Direct URL in code")
            
            # Cap at 99%
            score = min(score, 99)
            
            if score > best_score:
                best_score = score
                best_url = url_info
                best_reasons = reasons
        
        # =============================================================================
        # CRITICAL FIX: Use service-specific API endpoint when no matching URL found
        # =============================================================================
        # Instead of defaulting to a random URL from the codebase (which could be
        # completely unrelated like sleepnumber.com for a mixpanel_token), we now:
        # 1. Detect the service from the credential type
        # 2. Use the canonical API endpoint for that service
        # 3. Only fall back to codebase URLs if they actually match the service
        
        if not best_url or best_score < 30:
            # Detect service from credential type
            service_name, service_score = detect_service_from_credential(cred['raw'])
            service_endpoint = get_service_api_endpoint(service_name)
            
            if service_endpoint and service_endpoint.get('api_url'):
                # Use the canonical API endpoint for this service
                canonical_url = service_endpoint['api_url']
                best_url = {
                    'url': canonical_url,
                    'file': '[Service-specific endpoint]',
                    'environment': 'production'
                }
                best_score = max(service_score, 70)  # High confidence for service-matched endpoint
                best_reasons = [
                    f"Service detected: {service_name}",
                    f"Canonical API endpoint: {canonical_url}",
                    f"Auth method: {service_endpoint.get('auth_method', 'unknown')}"
                ]
                print(f"[AI Matcher] Using canonical endpoint for {service_name}: {canonical_url}")
            elif best_url and best_score < 30:
                # Low confidence match - warn but still use it
                best_reasons.append("WARNING: Low confidence match - verify manually")
                print(f"[AI Matcher] WARNING: Low confidence ({best_score}%) match for {cred['type']}")
            elif not best_url:
                # No URL found and no service endpoint - skip this credential
                print(f"[AI Matcher] SKIPPING {cred['type']}: No matching URL and no canonical endpoint")
                continue
        
        if best_url:
            correlations.append({
                'credential': {
                    'type': cred['type'],
                    'value': cred['value'],  # Full value - no masking per policy
                    'file': cred['file'],
                    'line': cred['line'],
                    'environment': cred_env
                },
                'url': best_url['url'],
                'url_file': best_url.get('file', ''),
                'confidence': best_score,
                'match_reasons': best_reasons,
                'llm_enhanced': False
            })
    
    # Sort by confidence descending
    correlations.sort(key=lambda x: x['confidence'], reverse=True)
    
    # Try LLM enhancement
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if api_key and correlations:
        correlations = await _enhance_correlations_with_llm(correlations, urls, credentials, api_key)
    
    return correlations


async def correlate_inbound_endpoints_to_servers(
    project_name: str,
    reports_dir: str = "/app/vulnerability_reports"
) -> List[Dict[str, Any]]:
    """
    AI-powered correlation of inbound API endpoints to their target server URLs.
    
    Analyzes:
    - Path patterns matching server base URLs
    - Framework detection (Express routes → Node servers)
    - Environment indicators in file paths
    - Code context for server configuration
    
    Returns list of endpoint-server pairs with confidence scores.
    """
    project_dir = os.path.join(reports_dir, project_name)
    endpoints_file = os.path.join(project_dir, f"{project_name}_api_endpoints.json")
    openapi_file = os.path.join(project_dir, f"{project_name}_openapi.yaml")
    
    if not os.path.exists(endpoints_file):
        return []
    
    # Load endpoints data
    with open(endpoints_file, 'r') as f:
        data = json.load(f)
    
    # Extract servers from OpenAPI
    servers = []
    if os.path.exists(openapi_file):
        try:
            import yaml
            with open(openapi_file, 'r') as f:
                spec = yaml.safe_load(f)
            for s in spec.get('servers', []):
                url = s.get('url', '')
                if url:
                    servers.append({
                        'url': url,
                        'description': s.get('description', ''),
                        'environment': _detect_environment_from_url(url)
                    })
        except (IOError, yaml.YAMLError, KeyError, AttributeError) as e:
            logger.debug(f"Failed to parse OpenAPI spec from {openapi_file}: {str(e)}")
    
    if not servers:
        # Default server
        servers = [{
            'url': 'http://localhost:8000',
            'description': 'Default development server',
            'environment': 'development'
        }]
    
    # Get inbound endpoints
    inbound = data.get('inbound_endpoints', [])
    
    if not inbound:
        return []
    
    correlations = []
    
    for ep in inbound:
        ep_path = ep.get('endpoint_path', '') or ep.get('path', '')
        ep_file = ep.get('path', '')
        ep_line = ep.get('line', 0)
        ep_framework = ep.get('metadata', {}).get('framework', '')
        ep_method = ep.get('metadata', {}).get('method', 'GET')
        ep_env = _detect_environment_from_path(ep_file)
        
        best_server = None
        best_score = 0
        best_reasons = []
        
        for server in servers:
            server_url = server['url']
            server_env = server['environment']
            
            score = 0
            reasons = []
            
            # Environment matching
            env_compatible, env_boost = _environments_compatible(ep_env, server_env)
            if env_compatible and env_boost > 0:
                score += env_boost
                reasons.append(f"Environment match ({ep_env}→{server_env})")
            
            # Framework-server type matching
            framework_matches = [
                (['express', 'node', 'koa', 'fastify'], ['node', 'localhost:3000', 'localhost:8080']),
                (['fastapi', 'flask', 'django'], ['python', 'localhost:8000', 'localhost:5000']),
                (['spring', 'java'], ['java', 'localhost:8080', 'localhost:9000']),
            ]
            
            for frameworks, server_hints in framework_matches:
                if any(f in ep_framework.lower() for f in frameworks):
                    if any(h in server_url.lower() for h in server_hints):
                        score += 20
                        reasons.append(f"Framework match ({ep_framework})")
                        break
            
            # Path prefix matching
            parsed = urlparse(server_url)
            server_path = parsed.path.rstrip('/')
            if server_path and ep_path.startswith(server_path):
                score += 25
                reasons.append(f"Path prefix match ({server_path})")
            
            # Domain keyword matching
            server_keywords = _extract_domain_keywords(server_url)
            path_keywords = set(re.findall(r'[a-z]{3,}', ep_file.lower()))
            overlap = server_keywords & path_keywords
            if overlap:
                score += 15
                reasons.append(f"Keyword overlap: {', '.join(list(overlap)[:3])}")
            
            # Default boost for first server
            if not best_server:
                score += 20
                reasons.append("Primary server")
            
            score = min(score, 99)
            
            if score > best_score:
                best_score = score
                best_server = server
                best_reasons = reasons
        
        if best_server:
            target_url = best_server['url'].rstrip('/') + ep_path
            correlations.append({
                'endpoint': {
                    'path': ep_path,
                    'method': ep_method,
                    'framework': ep_framework,
                    'file': ep_file,
                    'line': ep_line
                },
                'target_url': target_url,
                'server_url': best_server['url'],
                'confidence': best_score,
                'match_reasons': best_reasons
            })
    
    # Sort by confidence descending
    correlations.sort(key=lambda x: x['confidence'], reverse=True)
    
    return correlations


async def correlate_outbound_endpoints_to_servers(
    project_name: str,
    reports_dir: str = "/app/vulnerability_reports"
) -> List[Dict[str, Any]]:
    """
    AI-powered correlation of outbound API calls to their target server URLs.
    
    Analyzes:
    - Direct URL extraction from code
    - Environment variable references
    - Base URL patterns
    - Credential associations
    
    Returns list of outbound endpoint-server pairs with confidence scores.
    """
    project_dir = os.path.join(reports_dir, project_name)
    endpoints_file = os.path.join(project_dir, f"{project_name}_api_endpoints.json")
    openapi_file = os.path.join(project_dir, f"{project_name}_openapi.yaml")
    
    if not os.path.exists(endpoints_file):
        return []
    
    # Load endpoints data
    with open(endpoints_file, 'r') as f:
        data = json.load(f)
    
    # Extract servers from OpenAPI
    servers = []
    if os.path.exists(openapi_file):
        try:
            import yaml
            with open(openapi_file, 'r') as f:
                spec = yaml.safe_load(f)
            for s in spec.get('servers', []):
                url = s.get('url', '')
                if url:
                    servers.append({
                        'url': url,
                        'description': s.get('description', ''),
                        'environment': _detect_environment_from_url(url)
                    })
        except (IOError, yaml.YAMLError, KeyError, AttributeError) as e:
            logger.debug(f"Failed to parse OpenAPI spec from {openapi_file}: {str(e)}")
    
    # Get outbound endpoints (credentials and API calls)
    outbound = data.get('outbound_endpoints', [])
    
    if not outbound:
        return []
    
    correlations = []
    
    for ep in outbound:
        secret_type = ep.get('metadata', {}).get('secret_type', '')
        ep_code = ep.get('code', '')
        ep_file = ep.get('path', '')
        ep_line = ep.get('line', 0)
        ep_env = ep.get('metadata', {}).get('environment', '') or _detect_environment_from_path(ep_file)
        endpoint_path = ep.get('endpoint_path', '')
        
        # Skip pure URLs - we want credentials/API calls
        if secret_type == 'api_url':
            continue
        
        best_server = None
        best_score = 0
        best_reasons = []
        
        # Check if there's a direct URL in the code
        url_match = re.search(r'https?://[^\s\'"<>]+', ep_code)
        if url_match:
            direct_url = url_match.group(0).rstrip('/')
            best_server = {'url': direct_url, 'description': 'Direct URL in code', 'environment': _detect_environment_from_url(direct_url)}
            best_score = 95
            best_reasons = ["Direct URL extraction from code"]
        else:
            # Match to discovered servers
            for server in servers:
                server_url = server['url']
                server_env = server['environment']
                
                score = 0
                reasons = []
                
                # Environment matching
                env_compatible, env_boost = _environments_compatible(ep_env, server_env)
                if env_compatible and env_boost > 0:
                    score += env_boost
                    reasons.append(f"Environment match ({ep_env}→{server_env})")
                
                # Service type matching
                type_lower = secret_type.lower()
                url_lower = server_url.lower()
                
                service_matches = [
                    ('azure', ['azure-api.net', 'azure.com', 'microsoft.com']),
                    ('aws', ['amazonaws.com', 'aws.amazon.com']),
                    ('cognito', ['cognito', 'ecim']),
                    ('stripe', ['stripe.com']),
                    ('firebase', ['firebase', 'googleapis.com']),
                ]
                
                for service_key, url_patterns in service_matches:
                    if service_key in type_lower:
                        for pattern in url_patterns:
                            if pattern in url_lower:
                                score += 30
                                reasons.append(f"Service type match ({service_key})")
                                break
                
                # Domain keyword in code
                server_keywords = _extract_domain_keywords(server_url)
                code_lower = ep_code.lower()
                for keyword in server_keywords:
                    if keyword in code_lower and len(keyword) >= 4:
                        score += 20
                        reasons.append(f"Domain keyword '{keyword}' in code")
                        break
                
                # Default boost for first server
                if not best_server:
                    score += 20
                    reasons.append("Primary server")
                
                score = min(score, 99)
                
                if score > best_score:
                    best_score = score
                    best_server = server
                    best_reasons = reasons
        
        if best_server:
            correlations.append({
                'endpoint': {
                    'code': ep_code,  # Full unredacted code for security analyst validation
                    'secret_type': secret_type,
                    'environment': ep_env,
                    'file': ep_file,
                    'line': ep_line
                },
                'target_url': best_server['url'],
                'server_url': best_server['url'],
                'confidence': best_score,
                'match_reasons': best_reasons
            })
    
    # Sort by confidence descending
    correlations.sort(key=lambda x: x['confidence'], reverse=True)
    
    return correlations


async def correlate_servers_with_credentials(
    project_name: str,
    reports_dir: str = "/app/vulnerability_reports"
) -> List[Dict[str, Any]]:
    """
    AI-powered correlation of API servers with their associated credentials.
    
    Analyzes:
    - Environment matching (prod servers → prod credentials)
    - Domain patterns in credential code
    - Service type matching (Azure URLs → Azure keys)
    - File proximity
    
    Returns list of server-credential groups with confidence scores.
    """
    project_dir = os.path.join(reports_dir, project_name)
    endpoints_file = os.path.join(project_dir, f"{project_name}_api_endpoints.json")
    openapi_file = os.path.join(project_dir, f"{project_name}_openapi.yaml")
    
    if not os.path.exists(endpoints_file):
        return []
    
    # Load endpoints data
    with open(endpoints_file, 'r') as f:
        data = json.load(f)
    
    # Extract servers from OpenAPI
    servers = []
    if os.path.exists(openapi_file):
        try:
            import yaml
            with open(openapi_file, 'r') as f:
                spec = yaml.safe_load(f)
            for s in spec.get('servers', []):
                url = s.get('url', '')
                if url:
                    servers.append({
                        'url': url,
                        'description': s.get('description', ''),
                        'environment': _detect_environment_from_url(url)
                    })
        except (IOError, yaml.YAMLError, KeyError, AttributeError) as e:
            logger.debug(f"Failed to parse OpenAPI spec from {openapi_file}: {str(e)}")
    
    if not servers:
        return []
    
    # Get credentials (non-URL endpoints)
    credentials = []
    for ep in data.get('outbound_endpoints', []):
        secret_type = ep.get('metadata', {}).get('secret_type', '')
        if secret_type and secret_type != 'api_url':
            credentials.append({
                'type': secret_type,
                'value': extract_credential_value(ep),
                'file': ep.get('path', ''),
                'line': ep.get('line', 0),
                'code': ep.get('code', ''),
                'environment': ep.get('metadata', {}).get('environment', '') or _detect_environment_from_path(ep.get('path', ''))
            })
    
    if not credentials:
        return []
    
    # Group credentials by server
    server_correlations = []
    
    for server in servers:
        server_url = server['url']
        server_env = server['environment']
        server_keywords = _extract_domain_keywords(server_url)
        
        matched_creds = []
        
        for cred in credentials:
            cred_env = cred['environment']
            cred_code = cred['code'].lower()
            cred_type = cred['type'].lower()
            
            score = 0
            reasons = []
            
            # Environment matching
            env_compatible, env_boost = _environments_compatible(cred_env, server_env)
            if env_compatible and env_boost > 0:
                score += env_boost
                reasons.append(f"Environment match ({cred_env}→{server_env})")
            
            # Domain keyword in code
            for keyword in server_keywords:
                if keyword in cred_code and len(keyword) >= 4:
                    score += 20
                    reasons.append(f"Domain keyword '{keyword}'")
                    break
            
            # Service type matching
            url_lower = server_url.lower()
            service_matches = [
                ('azure', ['azure-api.net', 'azure.com', 'microsoft.com']),
                ('aws', ['amazonaws.com', 'aws.amazon.com']),
                ('cognito', ['cognito', 'ecim']),
                ('stripe', ['stripe.com']),
                ('firebase', ['firebase', 'googleapis.com']),
            ]
            
            for service_key, url_patterns in service_matches:
                if service_key in cred_type:
                    for pattern in url_patterns:
                        if pattern in url_lower:
                            score += 30
                            reasons.append(f"Service type match ({service_key})")
                            break
            
            # Direct URL in code
            parsed = urlparse(server_url)
            domain = parsed.netloc.lower()
            if domain and domain in cred_code:
                score += 40
                reasons.append("Direct URL reference")
            
            score = min(score, 99)
            
            if score >= 20:  # Minimum threshold
                matched_creds.append({
                    'credential': {
                        'type': cred['type'],
                        'value': cred['value'],  # Full value - no masking per policy
                        'environment': cred_env,
                        'file': cred['file']
                    },
                    'confidence': score,
                    'match_reasons': reasons
                })
        
        # Sort credentials by confidence
        matched_creds.sort(key=lambda x: x['confidence'], reverse=True)
        
        server_correlations.append({
            'server': {
                'url': server_url,
                'description': server['description'],
                'environment': server_env
            },
            'credentials': matched_creds[:10],  # Top 10 matches
            'credential_count': len(matched_creds),
            'top_confidence': matched_creds[0]['confidence'] if matched_creds else 0
        })
    
    # Sort servers by top credential confidence
    server_correlations.sort(key=lambda x: x['top_confidence'], reverse=True)
    
    return server_correlations


async def _enhance_correlations_with_llm(
    correlations: List[Dict],
    urls: List[Dict],
    credentials: List[Dict],
    api_key: str
) -> List[Dict]:
    """
    Use LLM to refine credential-URL correlations.
    
    Provides additional context analysis and confidence adjustments.
    """
    try:
        import anthropic
        # AI Safety imports
        try:
            from src.services.ai_safety.sanitize import sanitize_prompt_input
            from src.services.ai_safety.pii_masker import mask_pii, unmask_pii
            from src.services.ai_safety.validate import validate_agent_output
            _safety_available = True
        except ImportError:
            _safety_available = False

        client = anthropic.Anthropic(api_key=api_key)

        # Prepare summary for LLM
        summary = []
        for i, corr in enumerate(correlations[:15]):  # Limit to 15
            summary.append({
                'index': i,
                'credential_type': corr['credential']['type'],
                'credential_env': corr['credential']['environment'],
                'url': corr['url'],
                'current_confidence': corr['confidence'],
                'reasons': corr['match_reasons']
            })

        prompt = f"""Analyze these credential-to-URL correlations and refine the confidence scores.

Correlations:
{json.dumps(summary, indent=2)}

For each correlation, evaluate if the credential-URL pairing makes sense based on:
1. Environment alignment (prod creds → prod URLs)
2. Service type consistency (Azure keys → Azure URLs)
3. Naming patterns
4. Security best practices

Return a JSON array with objects containing:
- index (0-based position)
- confidence (refined 0-99 score)
- reasoning (brief explanation)

Only return the JSON array, no other text."""

        # AI Safety: sanitize and mask prompt
        if _safety_available:
            prompt = sanitize_prompt_input(prompt)
            prompt, pii_mappings = mask_pii(prompt)
        else:
            pii_mappings = {}

        response = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )

        result_text = response.content[0].text.strip()

        # AI Safety: validate output
        if _safety_available:
            validation = validate_agent_output(result_text)
            result_text = validation.get("sanitized_text", result_text)
            result_text = unmask_pii(result_text, pii_mappings)
        if result_text.startswith('['):
            llm_results = json.loads(result_text)
            
            for llm_item in llm_results:
                idx = llm_item.get('index', -1)
                if 0 <= idx < len(correlations):
                    correlations[idx]['confidence'] = min(llm_item.get('confidence', correlations[idx]['confidence']), 99)
                    correlations[idx]['llm_enhanced'] = True
                    if llm_item.get('reasoning'):
                        correlations[idx]['match_reasons'].append(f"AI: {llm_item['reasoning']}")
            
            # Re-sort after LLM refinement
            correlations.sort(key=lambda x: x['confidence'], reverse=True)
    
    except Exception as e:
        print(f"LLM correlation enhancement failed: {e}")
    
    return correlations


async def map_credentials_to_swagger_servers(
    project_name: str,
    reports_dir: str = "/app/vulnerability_reports"
) -> List[Dict[str, Any]]:
    """
    Map discovered credentials to OpenAPI/Swagger server URLs.
    
    This function specifically uses the servers discovered in swagger files
    and matches them with credentials for connection/authentication testing.
    
    Returns list of server-credential mappings suitable for API testing.
    """
    import yaml
    import glob
    
    project_dir = os.path.join(reports_dir, project_name)
    endpoints_file = os.path.join(project_dir, f"{project_name}_api_endpoints.json")
    
    if not os.path.exists(endpoints_file):
        return []
    
    # Load endpoints data for credentials
    with open(endpoints_file, 'r') as f:
        data = json.load(f)
    
    # Collect all servers from swagger files
    servers = []
    swagger_pattern = os.path.join(project_dir, "*_swagger.yaml")
    for swagger_file in glob.glob(swagger_pattern):
        try:
            with open(swagger_file, 'r') as f:
                spec = yaml.safe_load(f)
            for s in spec.get('servers', []):
                url = s.get('url', '')
                if url and url not in [srv['url'] for srv in servers]:
                    servers.append({
                        'url': url,
                        'description': s.get('description', ''),
                        'environment': _detect_environment_from_url(url),
                        'source_file': os.path.basename(swagger_file)
                    })
        except Exception as e:
            print(f"Error reading swagger file {swagger_file}: {e}")
    
    # Also check main openapi.yaml
    openapi_file = os.path.join(project_dir, f"{project_name}_openapi.yaml")
    if os.path.exists(openapi_file):
        try:
            with open(openapi_file, 'r') as f:
                spec = yaml.safe_load(f)
            for s in spec.get('servers', []):
                url = s.get('url', '')
                if url and url not in [srv['url'] for srv in servers]:
                    servers.append({
                        'url': url,
                        'description': s.get('description', ''),
                        'environment': _detect_environment_from_url(url),
                        'source_file': f"{project_name}_openapi.yaml"
                    })
        except (IOError, yaml.YAMLError, KeyError, AttributeError) as e:
            logger.debug(f"Failed to parse OpenAPI spec from {openapi_file}: {str(e)}")
    
    if not servers:
        return []
    
    # Get credentials (non-URL endpoints)
    credentials = []
    for ep in data.get('outbound_endpoints', []):
        secret_type = ep.get('metadata', {}).get('secret_type', '')
        if secret_type and secret_type != 'api_url':
            credentials.append({
                'type': secret_type,
                'value': extract_credential_value(ep),
                'file': ep.get('path', ''),
                'line': ep.get('line', 0),
                'code': ep.get('code', ''),
                'environment': ep.get('metadata', {}).get('environment', '') or _detect_environment_from_path(ep.get('path', '')),
                'raw': ep
            })
    
    # Map each server to its best matching credentials
    mappings = []
    
    for server in servers:
        server_url = server['url']
        server_env = server['environment']
        server_creds = []
        
        for cred in credentials:
            cred_env = cred['environment']
            cred_type = cred['type'].lower()
            cred_code = cred['code'].lower()
            
            score = 0
            reasons = []
            
            # Environment matching (+25)
            env_compatible, env_boost = _environments_compatible(cred_env, server_env)
            if env_compatible and env_boost > 0:
                score += env_boost
                reasons.append(f"Environment: {cred_env}→{server_env}")
            
            # Service type matching (+30)
            url_lower = server_url.lower()
            service_matches = [
                ('azure', ['azure-api.net', 'azure.com', 'microsoft.com']),
                ('aws', ['amazonaws.com', 'aws.amazon.com']),
                ('cognito', ['cognito', 'ecim']),
                ('stripe', ['stripe.com']),
                ('firebase', ['firebase', 'googleapis.com']),
                ('mixpanel', ['mixpanel.com']),
                ('api_key', []),  # Generic API key matches any server
            ]
            
            for service_key, url_patterns in service_matches:
                if service_key in cred_type:
                    if not url_patterns:  # Generic API key
                        score += 15
                        reasons.append("Generic API key")
                    else:
                        for pattern in url_patterns:
                            if pattern in url_lower:
                                score += 30
                                reasons.append(f"Service match: {service_key}")
                                break
            
            # Domain keyword in code (+20)
            url_keywords = _extract_domain_keywords(server_url)
            for keyword in url_keywords:
                if keyword in cred_code and len(keyword) >= 4:
                    score += 20
                    reasons.append(f"Domain '{keyword}' in code")
                    break
            
            # Direct URL in credential code (+40)
            parsed = urlparse(server_url)
            domain = parsed.netloc.lower()
            if domain and domain in cred_code:
                score += 40
                reasons.append("Direct URL reference")
            
            score = min(score, 99)
            
            if score >= 15:  # Only include if there's some confidence
                type_display = TYPE_DISPLAY_NAMES.get(cred['type'], cred['type'].replace('_', ' ').title())
                server_creds.append({
                    'credential_type': type_display,
                    'credential_value': cred['value'],  # Full value - no masking per policy
                    'credential_file': cred['file'],
                    'environment': cred_env,
                    'confidence': score,
                    'match_reasons': reasons
                })
        
        # Sort credentials by confidence
        server_creds.sort(key=lambda x: x['confidence'], reverse=True)
        
        mappings.append({
            'server_url': server_url,
            'server_description': server['description'],
            'server_environment': server_env,
            'source_file': server['source_file'],
            'credentials': server_creds[:5],  # Top 5 credentials per server
            'credential_count': len(server_creds),
            'top_confidence': server_creds[0]['confidence'] if server_creds else 0
        })
    
    # Sort by top confidence
    mappings.sort(key=lambda x: x['top_confidence'], reverse=True)
    
    return mappings
