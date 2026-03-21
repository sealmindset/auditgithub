"""
AI Credential-URL Testing Agent

A comprehensive AI-powered security testing agent that:
1. Tests credentials against discovered API endpoints (AuthN/Z)
2. Performs path discovery and fuzzing
3. Retrieves and analyzes sample data
4. Gathers OSINT intelligence from GitHub and the web
5. Generates executive summaries and risk assessments

Test Modes:
- none: No rate limits, aggressive testing
- cautious: Evasion techniques (random delays, user-agent rotation)
- insane: All safeties off, includes POST/PUT/DELETE probing
"""

import os
import re
import json
import random
import asyncio
import logging
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field, asdict

import httpx

logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================

# Common API path wordlist for fuzzing (reduced for faster tests)
# Focus on high-value security-relevant paths
COMMON_API_PATHS = [
    # Authentication (highest priority)
    "auth", "login", "oauth", "token", "me", "user", "users",
    # API Info
    "health", "status", "info", "version", "docs", "swagger", "graphql",
    # Hidden/Debug (security-relevant)
    "debug", "admin", "internal", ".env", ".git", "backup", "config",
]

# User agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "AuditGH-SecurityScanner/1.0",
]

# Sensitive data patterns
SENSITIVE_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "api_key": r"(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,})",
    "jwt": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
    "password": r"(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'\"]+)",
    "bearer_token": r"Bearer\s+[a-zA-Z0-9_-]+",
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
}

# =============================================================================
# Service Detection Patterns (from ai_credential_matcher.py)
# =============================================================================
# These patterns are used to detect the service type and determine the correct
# authentication headers to use for testing.

SERVICE_AUTH_PATTERNS = {
    'Azure': {
        'keywords': ['azure', 'ocp-apim', 'subscription', 'microsoft'],
        'domains': ['azure-api.net', 'azure.com', 'microsoft.com', 'windows.net', 'sleepiqapi.azure-api.net'],
        'secret_types': ['azure_key', 'azure_endpoint', 'subscription_key', 'ocp-apim'],
        'auth_headers': {
            'primary': 'Ocp-Apim-Subscription-Key',
            'alternatives': ['Subscription-Key', 'Api-Key', 'X-API-Key'],
            'method': 'header'
        }
    },
    'AWS': {
        'keywords': ['aws', 'amazon', 's3', 'lambda', 'dynamodb', 'ec2'],
        'domains': ['amazonaws.com', 'aws.amazon.com', 'execute-api'],
        'secret_types': ['aws_access_key', 'aws_secret'],
        'auth_headers': {
            'primary': 'Authorization',
            'prefix': 'Bearer',
            'alternatives': ['X-Amz-Security-Token', 'X-Api-Key'],
            'method': 'bearer'
        }
    },
    'AWS_Cognito': {
        'keywords': ['cognito', 'cognito_client', 'user_pool', 'identity_pool'],
        'domains': ['cognito-idp', 'cognito-identity', 'amazonaws.com'],
        'secret_types': ['cognito_client_id', 'cognito_client_secret', 'cognito_user_pool', 'cognito'],
        'auth_headers': {
            'primary': 'X-Amz-Target',
            'method': 'cognito_api'
        },
        # AWS Cognito uses a specific API - not standard REST auth headers
        # The client_id is used in the request body, not headers
        # Reference: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/
        'canonical_endpoints': [
            {
                'url': 'https://cognito-idp.us-east-1.amazonaws.com',
                'method': 'POST',
                'description': 'Cognito User Pool - DescribeUserPoolClient (validates client_id exists)',
                'auth_combinations': [
                    {
                        'method': 'cognito_describe_client',
                        'client_id': '{token}',
                        'note': 'Tests if client_id is valid by attempting to describe it'
                    },
                ],
                'headers': {
                    'Content-Type': 'application/x-amz-json-1.1',
                    'X-Amz-Target': 'AWSCognitoIdentityProviderService.DescribeUserPoolClient'
                },
                'body_template': {
                    'ClientId': '{token}'
                }
            },
            {
                'url': 'https://cognito-idp.us-east-1.amazonaws.com',
                'method': 'POST',
                'description': 'Cognito User Pool - InitiateAuth (test if client allows USER_PASSWORD_AUTH)',
                'auth_combinations': [
                    {
                        'method': 'cognito_initiate_auth',
                        'client_id': '{token}',
                        'note': 'Tests auth flow configuration - will fail but reveals if client_id is valid'
                    },
                ],
                'headers': {
                    'Content-Type': 'application/x-amz-json-1.1',
                    'X-Amz-Target': 'AWSCognitoIdentityProviderService.InitiateAuth'
                },
                'body_template': {
                    'AuthFlow': 'USER_PASSWORD_AUTH',
                    'ClientId': '{token}',
                    'AuthParameters': {
                        'USERNAME': 'test@example.com',
                        'PASSWORD': 'TestPassword123!'
                    }
                }
            },
            {
                'url': 'https://cognito-idp.us-east-2.amazonaws.com',
                'method': 'POST',
                'description': 'Cognito User Pool (us-east-2) - InitiateAuth',
                'auth_combinations': [
                    {
                        'method': 'cognito_initiate_auth',
                        'client_id': '{token}',
                        'note': 'Tests auth flow in us-east-2 region'
                    },
                ],
                'headers': {
                    'Content-Type': 'application/x-amz-json-1.1',
                    'X-Amz-Target': 'AWSCognitoIdentityProviderService.InitiateAuth'
                },
                'body_template': {
                    'AuthFlow': 'USER_PASSWORD_AUTH',
                    'ClientId': '{token}',
                    'AuthParameters': {
                        'USERNAME': 'test@example.com',
                        'PASSWORD': 'TestPassword123!'
                    }
                }
            }
        ],
        'documentation_url': 'https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html',
        'notes': [
            'cognito_client_id is NOT a bearer token - it identifies the app client',
            'Must be used with Cognito API endpoints, not arbitrary URLs',
            'Valid responses include: ResourceNotFoundException (wrong region), NotAuthorizedException (valid client, wrong creds)',
            'InvalidParameterException with "client_id" means the client_id format is valid but not found'
        ]
    },
    'Firebase': {
        'keywords': ['firebase', 'fcm', 'google', 'firestore', 'realtime'],
        'domains': ['firebase.google.com', 'firebaseio.com', 'googleapis.com', 'fcm.googleapis.com'],
        'secret_types': ['firebase_key', 'google_api_key', 'fcm_key', 'server_key'],
        'auth_headers': {
            'primary': 'Authorization',
            'prefix': 'key=',
            'alternatives': ['X-Firebase-Auth', 'X-Goog-Api-Key'],
            'method': 'key_prefix'
        }
    },
    'Stripe': {
        'keywords': ['stripe', 'payment', 'checkout'],
        'domains': ['stripe.com', 'api.stripe.com', 'js.stripe.com'],
        'secret_types': ['stripe_key', 'stripe_secret', 'sk_live', 'sk_test', 'pk_live', 'pk_test'],
        'auth_headers': {
            'primary': 'Authorization',
            'prefix': 'Bearer',
            'alternatives': ['Stripe-Version'],
            'method': 'bearer'
        },
        'canonical_endpoints': [
            {
                'url': 'https://api.stripe.com/v1/balance',
                'method': 'GET',
                'description': 'Get account balance - proves API key is valid',
                'auth_combinations': [
                    {'method': 'bearer', 'token': '{token}'},
                    {'method': 'basic', 'username': '{token}', 'password': ''},
                ]
            },
            {
                'url': 'https://api.stripe.com/v1/customers',
                'method': 'GET',
                'description': 'List customers - proves read access',
                'auth_combinations': [
                    {'method': 'bearer', 'token': '{token}'},
                ]
            }
        ],
        'documentation_url': 'https://stripe.com/docs/api/authentication'
    },
    'Twilio': {
        'keywords': ['twilio', 'sms', 'voice', 'messaging'],
        'domains': ['twilio.com', 'api.twilio.com'],
        'secret_types': ['twilio_sid', 'twilio_token', 'account_sid', 'auth_token'],
        'auth_headers': {
            'primary': 'Authorization',
            'method': 'basic'
        }
    },
    'SendGrid': {
        'keywords': ['sendgrid', 'email', 'sg.'],
        'domains': ['sendgrid.com', 'api.sendgrid.com', 'sendgrid.net'],
        'secret_types': ['sendgrid_key', 'sg_api_key'],
        'auth_headers': {
            'primary': 'Authorization',
            'prefix': 'Bearer',
            'method': 'bearer'
        }
    },
    'Mixpanel': {
        'keywords': ['mixpanel', 'analytics', 'tracking'],
        'domains': ['mixpanel.com', 'api.mixpanel.com', 'data.mixpanel.com'],
        'secret_types': ['mixpanel_token', 'mixpanel_key', 'project_token'],
        'auth_headers': {
            'primary': 'Authorization',
            'prefix': 'Basic',
            'alternatives': ['X-Mixpanel-Token'],
            'method': 'basic_token'
        },
        # Service Account API - https://developer.mixpanel.com/reference/service-accounts
        'canonical_endpoints': [
            {
                'url': 'https://mixpanel.com/api/app/me',
                'method': 'GET',
                'description': 'Service Account - Get current user/account info',
                'auth_combinations': [
                    # Try different username:password combinations for Basic auth
                    {'method': 'basic', 'username': '{service_account_id}', 'password': '{token}'},
                    {'method': 'basic', 'username': '{token}', 'password': ''},
                    {'method': 'basic', 'username': '', 'password': '{token}'},
                ]
            },
            {
                'url': 'https://mixpanel.com/api/app/workspaces',
                'method': 'GET',
                'description': 'Service Account - List workspaces',
                'auth_combinations': [
                    {'method': 'basic', 'username': '{service_account_id}', 'password': '{token}'},
                ]
            },
            {
                'url': 'https://api.mixpanel.com/track',
                'method': 'POST',
                'description': 'Track API - Send events (uses project token)',
                'auth_combinations': [
                    {'method': 'query_param', 'param': 'token', 'value': '{token}'},
                    {'method': 'basic', 'username': '{token}', 'password': ''},
                ]
            },
            {
                'url': 'https://data.mixpanel.com/api/2.0/export',
                'method': 'GET',
                'description': 'Data Export API',
                'auth_combinations': [
                    {'method': 'basic', 'username': '{api_secret}', 'password': ''},
                ]
            }
        ],
        'documentation_url': 'https://developer.mixpanel.com/reference/service-accounts'
    },
    'Instabug': {
        'keywords': ['instabug', 'bug', 'crash', 'feedback'],
        'domains': ['instabug.com', 'api.instabug.com'],
        'secret_types': ['instabug_key', 'instabug_token', 'app_token'],
        'auth_headers': {
            'primary': 'Authorization',
            'prefix': 'Bearer',
            'alternatives': ['X-Instabug-Token', 'X-App-Token'],
            'method': 'bearer'
        }
    },
    'Slack': {
        'keywords': ['slack', 'webhook', 'bot', 'xoxb', 'xoxp'],
        'domains': ['slack.com', 'api.slack.com', 'hooks.slack.com'],
        'secret_types': ['slack_token', 'bot_token', 'xoxb', 'xoxp', 'webhook_url'],
        'auth_headers': {
            'primary': 'Authorization',
            'prefix': 'Bearer',
            'method': 'bearer'
        },
        'canonical_endpoints': [
            {
                'url': 'https://slack.com/api/auth.test',
                'method': 'POST',
                'description': 'Test authentication - proves token is valid',
                'auth_combinations': [
                    {'method': 'bearer', 'token': '{token}'},
                ]
            },
            {
                'url': 'https://slack.com/api/users.list',
                'method': 'GET',
                'description': 'List users - proves read access',
                'auth_combinations': [
                    {'method': 'bearer', 'token': '{token}'},
                ]
            }
        ],
        'documentation_url': 'https://api.slack.com/authentication'
    },
    'GitHub': {
        'keywords': ['github', 'gh_', 'ghp_', 'gho_'],
        'domains': ['github.com', 'api.github.com', 'raw.githubusercontent.com'],
        'secret_types': ['github_token', 'personal_access_token', 'ghp_', 'gho_'],
        'auth_headers': {
            'primary': 'Authorization',
            'prefix': 'Bearer',
            'alternatives': ['X-GitHub-Api-Version'],
            'method': 'bearer'
        },
        'canonical_endpoints': [
            {
                'url': 'https://api.github.com/user',
                'method': 'GET',
                'description': 'Get authenticated user - proves token is valid',
                'auth_combinations': [
                    {'method': 'bearer', 'token': '{token}'},
                    {'method': 'header', 'header': 'Authorization', 'value': 'token {token}'},
                ]
            },
            {
                'url': 'https://api.github.com/rate_limit',
                'method': 'GET',
                'description': 'Check rate limit - shows token permissions',
                'auth_combinations': [
                    {'method': 'bearer', 'token': '{token}'},
                ]
            }
        ],
        'documentation_url': 'https://docs.github.com/en/rest/authentication'
    },
    'OpenAI': {
        'keywords': ['openai', 'gpt', 'chatgpt', 'davinci', 'sk-'],
        'domains': ['openai.com', 'api.openai.com'],
        'secret_types': ['openai_key', 'openai_api_key', 'sk-'],
        'auth_headers': {
            'primary': 'Authorization',
            'prefix': 'Bearer',
            'method': 'bearer'
        },
        'canonical_endpoints': [
            {
                'url': 'https://api.openai.com/v1/models',
                'method': 'GET',
                'description': 'List models - proves API key is valid',
                'auth_combinations': [
                    {'method': 'bearer', 'token': '{token}'},
                ]
            }
        ],
        'documentation_url': 'https://platform.openai.com/docs/api-reference/authentication'
    },
    'SleepIQ': {
        'keywords': ['sleepiq', 'sleepnumber', 'siq', 'sleep'],
        'domains': ['sleepiq.sleepnumber.com', 'sleepnumber.com', 'prod.sleepiq'],
        'secret_types': ['api_key', 'x-api-key', 'siq_key'],
        'auth_headers': {
            'primary': 'X-API-Key',
            'alternatives': ['Api-Key', 'Authorization'],
            'method': 'header'
        }
    },
    'Generic_API_Key': {
        'keywords': ['api', 'key', 'apikey'],
        'domains': [],
        'secret_types': ['api_key', 'x-api-key', 'apikey'],
        'auth_headers': {
            'primary': 'X-API-Key',
            'alternatives': ['Api-Key', 'Authorization', 'X-Auth-Token'],
            'method': 'header'
        }
    },
    'Generic_Bearer': {
        'keywords': ['bearer', 'token', 'jwt', 'access'],
        'domains': [],
        'secret_types': ['bearer_token', 'access_token', 'jwt', 'token'],
        'auth_headers': {
            'primary': 'Authorization',
            'prefix': 'Bearer',
            'method': 'bearer'
        }
    },
    'Generic_Basic': {
        'keywords': ['basic', 'username', 'password', 'credentials'],
        'domains': [],
        'secret_types': ['basic_auth', 'credentials', 'username_password'],
        'auth_headers': {
            'primary': 'Authorization',
            'prefix': 'Basic',
            'method': 'basic'
        }
    }
}


@dataclass
class TestResult:
    """Container for test results"""
    target_url: str
    credential_type: str
    credential_value: str
    credential_environment: str = ""
    confidence_score: int = 0
    
    # Service detection
    detected_service: str = ""
    service_detection_score: int = 0
    
    # Auth results
    auth_status: str = "not_tested"
    auth_status_code: int = 0
    auth_response_time_ms: int = 0
    auth_error_message: str = ""
    auth_headers_used: List[str] = field(default_factory=list)
    
    # Raw Request/Response capture
    auth_request_method: str = "GET"
    auth_request_url: str = ""
    auth_request_headers: Dict[str, str] = field(default_factory=dict)
    auth_request_body: str = ""
    auth_response_headers: Dict[str, str] = field(default_factory=dict)
    auth_response_body: str = ""
    auth_response_body_truncated: bool = False
    
    # Path discovery
    discovered_paths: List[Dict] = field(default_factory=list)
    discovered_paths_count: int = 0
    hidden_paths_found: int = 0
    
    # Data sampling
    sample_data_retrieved: List[Dict] = field(default_factory=list)
    data_sensitivity_indicators: List[Dict] = field(default_factory=list)
    
    # OSINT
    osint_findings: List[Dict] = field(default_factory=list)
    github_repos_found: int = 0
    documentation_links_found: int = 0
    
    # AI Analysis
    ai_overview: str = ""
    ai_risk_assessment: str = ""
    ai_recommendations: List[str] = field(default_factory=list)
    threat_level: str = "info"
    
    # Metadata
    test_mode: str = "cautious"
    tested_at: str = ""
    test_duration_seconds: int = 0
    llm_provider: str = ""
    llm_model: str = ""
    raw_llm_responses: List[Dict] = field(default_factory=list)


class AICredentialUrlAgent:
    """
    AI-powered agent for comprehensive credential-URL security testing.
    """
    
    def __init__(
        self,
        target_url: str,
        credential_type: str,
        credential_value: str,
        test_mode: str = "cautious",
        credential_environment: str = "",
        confidence_score: int = 0,
        github_token: Optional[str] = None
    ):
        self.target_url = self._normalize_url(target_url)
        self.credential_type = credential_type
        self.credential_value = credential_value
        self.test_mode = test_mode
        self.credential_environment = credential_environment
        self.confidence_score = confidence_score
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN", "")
        
        # Parse URL components
        parsed = urlparse(self.target_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.base_path = parsed.path or "/"
        
        # Results container
        # NOTE: Store the ACTUAL credential value, not masked, for security analyst validation
        # Security analysts need to see the real values to verify if credentials are active
        self.result = TestResult(
            target_url=self.target_url,
            credential_type=credential_type,
            credential_value=credential_value,  # Store actual value, not masked
            credential_environment=credential_environment,
            confidence_score=confidence_score,
            test_mode=test_mode
        )
        
        # Internal state
        self._start_time: Optional[datetime] = None
        self._http_client: Optional[httpx.AsyncClient] = None
        self._discovered_endpoints: set = set()
        
        logger.info(f"AICredentialUrlAgent initialized for {self.target_url} in {test_mode} mode")
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL to ensure proper format"""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        # Remove trailing slash for consistency
        return url.rstrip('/')
    
    def _mask_credential(self, value: str) -> str:
        """Return credential value - no masking per policy.
        
        Security analysts need to see the actual credential values to:
        1. Validate if the token is real/active
        2. Identify the token format and type
        3. Correlate with findings in the codebase
        """
        return value  # Full value - no masking per policy
    
    def _preserve_headers_for_storage(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Preserve header values for storage WITHOUT masking.
        
        Security auditors need to see the actual credential values to:
        1. Validate if the token is real/active
        2. Identify the token format and type
        3. Correlate with findings in the codebase
        
        The database already stores the credential_value unmasked,
        so headers should be consistent for audit purposes.
        """
        return dict(headers)
    
    def _format_raw_request(self, method: str, url: str, headers: Dict[str, str], body: Optional[str] = None) -> str:
        """Format HTTP request as raw text for display"""
        parsed = urlparse(url)
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        
        lines = [f"{method} {path} HTTP/1.1"]
        lines.append(f"Host: {parsed.netloc}")
        
        for key, value in headers.items():
            if key.lower() != 'host':
                lines.append(f"{key}: {value}")
        
        if body:
            lines.append("")
            lines.append(body)
        
        return '\n'.join(lines)
    
    def _format_raw_response(self, response) -> str:
        """Format HTTP response as raw text for display"""
        lines = [f"HTTP/1.1 {response.status_code} {response.reason_phrase or ''}"]
        
        for key, value in response.headers.items():
            lines.append(f"{key}: {value}")
        
        lines.append("")
        
        # Truncate body if too long
        body = response.text[:2000] if len(response.text) > 2000 else response.text
        lines.append(body)
        
        return '\n'.join(lines)
    
    def _detect_service(self) -> Tuple[str, Dict[str, Any], int]:
        """
        Detect the service type based on URL domain, credential type, and environment.
        Uses the same sophisticated pattern matching as ai_credential_matcher.py.
        
        Returns: (service_name, auth_config, confidence_score)
        """
        import base64
        
        cred_type_lower = self.credential_type.lower()
        url_lower = self.target_url.lower()
        env_lower = self.credential_environment.lower() if self.credential_environment else ""
        
        # Parse domain from URL
        parsed = urlparse(self.target_url)
        domain = parsed.netloc.lower()
        
        best_match = ('Unknown', {}, 0)
        
        for service_name, patterns in SERVICE_AUTH_PATTERNS.items():
            score = 0
            
            # Check domain match (strongest signal - 40 points)
            for pattern_domain in patterns.get('domains', []):
                if pattern_domain in domain:
                    score += 40
                    logger.debug(f"Domain match: {pattern_domain} in {domain} for {service_name}")
                    break
            
            # Check secret_type match (strong signal - 35 points)
            for secret_type in patterns.get('secret_types', []):
                if secret_type in cred_type_lower:
                    score += 35
                    logger.debug(f"Secret type match: {secret_type} in {cred_type_lower} for {service_name}")
                    break
            
            # Check keyword match in URL or credential type (moderate signal - 20 points)
            combined_text = f"{url_lower} {cred_type_lower} {env_lower}"
            for keyword in patterns.get('keywords', []):
                if keyword in combined_text:
                    score += 20
                    logger.debug(f"Keyword match: {keyword} for {service_name}")
                    break
            
            # Environment-based boost (5 points for prod match)
            if env_lower:
                if 'prod' in env_lower and 'prod' in url_lower:
                    score += 5
                elif 'stage' in env_lower and ('stage' in url_lower or 'staging' in url_lower):
                    score += 5
                elif 'test' in env_lower and 'test' in url_lower:
                    score += 5
            
            if score > best_match[2]:
                best_match = (service_name, patterns.get('auth_headers', {}), score)
        
        logger.info(f"Service detection: {best_match[0]} with confidence {best_match[2]} for {self.target_url}")
        return best_match
    
    def _get_headers(self, include_auth: bool = True) -> Dict[str, str]:
        """
        Build request headers based on detected service and credential type.
        Uses sophisticated service detection patterns for correct authentication.
        """
        import base64
        
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        
        # User agent rotation for cautious/insane modes
        if self.test_mode in ('cautious', 'insane'):
            headers['User-Agent'] = random.choice(USER_AGENTS)
        else:
            headers['User-Agent'] = 'AuditGH-SecurityScanner/1.0'
        
        if not include_auth:
            return headers
        
        # Detect service and get auth configuration
        service_name, auth_config, detection_score = self._detect_service()
        auth_headers = []
        
        # Get auth method from detected service
        method = auth_config.get('method', 'header')
        primary_header = auth_config.get('primary', 'Authorization')
        prefix = auth_config.get('prefix', '')
        alternatives = auth_config.get('alternatives', [])
        
        logger.info(f"Using auth method '{method}' for service '{service_name}' (score: {detection_score})")
        
        # Apply authentication based on detected method
        if method == 'header':
            # Direct header value (e.g., X-API-Key, Ocp-Apim-Subscription-Key)
            headers[primary_header] = self.credential_value
            auth_headers.append(primary_header)
            # Also add alternatives for better coverage
            for alt in alternatives[:2]:  # Limit to 2 alternatives
                headers[alt] = self.credential_value
                auth_headers.append(alt)
                
        elif method == 'bearer':
            # Bearer token authentication
            headers[primary_header] = f'Bearer {self.credential_value}'
            auth_headers.append(f'{primary_header}: Bearer')
            # Add X-API-Key as fallback for some services
            if 'X-Api-Key' in alternatives or 'X-API-Key' in alternatives:
                headers['X-API-Key'] = self.credential_value
                auth_headers.append('X-API-Key')
                
        elif method == 'basic':
            # Basic authentication (base64 encoded)
            # If credential looks like "user:pass", encode as-is
            # Otherwise, assume it's already the token/password
            if ':' in self.credential_value:
                encoded = base64.b64encode(self.credential_value.encode()).decode()
            else:
                # Assume it's a token that should be used as password with empty user
                encoded = base64.b64encode(f":{self.credential_value}".encode()).decode()
            headers[primary_header] = f'Basic {encoded}'
            auth_headers.append(f'{primary_header}: Basic')
            
        elif method == 'basic_token':
            # Basic auth where the token is the username (e.g., Mixpanel)
            encoded = base64.b64encode(f"{self.credential_value}:".encode()).decode()
            headers[primary_header] = f'Basic {encoded}'
            auth_headers.append(f'{primary_header}: Basic (token as user)')
            # Also try alternative headers
            for alt in alternatives[:1]:
                headers[alt] = self.credential_value
                auth_headers.append(alt)
                
        elif method == 'key_prefix':
            # Key with prefix (e.g., Firebase "key=VALUE")
            headers[primary_header] = f'{prefix}{self.credential_value}'
            auth_headers.append(f'{primary_header}: {prefix}...')
            # Also try alternatives
            for alt in alternatives[:2]:
                headers[alt] = self.credential_value
                auth_headers.append(alt)
        
        elif method == 'cognito_api':
            # AWS Cognito - client_id goes in request body, not headers
            # For header-based requests, we still add common headers
            # The actual Cognito API call uses POST with JSON body
            headers['X-Amz-Target'] = 'AWSCognitoIdentityProviderService.InitiateAuth'
            headers['Content-Type'] = 'application/x-amz-json-1.1'
            auth_headers.append('X-Amz-Target: Cognito InitiateAuth')
            auth_headers.append(f'ClientId (in body): {self.credential_value}')
                
        else:
            # Fallback: try multiple common approaches
            logger.warning(f"Unknown auth method '{method}', using fallback")
            headers['Authorization'] = f'Bearer {self.credential_value}'
            headers['X-API-Key'] = self.credential_value
            headers['X-Auth-Token'] = self.credential_value
            auth_headers.extend(['Authorization: Bearer', 'X-API-Key', 'X-Auth-Token'])
        
        # Store detected service info in result
        self.result.auth_headers_used = auth_headers
        self.result.detected_service = service_name
        self.result.service_detection_score = detection_score
        
        logger.debug(f"Auth headers configured: {auth_headers}")
        return headers
    
    async def _get_delay(self) -> float:
        """Get delay between requests based on test mode (reduced for faster tests)"""
        if self.test_mode == 'none':
            return 0
        elif self.test_mode == 'cautious':
            return random.uniform(0.1, 0.3)  # Reduced from 0.5-2.0s
        else:  # insane
            return random.uniform(0.05, 0.1)
    
    async def _make_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        data: Optional[Dict] = None,
        timeout: float = 10.0
    ) -> Tuple[Optional[httpx.Response], Optional[str]]:
        """Make HTTP request with error handling"""
        if headers is None:
            headers = self._get_headers()
        
        try:
            if self.test_mode == 'cautious':
                await asyncio.sleep(await self._get_delay())
            
            ssl_verify = os.getenv("SSL_VERIFY", "true").lower() != "false"
            async with httpx.AsyncClient(timeout=timeout, verify=ssl_verify, follow_redirects=True) as client:
                if method.upper() == "GET":
                    response = await client.get(url, headers=headers)
                elif method.upper() == "POST":
                    response = await client.post(url, headers=headers, json=data)
                elif method.upper() == "PUT":
                    response = await client.put(url, headers=headers, json=data)
                elif method.upper() == "DELETE":
                    response = await client.delete(url, headers=headers)
                elif method.upper() == "OPTIONS":
                    response = await client.options(url, headers=headers)
                elif method.upper() == "HEAD":
                    response = await client.head(url, headers=headers)
                else:
                    response = await client.request(method, url, headers=headers)
                
                return response, None
        except httpx.TimeoutException:
            return None, "Timeout"
        except httpx.ConnectError as e:
            return None, f"Connection failed: {str(e)[:100]}"
        except Exception as e:
            return None, f"Error: {str(e)[:100]}"
    
    async def _build_auth_headers_for_combination(
        self,
        auth_combo: Dict[str, str],
        credential_value: str
    ) -> Dict[str, str]:
        """
        Build headers for a specific authentication combination.
        
        Supports:
        - basic: HTTP Basic Auth (username:password base64 encoded)
        - bearer: Bearer token
        - header: Custom header with value
        - query_param: Query parameter (returns empty headers, URL modified separately)
        """
        import base64
        
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'User-Agent': 'AuditGH-SecurityScanner/1.0',
        }
        
        method = auth_combo.get('method', 'bearer')
        
        if method == 'basic':
            username = auth_combo.get('username', '').replace('{token}', credential_value)
            password = auth_combo.get('password', '').replace('{token}', credential_value)
            # Handle placeholders that need additional context
            username = username.replace('{service_account_id}', credential_value)
            username = username.replace('{api_secret}', credential_value)
            password = password.replace('{service_account_id}', credential_value)
            password = password.replace('{api_secret}', credential_value)
            
            credentials = f"{username}:{password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers['Authorization'] = f'Basic {encoded}'
            
        elif method == 'bearer':
            token = auth_combo.get('token', '{token}').replace('{token}', credential_value)
            headers['Authorization'] = f'Bearer {token}'
            
        elif method == 'header':
            header_name = auth_combo.get('header', 'X-API-Key')
            header_value = auth_combo.get('value', '{token}').replace('{token}', credential_value)
            headers[header_name] = header_value
            
        elif method == 'query_param':
            # Query params are handled in URL, not headers
            pass
        
        return headers
    
    def _replace_placeholders_in_body(self, obj: Any, credential_value: str) -> Any:
        """
        Recursively replace {token} placeholders in a body template.
        Works with dicts, lists, and strings.
        """
        if isinstance(obj, dict):
            return {k: self._replace_placeholders_in_body(v, credential_value) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._replace_placeholders_in_body(item, credential_value) for item in obj]
        elif isinstance(obj, str):
            return obj.replace('{token}', credential_value)
        else:
            return obj
    
    async def test_canonical_endpoints(self) -> Dict[str, Any]:
        """
        Test the credential against canonical API endpoints for the detected service.
        
        This method:
        1. Detects the service from credential type
        2. Gets the canonical endpoints for that service
        3. Tries multiple authentication combinations for each endpoint
        4. Returns the first successful combination with full proof
        
        Returns:
            Dict with 'success', 'endpoint', 'auth_combination', 'response', 'proof'
        """
        import base64
        
        service_name, auth_config, detection_score = self._detect_service()
        service_patterns = SERVICE_AUTH_PATTERNS.get(service_name, {})
        canonical_endpoints = service_patterns.get('canonical_endpoints', [])
        
        if not canonical_endpoints:
            logger.info(f"No canonical endpoints defined for service: {service_name}")
            return {'success': False, 'reason': 'No canonical endpoints for service'}
        
        logger.info(f"Testing {len(canonical_endpoints)} canonical endpoints for {service_name}")
        
        successful_tests = []
        all_attempts = []
        
        for endpoint_config in canonical_endpoints:
            endpoint_url = endpoint_config['url']
            http_method = endpoint_config.get('method', 'GET')
            description = endpoint_config.get('description', '')
            auth_combinations = endpoint_config.get('auth_combinations', [])
            
            logger.info(f"Testing endpoint: {endpoint_url} ({description})")
            
            for auth_combo in auth_combinations:
                # Build headers for this auth combination
                headers = await self._build_auth_headers_for_combination(
                    auth_combo, 
                    self.credential_value
                )
                
                # Handle endpoint-specific headers (e.g., Cognito API headers)
                endpoint_headers = endpoint_config.get('headers', {})
                headers.update(endpoint_headers)
                
                # Handle body template (for APIs like Cognito that use body-based auth)
                request_body = None
                body_template = endpoint_config.get('body_template')
                if body_template:
                    # Deep copy and replace placeholders
                    import copy
                    request_body = copy.deepcopy(body_template)
                    request_body = self._replace_placeholders_in_body(request_body, self.credential_value)
                
                # Handle query params
                test_url = endpoint_url
                if auth_combo.get('method') == 'query_param':
                    param_name = auth_combo.get('param', 'token')
                    param_value = auth_combo.get('value', '{token}').replace('{token}', self.credential_value)
                    separator = '&' if '?' in test_url else '?'
                    test_url = f"{test_url}{separator}{param_name}={param_value}"
                
                # Make the request
                start_time = datetime.now()
                response, error = await self._make_request(
                    test_url, 
                    method=http_method, 
                    headers=headers,
                    data=request_body
                )
                response_time = int((datetime.now() - start_time).total_seconds() * 1000)
                
                attempt_record = {
                    'endpoint': endpoint_url,
                    'method': http_method,
                    'auth_combination': auth_combo,
                    'headers_sent': self._preserve_headers_for_storage(headers),
                    'response_time_ms': response_time,
                    'error': error,
                    'status_code': response.status_code if response else None,
                    'response_body': None
                }
                
                if error:
                    logger.warning(f"Request failed: {error}")
                    all_attempts.append(attempt_record)
                    continue
                
                # Capture response
                try:
                    response_body = response.text[:5000]  # Limit size
                    attempt_record['response_body'] = response_body
                except (AttributeError, UnicodeDecodeError) as e:
                    logger.debug(f"Failed to capture response body: {str(e)}")
                    response_body = ""
                
                attempt_record['status_code'] = response.status_code
                all_attempts.append(attempt_record)
                
                # Check if authentication was successful
                # Success indicators: 2xx status, or specific error messages that indicate valid auth
                is_success = False
                success_reason = ""
                credential_validated = False  # Did we prove the credential is valid/exists?
                
                response_body_lower = response_body.lower()
                
                if response.status_code in (200, 201, 202, 204):
                    is_success = True
                    credential_validated = True
                    success_reason = f"HTTP {response.status_code} - Request succeeded"
                elif response.status_code == 400:
                    # AWS Cognito returns 400 with specific error types that prove client_id exists
                    # NotAuthorizedException = client_id valid, but wrong credentials
                    # UserNotFoundException = client_id valid, user doesn't exist
                    # InvalidParameterException = might indicate client_id format issue
                    if 'notauthorizedexception' in response_body_lower:
                        credential_validated = True
                        success_reason = "Cognito: Client ID valid - NotAuthorizedException (wrong credentials)"
                    elif 'usernotfoundexception' in response_body_lower:
                        credential_validated = True
                        success_reason = "Cognito: Client ID valid - UserNotFoundException"
                    elif 'resourcenotfoundexception' in response_body_lower:
                        success_reason = "Cognito: Client ID not found in this region"
                    elif 'invalidparameterexception' in response_body_lower:
                        if 'client' in response_body_lower:
                            success_reason = "Cognito: Invalid client_id format or not found"
                        else:
                            success_reason = "Cognito: Invalid parameter"
                    else:
                        success_reason = f"HTTP 400 - Bad Request: {response_body[:200]}"
                elif response.status_code == 401:
                    # Check if it's "invalid credentials" vs "missing credentials"
                    # Invalid credentials means the auth method is correct but creds are wrong
                    if 'invalid' in response_body_lower:
                        credential_validated = True
                        success_reason = "Auth method correct, credentials invalid (proves credential format is valid)"
                    else:
                        success_reason = "Authentication required"
                elif response.status_code == 403:
                    # Forbidden might mean auth worked but no permission
                    if 'permission' in response_body_lower or 'access' in response_body_lower:
                        is_success = True
                        credential_validated = True
                        success_reason = f"HTTP {response.status_code} - Authenticated but insufficient permissions"
                
                # For Cognito and similar services, "credential validated" is valuable even if not "success"
                # It proves the credential exists and is in the correct format
                
                # Build proof record for this attempt
                proof = {
                    'endpoint': endpoint_url,
                    'method': http_method,
                    'description': description,
                    'auth_combination': auth_combo,
                    'credential_validated': credential_validated,
                    'request': {
                        'method': http_method,
                        'url': test_url,
                        'headers': self._preserve_headers_for_storage(headers),
                        'body': request_body  # Include body for APIs like Cognito
                    },
                    'response': {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'body': response_body,
                        'response_time_ms': response_time
                    },
                    'success_reason': success_reason
                }
                
                attempt_record['credential_validated'] = credential_validated
                attempt_record['request_body'] = request_body
                
                if is_success or credential_validated:
                    logger.info(f"{'SUCCESS' if is_success else 'VALIDATED'}: {endpoint_url} - {success_reason}")
                    
                    successful_tests.append(proof)
                    
                    # Update result with auth info
                    self.result.auth_status = "yes" if is_success else "validated"
                    self.result.auth_status_code = response.status_code
                    self.result.auth_request_method = http_method
                    self.result.auth_request_url = test_url
                    self.result.auth_request_headers = self._preserve_headers_for_storage(headers)
                    self.result.auth_request_body = json.dumps(request_body) if request_body else ""
                    self.result.auth_response_headers = dict(response.headers)
                    self.result.auth_response_body = response_body
                    self.result.auth_response_time_ms = response_time
                    
                    # Return first success or validation
                    return {
                        'success': is_success,
                        'credential_validated': credential_validated,
                        'service': service_name,
                        'endpoint': endpoint_url,
                        'auth_combination': auth_combo,
                        'proof': proof,
                        'all_attempts': all_attempts
                    }
        
        # No successful auth found
        logger.info(f"No successful authentication found for {service_name}")
        return {
            'success': False,
            'service': service_name,
            'reason': 'All authentication combinations failed',
            'all_attempts': all_attempts,
            'documentation_url': service_patterns.get('documentation_url', '')
        }
    
    async def test_authentication(self) -> bool:
        """Test if credentials authenticate successfully"""
        logger.info(f"Testing authentication for {self.target_url}")
        
        start_time = datetime.now()
        headers = self._get_headers(include_auth=True)
        
        response, error = await self._make_request(self.target_url, headers=headers)
        
        response_time = int((datetime.now() - start_time).total_seconds() * 1000)
        self.result.auth_response_time_ms = response_time
        
        # Capture request details (preserve actual values for audit validation)
        self.result.auth_request_method = "GET"
        self.result.auth_request_url = self.target_url
        self.result.auth_request_headers = self._preserve_headers_for_storage(headers)
        self.result.auth_request_body = ""  # GET requests typically have no body
        
        if error:
            self.result.auth_status = "failed"
            self.result.auth_error_message = error
            logger.warning(f"Auth test failed: {error}")
            return False
        
        self.result.auth_status_code = response.status_code
        
        # Capture response details
        self.result.auth_response_headers = dict(response.headers)
        
        # Capture response body (truncate if too large)
        try:
            body_text = response.text
            max_body_size = 10000  # 10KB limit for storage
            if len(body_text) > max_body_size:
                self.result.auth_response_body = body_text[:max_body_size]
                self.result.auth_response_body_truncated = True
            else:
                self.result.auth_response_body = body_text
                self.result.auth_response_body_truncated = False
        except Exception as e:
            self.result.auth_response_body = f"[Error reading response body: {str(e)}]"
            self.result.auth_response_body_truncated = False
        
        # Determine auth status based on response
        if response.status_code in (200, 201, 202, 204):
            self.result.auth_status = "yes"
            logger.info(f"Auth successful: {response.status_code}")
            return True
        elif response.status_code in (401, 403):
            self.result.auth_status = "failed"
            self.result.auth_error_message = f"HTTP {response.status_code}: Unauthorized/Forbidden"
            logger.info(f"Auth failed: {response.status_code}")
            return False
        elif response.status_code in (404,):
            # Endpoint might not exist, but we reached the server
            self.result.auth_status = "failed"
            self.result.auth_error_message = f"HTTP {response.status_code}: Endpoint not found"
            return False
        else:
            # Other status codes - might still be authenticated
            self.result.auth_status = "yes" if response.status_code < 400 else "failed"
            self.result.auth_error_message = f"HTTP {response.status_code}"
            return response.status_code < 400
    
    async def discover_paths(self) -> List[Dict]:
        """Discover API paths through fuzzing"""
        logger.info(f"Starting path discovery for {self.base_url}")
        
        discovered = []
        headers = self._get_headers(include_auth=True)
        
        # Combine base paths with common paths
        paths_to_test = set()
        
        # Add common paths
        for path in COMMON_API_PATHS:
            paths_to_test.add(f"/{path}")
            paths_to_test.add(f"{self.base_path}/{path}")
        
        # Add variations based on base path
        if self.base_path and self.base_path != "/":
            parts = self.base_path.strip('/').split('/')
            for i in range(len(parts)):
                partial = '/' + '/'.join(parts[:i+1])
                paths_to_test.add(partial)
        
        # Limit paths based on test mode (reduced for faster tests)
        max_paths = {
            'none': 50,
            'cautious': 25,
            'insane': 100
        }.get(self.test_mode, 25)
        
        paths_to_test = list(paths_to_test)[:max_paths]
        
        # Test paths
        methods_to_test = ['GET']
        if self.test_mode == 'insane':
            methods_to_test.extend(['POST', 'PUT', 'DELETE', 'OPTIONS'])
        
        for path in paths_to_test:
            url = urljoin(self.base_url, path)
            
            if url in self._discovered_endpoints:
                continue
            
            for method in methods_to_test:
                response, error = await self._make_request(url, method=method, headers=headers)
                
                if response and response.status_code not in (404, 405, 502, 503):
                    self._discovered_endpoints.add(url)
                    
                    # Get sample data for successful responses
                    sample_data = None
                    if response.status_code in (200, 201) and method == 'GET':
                        try:
                            content = response.text[:2000]  # Limit sample size
                            if response.headers.get('content-type', '').startswith('application/json'):
                                sample_data = json.loads(content) if len(content) < 2000 else {"truncated": True, "preview": content[:500]}
                            else:
                                sample_data = {"type": response.headers.get('content-type', 'unknown'), "preview": content[:500]}
                        except (json.JSONDecodeError, AttributeError, UnicodeDecodeError) as e:
                            logger.debug(f"Failed to parse sample data: {str(e)}")
                            sample_data = {"raw": response.text[:500]}
                    
                    path_info = {
                        "method": method,
                        "path": path,
                        "full_url": url,
                        "status_code": response.status_code,
                        "success": response.status_code < 400,
                        "sample_data": sample_data,
                        "content_type": response.headers.get('content-type', ''),
                        "content_length": len(response.content)
                    }
                    discovered.append(path_info)
                    
                    # Check if this might be a hidden/debug endpoint
                    if any(h in path.lower() for h in ['debug', 'internal', 'admin', 'hidden', 'secret', 'backup', '.env', '.git']):
                        self.result.hidden_paths_found += 1
        
        self.result.discovered_paths = discovered
        self.result.discovered_paths_count = len(discovered)
        
        logger.info(f"Discovered {len(discovered)} paths, {self.result.hidden_paths_found} potentially hidden")
        return discovered
    
    async def analyze_sample_data(self) -> List[Dict]:
        """Analyze retrieved data for sensitive information"""
        logger.info("Analyzing sample data for sensitive information")
        
        sensitivity_findings = []
        
        for path_info in self.result.discovered_paths:
            sample = path_info.get('sample_data')
            if not sample:
                continue
            
            # Convert to string for pattern matching
            sample_str = json.dumps(sample) if isinstance(sample, dict) else str(sample)
            
            for pattern_name, pattern in SENSITIVE_PATTERNS.items():
                matches = re.findall(pattern, sample_str, re.IGNORECASE)
                if matches:
                    sensitivity_findings.append({
                        "path": path_info.get('path'),
                        "type": pattern_name,
                        "count": len(matches),
                        "severity": "high" if pattern_name in ('ssn', 'credit_card', 'private_key', 'aws_key') else "medium"
                    })
        
        self.result.data_sensitivity_indicators = sensitivity_findings
        
        # Also store sample data
        self.result.sample_data_retrieved = [
            {
                "path": p.get('path'),
                "status": p.get('status_code'),
                "data_preview": str(p.get('sample_data', ''))[:500]
            }
            for p in self.result.discovered_paths
            if p.get('sample_data')
        ][:20]  # Limit to 20 samples
        
        logger.info(f"Found {len(sensitivity_findings)} sensitive data indicators")
        return sensitivity_findings
    
    async def gather_osint(self) -> List[Dict]:
        """
        Gather OSINT from GitHub and web sources.
        
        CRITICAL: This searches PUBLIC GitHub repos OUTSIDE the organization
        to find how other developers authenticate to the same services.
        This is the key to learning correct auth patterns.
        """
        logger.info(f"Gathering OSINT for {self.target_url} (searching PUBLIC GitHub)")
        
        findings = []
        parsed = urlparse(self.target_url)
        domain = parsed.netloc
        
        # GitHub Code Search - searches ALL PUBLIC repos
        if self.github_token:
            github_findings = await self._search_github(domain)
            findings.extend(github_findings)
            
            # Count internal vs external repos
            internal_count = len([f for f in github_findings if f.get('type') == 'GitHub_Internal'])
            external_count = len([f for f in github_findings if f.get('type') == 'GitHub_External'])
            self.result.github_repos_found = internal_count + external_count
            
            logger.info(f"OSINT: Found {external_count} EXTERNAL public repos, {internal_count} internal repos")
            
            # =========================================================================
            # CRITICAL: Extract and summarize auth patterns from EXTERNAL PUBLIC repos
            # This is the most valuable OSINT - how do OTHERS authenticate?
            # =========================================================================
            all_auth_patterns = []
            external_with_endpoints = []
            
            for f in github_findings:
                if f.get('type') == 'GitHub_External':
                    endpoints = f.get('api_endpoints_found', [])
                    if endpoints:
                        external_with_endpoints.append(f)
                    
                    # Collect auth patterns from external repos
                    for ep in endpoints:
                        if ep.get('type') == 'auth_pattern':
                            all_auth_patterns.append({
                                'repo': f.get('repo_name', 'unknown'),
                                'headers': ep.get('auth_headers', []),
                                'methods': ep.get('auth_methods', []),
                                'snippets': ep.get('code_snippets', [])
                            })
            
            # Create auth pattern summary if we found any
            if all_auth_patterns:
                # Aggregate all unique headers found
                all_headers = []
                all_methods = []
                for ap in all_auth_patterns:
                    all_headers.extend(ap.get('headers', []))
                    all_methods.extend(ap.get('methods', []))
                
                unique_headers = list(set(all_headers))
                unique_methods = list(set(all_methods))
                
                auth_summary = {
                    'type': 'External_Auth_Patterns',
                    'description': f'Auth patterns from {len(all_auth_patterns)} external PUBLIC repos',
                    'relevance': 99,  # Highest relevance - this is gold
                    'discovered_headers': unique_headers,
                    'discovered_methods': unique_methods,
                    'source_repos': [ap['repo'] for ap in all_auth_patterns],
                    'details': all_auth_patterns[:5]  # Top 5 examples
                }
                
                # Insert at the very beginning - this is the most valuable OSINT
                findings.insert(0, auth_summary)
                logger.info(f"OSINT GOLD: Found auth patterns from external repos: {unique_headers}")
            
            if external_with_endpoints:
                # Create a summary card for external API usage
                external_api_summary = {
                    'type': 'External_API_Usage_Summary',
                    'description': f'{len(external_with_endpoints)} external PUBLIC repos accessing this API',
                    'relevance': 95,
                    'repos': []
                }
                
                for repo_finding in external_with_endpoints:
                    repo_summary = {
                        'repo_name': repo_finding.get('repo_name', 'unknown'),
                        'file_path': repo_finding.get('file_path', ''),
                        'url': repo_finding.get('url', ''),
                        'api_endpoints': repo_finding.get('api_endpoints_found', [])
                    }
                    external_api_summary['repos'].append(repo_summary)
                
                # Insert after auth patterns
                insert_pos = 1 if all_auth_patterns else 0
                findings.insert(insert_pos, external_api_summary)
        
        # Search for documentation patterns
        doc_findings = await self._search_documentation(domain)
        findings.extend(doc_findings)
        self.result.documentation_links_found = len([f for f in doc_findings if f.get('type') == 'Documentation'])
        
        self.result.osint_findings = findings
        logger.info(f"Found {len(findings)} OSINT sources ({self.result.github_repos_found} GitHub repos, {external_count} external)")
        return findings
    
    async def _search_github(self, domain: str) -> List[Dict]:
        """
        Search GitHub for references to the target URL.
        
        IMPORTANT: This searches ALL of public GitHub, not just the organization.
        This is critical for OSINT - we want to find how OTHER developers/companies
        authenticate to the same services, which reveals auth patterns we can use.
        """
        findings = []
        
        if not self.github_token:
            return findings
        
        headers = {
            'Authorization': f'token {self.github_token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'AuditGH-SecurityScanner'
        }
        
        # Get the org from the token to identify internal vs external repos
        current_org = None
        try:
            org_response, _ = await self._make_request(
                "https://api.github.com/user/orgs",
                headers=headers
            )
            if org_response and org_response.status_code == 200:
                orgs = org_response.json()
                if orgs:
                    current_org = orgs[0].get('login', '').lower()
        except (json.JSONDecodeError, KeyError, IndexError, AttributeError) as e:
            logger.debug(f"Failed to get GitHub user organizations: {str(e)}")
        
        # Search for domain in code - use more specific queries
        parsed = urlparse(self.target_url)
        
        # Extract domain parts for broader search
        domain_parts = domain.split('.')
        # Get the main service identifier (e.g., "sleepiq" from "prod-apps-svc.sleepiq.sleepnumber.com")
        service_identifiers = [p for p in domain_parts if len(p) > 3 and p not in ('com', 'net', 'org', 'io', 'api', 'www', 'prod', 'dev', 'stage', 'staging', 'test')]
        
        # Build search queries - EXPLICITLY search PUBLIC repos outside the org
        # The key insight: we want to find how OTHERS use the same API
        search_queries = []
        
        # 1. Search for the exact domain in PUBLIC repos (excluding our org)
        if current_org:
            search_queries.append(f'"{domain}" NOT org:{current_org}')
        else:
            search_queries.append(f'"{domain}"')
        
        # 2. Search for service-specific identifiers in PUBLIC repos
        for identifier in service_identifiers[:2]:
            if current_org:
                search_queries.append(f'"{identifier}" api NOT org:{current_org}')
            else:
                search_queries.append(f'"{identifier}" api')
        
        # 3. Add path-based search if meaningful
        if parsed.path and len(parsed.path) > 5:
            # Extract meaningful path segments
            path_parts = [p for p in parsed.path.split('/') if p and len(p) > 3]
            if path_parts:
                path_query = f'"{path_parts[0]}"'
                if current_org:
                    path_query += f' NOT org:{current_org}'
                search_queries.append(path_query)
        
        # 4. Add credential-type specific searches to find auth patterns in PUBLIC repos
        cred_type_lower = self.credential_type.lower()
        public_filter = f' NOT org:{current_org}' if current_org else ''
        
        if 'azure' in cred_type_lower or 'azure' in domain:
            search_queries.append(f'"Ocp-Apim-Subscription-Key"{public_filter}')
            search_queries.append(f'"azure-api.net"{public_filter}')
        elif 'aws' in cred_type_lower or 'cognito' in cred_type_lower:
            search_queries.append(f'"cognito-idp" "InitiateAuth"{public_filter}')
        elif 'stripe' in cred_type_lower:
            search_queries.append(f'"api.stripe.com"{public_filter}')
        elif 'github' in cred_type_lower:
            search_queries.append(f'"api.github.com" Authorization{public_filter}')
        elif 'openai' in cred_type_lower:
            search_queries.append(f'"api.openai.com" Authorization{public_filter}')
        elif 'slack' in cred_type_lower:
            search_queries.append(f'"slack.com/api" token{public_filter}')
        elif 'mixpanel' in cred_type_lower:
            search_queries.append(f'"mixpanel.com" Authorization{public_filter}')
        elif 'firebase' in cred_type_lower:
            search_queries.append(f'"fcm.googleapis.com" Authorization{public_filter}')
        elif 'instabug' in cred_type_lower:
            search_queries.append(f'"instabug.com" api{public_filter}')
        
        search_queries = [q for q in search_queries if q]
        logger.info(f"OSINT search queries (targeting PUBLIC repos): {search_queries[:6]}")
        
        internal_repos = []
        external_repos = []
        
        for query in search_queries[:4]:  # Limit to 4 queries
            try:
                url = f"https://api.github.com/search/code?q={query}&per_page=20"
                response, error = await self._make_request(url, headers=headers)
                
                if response and response.status_code == 200:
                    data = response.json()
                    for item in data.get('items', [])[:20]:
                        repo_full_name = item.get('repository', {}).get('full_name', 'unknown')
                        repo_owner = repo_full_name.split('/')[0].lower() if '/' in repo_full_name else ''
                        file_path = item.get('path', '')
                        html_url = item.get('html_url', '')
                        
                        # Determine if internal or external
                        is_internal = current_org and repo_owner == current_org
                        
                        finding = {
                            "url": html_url,
                            "type": "GitHub_Internal" if is_internal else "GitHub_External",
                            "description": f"Found in {repo_full_name}",
                            "relevance": 85 if is_internal else 75,
                            "file_path": file_path,
                            "repo_name": repo_full_name,
                            "is_internal": is_internal,
                            "api_endpoints_found": []  # Will be populated below
                        }
                        
                        if is_internal:
                            internal_repos.append(finding)
                        else:
                            external_repos.append(finding)
                
                await asyncio.sleep(1)  # Rate limiting for GitHub API
            except Exception as e:
                logger.warning(f"GitHub search error: {e}")
        
        # For external repos, try to fetch the file content to extract actual API endpoints
        for finding in external_repos[:5]:  # Limit to 5 external repos
            try:
                api_endpoints = await self._extract_api_endpoints_from_github_file(
                    finding['repo_name'],
                    finding['file_path'],
                    domain,
                    headers
                )
                finding['api_endpoints_found'] = api_endpoints
            except Exception as e:
                logger.warning(f"Error extracting endpoints from {finding['repo_name']}: {e}")
        
        # Combine findings with external repos first (more interesting for OSINT)
        findings.extend(external_repos)
        findings.extend(internal_repos)
        
        return findings
    
    async def _extract_api_endpoints_from_github_file(
        self,
        repo_full_name: str,
        file_path: str,
        target_domain: str,
        headers: Dict
    ) -> List[Dict]:
        """
        Fetch a GitHub file and extract API endpoint URLs AND authentication patterns from it.
        
        This is the KEY OSINT function - it analyzes how OTHER developers authenticate
        to the same services, revealing auth patterns we can use.
        
        Returns a list of API endpoints found in the code, including auth patterns.
        """
        endpoints = []
        
        try:
            # Get file content via GitHub API
            url = f"https://api.github.com/repos/{repo_full_name}/contents/{file_path}"
            response, error = await self._make_request(url, headers=headers)
            
            if not response or response.status_code != 200:
                return endpoints
            
            data = response.json()
            
            # Decode base64 content
            import base64
            content = ""
            if data.get('encoding') == 'base64' and data.get('content'):
                try:
                    content = base64.b64decode(data['content']).decode('utf-8', errors='ignore')
                except (ValueError, UnicodeDecodeError) as e:
                    logger.debug(f"Failed to decode base64 content from GitHub file: {str(e)}")
                    return endpoints
            
            # Extract URLs from the code
            # Pattern to match URLs with the target domain
            url_pattern = rf'https?://[^\s\'"<>]*{re.escape(target_domain)}[^\s\'"<>]*'
            found_urls = re.findall(url_pattern, content, re.IGNORECASE)
            
            # Also look for API path patterns
            path_patterns = [
                r'/api/v\d+/[a-zA-Z0-9/_-]+',
                r'/v\d+/[a-zA-Z0-9/_-]+',
                r'/rest/[a-zA-Z0-9/_-]+',
                r'/graphql',
            ]
            
            for url_found in set(found_urls):
                # Clean up the URL
                url_found = url_found.rstrip('",\')}]')
                endpoints.append({
                    'url': url_found,
                    'type': 'full_url',
                    'context': 'Found in external public repo'
                })
            
            # Extract API paths near the domain reference
            for pattern in path_patterns:
                paths = re.findall(pattern, content)
                for path in set(paths):
                    endpoints.append({
                        'url': path,
                        'type': 'api_path',
                        'context': 'API path from external public repo'
                    })
            
            # =========================================================================
            # CRITICAL OSINT: Extract authentication patterns from external code
            # This reveals how OTHER developers authenticate to the same services
            # =========================================================================
            auth_patterns = self._extract_auth_headers_from_code(content)
            if auth_patterns:
                endpoints.append({
                    'url': f'AUTH_PATTERN:{repo_full_name}',
                    'type': 'auth_pattern',
                    'context': 'Authentication pattern from external public repo',
                    'auth_headers': auth_patterns.get('headers', []),
                    'auth_methods': auth_patterns.get('methods', []),
                    'code_snippets': auth_patterns.get('snippets', [])
                })
                logger.info(f"OSINT: Found auth patterns in {repo_full_name}: {auth_patterns.get('headers', [])}")
            
            # Deduplicate
            seen = set()
            unique_endpoints = []
            for ep in endpoints:
                key = ep['url'] if ep['type'] != 'auth_pattern' else f"auth:{ep.get('auth_headers', [])}"
                if key not in seen:
                    seen.add(key)
                    unique_endpoints.append(ep)
            
            return unique_endpoints[:15]  # Increased limit to capture auth patterns
            
        except Exception as e:
            logger.warning(f"Error extracting endpoints: {e}")
            return []
    
    def _extract_auth_headers_from_code(self, content: str) -> Dict:
        """
        Extract authentication header patterns from code.
        
        This is CRITICAL for OSINT - we analyze how other developers
        authenticate to the same services to learn the correct auth method.
        """
        result = {
            'headers': [],
            'methods': [],
            'snippets': []
        }
        
        # Common auth header patterns to look for
        auth_header_patterns = [
            # Header name patterns
            (r'["\']Authorization["\']\s*[,:=]\s*["\']Bearer\s+', 'Authorization: Bearer'),
            (r'["\']Authorization["\']\s*[,:=]\s*["\']Basic\s+', 'Authorization: Basic'),
            (r'["\']Authorization["\']\s*[,:=]', 'Authorization'),
            (r'["\']X-API-Key["\']\s*[,:=]', 'X-API-Key'),
            (r'["\']X-Api-Key["\']\s*[,:=]', 'X-Api-Key'),
            (r'["\']api-key["\']\s*[,:=]', 'api-key'),
            (r'["\']apikey["\']\s*[,:=]', 'apikey'),
            (r'["\']Ocp-Apim-Subscription-Key["\']\s*[,:=]', 'Ocp-Apim-Subscription-Key'),
            (r'["\']X-Auth-Token["\']\s*[,:=]', 'X-Auth-Token'),
            (r'["\']X-Access-Token["\']\s*[,:=]', 'X-Access-Token'),
            (r'["\']token["\']\s*[,:=]', 'token'),
            (r'["\']access_token["\']\s*[,:=]', 'access_token'),
            (r'["\']X-Subscription-Key["\']\s*[,:=]', 'X-Subscription-Key'),
        ]
        
        # Auth method patterns
        method_patterns = [
            (r'Bearer\s+[\$\{]?[a-zA-Z_]+', 'Bearer token'),
            (r'Basic\s+[\$\{]?[a-zA-Z_]+', 'Basic auth'),
            (r'\.setRequestHeader\s*\(["\']Authorization', 'setRequestHeader'),
            (r'headers\s*\[\s*["\']Authorization', 'headers dict'),
            (r'\.header\s*\(["\']Authorization', 'header method'),
            (r'fetch\s*\([^)]*headers', 'fetch with headers'),
            (r'axios\s*\.\s*(get|post|put|delete)\s*\([^)]*headers', 'axios with headers'),
            (r'requests\s*\.\s*(get|post|put|delete)\s*\([^)]*headers', 'requests with headers'),
        ]
        
        for pattern, header_name in auth_header_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                if header_name not in result['headers']:
                    result['headers'].append(header_name)
                    # Extract a code snippet around the match
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        start = max(0, match.start() - 50)
                        end = min(len(content), match.end() + 100)
                        snippet = content[start:end].strip()
                        # Clean up the snippet
                        snippet = re.sub(r'\s+', ' ', snippet)[:200]
                        result['snippets'].append(snippet)
        
        for pattern, method_name in method_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                if method_name not in result['methods']:
                    result['methods'].append(method_name)
        
        return result if result['headers'] or result['methods'] else None
    
    async def _extract_auth_patterns_from_code(self, content: str, target_domain: str) -> Dict:
        """
        Analyze code to extract authentication patterns.
        Returns a dict describing how auth is performed.
        """
        auth_patterns = {
            'method': None,  # header, query_param, body, cookie
            'header_name': None,
            'header_format': None,  # Bearer {token}, Basic {base64}, raw
            'query_param_name': None,
            'body_field': None,
            'cookie_name': None,
            'examples': [],
            'code_snippets': []
        }
        
        # Pattern 1: Query parameter auth (like SleepIQ example)
        # access_token={{token}}, token=xxx, api_key=xxx
        query_patterns = [
            (r'[?&](access_token|token|api_key|apikey|key|auth)=\{\{?(\w+)\}?\}?', 'query_param'),
            (r'[?&](access_token|token|api_key|apikey|key|auth)=["\']?\$?\{?(\w+)\}?["\']?', 'query_param'),
            (r'[?&](access_token|token|api_key|apikey|key)=', 'query_param'),
        ]
        
        for pattern, auth_type in query_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                param_name = matches[0][0] if isinstance(matches[0], tuple) else matches[0]
                auth_patterns['method'] = 'query_param'
                auth_patterns['query_param_name'] = param_name
                # Extract code snippet for context
                for line in content.split('\n'):
                    if param_name in line and target_domain in line.lower():
                        auth_patterns['code_snippets'].append(line.strip()[:200])
                        break
                break
        
        # Pattern 2: Header-based auth
        header_patterns = [
            # Authorization: Bearer xxx
            (r'["\']?Authorization["\']?\s*[,:=]\s*["\']?Bearer\s+', 'header', 'Authorization', 'Bearer {token}'),
            # Authorization: Basic xxx
            (r'["\']?Authorization["\']?\s*[,:=]\s*["\']?Basic\s+', 'header', 'Authorization', 'Basic {base64}'),
            # X-API-Key: xxx
            (r'["\']?(X-API-Key|x-api-key)["\']?\s*[,:=]', 'header', 'X-API-Key', '{token}'),
            # Api-Key: xxx
            (r'["\']?(Api-Key|api-key|apikey)["\']?\s*[,:=]', 'header', 'Api-Key', '{token}'),
            # Ocp-Apim-Subscription-Key (Azure)
            (r'["\']?(Ocp-Apim-Subscription-Key)["\']?\s*[,:=]', 'header', 'Ocp-Apim-Subscription-Key', '{token}'),
        ]
        
        for pattern, auth_type, header_name, header_format in header_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                if not auth_patterns['method']:  # Don't override query param if found
                    auth_patterns['method'] = 'header'
                auth_patterns['header_name'] = header_name
                auth_patterns['header_format'] = header_format
                # Extract code snippet
                for line in content.split('\n'):
                    if header_name.lower() in line.lower():
                        auth_patterns['code_snippets'].append(line.strip()[:200])
                        break
                break
        
        # Pattern 3: Cookie-based auth
        cookie_patterns = [
            (r'cookies?\s*[=:]\s*', 'cookie'),
            (r'\.cookies\s*\[', 'cookie'),
            (r'setCookie|set-cookie', 'cookie'),
        ]
        
        for pattern, auth_type in cookie_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                if not auth_patterns['method']:
                    auth_patterns['method'] = 'cookie'
                auth_patterns['cookie_name'] = 'session'  # Generic
                break
        
        # Pattern 4: Body-based auth (login endpoints)
        body_patterns = [
            (r'["\']?(username|email|user)["\']?\s*[,:=]', 'body', 'username'),
            (r'["\']?(password|passwd|pwd)["\']?\s*[,:=]', 'body', 'password'),
            (r'["\']?(client_id|clientId)["\']?\s*[,:=]', 'body', 'client_id'),
            (r'["\']?(client_secret|clientSecret)["\']?\s*[,:=]', 'body', 'client_secret'),
        ]
        
        for pattern, auth_type, field_name in body_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                if not auth_patterns['method']:
                    auth_patterns['method'] = 'body'
                auth_patterns['body_field'] = field_name
        
        # Extract example URLs with auth
        url_with_auth = re.findall(
            rf'https?://[^\s\'"]*{re.escape(target_domain)}[^\s\'"]*(?:token|key|auth)[^\s\'"]*',
            content,
            re.IGNORECASE
        )
        auth_patterns['examples'] = list(set(url_with_auth))[:5]
        
        return auth_patterns
    
    async def learn_auth_from_osint(self) -> Dict:
        """
        Analyze OSINT findings to learn how authentication is performed.
        Returns learned auth patterns that can be used to construct requests.
        """
        logger.info("Learning authentication patterns from OSINT...")
        
        learned_patterns = {
            'primary_method': None,
            'all_methods_found': [],
            'recommended_headers': {},
            'recommended_query_params': {},
            'recommended_body': {},
            'code_examples': [],
            'confidence': 0
        }
        
        if not self.github_token:
            return learned_patterns
        
        headers = {
            'Authorization': f'token {self.github_token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'AuditGH-SecurityScanner'
        }
        
        parsed = urlparse(self.target_url)
        domain = parsed.netloc
        
        # Get OSINT findings
        osint = self.result.osint_findings or []
        
        # Analyze each external repo's code
        auth_methods_found = []
        
        for finding in osint:
            if finding.get('type') not in ('GitHub_External', 'GitHub_Internal'):
                continue
            
            repo_name = finding.get('repo_name', '')
            file_path = finding.get('file_path', '')
            
            if not repo_name or not file_path:
                continue
            
            try:
                # Fetch file content
                url = f"https://api.github.com/repos/{repo_name}/contents/{file_path}"
                response, error = await self._make_request(url, headers=headers)
                
                if not response or response.status_code != 200:
                    continue
                
                data = response.json()
                
                import base64
                if data.get('encoding') == 'base64' and data.get('content'):
                    content = base64.b64decode(data['content']).decode('utf-8', errors='ignore')
                    
                    # Extract auth patterns from this file
                    patterns = await self._extract_auth_patterns_from_code(content, domain)
                    
                    if patterns.get('method'):
                        auth_methods_found.append({
                            'repo': repo_name,
                            'file': file_path,
                            'patterns': patterns
                        })
                        
                        # Add code examples
                        for snippet in patterns.get('code_snippets', []):
                            learned_patterns['code_examples'].append({
                                'repo': repo_name,
                                'snippet': snippet
                            })
                
                await asyncio.sleep(0.5)  # Rate limiting
                
            except Exception as e:
                logger.warning(f"Error analyzing {repo_name}/{file_path}: {e}")
        
        # Aggregate findings
        if auth_methods_found:
            # Count method occurrences
            method_counts = {}
            for item in auth_methods_found:
                method = item['patterns'].get('method')
                if method:
                    method_counts[method] = method_counts.get(method, 0) + 1
            
            # Primary method is the most common
            if method_counts:
                learned_patterns['primary_method'] = max(method_counts, key=method_counts.get)
                learned_patterns['all_methods_found'] = list(method_counts.keys())
            
            # Build recommended auth based on findings
            for item in auth_methods_found:
                patterns = item['patterns']
                
                if patterns.get('header_name'):
                    header_name = patterns['header_name']
                    header_format = patterns.get('header_format', '{token}')
                    learned_patterns['recommended_headers'][header_name] = header_format
                
                if patterns.get('query_param_name'):
                    param_name = patterns['query_param_name']
                    learned_patterns['recommended_query_params'][param_name] = '{token}'
                
                if patterns.get('body_field'):
                    field_name = patterns['body_field']
                    learned_patterns['recommended_body'][field_name] = '{token}'
            
            # Calculate confidence based on consistency
            if len(auth_methods_found) >= 3:
                learned_patterns['confidence'] = 90
            elif len(auth_methods_found) >= 2:
                learned_patterns['confidence'] = 75
            else:
                learned_patterns['confidence'] = 50
        
        logger.info(f"Learned auth patterns: {learned_patterns['primary_method']} (confidence: {learned_patterns['confidence']}%)")
        return learned_patterns
    
    async def build_request_from_learned_patterns(self, learned_patterns: Dict) -> Tuple[Dict, Dict, Optional[str]]:
        """
        Build HTTP request headers, query params, and body based on learned patterns.
        Returns (headers, query_params, body)
        """
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'application/json, text/plain, */*'
        }
        query_params = {}
        body = None
        
        token = self.credential_value
        
        # Apply learned header patterns
        for header_name, header_format in learned_patterns.get('recommended_headers', {}).items():
            if '{token}' in header_format:
                headers[header_name] = header_format.replace('{token}', token)
            elif '{base64}' in header_format:
                import base64
                # Try token:empty and empty:token for Basic auth
                encoded = base64.b64encode(f"{token}:".encode()).decode()
                headers[header_name] = header_format.replace('{base64}', encoded)
            else:
                headers[header_name] = token
        
        # Apply learned query param patterns
        for param_name, param_format in learned_patterns.get('recommended_query_params', {}).items():
            query_params[param_name] = token
        
        # Apply learned body patterns
        if learned_patterns.get('recommended_body'):
            body_dict = {}
            for field_name, field_format in learned_patterns['recommended_body'].items():
                body_dict[field_name] = token
            body = json.dumps(body_dict)
            headers['Content-Type'] = 'application/json'
        
        return headers, query_params, body
    
    async def try_intelligent_auth_combinations(
        self,
        learned_patterns: Dict,
        discovered_paths: List[Dict],
        additional_credentials: Optional[List[Dict]] = None
    ) -> Dict:
        """
        Intelligently try authentication combinations using:
        1. Learned patterns from OSINT
        2. Discovered paths from fuzzing
        3. All available credentials
        4. Service-specific auth methods
        
        Returns the first successful combination or details of all attempts.
        """
        logger.info("Trying intelligent auth combinations...")
        
        attempts = []
        successful_auth = None
        
        # Get base URL and paths to try
        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Collect paths to test (original + discovered)
        paths_to_test = [parsed.path or '/']
        
        # Add discovered paths that returned non-404 responses
        for path_info in (discovered_paths or [])[:10]:  # Limit to 10 paths
            path = path_info.get('path', '')
            status = path_info.get('status_code', 0)
            if path and status not in (404, 0):
                if not path.startswith('/'):
                    path = '/' + path
                if path not in paths_to_test:
                    paths_to_test.append(path)
        
        # Collect credentials to test
        credentials_to_test = [
            {'type': self.credential_type, 'value': self.credential_value}
        ]
        
        # Add additional credentials if provided
        if additional_credentials:
            for cred in additional_credentials[:5]:  # Limit to 5 additional
                if cred.get('value') and cred.get('value') != self.credential_value:
                    credentials_to_test.append(cred)
        
        logger.info(f"Testing {len(paths_to_test)} paths with {len(credentials_to_test)} credentials")
        
        # Build auth header combinations based on learned patterns and service detection
        service_name, auth_config, detection_score = self._detect_service()
        
        # Define header combinations to try
        header_combinations = []
        
        # 1. Learned patterns from OSINT (highest priority)
        if learned_patterns.get('recommended_headers'):
            header_combinations.append({
                'name': 'osint_learned',
                'headers': learned_patterns['recommended_headers'],
                'priority': 1
            })
        
        # 2. Service-specific headers
        service_headers = self._get_service_header_combinations(service_name)
        for combo in service_headers:
            header_combinations.append({
                'name': f'service_{service_name}_{combo["name"]}',
                'headers': combo['headers'],
                'priority': 2
            })
        
        # 3. Common fallback headers
        header_combinations.append({
            'name': 'bearer_auth',
            'headers': {'Authorization': 'Bearer {token}'},
            'priority': 3
        })
        header_combinations.append({
            'name': 'api_key_header',
            'headers': {'X-API-Key': '{token}', 'Api-Key': '{token}'},
            'priority': 3
        })
        
        # Test combinations
        for cred in credentials_to_test:
            token = cred['value']
            cred_type = cred['type']
            
            for path in paths_to_test[:5]:  # Limit paths per credential
                test_url = f"{base_url}{path}"
                
                for combo in header_combinations[:6]:  # Limit header combos
                    # Build headers with actual credential value
                    headers = {
                        'User-Agent': random.choice(USER_AGENTS),
                        'Accept': 'application/json, text/plain, */*'
                    }
                    
                    for header_name, header_format in combo['headers'].items():
                        if '{token}' in str(header_format):
                            headers[header_name] = header_format.replace('{token}', token)
                        elif '{base64}' in str(header_format):
                            import base64
                            encoded = base64.b64encode(f"{token}:".encode()).decode()
                            headers[header_name] = header_format.replace('{base64}', encoded)
                        else:
                            headers[header_name] = token
                    
                    # Make request
                    try:
                        response, error = await self._make_request(test_url, headers=headers)
                        
                        attempt = {
                            'url': test_url,
                            'credential_type': cred_type,
                            'credential_value': token,  # Full value for audit
                            'header_combo': combo['name'],
                            'headers_sent': self._preserve_headers_for_storage(headers),
                            'status_code': response.status_code if response else None,
                            'error': error,
                            'success': False
                        }
                        
                        if response:
                            is_success = response.status_code in (200, 201, 202, 204)
                            is_auth_error = response.status_code in (401, 403)
                            
                            attempt['success'] = is_success
                            attempt['response_preview'] = response.text[:500] if response.text else ''
                            
                            if is_success:
                                logger.info(f"SUCCESS: {combo['name']} worked on {test_url} with {cred_type}")
                                successful_auth = attempt
                                
                                # Update result with successful auth
                                self.result.auth_status = "yes"
                                self.result.auth_status_code = response.status_code
                                self.result.auth_request_headers = attempt['headers_sent']
                                self.result.auth_request_url = test_url
                                self.result.auth_method_used = combo['name']
                                self.result.auth_response_body = response.text[:10000]
                                self.result.auth_response_headers = dict(response.headers)
                                
                                attempts.append(attempt)
                                
                                return {
                                    'success': True,
                                    'winning_combination': attempt,
                                    'all_attempts': attempts
                                }
                            
                            elif not is_auth_error:
                                # Non-auth error (404, 500, etc.) - might be wrong path
                                logger.debug(f"Non-auth response {response.status_code} for {test_url}")
                        
                        attempts.append(attempt)
                        
                        # Rate limiting
                        await asyncio.sleep(0.1)
                        
                    except Exception as e:
                        logger.warning(f"Error testing {test_url}: {e}")
                        attempts.append({
                            'url': test_url,
                            'credential_type': cred_type,
                            'header_combo': combo['name'],
                            'error': str(e),
                            'success': False
                        })
        
        logger.info(f"Tried {len(attempts)} combinations, no successful auth found")
        return {
            'success': False,
            'all_attempts': attempts
        }
    
    def _get_service_header_combinations(self, service_name: str) -> List[Dict]:
        """Get service-specific header combinations to try."""
        combinations = []
        
        if service_name == 'Azure':
            combinations = [
                {'name': 'subscription_key', 'headers': {
                    'Ocp-Apim-Subscription-Key': '{token}',
                    'Subscription-Key': '{token}',
                    'Api-Key': '{token}'
                }},
                {'name': 'bearer', 'headers': {'Authorization': 'Bearer {token}'}},
            ]
        elif service_name == 'AWS':
            combinations = [
                {'name': 'x_api_key', 'headers': {'x-api-key': '{token}'}},
                {'name': 'authorization', 'headers': {'Authorization': '{token}'}},
            ]
        elif service_name == 'GitHub':
            combinations = [
                {'name': 'bearer', 'headers': {'Authorization': 'Bearer {token}'}},
                {'name': 'token', 'headers': {'Authorization': 'token {token}'}},
            ]
        elif service_name == 'OpenAI':
            combinations = [
                {'name': 'bearer', 'headers': {'Authorization': 'Bearer {token}'}},
            ]
        elif service_name == 'Stripe':
            combinations = [
                {'name': 'bearer', 'headers': {'Authorization': 'Bearer {token}'}},
                {'name': 'basic', 'headers': {'Authorization': 'Basic {base64}'}},
            ]
        elif service_name == 'Slack':
            combinations = [
                {'name': 'bearer', 'headers': {'Authorization': 'Bearer {token}'}},
            ]
        elif service_name == 'Mixpanel':
            combinations = [
                {'name': 'basic_token', 'headers': {'Authorization': 'Basic {base64}'}},
            ]
        elif service_name == 'Firebase':
            combinations = [
                {'name': 'key_param', 'headers': {}},  # Firebase uses query param
            ]
        else:
            # Generic combinations for unknown services
            combinations = [
                {'name': 'bearer', 'headers': {'Authorization': 'Bearer {token}'}},
                {'name': 'api_key', 'headers': {'X-API-Key': '{token}', 'Api-Key': '{token}'}},
                {'name': 'basic', 'headers': {'Authorization': 'Basic {base64}'}},
            ]
        
        return combinations
    
    async def _search_documentation(self, domain: str) -> List[Dict]:
        """Search for API documentation"""
        findings = []
        
        # Common documentation URL patterns
        doc_patterns = [
            f"https://{domain}/docs",
            f"https://{domain}/api/docs",
            f"https://{domain}/swagger",
            f"https://{domain}/openapi",
            f"https://docs.{domain}",
            f"https://developer.{domain}",
            f"https://api.{domain}/docs",
        ]
        
        for doc_url in doc_patterns:
            try:
                response, error = await self._make_request(doc_url, headers={'User-Agent': random.choice(USER_AGENTS)})

                if response and response.status_code == 200:
                    findings.append({
                        "url": doc_url,
                        "type": "Documentation",
                        "description": "API documentation endpoint",
                        "relevance": 90
                    })
            except Exception as e:
                logger.debug(f"Failed to check documentation endpoint {doc_url}: {str(e)}")
        
        return findings
    
    async def generate_ai_analysis(self) -> Dict:
        """Generate AI-powered analysis and recommendations"""
        logger.info("Generating AI analysis")
        
        # Try to use available LLM
        try:
            analysis = await self._call_llm_for_analysis()
            if analysis:
                return analysis
        except Exception as e:
            logger.warning(f"LLM analysis failed: {e}")
        
        # Fallback to rule-based analysis
        return self._generate_rule_based_analysis()
    
    async def _call_llm_for_analysis(self) -> Optional[Dict]:
        """Call LLM for intelligent analysis with AI safety controls."""
        # AI Safety imports
        try:
            from src.services.ai_safety.sanitize import sanitize_prompt_input
            from src.services.ai_safety.pii_masker import mask_pii, unmask_pii
            from src.services.ai_safety.validate import validate_agent_output
            _safety_available = True
        except ImportError:
            _safety_available = False

        # Check for Anthropic
        anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
        if anthropic_key:
            try:
                import anthropic
                client = anthropic.Anthropic(api_key=anthropic_key)

                prompt = self._build_analysis_prompt()

                # AI Safety: sanitize and mask
                if _safety_available:
                    prompt = sanitize_prompt_input(prompt)
                    prompt, pii_mappings = mask_pii(prompt)
                else:
                    pii_mappings = {}

                message = client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=2000,
                    messages=[{"role": "user", "content": prompt}]
                )

                response_text = message.content[0].text

                # AI Safety: validate and unmask
                if _safety_available:
                    validation = validate_agent_output(response_text)
                    response_text = validation.get("sanitized_text", response_text)
                    response_text = unmask_pii(response_text, pii_mappings)

                self.result.llm_provider = "anthropic"
                self.result.llm_model = "claude-sonnet-4-20250514"
                self.result.raw_llm_responses.append({
                    "prompt": prompt[:500],
                    "response": response_text[:2000]
                })

                return self._parse_llm_response(response_text)
            except Exception as e:
                logger.warning(f"Anthropic API error: {e}")

        # Check for OpenAI
        openai_key = os.environ.get("OPENAI_API_KEY")
        if openai_key:
            try:
                import openai
                client = openai.OpenAI(api_key=openai_key)

                prompt = self._build_analysis_prompt()

                # AI Safety: sanitize and mask
                if _safety_available:
                    prompt = sanitize_prompt_input(prompt)
                    prompt, pii_mappings = mask_pii(prompt)
                else:
                    pii_mappings = {}

                response = client.chat.completions.create(
                    model="gpt-4o",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=2000
                )

                response_text = response.choices[0].message.content

                # AI Safety: validate and unmask
                if _safety_available:
                    validation = validate_agent_output(response_text)
                    response_text = validation.get("sanitized_text", response_text)
                    response_text = unmask_pii(response_text, pii_mappings)

                self.result.llm_provider = "openai"
                self.result.llm_model = "gpt-4o"
                self.result.raw_llm_responses.append({
                    "prompt": prompt[:500],
                    "response": response_text[:2000]
                })

                return self._parse_llm_response(response_text)
            except Exception as e:
                logger.warning(f"OpenAI API error: {e}")

        return None
    
    def _build_analysis_prompt(self) -> str:
        """Build prompt for LLM analysis"""
        return f"""You are a senior security analyst reviewing API security test results. Analyze the following findings and provide:

1. OVERVIEW: A 2-3 sentence executive summary suitable for both technical analysts and leadership.
2. RISK_ASSESSMENT: Detailed risk analysis of the findings.
3. THREAT_LEVEL: One of: critical, high, medium, low, info
4. RECOMMENDATIONS: List of actionable security recommendations (as JSON array of strings).

TEST RESULTS:
- Target URL: {self.target_url}
- Authentication Status: {self.result.auth_status} (HTTP {self.result.auth_status_code})
- Credential Type: {self.credential_type}
- Discovered Paths: {self.result.discovered_paths_count} ({self.result.hidden_paths_found} potentially hidden)
- Sensitive Data Found: {len(self.result.data_sensitivity_indicators)} indicators
- OSINT Sources: {len(self.result.osint_findings)} ({self.result.github_repos_found} GitHub repos)

DISCOVERED PATHS (sample):
{json.dumps(self.result.discovered_paths[:10], indent=2)}

SENSITIVE DATA INDICATORS:
{json.dumps(self.result.data_sensitivity_indicators[:10], indent=2)}

OSINT FINDINGS:
{json.dumps(self.result.osint_findings[:10], indent=2)}

Respond in the following JSON format:
{{
    "overview": "...",
    "risk_assessment": "...",
    "threat_level": "...",
    "recommendations": ["...", "..."]
}}"""
    
    def _parse_llm_response(self, response: str) -> Dict:
        """Parse LLM response into structured data"""
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                data = json.loads(json_match.group())
                self.result.ai_overview = data.get('overview', '')
                self.result.ai_risk_assessment = data.get('risk_assessment', '')
                self.result.threat_level = data.get('threat_level', 'info')
                self.result.ai_recommendations = data.get('recommendations', [])
                return data
        except json.JSONDecodeError:
            pass
        
        # Fallback: use response as overview
        self.result.ai_overview = response[:1000]
        return {"overview": response[:1000]}
    
    def _generate_rule_based_analysis(self) -> Dict:
        """Generate analysis using rules when LLM is unavailable"""
        
        # Determine threat level
        threat_level = "info"
        if self.result.auth_status == "yes":
            threat_level = "medium"
            if self.result.hidden_paths_found > 0:
                threat_level = "high"
            if len(self.result.data_sensitivity_indicators) > 0:
                threat_level = "high"
                if any(s.get('severity') == 'high' for s in self.result.data_sensitivity_indicators):
                    threat_level = "critical"
        
        # Generate overview
        overview = f"Security assessment of {self.target_url}. "
        if self.result.auth_status == "yes":
            overview += f"Authentication successful using {self.credential_type}. "
        else:
            overview += f"Authentication failed ({self.result.auth_error_message}). "
        
        overview += f"Discovered {self.result.discovered_paths_count} API paths"
        if self.result.hidden_paths_found > 0:
            overview += f" including {self.result.hidden_paths_found} potentially hidden endpoints"
        overview += ". "
        
        if self.result.data_sensitivity_indicators:
            overview += f"Found {len(self.result.data_sensitivity_indicators)} sensitive data indicators. "
        
        if self.result.github_repos_found > 0:
            overview += f"OSINT revealed {self.result.github_repos_found} GitHub repositories referencing this API."
        
        # Generate recommendations
        recommendations = []
        if self.result.auth_status == "yes":
            recommendations.append("Review credential rotation policy - current credentials provide API access")
        if self.result.hidden_paths_found > 0:
            recommendations.append("Audit hidden/debug endpoints for production exposure")
        if self.result.data_sensitivity_indicators:
            recommendations.append("Review data exposure - sensitive information detected in API responses")
        if self.result.github_repos_found > 0:
            recommendations.append("Review GitHub exposure - API patterns found in public repositories")
        if not recommendations:
            recommendations.append("Continue monitoring API security posture")
        
        # Risk assessment
        risk_assessment = f"Threat Level: {threat_level.upper()}. "
        if self.result.auth_status == "yes":
            risk_assessment += "Valid credentials provide access to the API. "
        if self.result.hidden_paths_found > 0:
            risk_assessment += f"{self.result.hidden_paths_found} hidden/debug endpoints may expose sensitive functionality. "
        if self.result.data_sensitivity_indicators:
            high_severity = [s for s in self.result.data_sensitivity_indicators if s.get('severity') == 'high']
            if high_severity:
                risk_assessment += f"High-severity data exposure detected ({len(high_severity)} findings). "
        
        self.result.ai_overview = overview
        self.result.ai_risk_assessment = risk_assessment
        self.result.threat_level = threat_level
        self.result.ai_recommendations = recommendations
        
        return {
            "overview": overview,
            "risk_assessment": risk_assessment,
            "threat_level": threat_level,
            "recommendations": recommendations
        }
    
    async def run(self) -> TestResult:
        """
        Execute the full testing workflow.
        
        NEW FLOW (OSINT-first approach):
        1. Gather OSINT first - find how others use this API
        2. Learn auth patterns from discovered code
        3. Build request using learned patterns
        4. Test authentication with learned method
        5. Fall back to canonical endpoints if needed
        6. Discover paths and analyze data
        7. Generate AI analysis
        """
        self._start_time = datetime.now()
        logger.info(f"Starting OSINT-first test for {self.target_url} in {self.test_mode} mode")
        
        try:
            # =========================================================================
            # STEP 1: OSINT FIRST - Discover how this API is used in the wild
            # =========================================================================
            logger.info("Step 1: Gathering OSINT to learn API usage patterns...")
            await self.gather_osint()
            
            # =========================================================================
            # STEP 2: LEARN FROM OSINT - Extract auth patterns from discovered code
            # =========================================================================
            logger.info("Step 2: Learning authentication patterns from OSINT...")
            learned_patterns = await self.learn_auth_from_osint()
            
            # Store learned patterns in result for transparency
            self.result.osint_findings.insert(0, {
                'type': 'Learned_Auth_Patterns',
                'description': f"Learned auth method: {learned_patterns.get('primary_method', 'unknown')}",
                'confidence': learned_patterns.get('confidence', 0),
                'primary_method': learned_patterns.get('primary_method'),
                'all_methods_found': learned_patterns.get('all_methods_found', []),
                'recommended_headers': learned_patterns.get('recommended_headers', {}),
                'recommended_query_params': learned_patterns.get('recommended_query_params', {}),
                'code_examples': learned_patterns.get('code_examples', [])[:5]  # Limit examples
            })
            
            # =========================================================================
            # STEP 3: BUILD REQUEST FROM LEARNED PATTERNS
            # =========================================================================
            auth_tested = False
            
            if learned_patterns.get('confidence', 0) >= 50:
                logger.info(f"Step 3: Building request from learned patterns (confidence: {learned_patterns['confidence']}%)...")
                
                # Build request using learned patterns
                learned_headers, learned_params, learned_body = await self.build_request_from_learned_patterns(learned_patterns)
                
                # Construct URL with query params if needed
                test_url = self.target_url
                if learned_params:
                    parsed = urlparse(self.target_url)
                    query_string = '&'.join(f"{k}={v}" for k, v in learned_params.items())
                    if parsed.query:
                        test_url = f"{self.target_url}&{query_string}"
                    else:
                        test_url = f"{self.target_url}?{query_string}"
                
                # Test with learned auth
                logger.info(f"Testing with learned auth: {learned_patterns.get('primary_method')}")
                
                method = 'POST' if learned_body else 'GET'
                response, error = await self._make_request(
                    test_url,
                    method=method,
                    headers=learned_headers,
                    data=learned_body
                )
                
                if response:
                    is_success = response.status_code in (200, 201, 202, 204)
                    
                    # Store the learned auth attempt
                    self.result.auth_request_headers = self._preserve_headers_for_storage(learned_headers)
                    self.result.auth_status_code = response.status_code
                    self.result.raw_http_request = self._format_raw_request(
                        method, test_url, learned_headers, learned_body
                    )
                    self.result.raw_http_response = self._format_raw_response(response)
                    
                    if is_success:
                        self.result.auth_status = "yes"
                        self.result.auth_method_used = f"learned_{learned_patterns.get('primary_method', 'unknown')}"
                        auth_tested = True
                        
                        # Add proof of learned auth success
                        self.result.osint_findings.insert(0, {
                            'type': 'Learned_Auth_Success',
                            'description': f"Successfully authenticated using learned {learned_patterns.get('primary_method')} method",
                            'endpoint': test_url,
                            'method': method,
                            'status_code': response.status_code,
                            'headers_used': dict(learned_headers),  # Full values - no masking per policy
                            'query_params_used': learned_params,
                            'body_used': learned_body  # Full value - no masking per policy
                        })
                        
                        logger.info(f"SUCCESS: Learned auth worked! Status: {response.status_code}")
                    else:
                        logger.info(f"Learned auth returned {response.status_code}, will try other methods")
            
            # =========================================================================
            # STEP 4: FALLBACK - Try canonical endpoints and standard auth methods
            # =========================================================================
            if not auth_tested or self.result.auth_status != "yes":
                logger.info("Step 4: Trying canonical endpoints and standard auth methods...")
                
                service_name, auth_config, detection_score = self._detect_service()
                service_patterns = SERVICE_AUTH_PATTERNS.get(service_name, {})
                service_domains = service_patterns.get('domains', [])
                
                parsed_url = urlparse(self.target_url)
                target_domain = parsed_url.netloc.lower()
                
                # Check if target URL is for the correct service
                domain_matches_service = any(
                    service_domain in target_domain 
                    for service_domain in service_domains
                )
                
                if not domain_matches_service and service_patterns.get('canonical_endpoints'):
                    # Target URL doesn't match service domain - test canonical endpoints
                    logger.warning(
                        f"Target URL {self.target_url} does not match {service_name} domains. "
                        f"Testing canonical endpoints for {service_name}."
                    )
                    
                    canonical_result = await self.test_canonical_endpoints()
                    
                    if canonical_result.get('success'):
                        proof = canonical_result.get('proof', {})
                        logger.info(f"SUCCESS: Found working auth via canonical endpoint!")
                        
                        self.target_url = proof.get('endpoint', self.target_url)
                        self.result.target_url = self.target_url
                        
                        self.result.osint_findings.append({
                            'type': 'Canonical_Endpoint_Discovery',
                            'description': f'Tested {len(canonical_result.get("all_attempts", []))} auth combinations',
                            'service': service_name,
                            'working_endpoint': proof.get('endpoint'),
                            'working_auth': proof.get('auth_combination'),
                            'all_attempts': canonical_result.get('all_attempts', [])
                        })
                    else:
                        self.result.osint_findings.append({
                            'type': 'Canonical_Endpoint_Discovery',
                            'description': f'All {len(canonical_result.get("all_attempts", []))} auth combinations failed',
                            'service': service_name,
                            'documentation_url': canonical_result.get('documentation_url', ''),
                            'all_attempts': canonical_result.get('all_attempts', []),
                            'recommendation': f'Review {service_name} documentation for correct auth method'
                        })
                        
                        # Test original URL as fallback
                        if not auth_tested:
                            await self.test_authentication()
                else:
                    # Test against provided URL with standard methods
                    if not auth_tested:
                        await self.test_authentication()
                    
                    # If auth failed, try canonical endpoints
                    if self.result.auth_status != "yes" and service_patterns.get('canonical_endpoints'):
                        logger.info(f"Auth failed, trying canonical endpoints for {service_name}")
                        canonical_result = await self.test_canonical_endpoints()
                        
                        if canonical_result.get('success'):
                            proof = canonical_result.get('proof', {})
                            self.result.osint_findings.append({
                                'type': 'Canonical_Endpoint_Discovery',
                                'description': 'Found working auth after initial failure',
                                'service': service_name,
                                'working_endpoint': proof.get('endpoint'),
                                'working_auth': proof.get('auth_combination'),
                                'all_attempts': canonical_result.get('all_attempts', [])
                            })
            
            # =========================================================================
            # STEP 5: Discover Paths (even if auth failed)
            # =========================================================================
            logger.info("Step 5: Discovering API paths...")
            await self.discover_paths()
            
            # =========================================================================
            # STEP 5.5: INTELLIGENT AUTH COMBINATIONS (if auth still failed)
            # Use OSINT patterns + discovered paths + service knowledge
            # =========================================================================
            if self.result.auth_status != "yes" and self.result.discovered_paths:
                logger.info("Step 5.5: Trying intelligent auth combinations with discovered paths...")
                
                intelligent_result = await self.try_intelligent_auth_combinations(
                    learned_patterns=learned_patterns,
                    discovered_paths=self.result.discovered_paths
                )
                
                if intelligent_result.get('success'):
                    winning = intelligent_result.get('winning_combination', {})
                    self.result.osint_findings.insert(0, {
                        'type': 'Intelligent_Auth_Success',
                        'description': f"Found working auth via intelligent combination testing",
                        'winning_url': winning.get('url'),
                        'winning_header_combo': winning.get('header_combo'),
                        'credential_used': winning.get('credential_type'),
                        'status_code': winning.get('status_code'),
                        'total_attempts': len(intelligent_result.get('all_attempts', []))
                    })
                    logger.info(f"SUCCESS: Intelligent auth found working combination!")
                else:
                    # Store all failed attempts for debugging
                    self.result.osint_findings.append({
                        'type': 'Intelligent_Auth_Attempts',
                        'description': f"Tried {len(intelligent_result.get('all_attempts', []))} combinations without success",
                        'attempts_summary': [
                            {
                                'url': a.get('url'),
                                'header_combo': a.get('header_combo'),
                                'status': a.get('status_code'),
                                'credential_type': a.get('credential_type')
                            }
                            for a in intelligent_result.get('all_attempts', [])[:20]  # Limit stored attempts
                        ]
                    })
            
            # =========================================================================
            # STEP 6: Analyze Sample Data
            # =========================================================================
            logger.info("Step 6: Analyzing sample data...")
            await self.analyze_sample_data()
            
            # =========================================================================
            # STEP 7: Generate AI Analysis
            # =========================================================================
            logger.info("Step 7: Generating AI analysis...")
            await self.generate_ai_analysis()
            
        except Exception as e:
            logger.error(f"Test execution error: {e}")
            self.result.ai_overview = f"Test execution encountered an error: {str(e)}"
            self.result.threat_level = "info"
        
        # Record timing
        self.result.tested_at = datetime.now().isoformat()
        self.result.test_duration_seconds = int((datetime.now() - self._start_time).total_seconds())
        
        logger.info(f"Test completed in {self.result.test_duration_seconds}s - Auth: {self.result.auth_status}, Paths: {self.result.discovered_paths_count}")
        
        return self.result
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for database storage"""
        return asdict(self.result)


async def test_credential_url(
    target_url: str,
    credential_type: str,
    credential_value: str,
    test_mode: str = "cautious",
    credential_environment: str = "",
    confidence_score: int = 0,
    github_token: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convenience function to test a single credential-URL pair.
    
    Args:
        target_url: The API endpoint URL to test
        credential_type: Type of credential (API Key, Bearer Token, etc.)
        credential_value: The actual credential value
        test_mode: Testing mode (none, cautious, insane)
        credential_environment: Environment (prod, staging, dev, etc.)
        confidence_score: AI confidence score for this credential-URL match
        github_token: Optional GitHub token for OSINT
    
    Returns:
        Dictionary containing all test results
    """
    agent = AICredentialUrlAgent(
        target_url=target_url,
        credential_type=credential_type,
        credential_value=credential_value,
        test_mode=test_mode,
        credential_environment=credential_environment,
        confidence_score=confidence_score,
        github_token=github_token
    )
    
    result = await agent.run()
    return agent.to_dict()


# CLI for testing
if __name__ == "__main__":
    import sys
    
    async def main():
        if len(sys.argv) < 4:
            print("Usage: python ai_credential_url_agent.py <url> <cred_type> <cred_value> [mode]")
            sys.exit(1)
        
        url = sys.argv[1]
        cred_type = sys.argv[2]
        cred_value = sys.argv[3]
        mode = sys.argv[4] if len(sys.argv) > 4 else "cautious"
        
        result = await test_credential_url(url, cred_type, cred_value, mode)
        print(json.dumps(result, indent=2, default=str))
    
    asyncio.run(main())
