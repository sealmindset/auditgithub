"""
AI-Powered Credential Tester

Safe credential testing engine with rate limiting and sandboxing.
Tests discovered credentials against their mapped target URLs to determine
if credentials are valid and what access they provide.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

import aiohttp

logger = logging.getLogger(__name__)


class TestMode(Enum):
    """Test modes with increasing levels of interaction."""
    PASSIVE = "passive"      # Only test authentication, no data access
    ACTIVE = "active"        # Test auth + enumerate accessible paths
    AGGRESSIVE = "aggressive"  # Full path discovery + sample data retrieval


class AuthStatus(Enum):
    """Authentication status results."""
    AUTHENTICATED = "authenticated"
    DENIED = "denied"
    EXPIRED = "expired"
    INVALID = "invalid"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"
    UNKNOWN = "unknown"


class ThreatLevel(Enum):
    """Threat level assessment."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class TestConfig:
    """Configuration for credential testing."""
    max_requests_per_minute: int = 10
    timeout_seconds: int = 10
    max_redirects: int = 3
    user_agent: str = "AuditGH-Security-Scanner/1.0"
    verify_ssl: bool = True
    max_path_discovery: int = 50
    mask_credential_after: int = 0  # 0 = no masking per policy


@dataclass
class DiscoveredCredential:
    """A credential discovered in the codebase."""
    id: str
    credential_type: str  # api_key, bearer_token, basic_auth, etc.
    credential_value: str
    file_path: str
    line_number: int
    environment: str = ""  # prod, staging, dev, etc.
    service_hint: str = ""  # Azure, AWS, Stripe, etc.
    
    def masked_value(self, show_chars: int = 0) -> str:
        """Return credential value - no masking per policy."""
        # Per policy: secrets should not be masked for security analyst validation
        return self.credential_value


@dataclass
class TestRequest:
    """A generated test request."""
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    auth_header_name: str = ""
    auth_header_value: str = ""


@dataclass
class PathDiscovery:
    """Discovered accessible path."""
    path: str
    method: str
    status_code: int
    response_size: int
    has_data: bool
    data_preview: str = ""


@dataclass
class TestResult:
    """Result of a credential test."""
    credential_id: str
    target_url: str
    credential_type: str
    credential_value: str  # Full value - no masking per policy
    auth_status: AuthStatus
    auth_status_code: int
    auth_response_time_ms: int
    auth_error_message: str = ""
    auth_headers_used: Dict[str, str] = field(default_factory=dict)
    discovered_paths: List[PathDiscovery] = field(default_factory=list)
    discovered_paths_count: int = 0
    hidden_paths_found: int = 0
    sample_data_retrieved: Dict[str, Any] = field(default_factory=dict)
    data_sensitivity_indicators: List[str] = field(default_factory=list)
    threat_level: ThreatLevel = ThreatLevel.INFO
    test_mode: TestMode = TestMode.PASSIVE
    tested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    test_duration_seconds: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "credential_id": self.credential_id,
            "target_url": self.target_url,
            "credential_type": self.credential_type,
            "credential_value": self.credential_value,  # Full value - no masking per policy
            "auth_status": self.auth_status.value,
            "auth_status_code": self.auth_status_code,
            "auth_response_time_ms": self.auth_response_time_ms,
            "auth_error_message": self.auth_error_message,
            "auth_headers_used": self.auth_headers_used,  # Full values - no masking per policy
            "discovered_paths": [
                {"path": p.path, "method": p.method, "status_code": p.status_code, "has_data": p.has_data}
                for p in self.discovered_paths
            ],
            "discovered_paths_count": self.discovered_paths_count,
            "hidden_paths_found": self.hidden_paths_found,
            "sample_data_retrieved": self.sample_data_retrieved,
            "data_sensitivity_indicators": self.data_sensitivity_indicators,
            "threat_level": self.threat_level.value,
            "test_mode": self.test_mode.value,
            "tested_at": self.tested_at.isoformat(),
            "test_duration_seconds": self.test_duration_seconds,
        }


class RateLimiter:
    """Simple rate limiter for API requests."""
    
    def __init__(self, max_requests_per_minute: int = 10):
        self.max_rpm = max_requests_per_minute
        self.requests: Dict[str, List[float]] = {}  # domain -> timestamps
    
    async def acquire(self, domain: str) -> bool:
        """Acquire permission to make a request. Returns True if allowed."""
        now = time.time()
        minute_ago = now - 60
        
        if domain not in self.requests:
            self.requests[domain] = []
        
        # Clean old requests
        self.requests[domain] = [t for t in self.requests[domain] if t > minute_ago]
        
        if len(self.requests[domain]) >= self.max_rpm:
            # Calculate wait time
            oldest = min(self.requests[domain])
            wait_time = 60 - (now - oldest)
            if wait_time > 0:
                logger.info(f"Rate limited for {domain}, waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)
        
        self.requests[domain].append(now)
        return True


class CredentialTester:
    """
    Safe credential testing engine with rate limiting and sandboxing.
    """
    
    def __init__(self, config: TestConfig = None):
        self.config = config or TestConfig()
        self.rate_limiter = RateLimiter(self.config.max_requests_per_minute)
    
    def _generate_auth_header(
        self,
        credential_type: str,
        credential_value: str
    ) -> Tuple[str, str]:
        """
        Generate appropriate authentication header based on credential type.
        
        Returns: (header_name, header_value)
        """
        cred_type_lower = credential_type.lower()
        
        if "bearer" in cred_type_lower or "token" in cred_type_lower:
            return ("Authorization", f"Bearer {credential_value}")
        
        elif "basic" in cred_type_lower:
            # Assume credential_value is "user:pass" format
            if ":" not in credential_value:
                credential_value = f"{credential_value}:"
            encoded = base64.b64encode(credential_value.encode()).decode()
            return ("Authorization", f"Basic {encoded}")
        
        elif "api_key" in cred_type_lower or "apikey" in cred_type_lower:
            # Try common API key header patterns
            return ("X-API-Key", credential_value)
        
        elif "x-api-key" in cred_type_lower:
            return ("X-API-Key", credential_value)
        
        elif "subscription" in cred_type_lower or "ocp-apim" in cred_type_lower:
            return ("Ocp-Apim-Subscription-Key", credential_value)
        
        elif "azure" in cred_type_lower:
            return ("Ocp-Apim-Subscription-Key", credential_value)
        
        elif "aws" in cred_type_lower:
            # AWS requires signature - just test with basic header
            return ("X-Api-Key", credential_value)
        
        else:
            # Default to Authorization header
            return ("Authorization", credential_value)
    
    def _analyze_response(
        self,
        status_code: int,
        response_text: str,
        response_headers: Dict[str, str]
    ) -> Tuple[AuthStatus, List[str]]:
        """
        Analyze HTTP response to determine authentication status.
        
        Returns: (auth_status, sensitivity_indicators)
        """
        sensitivity_indicators = []
        
        # Check for sensitive data patterns in response
        sensitive_patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "email"),
            (r'\b\d{3}-\d{2}-\d{4}\b', "ssn"),
            (r'\b\d{16}\b', "credit_card"),
            (r'"password"\s*:', "password_field"),
            (r'"secret"\s*:', "secret_field"),
            (r'"token"\s*:', "token_field"),
            (r'"api_key"\s*:', "api_key_field"),
            (r'"private_key"\s*:', "private_key_field"),
        ]
        
        for pattern, indicator in sensitive_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                sensitivity_indicators.append(indicator)
        
        # Determine auth status from status code
        if status_code == 200:
            return (AuthStatus.AUTHENTICATED, sensitivity_indicators)
        elif status_code == 201:
            return (AuthStatus.AUTHENTICATED, sensitivity_indicators)
        elif status_code == 204:
            return (AuthStatus.AUTHENTICATED, sensitivity_indicators)
        elif status_code == 401:
            # Check if it's expired vs invalid
            if "expired" in response_text.lower():
                return (AuthStatus.EXPIRED, sensitivity_indicators)
            return (AuthStatus.DENIED, sensitivity_indicators)
        elif status_code == 403:
            return (AuthStatus.DENIED, sensitivity_indicators)
        elif status_code == 429:
            return (AuthStatus.RATE_LIMITED, sensitivity_indicators)
        elif status_code >= 500:
            return (AuthStatus.ERROR, sensitivity_indicators)
        else:
            return (AuthStatus.UNKNOWN, sensitivity_indicators)
    
    def _assess_threat_level(
        self,
        auth_status: AuthStatus,
        sensitivity_indicators: List[str],
        discovered_paths_count: int,
        credential_environment: str
    ) -> ThreatLevel:
        """Assess the threat level based on test results."""
        
        if auth_status != AuthStatus.AUTHENTICATED:
            return ThreatLevel.INFO
        
        # Authenticated - assess based on what was found
        critical_indicators = {"ssn", "credit_card", "private_key_field"}
        high_indicators = {"password_field", "secret_field", "token_field"}
        
        if sensitivity_indicators:
            if any(i in critical_indicators for i in sensitivity_indicators):
                return ThreatLevel.CRITICAL
            if any(i in high_indicators for i in sensitivity_indicators):
                return ThreatLevel.HIGH
        
        # Check environment
        if credential_environment and "prod" in credential_environment.lower():
            if discovered_paths_count > 10:
                return ThreatLevel.HIGH
            return ThreatLevel.MEDIUM
        
        if discovered_paths_count > 20:
            return ThreatLevel.MEDIUM
        
        return ThreatLevel.LOW
    
    async def test_credential(
        self,
        credential: DiscoveredCredential,
        target_url: str,
        test_mode: TestMode = TestMode.PASSIVE
    ) -> TestResult:
        """
        Test a credential against a target URL.
        
        Args:
            credential: The discovered credential to test
            target_url: The URL to test against
            test_mode: Level of testing (passive, active, aggressive)
        
        Returns:
            TestResult with authentication status and findings
        """
        start_time = time.time()
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc
        
        # Rate limit
        await self.rate_limiter.acquire(domain)
        
        # Generate auth header
        header_name, header_value = self._generate_auth_header(
            credential.credential_type,
            credential.credential_value
        )
        
        headers = {
            "User-Agent": self.config.user_agent,
            header_name: header_value,
            "Accept": "application/json",
        }
        
        result = TestResult(
            credential_id=credential.id,
            target_url=target_url,
            credential_type=credential.credential_type,
            credential_value=credential.credential_value,  # Full value - no masking per policy
            auth_status=AuthStatus.UNKNOWN,
            auth_status_code=0,
            auth_response_time_ms=0,
            auth_headers_used={header_name: header_value},  # Full value - no masking per policy
            test_mode=test_mode,
        )
        
        try:
            connector = aiohttp.TCPConnector(ssl=self.config.verify_ssl)
            timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                # Initial auth test
                request_start = time.time()
                async with session.get(
                    target_url,
                    headers=headers,
                    allow_redirects=True,
                    max_redirects=self.config.max_redirects
                ) as response:
                    request_time = int((time.time() - request_start) * 1000)
                    response_text = await response.text()
                    
                    result.auth_status_code = response.status
                    result.auth_response_time_ms = request_time
                    
                    auth_status, sensitivity_indicators = self._analyze_response(
                        response.status,
                        response_text,
                        dict(response.headers)
                    )
                    result.auth_status = auth_status
                    result.data_sensitivity_indicators = sensitivity_indicators
                
                # Path discovery for active/aggressive modes
                if test_mode in (TestMode.ACTIVE, TestMode.AGGRESSIVE) and auth_status == AuthStatus.AUTHENTICATED:
                    discovered = await self._discover_paths(
                        session, target_url, headers, test_mode
                    )
                    result.discovered_paths = discovered
                    result.discovered_paths_count = len(discovered)
                    result.hidden_paths_found = len([p for p in discovered if p.status_code == 200])
                    
                    # Sample data for aggressive mode
                    if test_mode == TestMode.AGGRESSIVE and discovered:
                        result.sample_data_retrieved = await self._retrieve_sample_data(
                            session, target_url, headers, discovered[:5]
                        )
        
        except asyncio.TimeoutError:
            result.auth_status = AuthStatus.ERROR
            result.auth_error_message = "Request timed out"
        except aiohttp.ClientError as e:
            result.auth_status = AuthStatus.ERROR
            result.auth_error_message = str(e)
        except Exception as e:
            result.auth_status = AuthStatus.ERROR
            result.auth_error_message = f"Unexpected error: {str(e)}"
            logger.exception(f"Error testing credential against {target_url}")
        
        # Assess threat level
        result.threat_level = self._assess_threat_level(
            result.auth_status,
            result.data_sensitivity_indicators,
            result.discovered_paths_count,
            credential.environment
        )
        
        result.test_duration_seconds = int(time.time() - start_time)
        
        logger.info(
            f"Credential test complete: {target_url} - "
            f"Status: {result.auth_status.value}, "
            f"Threat: {result.threat_level.value}"
        )
        
        return result
    
    async def _discover_paths(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        headers: Dict[str, str],
        test_mode: TestMode
    ) -> List[PathDiscovery]:
        """Discover accessible paths with the credential."""
        
        # Common API paths to check
        common_paths = [
            "/api", "/api/v1", "/api/v2",
            "/users", "/user", "/me", "/profile",
            "/admin", "/dashboard",
            "/data", "/export", "/download",
            "/config", "/settings", "/configuration",
            "/health", "/status", "/info",
            "/docs", "/swagger", "/openapi",
        ]
        
        if test_mode == TestMode.AGGRESSIVE:
            common_paths.extend([
                "/internal", "/private", "/secret",
                "/backup", "/dump", "/debug",
                "/logs", "/audit", "/metrics",
            ])
        
        discovered = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in common_paths[:self.config.max_path_discovery]:
            await self.rate_limiter.acquire(parsed.netloc)
            
            try:
                url = urljoin(base, path)
                async with session.get(url, headers=headers, allow_redirects=False) as response:
                    if response.status in (200, 201, 204):
                        text = await response.text()
                        discovered.append(PathDiscovery(
                            path=path,
                            method="GET",
                            status_code=response.status,
                            response_size=len(text),
                            has_data=len(text) > 10,
                            data_preview=text[:100] if len(text) > 0 else ""
                        ))
            except Exception:
                continue
        
        return discovered
    
    async def _retrieve_sample_data(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        headers: Dict[str, str],
        paths: List[PathDiscovery]
    ) -> Dict[str, Any]:
        """Retrieve sample data from discovered paths."""
        
        samples = {}
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for path_info in paths:
            try:
                url = urljoin(base, path_info.path)
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        text = await response.text()
                        # Store truncated sample
                        samples[path_info.path] = {
                            "status": response.status,
                            "size": len(text),
                            "preview": text[:500] if text else "",
                            "content_type": response.headers.get("Content-Type", "")
                        }
            except Exception:
                continue
        
        return samples


async def test_credential_url_pair(
    credential_type: str,
    credential_value: str,
    target_url: str,
    test_mode: str = "passive",
    credential_id: str = None,
    file_path: str = "",
    line_number: int = 0,
    environment: str = ""
) -> Dict[str, Any]:
    """
    Convenience function to test a single credential-URL pair.
    
    Returns dict suitable for storing in credential_url_test_results table.
    """
    cred = DiscoveredCredential(
        id=credential_id or hashlib.md5(f"{credential_type}:{credential_value}".encode(), usedforsecurity=False).hexdigest(),
        credential_type=credential_type,
        credential_value=credential_value,
        file_path=file_path,
        line_number=line_number,
        environment=environment
    )
    
    mode = TestMode(test_mode) if test_mode in [m.value for m in TestMode] else TestMode.PASSIVE
    
    tester = CredentialTester()
    result = await tester.test_credential(cred, target_url, mode)
    
    return result.to_dict()
