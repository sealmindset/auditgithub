#!/usr/bin/env python3
"""
AI-Powered API Path Discovery Agent

Uses static code analysis, dynamic server probing, and LLM inference
to reverse engineer API paths from discovered servers.
"""
import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ProbeResult:
    """Result from probing a single path."""
    path: str
    status_code: int
    content_type: str = ""
    body_preview: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    
    @property
    def exists(self) -> bool:
        """Path likely exists if not 404."""
        return self.status_code != 404
    
    @property
    def needs_auth(self) -> bool:
        """Path exists but requires auth."""
        return self.status_code in [401, 403]


@dataclass 
class CodeClue:
    """API clue extracted from source code."""
    source: str  # File where found
    clue_type: str  # retrofit, constant, model, etc.
    value: str  # The actual path or pattern
    method: str = "GET"  # HTTP method if known
    confidence: float = 0.5


# Probe path lists by aggressiveness level
PROBE_PATHS_LIGHT = [
    # OpenAPI/Swagger
    "/swagger.json", "/openapi.json", "/api-docs",
    # Health/Status
    "/health", "/status", "/ping", "/",
    # Common API roots
    "/api", "/api/v1", "/api/v2", "/v1", "/v2",
]

PROBE_PATHS_MEDIUM = PROBE_PATHS_LIGHT + [
    # Auth endpoints
    "/auth", "/login", "/oauth", "/token", "/oauth/token",
    "/auth/login", "/api/auth", "/api/login",
    # User management
    "/users", "/user", "/me", "/profile", "/account",
    "/api/users", "/api/user", "/api/me",
    # Common resources
    "/devices", "/sessions", "/settings", "/config",
    "/api/devices", "/api/sessions",
    # More OpenAPI locations
    "/v3/api-docs", "/v2/api-docs", "/swagger/v1/swagger.json",
    "/.well-known/openapi.json", "/docs", "/redoc",
]

PROBE_PATHS_FULL = PROBE_PATHS_MEDIUM + [
    # Extended auth
    "/register", "/signup", "/logout", "/refresh",
    "/api/auth/refresh", "/oauth/authorize", "/oauth/revoke",
    "/password/reset", "/forgot-password", "/verify",
    # User resources
    "/users/me", "/api/users/me", "/profile/settings",
    # IoT/Device specific
    "/beds", "/bed", "/sleep", "/sleeper", "/sleepers",
    "/api/bed", "/api/beds", "/api/sleep",
    # Data/Analytics
    "/data", "/analytics", "/events", "/metrics", "/stats",
    "/api/data", "/api/analytics", "/api/events",
    # Notifications
    "/notifications", "/push", "/alerts", "/messages",
    "/api/notifications", "/api/push",
    # Settings/Config
    "/preferences", "/api/settings", "/api/config",
    # Version/Info
    "/version", "/info", "/about", "/api/version",
    # Search/Query
    "/search", "/query", "/api/search",
    # Admin (often 403)
    "/admin", "/api/admin", "/internal",
    # Common REST patterns
    "/items", "/products", "/orders", "/subscriptions",
    "/api/items", "/api/products", "/api/orders",
    # GraphQL
    "/graphql", "/api/graphql", "/gql",
    # WebSocket
    "/ws", "/websocket", "/socket",
]


def get_probe_paths(level: str) -> List[str]:
    """Get probe paths for aggressiveness level."""
    if level == "light":
        return PROBE_PATHS_LIGHT
    elif level == "medium":
        return PROBE_PATHS_MEDIUM
    else:  # full
        return PROBE_PATHS_FULL


async def probe_server(
    server_url: str,
    paths: List[str],
    headers: Dict[str, str] = None,
    timeout: float = 5.0
) -> List[ProbeResult]:
    """
    Probe a server with multiple paths and collect results.
    """
    import httpx
    
    results = []
    base_url = server_url.rstrip('/')
    
    default_headers = {
        "User-Agent": "AuditGH-AIDiscovery/1.0",
        "Accept": "application/json, text/html, */*"
    }
    if headers:
        default_headers.update(headers)
    
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for path in paths:
            url = base_url + path
            try:
                resp = await client.get(url, headers=default_headers)
                
                content_type = resp.headers.get('content-type', '')
                body = ""
                if resp.status_code != 404:
                    # Capture preview of body for analysis
                    try:
                        body = resp.text[:500]
                    except:
                        pass
                
                results.append(ProbeResult(
                    path=path,
                    status_code=resp.status_code,
                    content_type=content_type,
                    body_preview=body,
                    headers=dict(resp.headers)
                ))
                
            except httpx.TimeoutException:
                results.append(ProbeResult(path=path, status_code=-1, body_preview="timeout"))
            except Exception as e:
                results.append(ProbeResult(path=path, status_code=-2, body_preview=str(e)[:100]))
    
    return results


def extract_code_clues(repo_path: Path, project_name: str) -> List[CodeClue]:
    """
    Extract API clues from source code.
    Looks for Retrofit annotations, URL constants, path strings, etc.
    """
    clues = []
    
    # Patterns to search for
    patterns = [
        # Retrofit annotations
        (r'@(GET|POST|PUT|DELETE|PATCH|HEAD)\s*\(\s*["\']([^"\']+)["\']', 'retrofit'),
        # URL path constants
        (r'(?:const\s+val|static\s+final\s+String)\s+\w*(?:URL|PATH|ENDPOINT|API)\w*\s*=\s*["\']([^"\']+)["\']', 'constant'),
        # Path concatenation
        (r'["\']\/(?:api|v\d+)?\/[a-z_\-]+(?:\/[a-z_\-\{\}]+)*["\']', 'path_string'),
        # Interface method hints
        (r'fun\s+(?:get|fetch|load|create|update|delete)(\w+)\s*\(', 'method_name'),
    ]
    
    kt_files = list(repo_path.rglob("*.kt")) + list(repo_path.rglob("*.java"))
    
    for file_path in kt_files[:100]:  # Limit for performance
        try:
            content = file_path.read_text(errors='ignore')
            
            for pattern, clue_type in patterns:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    if clue_type == 'retrofit':
                        method = match.group(1).upper()
                        path = match.group(2)
                        clues.append(CodeClue(
                            source=str(file_path.name),
                            clue_type=clue_type,
                            value=path,
                            method=method,
                            confidence=0.9
                        ))
                    elif clue_type == 'constant':
                        clues.append(CodeClue(
                            source=str(file_path.name),
                            clue_type=clue_type,
                            value=match.group(1),
                            confidence=0.7
                        ))
                    elif clue_type == 'path_string':
                        path = match.group(0).strip('"\'')
                        clues.append(CodeClue(
                            source=str(file_path.name),
                            clue_type=clue_type,
                            value=path,
                            confidence=0.5
                        ))
                    elif clue_type == 'method_name':
                        # Infer endpoint from method name
                        name = match.group(1)
                        # Convert camelCase to path
                        path = "/" + re.sub(r'([A-Z])', r'/\1', name).lower().strip('/')
                        clues.append(CodeClue(
                            source=str(file_path.name),
                            clue_type=clue_type,
                            value=path,
                            confidence=0.3
                        ))
        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")
    
    return clues


async def analyze_with_llm(
    server_url: str,
    project_name: str,
    code_clues: List[CodeClue],
    probe_results: List[ProbeResult],
    credentials: List[Dict]
) -> Dict:
    """
    Use Claude to analyze clues and infer API structure.
    """
    import anthropic
    
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {"error": "ANTHROPIC_API_KEY not set", "paths": []}
    
    # Prepare context for LLM
    clues_summary = []
    for clue in code_clues[:30]:  # Limit for token efficiency
        clues_summary.append(f"- [{clue.clue_type}] {clue.method} {clue.value} (from {clue.source})")
    
    probe_summary = []
    for result in probe_results:
        if result.status_code != 404 and result.status_code > 0:
            probe_summary.append(f"- {result.path}: {result.status_code} ({result.content_type[:30]})")
    
    cred_types = [c.get('type', 'unknown') for c in credentials[:5]]
    
    prompt = f"""You are an API security analyst reverse-engineering an API structure.

## Target
- Server: {server_url}
- Application: {project_name}
- Credential types found: {', '.join(cred_types) if cred_types else 'None identified'}

## Code Clues (from source analysis)
{chr(10).join(clues_summary) if clues_summary else 'No specific clues found'}

## Probe Results (paths that responded)
{chr(10).join(probe_summary) if probe_summary else 'No successful probes'}

## Task
Based on the clues above, infer the likely API structure. Output a JSON array of endpoints:

```json
[
  {{"path": "/api/v1/users", "method": "GET", "description": "List users", "auth_required": true, "confidence": 0.8}},
  ...
]
```

Consider:
1. Standard REST patterns for this app domain
2. Auth flows (what credential types suggest)
3. Resource hierarchies
4. Paths hinted at by code clues
5. Response patterns from probing

Output ONLY the JSON array, no explanation."""

    try:
        client = anthropic.Anthropic(api_key=api_key)
        
        message = client.messages.create(
            model="claude-3-haiku-20240307",  # Fast and cheap for this use case
            max_tokens=2000,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        response_text = message.content[0].text
        
        # Extract JSON from response
        json_match = re.search(r'\[[\s\S]*\]', response_text)
        if json_match:
            paths = json.loads(json_match.group())
            return {"paths": paths, "raw_response": response_text[:500]}
        else:
            return {"paths": [], "error": "Could not parse JSON from response", "raw": response_text[:500]}
            
    except Exception as e:
        logger.error(f"LLM analysis failed: {e}")
        return {"error": str(e), "paths": []}


async def discover_api_paths(
    project_id: str,
    project_name: str,
    server_url: str,
    level: str = "medium",
    credentials: List[Dict] = None,
    repo_path: Optional[Path] = None
) -> Dict:
    """
    Main entry point for AI-powered API discovery.
    
    Args:
        project_id: Project identifier
        project_name: Human-readable project name
        server_url: Target server URL
        level: Probe aggressiveness (light, medium, full)
        credentials: Optional credentials for authenticated probing
        repo_path: Optional path to repo for code analysis
        
    Returns:
        Dict with discovered paths and analysis
    """
    results = {
        "server_url": server_url,
        "level": level,
        "code_clues": [],
        "probe_results": [],
        "ai_paths": [],
        "combined_paths": [],
        "errors": []
    }
    
    # Build auth headers if credentials provided
    headers = {}
    if credentials:
        for cred in credentials:
            cred_type = cred.get('type', '').lower()
            cred_value = cred.get('value', '')
            if cred_value:
                if 'azure' in cred_type:
                    headers['Ocp-Apim-Subscription-Key'] = cred_value
                elif 'bearer' in cred_type or 'token' in cred_type:
                    headers['Authorization'] = f'Bearer {cred_value}'
                break  # Use first matching credential
    
    # Phase 1: Extract code clues
    code_clues = []
    if repo_path and repo_path.exists():
        try:
            code_clues = extract_code_clues(repo_path, project_name)
            results["code_clues"] = [
                {"type": c.clue_type, "value": c.value, "method": c.method, "source": c.source}
                for c in code_clues
            ]
        except Exception as e:
            results["errors"].append(f"Code analysis failed: {e}")
    
    # Phase 2: Probe server
    probe_paths = get_probe_paths(level)
    try:
        probe_results = await probe_server(server_url, probe_paths, headers)
        results["probe_results"] = [
            {"path": r.path, "status": r.status_code, "exists": r.exists, "needs_auth": r.needs_auth}
            for r in probe_results if r.status_code > 0
        ]
    except Exception as e:
        results["errors"].append(f"Server probing failed: {e}")
        probe_results = []
    
    # Phase 3: AI analysis
    try:
        ai_result = await analyze_with_llm(
            server_url=server_url,
            project_name=project_name,
            code_clues=code_clues,
            probe_results=[r for r in probe_results if r.exists],
            credentials=credentials or []
        )
        results["ai_paths"] = ai_result.get("paths", [])
        if "error" in ai_result:
            results["errors"].append(f"AI analysis: {ai_result['error']}")
    except Exception as e:
        results["errors"].append(f"AI analysis failed: {e}")
    
    # Combine and deduplicate paths
    all_paths = {}
    
    # From code clues
    for clue in code_clues:
        if clue.value.startswith('/'):
            key = (clue.value, clue.method)
            if key not in all_paths or all_paths[key]["confidence"] < clue.confidence:
                all_paths[key] = {
                    "path": clue.value,
                    "method": clue.method,
                    "source": "code",
                    "confidence": clue.confidence
                }
    
    # From successful probes
    for result in probe_results:
        if result.exists and result.path.startswith('/'):
            key = (result.path, "GET")
            if key not in all_paths:
                all_paths[key] = {
                    "path": result.path,
                    "method": "GET",
                    "source": "probe",
                    "confidence": 0.95 if result.status_code == 200 else 0.7,
                    "status": result.status_code
                }
    
    # From AI analysis
    for ai_path in results.get("ai_paths", []):
        path = ai_path.get("path", "")
        method = ai_path.get("method", "GET")
        if path:
            key = (path, method)
            if key not in all_paths or all_paths[key].get("source") != "probe":
                all_paths[key] = {
                    "path": path,
                    "method": method,
                    "source": "ai",
                    "confidence": ai_path.get("confidence", 0.5),
                    "description": ai_path.get("description", ""),
                    "auth_required": ai_path.get("auth_required", True)
                }
    
    results["combined_paths"] = sorted(
        all_paths.values(),
        key=lambda x: x["confidence"],
        reverse=True
    )
    
    return results


# Sync wrapper
def discover_api_paths_sync(*args, **kwargs) -> Dict:
    """Synchronous wrapper for discover_api_paths."""
    return asyncio.run(discover_api_paths(*args, **kwargs))
