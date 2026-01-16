#!/usr/bin/env python3
"""
OpenAPI Spider - Discovers OpenAPI/Swagger documentation from API servers.

This module probes discovered API servers for OpenAPI specifications and 
merges them into the generated spec to provide actual paths and methods.
"""
import asyncio
import logging
import json
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# Common OpenAPI/Swagger document paths to probe
OPENAPI_PATHS = [
    '/swagger.json',
    '/swagger.yaml',
    '/openapi.json', 
    '/openapi.yaml',
    '/api-docs',
    '/v3/api-docs',
    '/v2/api-docs',
    '/swagger/v1/swagger.json',
    '/swagger/v2/swagger.json',
    '/.well-known/openapi.json',
    '/.well-known/openapi.yaml',
    '/docs/openapi.json',
    '/api/swagger.json',
    '/api/openapi.json',
    '/spec.json',
    '/spec.yaml',
]


async def spider_server_openapi(
    server_url: str,
    credentials: Optional[Dict] = None,
    timeout: float = 10.0
) -> Optional[Dict]:
    """
    Probe a server for OpenAPI specification documents.
    
    Args:
        server_url: Base URL of the API server
        credentials: Optional dict with 'type' and 'value' for auth
        timeout: Request timeout in seconds
        
    Returns:
        OpenAPI spec dict if found, None otherwise
    """
    import httpx
    
    # Build auth headers if credentials provided
    headers = {"User-Agent": "AuditGH-OpenAPI-Spider/1.0"}
    if credentials:
        cred_type = credentials.get('type', '').lower()
        cred_value = credentials.get('value', '')
        
        if cred_value:
            if 'bearer' in cred_type or 'token' in cred_type or 'jwt' in cred_type:
                headers['Authorization'] = f'Bearer {cred_value}'
            elif 'azure' in cred_type or 'subscription' in cred_type:
                headers['Ocp-Apim-Subscription-Key'] = cred_value
            elif 'basic' in cred_type:
                import base64
                headers['Authorization'] = f'Basic {cred_value}'
            elif 'api_key' in cred_type:
                headers['X-API-Key'] = cred_value
            else:
                # Default to bearer
                headers['Authorization'] = f'Bearer {cred_value}'
    
    # Normalize server URL
    if not server_url.endswith('/'):
        base_url = server_url.rstrip('/')
    else:
        base_url = server_url.rstrip('/')
    
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for path in OPENAPI_PATHS:
            spec_url = base_url + path
            try:
                logger.debug(f"Probing {spec_url}")
                response = await client.get(spec_url, headers=headers)
                
                if response.status_code == 200:
                    content_type = response.headers.get('content-type', '')
                    content = response.text
                    
                    # Try to parse as JSON first
                    if 'json' in content_type or path.endswith('.json') or content.strip().startswith('{'):
                        try:
                            spec = json.loads(content)
                            if _is_valid_openapi(spec):
                                logger.info(f"Found OpenAPI spec at {spec_url}")
                                return {
                                    'source_url': spec_url,
                                    'spec': spec
                                }
                        except json.JSONDecodeError:
                            pass
                    
                    # Try YAML
                    if 'yaml' in content_type or path.endswith('.yaml') or path.endswith('.yml'):
                        try:
                            import yaml
                            spec = yaml.safe_load(content)
                            if _is_valid_openapi(spec):
                                logger.info(f"Found OpenAPI spec at {spec_url}")
                                return {
                                    'source_url': spec_url,
                                    'spec': spec
                                }
                        except:
                            pass
                            
            except httpx.TimeoutException:
                logger.debug(f"Timeout probing {spec_url}")
            except httpx.RequestError as e:
                logger.debug(f"Error probing {spec_url}: {e}")
            except Exception as e:
                logger.debug(f"Unexpected error probing {spec_url}: {e}")
    
    return None


def _is_valid_openapi(spec: Dict) -> bool:
    """Check if a dict looks like a valid OpenAPI/Swagger spec."""
    if not isinstance(spec, dict):
        return False
    
    # OpenAPI 3.x
    if 'openapi' in spec and 'info' in spec:
        return True
    
    # Swagger 2.x
    if 'swagger' in spec and 'info' in spec:
        return True
    
    return False


async def spider_all_servers(
    servers: List[str],
    credentials_map: Optional[Dict[str, Dict]] = None,
    max_concurrent: int = 5
) -> Dict[str, Dict]:
    """
    Spider multiple servers for OpenAPI specs.
    
    Args:
        servers: List of server URLs to probe
        credentials_map: Dict mapping server URL to credentials
        max_concurrent: Max concurrent requests
        
    Returns:
        Dict mapping server URL to discovered spec
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    results = {}
    
    async def probe_with_limit(server_url: str):
        async with semaphore:
            creds = credentials_map.get(server_url) if credentials_map else None
            result = await spider_server_openapi(server_url, creds)
            if result:
                results[server_url] = result
    
    tasks = [probe_with_limit(server) for server in servers]
    await asyncio.gather(*tasks, return_exceptions=True)
    
    logger.info(f"Discovered OpenAPI specs from {len(results)}/{len(servers)} servers")
    return results


def merge_discovered_specs(base_spec: Dict, discovered_specs: Dict[str, Dict]) -> Dict:
    """
    Merge discovered OpenAPI specs into the base spec.
    
    Args:
        base_spec: The base OpenAPI spec to merge into
        discovered_specs: Dict mapping server URL to discovered spec data
        
    Returns:
        Merged OpenAPI spec
    """
    merged = base_spec.copy()
    
    if 'paths' not in merged:
        merged['paths'] = {}
    
    if 'components' not in merged:
        merged['components'] = {}
    
    if 'securitySchemes' not in merged.get('components', {}):
        merged['components']['securitySchemes'] = {}
    
    for server_url, spec_data in discovered_specs.items():
        spec = spec_data.get('spec', {})
        source_url = spec_data.get('source_url', server_url)
        
        # Merge paths, tagged with source server
        for path, methods in spec.get('paths', {}).items():
            # Avoid path collisions by prefixing with server identifier
            parsed = urlparse(server_url)
            server_tag = parsed.netloc.replace('.', '_').replace('-', '_')
            
            if path not in merged['paths']:
                merged['paths'][path] = {}
            
            for method, details in methods.items():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']:
                    # Add server info to operation
                    op = details.copy() if isinstance(details, dict) else {}
                    op['x-discovered-from'] = source_url
                    
                    # Add tag for organization
                    if 'tags' not in op:
                        op['tags'] = []
                    op['tags'].append(f"Server: {parsed.netloc}")
                    
                    merged['paths'][path][method.lower()] = op
        
        # Merge security schemes
        components = spec.get('components', {})
        if not components and 'securityDefinitions' in spec:
            # Swagger 2.x compatibility
            components = {'securitySchemes': spec.get('securityDefinitions', {})}
        
        for scheme_name, scheme_def in components.get('securitySchemes', {}).items():
            if scheme_name not in merged['components']['securitySchemes']:
                merged['components']['securitySchemes'][scheme_name] = scheme_def
    
    return merged


def generate_security_schemes_from_credentials(credentials: List[Dict]) -> Dict:
    """
    Generate OpenAPI securitySchemes from discovered credentials.
    
    Args:
        credentials: List of credential dicts with 'type', 'name', 'category'
        
    Returns:
        Dict of securitySchemes for OpenAPI spec
    """
    schemes = {}
    
    for cred in credentials:
        cred_type = cred.get('type', '').lower()
        cred_name = cred.get('name', 'unknown')
        category = cred.get('category', 'Other')
        
        # Sanitize name for use as scheme ID
        scheme_id = re.sub(r'[^a-zA-Z0-9_]', '_', cred_name)
        
        if 'azure' in cred_type or 'subscription' in cred_type:
            schemes[f'azure_{scheme_id}'] = {
                'type': 'apiKey',
                'in': 'header',
                'name': 'Ocp-Apim-Subscription-Key',
                'description': f'Azure API Subscription Key ({cred_name})'
            }
        elif 'bearer' in cred_type or 'jwt' in cred_type or 'token' in cred_type:
            schemes[f'bearer_{scheme_id}'] = {
                'type': 'http',
                'scheme': 'bearer',
                'bearerFormat': 'JWT' if 'jwt' in cred_type else None,
                'description': f'Bearer Token ({cred_name})'
            }
        elif 'basic' in cred_type:
            schemes[f'basic_{scheme_id}'] = {
                'type': 'http',
                'scheme': 'basic',
                'description': f'Basic Auth ({cred_name})'
            }
        elif 'api_key' in cred_type or 'apikey' in cred_type:
            schemes[f'apiKey_{scheme_id}'] = {
                'type': 'apiKey',
                'in': 'header',
                'name': 'X-API-Key',
                'description': f'API Key ({cred_name})'
            }
        elif 'mixpanel' in cred_type:
            schemes[f'mixpanel_{scheme_id}'] = {
                'type': 'http',
                'scheme': 'basic',
                'description': f'Mixpanel Token (use token as username, empty password)'
            }
        else:
            # Default to API key
            schemes[f'apiKey_{scheme_id}'] = {
                'type': 'apiKey',
                'in': 'header',
                'name': 'X-API-Key',
                'description': f'API Key ({cred_name})'
            }
    
    return schemes


# Sync wrapper for non-async contexts
def spider_servers_sync(servers: List[str], credentials_map: Optional[Dict] = None) -> Dict[str, Dict]:
    """Synchronous wrapper for spider_all_servers."""
    return asyncio.run(spider_all_servers(servers, credentials_map))


if __name__ == "__main__":
    # Test the spider
    import sys
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) > 1:
        test_url = sys.argv[1]
        result = asyncio.run(spider_server_openapi(test_url))
        if result:
            print(f"Found spec at: {result['source_url']}")
            print(f"Paths: {list(result['spec'].get('paths', {}).keys())[:10]}")
        else:
            print("No OpenAPI spec found")
    else:
        print("Usage: python openapi_spider.py <server_url>")
