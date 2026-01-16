"""
Kotlin Parser for API Endpoint Detection

Uses Tree-sitter for AST parsing of Kotlin files to accurately
extract Retrofit API annotations and HTTP client calls.
"""

import logging
from pathlib import Path
from typing import List, Dict, Optional, Any
import re

logger = logging.getLogger(__name__)

# Try to import tree-sitter, fall back gracefully
TREE_SITTER_AVAILABLE = False
try:
    import tree_sitter_kotlin as tskotlin
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    logger.debug("Tree-sitter-kotlin not available, using regex fallback")


class KotlinAPIParser:
    """
    Parse Kotlin files to extract API endpoint definitions.
    
    Supports:
    - Retrofit annotations (@GET, @POST, @PUT, @DELETE, @PATCH)
    - OkHttp Request.Builder patterns
    - Ktor client calls
    - Base URL configurations
    """
    
    RETROFIT_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
    
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        self.parser = None
        self._init_parser()
    
    def _init_parser(self):
        """Initialize Tree-sitter parser if available."""
        if TREE_SITTER_AVAILABLE:
            try:
                self.parser = Parser(Language(tskotlin.language()))
                logger.debug("Tree-sitter Kotlin parser initialized")
            except Exception as e:
                logger.debug(f"Failed to initialize Tree-sitter: {e}")
                self.parser = None
    
    def scan_retrofit_interfaces(self) -> List[Dict]:
        """
        Scan for Retrofit interface definitions.
        
        Returns list of API endpoints with metadata.
        """
        endpoints = []
        
        # Scan ALL Kotlin and Java files - don't filter by imports
        # because files may use wildcard imports or annotations without explicit imports
        kotlin_files = list(self.repo_path.rglob("*.kt"))
        java_files = list(self.repo_path.rglob("*.java"))
        
        logger.debug(f"Scanning {len(kotlin_files)} Kotlin + {len(java_files)} Java files for Retrofit annotations")
        
        for file_path in kotlin_files + java_files:
            path_str = str(file_path)
            
            # Skip build/test directories
            if any(skip in path_str for skip in ['/build/', '/.gradle/', '/generated/']):
                continue
            
            try:
                content = file_path.read_text(errors='ignore')
                
                # Always use regex for reliability - Tree-sitter has issues with some Kotlin
                file_endpoints = self._parse_with_regex(content, file_path)
                endpoints.extend(file_endpoints)
                
            except Exception as e:
                logger.debug(f"Error parsing {file_path}: {e}")
                continue
        
        logger.info(f"Found {len(endpoints)} Retrofit API endpoints")
        return endpoints
    
    def _parse_with_tree_sitter(self, content: str, file_path: Path) -> List[Dict]:
        """Parse Kotlin file using Tree-sitter AST."""
        endpoints = []
        
        try:
            tree = self.parser.parse(bytes(content, "utf8"))
            root_node = tree.root_node
            
            # Find all annotation nodes
            annotations = self._find_annotations(root_node, content)
            
            for annotation in annotations:
                if annotation.get('name') in self.RETROFIT_METHODS:
                    endpoints.append({
                        "category": "outbound",
                        "rule_id": "tree-sitter-retrofit",
                        "path": str(file_path.relative_to(self.repo_path)),
                        "line": annotation['line'],
                        "code": annotation['code'],
                        "endpoint_path": annotation['path'],
                        "message": f"Retrofit {annotation['name']} endpoint: {annotation['path']}",
                        "metadata": {
                            "category": "api-discovery",
                            "subcategory": "outbound",
                            "pattern_type": "retrofit_annotation",
                            "http_method": annotation['name'],
                            "framework": "retrofit",
                            "function_name": annotation.get('function', '')
                        }
                    })
        except Exception as e:
            logger.debug(f"Tree-sitter parse error: {e}")
            # Fall back to regex
            return self._parse_with_regex(content, file_path)
        
        return endpoints
    
    def _find_annotations(self, node: Any, content: str, annotations: List = None) -> List[Dict]:
        """Recursively find annotation nodes in AST."""
        if annotations is None:
            annotations = []
        
        # Look for annotation nodes
        if node.type == 'annotation':
            annotation_text = content[node.start_byte:node.end_byte]
            
            # Parse Retrofit annotations
            match = re.match(r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*"([^"]+)"\s*\)', annotation_text)
            if match:
                method = match.group(1)
                path = match.group(2)
                
                # Get the function name if this annotates a function
                func_name = self._get_next_function_name(node, content)
                
                annotations.append({
                    'name': method,
                    'path': path,
                    'line': node.start_point[0] + 1,
                    'code': annotation_text,
                    'function': func_name
                })
        
        # Recurse into children
        for child in node.children:
            self._find_annotations(child, content, annotations)
        
        return annotations
    
    def _get_next_function_name(self, node: Any, content: str) -> str:
        """Get the function name that follows an annotation."""
        # Look at next sibling or parent's next child for function declaration
        parent = node.parent
        if parent:
            found_current = False
            for sibling in parent.children:
                if found_current:
                    if sibling.type in ['function_declaration', 'simple_function']:
                        # Extract function name
                        func_text = content[sibling.start_byte:sibling.end_byte]
                        match = re.search(r'\bfun\s+(\w+)', func_text)
                        if match:
                            return match.group(1)
                if sibling == node:
                    found_current = True
        return ""
    
    def _parse_with_regex(self, content: str, file_path: Path) -> List[Dict]:
        """Parse Kotlin file using regex patterns."""
        endpoints = []
        
        # Pattern: @METHOD("path") or @METHOD(value = "path")
        # Must be followed by a function declaration
        pattern = r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*(?:value\s*=\s*)?\"([^\"]+)\"\s*\)'
        
        for match in re.finditer(pattern, content):
            method = match.group(1)
            path = match.group(2)
            
            # Skip empty or placeholder paths
            if not path or path in ['""', "''"] or len(path) < 2:
                continue
            
            # Calculate line number
            line_num = content[:match.start()].count('\n') + 1
            
            # Get surrounding context (annotation + function signature)
            context_start = max(0, match.start() - 20)
            context_end = min(len(content), match.end() + 100)
            code_section = content[context_start:context_end]
            
            # Extract the line containing the annotation
            line_start = content.rfind('\n', 0, match.start()) + 1
            line_end = content.find('\n', match.end())
            if line_end == -1:
                line_end = len(content)
            code_line = content[line_start:line_end].strip()
            
            # Try to get function name
            func_match = re.search(r'(?:suspend\s+)?fun\s+(\w+)', content[match.end():match.end()+200])
            func_name = func_match.group(1) if func_match else ""
            
            endpoints.append({
                "category": "outbound",
                "rule_id": "regex-retrofit",
                "path": str(file_path.relative_to(self.repo_path)),
                "line": line_num,
                "code": code_line[:150],
                "endpoint_path": path,
                "message": f"Retrofit {method}: {path}",
                "metadata": {
                    "category": "api-discovery",
                    "subcategory": "outbound",
                    "pattern_type": "retrofit_annotation",
                    "http_method": method,
                    "framework": "retrofit",
                    "function_name": func_name
                }
            })
        
        return endpoints


class EnhancedKotlinScanner:
    """
    Enhanced regex-based scanner for Kotlin/Java API patterns.
    
    More precise than Semgrep for Kotlin, with context-aware parsing.
    """
    
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
    
    def scan_all_api_patterns(self) -> Dict[str, List[Dict]]:
        """
        Scan for all API patterns in Kotlin/Java files.
        
        Returns dict with:
          - 'retrofit': Retrofit endpoint annotations
          - 'okhttp': OkHttp Request.Builder patterns  
          - 'ktor': Ktor client calls
          - 'base_urls': Base URL configurations
          - 'endpoints': Generic endpoint constants
        """
        results = {
            'retrofit': [],
            'okhttp': [],
            'ktor': [],
            'base_urls': [],
            'endpoints': []
        }
        
        # Use dedicated Retrofit parser
        retrofit_parser = KotlinAPIParser(self.repo_path)
        results['retrofit'] = retrofit_parser.scan_retrofit_interfaces()
        
        # Scan for other patterns
        for ext in ['.kt', '.java']:
            for file_path in self.repo_path.rglob(f'*{ext}'):
                path_str = str(file_path)
                
                # Skip build/test directories
                if any(skip in path_str for skip in ['/build/', '/.gradle/', '/generated/', '/test/', '/androidTest/']):
                    continue
                
                try:
                    content = file_path.read_text(errors='ignore')
                    
                    # OkHttp patterns
                    results['okhttp'].extend(self._scan_okhttp(content, file_path))
                    
                    # Ktor patterns
                    results['ktor'].extend(self._scan_ktor(content, file_path))
                    
                    # Base URL configurations
                    results['base_urls'].extend(self._scan_base_urls(content, file_path))
                    
                except Exception as e:
                    logger.debug(f"Error scanning {file_path}: {e}")
                    continue
        
        return results
    
    def _scan_okhttp(self, content: str, file_path: Path) -> List[Dict]:
        """Scan for OkHttp Request.Builder patterns."""
        endpoints = []
        
        # Pattern: Request.Builder().url("...")
        pattern = r'Request\.Builder\(\)[^}]*\.url\s*\(\s*\"([^\"]+)\"\s*\)'
        
        for match in re.finditer(pattern, content, re.DOTALL):
            url = match.group(1)
            if self._is_valid_url(url):
                line_num = content[:match.start()].count('\n') + 1
                endpoints.append({
                    "category": "outbound",
                    "rule_id": "regex-okhttp",
                    "path": str(file_path.relative_to(self.repo_path)),
                    "line": line_num,
                    "code": match.group(0),  # Full unredacted code for security analyst validation
                    "endpoint_path": url,
                    "message": f"OkHttp request: {url}",
                    "metadata": {
                        "category": "api-discovery",
                        "subcategory": "outbound",
                        "framework": "okhttp"
                    }
                })
        
        return endpoints
    
    def _scan_ktor(self, content: str, file_path: Path) -> List[Dict]:
        """Scan for Ktor client calls."""
        endpoints = []
        
        # Pattern: client.get("...") or httpClient.post("...")
        pattern = r'(?:client|httpClient)\.(get|post|put|delete|patch)\s*(?:<[^>]*>)?\s*\(\s*\"([^\"]+)\"'
        
        for match in re.finditer(pattern, content, re.IGNORECASE):
            method = match.group(1).upper()
            url = match.group(2)
            if self._is_valid_url(url):
                line_num = content[:match.start()].count('\n') + 1
                endpoints.append({
                    "category": "outbound",
                    "rule_id": "regex-ktor",
                    "path": str(file_path.relative_to(self.repo_path)),
                    "line": line_num,
                    "code": match.group(0),  # Full unredacted code for security analyst validation
                    "endpoint_path": url,
                    "message": f"Ktor {method}: {url}",
                    "metadata": {
                        "category": "api-discovery",
                        "subcategory": "outbound",
                        "http_method": method,
                        "framework": "ktor"
                    }
                })
        
        return endpoints
    
    def _scan_base_urls(self, content: str, file_path: Path) -> List[Dict]:
        """Scan for base URL configurations."""
        endpoints = []
        
        patterns = [
            (r'(?:BASE_URL|baseUrl|BASE_API_URL|API_URL|API_BASE_URL)\s*[=:]\s*\"(https?://[^\"]+)\"', 'base_url_constant'),
            (r'Retrofit\.Builder\(\)[^}]*\.baseUrl\s*\(\s*\"([^\"]+)\"', 'retrofit_base_url'),
        ]
        
        for pattern, pattern_type in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                url = match.group(1)
                if self._is_valid_url(url):
                    line_num = content[:match.start()].count('\n') + 1
                    endpoints.append({
                        "category": "config",
                        "rule_id": f"regex-{pattern_type}",
                        "path": str(file_path.relative_to(self.repo_path)),
                        "line": line_num,
                        "code": match.group(0),  # Full unredacted code for security analyst validation
                        "endpoint_path": url,
                        "message": f"Base URL: {url}",
                        "metadata": {
                            "category": "api-discovery",
                            "subcategory": "config",
                            "pattern_type": pattern_type
                        }
                    })
        
        return endpoints
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is a valid API endpoint (not test/example)."""
        if not url or len(url) < 5:
            return False
        
        exclude_patterns = [
            'localhost', '127.0.0.1', '10.0.', '192.168.',
            'example.com', 'test.', 'mock', 'placeholder',
            '.png', '.jpg', '.svg', '.gif', '.css', '.js',
            'schemas.android.com', 'schemas.microsoft.com',
            'www.w3.org', 'gradle.org', 'maven.org'
        ]
        
        url_lower = url.lower()
        return not any(exc in url_lower for exc in exclude_patterns)


def scan_api_keys_and_secrets(repo_path: Path) -> List[Dict]:
    """
    Scan properties and config files for API keys, tokens, and secrets.
    
    Detects:
    - Mixpanel, Firebase, Azure, AWS API keys
    - OAuth client IDs and secrets
    - Authentication tokens and signatures
    - API endpoint URLs
    """
    secrets = []
    
    # Patterns for API keys and secrets
    key_patterns = [
        # Generic API keys
        (r'(\w+\.)?(?:api[_-]?key|apikey)\s*[=:]\s*([a-zA-Z0-9_\-]{20,})', 'api_key'),
        (r'(\w+\.)?(?:key)\s*[=:]\s*([a-f0-9]{32,})', 'hex_key'),
        
        # Service-specific patterns
        (r'(\w+\.)?mixpanel\.key\s*[=:]\s*([a-f0-9]{32})', 'mixpanel_token'),
        (r'(\w+\.)?firebase[_\.]?(?:key|token)\s*[=:]\s*([a-zA-Z0-9_\-]{20,})', 'firebase_key'),
        (r'(\w+\.)?cognito\.client[_]?id\s*[=:]\s*([a-zA-Z0-9]{20,})', 'cognito_client_id'),
        (r'(\w+\.)?instabug\.key\s*[=:]\s*([a-f0-9]{32})', 'instabug_key'),
        
        # Azure keys
        (r'(\w+\.)?azure\.(?:shared[_]?key|key)\s*[=:]\s*([a-zA-Z0-9+/=]{20,})', 'azure_key'),
        (r'(\w+\.)?azure\.endpoint\s*[=:]\s*(sb://[^\s]+)', 'azure_endpoint'),
        
        # OAuth/Auth tokens
        (r'(\w+\.)?(?:sig|signature)\s*[=:]\s*([a-zA-Z0-9_\-]{20,})', 'signature'),
        (r'(\w+\.)?(?:ocp|subscription[_-]?key)\s*[=:]\s*([a-f0-9]{32})', 'subscription_key'),
        (r'(\w+\.)?(?:secret|client[_]?secret)\s*[=:]\s*([^\s]{16,})', 'client_secret'),
        
        # API endpoint URLs
        (r'(\w+\.)?(?:api[_]?url|endpoint)\s*[=:]\s*(https?://[^\s]+)', 'api_url'),
    ]
    
    # Scan properties files
    for pattern_glob in ['*.properties', '*.config', '*.env', '.env*']:
        for file_path in repo_path.rglob(pattern_glob):
            path_str = str(file_path)
            
            # Skip build directories
            if any(skip in path_str for skip in ['/build/', '/.gradle/', '/generated/']):
                continue
            
            try:
                content = file_path.read_text(errors='ignore')
                lines = content.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    # Skip comments
                    if line.strip().startswith('#') or line.strip().startswith('//'):
                        continue
                    
                    for pattern, secret_type in key_patterns:
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            # Get the environment prefix and value
                            env_prefix = match.group(1) or ''
                            value = match.group(2) if match.lastindex >= 2 else match.group(1)
                            
                            # Determine category
                            if 'url' in secret_type or 'endpoint' in secret_type:
                                category = 'config'
                                subcategory = 'api_url'
                            else:
                                category = 'auth'
                                subcategory = 'secret'
                            
                            secrets.append({
                                "category": category,
                                "rule_id": f"properties-{secret_type}",
                                "path": str(file_path.relative_to(repo_path)),
                                "line": line_num,
                                "code": line.strip(),  # Full unredacted code for security analyst validation
                                "endpoint_path": value if 'url' in secret_type else f"{env_prefix}{secret_type}",
                                "message": f"API credential: {secret_type} ({env_prefix.rstrip('.')})" if env_prefix else f"API credential: {secret_type}",
                                "metadata": {
                                    "category": "api-discovery",
                                    "subcategory": subcategory,
                                    "secret_type": secret_type,
                                    "environment": env_prefix.rstrip('.') if env_prefix else "default"
                                }
                            })
            except Exception as e:
                logger.debug(f"Error scanning {file_path}: {e}")
                continue
    
    logger.info(f"Found {len(secrets)} API keys/secrets in properties files")
    return secrets


def scan_kotlin_apis(repo_path: Path) -> List[Dict]:
    """
    Main entry point for Kotlin API scanning.
    
    Uses both Tree-sitter (if available) and enhanced regex.
    Returns combined list of all detected API endpoints.
    """
    scanner = EnhancedKotlinScanner(repo_path)
    results = scanner.scan_all_api_patterns()
    
    # Combine all results
    all_endpoints = []
    for category, endpoints in results.items():
        all_endpoints.extend(endpoints)
    
    # Also scan for API keys and secrets in properties files
    api_secrets = scan_api_keys_and_secrets(repo_path)
    all_endpoints.extend(api_secrets)
    
    # Deduplicate by (path, line, endpoint_path)
    seen = set()
    unique_endpoints = []
    for ep in all_endpoints:
        key = (ep.get('path'), ep.get('line'), ep.get('endpoint_path'))
        if key not in seen:
            seen.add(key)
            unique_endpoints.append(ep)
    
    logger.info(f"Total unique Kotlin API endpoints found: {len(unique_endpoints)}")
    return unique_endpoints

