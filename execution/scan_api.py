#!/usr/bin/env python3
"""
API Security Scanner - Execution Module

Implements the 4-phase API audit methodology:
1. Discovery Agent: Framework fingerprinting
2. Extraction Agent: Endpoint discovery using Semgrep
3. Synthesis Agent: OpenAPI specification generation
4. Security Agent: Vulnerability assessment

Usage:
    python scan_api.py --path /repo --name repo-name --output /reports
"""

import os
import sys
import argparse
import json
import logging
import subprocess
import shutil
import datetime
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# Import dedicated Kotlin parser
try:
    from execution.kotlin_parser import scan_kotlin_apis, EnhancedKotlinScanner
    KOTLIN_PARSER_AVAILABLE = True
except ImportError:
    try:
        from kotlin_parser import scan_kotlin_apis, EnhancedKotlinScanner
        KOTLIN_PARSER_AVAILABLE = True
    except ImportError:
        KOTLIN_PARSER_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Framework detection patterns
FRAMEWORK_PATTERNS = {
    "python": {
        "fastapi": ["fastapi", "starlette"],
        "flask": ["flask", "flask-restful", "flask-restx"],
        "django": ["django", "djangorestframework", "django-rest-framework"],
    },
    "javascript": {
        "express": ["express"],
        "koa": ["koa"],
        "fastify": ["fastify"],
        "hapi": ["@hapi/hapi", "hapi"],
    },
    "java": {
        "spring": ["spring-boot", "spring-web", "spring-webflux"],
        "jax-rs": ["jersey", "jax-rs"],
    },
    "go": {
        "gin": ["github.com/gin-gonic/gin"],
        "echo": ["github.com/labstack/echo"],
        "fiber": ["github.com/gofiber/fiber"],
    }
}

HTTP_CLIENT_PATTERNS = {
    "python": ["requests", "httpx", "aiohttp", "urllib3"],
    "javascript": ["axios", "node-fetch", "got", "superagent"],
    "java": ["okhttp", "retrofit", "httpclient"],
    "go": ["net/http", "resty"],
}


class APIScanner:
    """Main API security scanner implementing the 4-phase methodology."""
    
    def __init__(self, repo_path: str, repo_name: str, report_dir: str):
        self.repo_path = Path(repo_path)
        self.repo_name = repo_name
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        
        # Results storage
        self.fingerprint: Dict[str, Any] = {}
        self.inbound_endpoints: List[Dict] = []
        self.outbound_endpoints: List[Dict] = []
        self.auth_vectors: List[Dict] = []
        self.openapi_spec: Dict[str, Any] = {}
        self.threat_matrix: List[Dict] = []
    
    # =========================================================================
    # Phase 1: Discovery Agent
    # =========================================================================
    def phase1_discovery(self) -> Dict[str, Any]:
        """Framework fingerprinting and dependency analysis."""
        logger.info("Phase 1: Discovery Agent - Framework fingerprinting")
        
        fingerprint = {
            "language": None,
            "frameworks": [],
            "http_clients": [],
            "api_specs_found": [],
            "config_sources": [],
        }
        
        # Detect language and frameworks from dependency files
        fingerprint.update(self._detect_python_deps())
        fingerprint.update(self._detect_js_deps())
        fingerprint.update(self._detect_java_deps())
        fingerprint.update(self._detect_go_deps())
        
        # Find existing OpenAPI/Swagger specs
        fingerprint["api_specs_found"] = self._find_api_specs()
        
        # Find config files
        fingerprint["config_sources"] = self._find_config_files()
        
        self.fingerprint = fingerprint
        
        # Save fingerprint
        output_path = self.report_dir / f"{self.repo_name}_fingerprint.json"
        with open(output_path, 'w') as f:
            json.dump(fingerprint, f, indent=2)
        
        logger.info(f"Discovery complete: {fingerprint}")
        return fingerprint
    
    def _detect_python_deps(self) -> Dict:
        """Detect Python frameworks and HTTP clients."""
        result = {"language": None, "frameworks": [], "http_clients": []}
        
        dep_files = ["requirements.txt", "pyproject.toml", "Pipfile"]
        deps_content = ""
        
        for dep_file in dep_files:
            dep_path = self.repo_path / dep_file
            if dep_path.exists():
                deps_content += dep_path.read_text().lower()
        
        if not deps_content:
            return result
        
        result["language"] = "python"
        
        # Check frameworks
        for framework, packages in FRAMEWORK_PATTERNS["python"].items():
            if any(pkg in deps_content for pkg in packages):
                result["frameworks"].append(framework)
        
        # Check HTTP clients
        for client in HTTP_CLIENT_PATTERNS["python"]:
            if client in deps_content:
                result["http_clients"].append(client)
        
        return result
    
    def _detect_js_deps(self) -> Dict:
        """Detect JavaScript frameworks and HTTP clients."""
        result = {"language": None, "frameworks": [], "http_clients": []}
        
        package_json = self.repo_path / "package.json"
        if not package_json.exists():
            return result
        
        try:
            pkg = json.loads(package_json.read_text())
            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            dep_names = [d.lower() for d in deps.keys()]
        except (json.JSONDecodeError, Exception):
            return result
        
        if not dep_names:
            return result
        
        result["language"] = "javascript"
        
        # Check frameworks
        for framework, packages in FRAMEWORK_PATTERNS["javascript"].items():
            if any(pkg in dep_names for pkg in packages):
                result["frameworks"].append(framework)
        
        # Check HTTP clients
        for client in HTTP_CLIENT_PATTERNS["javascript"]:
            if client in dep_names:
                result["http_clients"].append(client)
        
        return result
    
    def _detect_java_deps(self) -> Dict:
        """Detect Java/Kotlin/Android frameworks and HTTP clients."""
        result = {"language": None, "frameworks": [], "http_clients": []}
        
        # Check for various Gradle and Maven files
        build_files = [
            self.repo_path / "pom.xml",
            self.repo_path / "build.gradle",
            self.repo_path / "build.gradle.kts",
            self.repo_path / "app" / "build.gradle",
            self.repo_path / "app" / "build.gradle.kts",
            self.repo_path / "settings.gradle",
            self.repo_path / "settings.gradle.kts",
        ]
        
        deps_content = ""
        found_files = []
        for build_file in build_files:
            if build_file.exists():
                try:
                    deps_content += build_file.read_text().lower() + "\n"
                    found_files.append(build_file.name)
                except Exception as e:
                    logger.debug(f"Error reading {build_file}: {e}")
        
        logger.debug(f"Found build files: {found_files}")
        
        # ALWAYS check for Kotlin files in the repo, regardless of build file content
        has_kotlin_files = False
        try:
            kotlin_files = list(self.repo_path.rglob("*.kt"))
            has_kotlin_files = len(kotlin_files) > 0
            if has_kotlin_files:
                logger.debug(f"Found {len(kotlin_files)} Kotlin files")
        except Exception as e:
            logger.debug(f"Error checking for Kotlin files: {e}")
        
        # Detect language
        if has_kotlin_files or "kotlin" in deps_content:
            result["language"] = "kotlin"
        elif deps_content and ("java" in deps_content or found_files):
            result["language"] = "java"
        
        # If no deps_content but has Kotlin files, still continue
        if not deps_content and not has_kotlin_files:
            return result
        
        # Detect Android (from build files or presence of AndroidManifest)
        android_manifest = self.repo_path / "app" / "src" / "main" / "AndroidManifest.xml"
        if "com.android" in deps_content or "android {" in deps_content or android_manifest.exists():
            result["frameworks"].append("android")
        
        # Detect HTTP clients (Retrofit, OkHttp, Ktor, Volley)
        http_client_patterns = {
            "retrofit": ["retrofit", "com.squareup.retrofit", "retrofit2"],
            "okhttp": ["okhttp", "com.squareup.okhttp"],
            "ktor": ["io.ktor", "ktor-client"],
            "volley": ["com.android.volley", "volley"],
            "fuel": ["com.github.kittinunf.fuel", "fuel"],
        }
        
        for client, patterns in http_client_patterns.items():
            if any(p in deps_content for p in patterns):
                result["http_clients"].append(client)
                if client not in result["frameworks"]:
                    result["frameworks"].append(client)
        
        # Detect Spring
        if any(p in deps_content for p in ["spring-boot", "spring-web"]):
            result["frameworks"].append("spring")
        
        logger.debug(f"Java/Kotlin detection result: {result}")
        return result
    
    def _detect_go_deps(self) -> Dict:
        """Detect Go frameworks."""
        result = {"language": None, "frameworks": [], "http_clients": []}
        
        go_mod = self.repo_path / "go.mod"
        if not go_mod.exists():
            return result
        
        deps_content = go_mod.read_text().lower()
        result["language"] = "go"
        
        for framework, packages in FRAMEWORK_PATTERNS["go"].items():
            if any(pkg.lower() in deps_content for pkg in packages):
                result["frameworks"].append(framework)
        
        return result
    
    def _find_api_specs(self) -> List[str]:
        """Find existing OpenAPI/Swagger specification files."""
        specs = []
        patterns = ["**/openapi.*", "**/swagger.*", "**/*api-spec*"]
        
        for pattern in patterns:
            for path in self.repo_path.glob(pattern):
                if path.suffix in [".yaml", ".yml", ".json"]:
                    specs.append(str(path.relative_to(self.repo_path)))
        
        return specs
    
    def _find_config_files(self) -> List[str]:
        """Find configuration files that may contain API endpoints."""
        configs = []
        patterns = ["**/.env*", "**/config.*", "**/settings.*", "**/application.*"]
        
        for pattern in patterns:
            for path in self.repo_path.glob(pattern):
                if path.is_file() and not path.name.startswith(".git"):
                    configs.append(str(path.relative_to(self.repo_path)))
        
        return configs[:20]  # Limit to 20 files
    
    # =========================================================================
    # Phase 2: Extraction Agent
    # =========================================================================
    def phase2_extraction(self) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        """Extract API endpoints using Semgrep."""
        logger.info("Phase 2: Extraction Agent - Endpoint discovery")
        
        semgrep_bin = shutil.which("semgrep")
        if not semgrep_bin:
            logger.error("Semgrep not installed")
            return [], [], []
        
        # Find semgrep rules directory
        rules_dir = Path(__file__).parent.parent / "semgrep-rules"
        if not rules_dir.exists():
            rules_dir = Path("/app/semgrep-rules")
        
        # Run endpoint detection
        self.inbound_endpoints = self._run_semgrep_rules(
            rules_dir / "api-endpoints.yaml", 
            "inbound"
        )
        
        # Run outbound detection
        self.outbound_endpoints = self._run_semgrep_rules(
            rules_dir / "api-outbound.yaml",
            "outbound"
        )
        
        # Run auth detection
        self.auth_vectors = self._run_semgrep_rules(
            rules_dir / "api-auth.yaml",
            "auth"
        )
        
        # =====================================================================
        # Kotlin/Android-specific: Use dedicated Kotlin parser instead of Semgrep
        # This bypasses Semgrep's Kotlin parsing issues and over-matching
        # =====================================================================
        if KOTLIN_PARSER_AVAILABLE:
            logger.info("Using dedicated Kotlin API parser (Tree-sitter + regex)")
            kotlin_endpoints = scan_kotlin_apis(self.repo_path)
            self.outbound_endpoints.extend(kotlin_endpoints)
        else:
            # Fallback to built-in regex scanner
            logger.info("Kotlin parser not available, using built-in regex scanner")
            kotlin_endpoints = self._scan_kotlin_api_patterns()
            self.outbound_endpoints.extend(kotlin_endpoints)
        
        # =====================================================================
        # Scan for hardcoded API URL patterns in source code
        # =====================================================================
        url_patterns = self._scan_for_api_urls()
        self.outbound_endpoints.extend(url_patterns)
        
        # Save extraction results
        self._save_extraction_results()
        
        logger.info(
            f"Extraction complete: {len(self.inbound_endpoints)} inbound, "
            f"{len(self.outbound_endpoints)} outbound, {len(self.auth_vectors)} auth"
        )
        
        return self.inbound_endpoints, self.outbound_endpoints, self.auth_vectors
    
    def _scan_kotlin_api_patterns(self) -> List[Dict]:
        """
        Directly scan Kotlin/Java files for API patterns.
        
        Looks for:
        - Retrofit interface definitions with @GET, @POST, etc.
        - OkHttp Request.Builder patterns
        - Base URL configurations
        - API client classes
        """
        logger.info("Scanning Kotlin/Java code for API patterns...")
        endpoints = []
        
        # Patterns for Kotlin/Java API detection
        patterns = [
            # Retrofit annotations - very specific patterns
            (r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*"([^"]+)"\s*\)', 'retrofit_annotation'),
            (r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*value\s*=\s*"([^"]+)"', 'retrofit_annotation'),
            
            # Retrofit interface functions (Kotlin)
            (r'suspend\s+fun\s+(\w+)\s*\([^)]*\).*@(GET|POST|PUT|DELETE|PATCH)', 'retrofit_suspend_fun'),
            
            # Base URL patterns
            (r'(?:BASE_URL|baseUrl|apiUrl|API_URL|BASE_API_URL)\s*[=:]\s*"(https?://[^"]+)"', 'base_url'),
            (r'Retrofit\.Builder\(\)[\s\S]*?\.baseUrl\s*\(\s*"([^"]+)"\s*\)', 'retrofit_base_url'),
            
            # OkHttp Request.Builder
            (r'Request\.Builder\(\)[\s\S]*?\.url\s*\(\s*"([^"]+)"\s*\)', 'okhttp_request'),
            (r'\.url\s*\(\s*"([^"]+)"\s*\)', 'url_call'),
            
            # Ktor client
            (r'client\.(get|post|put|delete|patch)\s*<[^>]*>\s*\(\s*"([^"]+)"', 'ktor_client'),
            (r'httpClient\.(get|post|put|delete|patch)\s*\(\s*"([^"]+)"', 'ktor_client'),
            
            # API endpoint constants
            (r'const\s+val\s+\w*(?:ENDPOINT|API|URL|PATH)\w*\s*=\s*"([^"]+)"', 'api_constant'),
            (r'(?:ENDPOINT|API_PATH|SERVICE_URL)\s*=\s*"([^"]+)"', 'api_constant'),
        ]
        
        # Exclusions
        exclude_patterns = [
            r'localhost', r'127\.0\.0\.1', r'example\.com', r'test\.',
            r'schemas?\.', r'android\.com', r'google\.com', r'gradle',
            r'\.png', r'\.jpg', r'\.svg', r'content://', r'file://',
        ]
        
        # Scan .kt and .java files
        for ext in ['.kt', '.java']:
            for file_path in self.repo_path.rglob(f'*{ext}'):
                path_str = str(file_path)
                
                # Skip build/test directories
                if any(skip in path_str for skip in ['/build/', '/.gradle/', '/test/', '/androidTest/']):
                    continue
                
                try:
                    content = file_path.read_text(errors='ignore')
                    
                    for pattern, pattern_type in patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                        
                        for match in matches:
                            # Extract the URL/path (usually in group 1 or 2)
                            if match.lastindex >= 2:
                                endpoint = match.group(2)
                                method = match.group(1).upper() if match.group(1).upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'] else 'GET'
                            else:
                                endpoint = match.group(1)
                                method = 'GET'
                            
                            # Skip excluded patterns
                            if any(re.search(exc, endpoint, re.IGNORECASE) for exc in exclude_patterns):
                                continue
                            
                            # Skip very short or empty
                            if len(endpoint) < 2:
                                continue
                            
                            # Calculate line number
                            line_num = content[:match.start()].count('\n') + 1
                            
                            # Get line content
                            line_start = content.rfind('\n', 0, match.start()) + 1
                            line_end = content.find('\n', match.end())
                            if line_end == -1:
                                line_end = len(content)
                            line_content = content[line_start:line_end].strip()
                            
                            endpoints.append({
                                "category": "outbound",
                                "rule_id": f"kotlin-{pattern_type}",
                                "path": str(file_path.relative_to(self.repo_path)),
                                "line": line_num,
                                "code": line_content[:200],
                                "endpoint_path": endpoint,
                                "message": f"API endpoint: {method} {endpoint}",
                                "metadata": {
                                    "category": "api-discovery",
                                    "subcategory": "outbound",
                                    "pattern_type": pattern_type,
                                    "http_method": method,
                                    "framework": "retrofit" if "retrofit" in pattern_type else "kotlin"
                                }
                            })
                            
                except Exception as e:
                    logger.debug(f"Error scanning {file_path}: {e}")
                    continue
        
        # Deduplicate
        seen = set()
        unique = []
        for ep in endpoints:
            key = (ep.get("endpoint_path", ""), ep.get("path", ""))
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        
        logger.info(f"Found {len(unique)} Kotlin/Java API patterns")
        return unique
    
    def _scan_for_api_urls(self) -> List[Dict]:
        """
        Scan source code for hardcoded API URL patterns.
        
        Based on API discovery best practices:
        - /api, /api/v1, /graphql, /auth indicators
        - REST resource naming conventions
        - Versioned paths
        - Authentication endpoints
        """
        logger.info("Scanning for hardcoded API URL patterns...")
        
        api_endpoints = []
        
        # Only scan code files (not JSON/XML which are often config with many paths)
        extensions = ['.kt', '.java', '.swift', '.m', '.ts', '.js', '.py', '.go']
        
        # HIGH-CONFIDENCE patterns: These strongly indicate API endpoints
        api_indicators = [
            # Full URLs with API in path (most reliable)
            (r'["\'](https?://[a-zA-Z0-9.-]+(?::\d+)?/api(?:/[a-zA-Z0-9/_{}:-]+)?)["\']', 'api_url'),
            
            # API subdomain patterns
            (r'["\'](https?://api\.[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9/_{}:-]+)?)["\']', 'api_subdomain'),
            
            # GraphQL endpoints
            (r'["\'](https?://[a-zA-Z0-9.-]+(?::\d+)?/graphql)["\']', 'graphql'),
            
            # Versioned API paths /v1/, /v2/, etc.
            (r'["\'](/v\d+/[a-zA-Z][a-zA-Z0-9/_{}:-]*)["\']', 'versioned_path'),
            (r'["\'](/api/v\d+/[a-zA-Z][a-zA-Z0-9/_{}:-]*)["\']', 'api_versioned'),
            
            # Auth/Login endpoints
            (r'["\']((?:https?://[a-zA-Z0-9.-]+)?/(?:auth|login|oauth|token|signin|signup)/[a-zA-Z0-9/_{}:-]*)["\']', 'auth_endpoint'),
            
            # REST resource paths with /api/ prefix
            (r'["\'](/api/[a-zA-Z]+(?:/[a-zA-Z0-9/_{}:-]+)?)["\']', 'api_resource'),
            
            # Paths with path parameters {id}, {userId}, etc. (strong API indicator)
            (r'["\']([a-zA-Z/]+/\{[a-zA-Z]+\}(?:/[a-zA-Z/{}]+)?)["\']', 'parameterized'),
            
            # Retrofit annotations (very reliable for Android)
            (r'@(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*["\']([^"\']+)["\']', 'retrofit'),
            
            # Base URL configurations
            (r'(?:baseUrl|BASE_URL|apiUrl|API_URL)\s*[=:]\s*["\']([^"\']+)["\']', 'base_url_config'),
        ]
        
        # Exclusion patterns - skip these matches
        exclude_patterns = [
            r'localhost', r'127\.0\.0\.1', r'0\.0\.0\.0',
            r'example\.com', r'test\.com', r'mock', r'dummy',
            r'schemas?\.', r'xmlns', r'w3\.org', r'json-schema',
            r'android\.com', r'google\.com', r'googleapis\.com/auth',
            r'gradle\.org', r'maven', r'jitpack', r'github\.com',
            r'stackoverflow', r'documentation', r'readme',
            r'/drawable', r'/layout', r'/values', r'/res/',
            r'\.png', r'\.jpg', r'\.svg', r'\.gif', r'\.ico',
            r'font', r'asset', r'image', r'style', r'theme',
        ]
        
        # Skip directories
        skip_dirs = ['/build/', '/node_modules/', '/.gradle/', '/vendor/', '/.git/', 
                     '/test/', '/tests/', '/__tests__/', '/mock/', '/fixture/']
        
        try:
            for ext in extensions:
                for file_path in self.repo_path.rglob(f'*{ext}'):
                    path_str = str(file_path)
                    
                    # Skip unwanted directories
                    if any(skip in path_str for skip in skip_dirs):
                        continue
                    
                    try:
                        content = file_path.read_text(errors='ignore')
                        
                        for pattern, pattern_type in api_indicators:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            
                            for match in matches:
                                url = match.group(1)
                                
                                # Skip excluded patterns
                                if any(re.search(exc, url, re.IGNORECASE) for exc in exclude_patterns):
                                    continue
                                
                                # Skip very short paths (likely false positives)
                                if len(url) < 6:
                                    continue
                                
                                # Skip if it's just a version number
                                if re.match(r'^/v\d+/?$', url):
                                    continue
                                
                                # Skip paths that look like file paths
                                if re.search(r'\.(xml|html|css|png|jpg|js|json)$', url):
                                    continue
                                
                                # Find line number
                                line_num = content[:match.start()].count('\n') + 1
                                line_start = content.rfind('\n', 0, match.start()) + 1
                                line_end = content.find('\n', match.end())
                                if line_end == -1:
                                    line_end = len(content)
                                line_content = content[line_start:line_end].strip()
                                
                                api_endpoints.append({
                                    "category": "outbound",
                                    "rule_id": f"url-pattern-{pattern_type}",
                                    "path": str(file_path.relative_to(self.repo_path)),
                                    "line": line_num,
                                    "code": line_content[:200],
                                    "endpoint_path": url,
                                    "message": f"API endpoint: {url}",
                                    "metadata": {
                                        "category": "api-discovery",
                                        "subcategory": "outbound",
                                        "pattern_type": pattern_type,
                                        "framework": "hardcoded"
                                    }
                                })
                                
                    except Exception as e:
                        logger.debug(f"Error scanning {file_path}: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"Error in URL pattern scanning: {e}")
        
        # Deduplicate by URL + file
        seen = set()
        unique_endpoints = []
        for ep in api_endpoints:
            key = (ep.get("endpoint_path", ""), ep.get("path", ""))
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(ep)
        
        logger.info(f"Found {len(unique_endpoints)} API URLs")
        return unique_endpoints
    
    def _run_semgrep_rules(self, rules_path: Path, category: str) -> List[Dict]:
        """Run Semgrep with specified rules."""
        if not rules_path.exists():
            logger.warning(f"Semgrep rules not found: {rules_path}")
            return []
        
        output_file = self.report_dir / f"{self.repo_name}_semgrep_{category}.json"
        
        try:
            cmd = [
                "semgrep", "scan",
                f"--config={rules_path}",
                "--json",
                f"--output={output_file}",
                str(self.repo_path)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if output_file.exists():
                with open(output_file) as f:
                    data = json.load(f)
                return self._parse_semgrep_results(data, category)
            
        except subprocess.TimeoutExpired:
            logger.error(f"Semgrep {category} scan timed out")
        except Exception as e:
            logger.error(f"Semgrep {category} scan failed: {e}")
        
        return []
    
    def _parse_semgrep_results(self, data: Dict, category: str) -> List[Dict]:
        """Parse Semgrep JSON output into structured endpoint data."""
        endpoints = []
        
        for result in data.get("results", []):
            endpoint = {
                "category": category,
                "rule_id": result.get("check_id", ""),
                "path": result.get("path", ""),
                "line": result.get("start", {}).get("line", 0),
                "code": result.get("extra", {}).get("lines", ""),
                "message": result.get("extra", {}).get("message", ""),
                "metadata": result.get("extra", {}).get("metadata", {}),
            }
            
            # Extract endpoint path from message if present
            msg = endpoint["message"]
            if "endpoint:" in msg.lower() or "route:" in msg.lower():
                # Try to extract path
                match = re.search(r'["\']([/\w{}:-]+)["\']', endpoint["code"])
                if match:
                    endpoint["endpoint_path"] = match.group(1)
            
            endpoints.append(endpoint)
        
        return endpoints
    
    def _save_extraction_results(self):
        """Save all extraction results to files."""
        output = {
            "repository": self.repo_name,
            "timestamp": datetime.datetime.now().isoformat(),
            "inbound_endpoints": self.inbound_endpoints,
            "outbound_endpoints": self.outbound_endpoints,
            "auth_vectors": self.auth_vectors,
        }
        
        with open(self.report_dir / f"{self.repo_name}_api_endpoints.json", 'w') as f:
            json.dump(output, f, indent=2)
    
    # =========================================================================
    # Phase 3: Synthesis Agent (OpenAPI Generation)
    # =========================================================================
    def phase3_synthesis(self, use_ai: bool = False) -> Dict[str, Any]:
        """Generate OpenAPI specification from extracted endpoints."""
        logger.info("Phase 3: Synthesis Agent - OpenAPI generation")
        
        # Build basic OpenAPI structure
        openapi = {
            "openapi": "3.0.3",
            "info": {
                "title": f"{self.repo_name} API",
                "version": "1.0.0",
                "description": f"Auto-generated API specification for {self.repo_name}",
            },
            "servers": self._infer_servers(),
            "paths": self._build_paths(),
            "components": {
                "securitySchemes": self._build_security_schemes(),
            }
        }
        
        self.openapi_spec = openapi
        
        # Save OpenAPI spec
        output_yaml = self.report_dir / f"{self.repo_name}_openapi.yaml"
        output_json = self.report_dir / f"{self.repo_name}_openapi.json"
        
        try:
            import yaml
            with open(output_yaml, 'w') as f:
                yaml.dump(openapi, f, default_flow_style=False, sort_keys=False)
        except ImportError:
            pass  # yaml not available
        
        with open(output_json, 'w') as f:
            json.dump(openapi, f, indent=2)
        
        logger.info(f"OpenAPI spec generated: {len(openapi['paths'])} paths")
        return openapi
    
    def _infer_servers(self) -> List[Dict]:
        """Infer server URLs from config files."""
        servers = []
        
        # Check for API_URL or similar in config
        for config_file in self.fingerprint.get("config_sources", []):
            config_path = self.repo_path / config_file
            if config_path.exists():
                try:
                    content = config_path.read_text()
                    # Look for URL patterns
                    urls = re.findall(
                        r'(?:API_URL|BASE_URL|SERVER_URL)\s*[=:]\s*["\']?(https?://[^\s"\']+)',
                        content, re.IGNORECASE
                    )
                    for url in urls:
                        servers.append({"url": url})
                except Exception:
                    pass
        
        if not servers:
            servers = [{"url": "http://localhost:8000", "description": "Development server"}]
        
        return servers
    
    def _build_paths(self) -> Dict[str, Any]:
        """Build OpenAPI paths from extracted endpoints."""
        paths: Dict[str, Any] = {}
        
        for endpoint in self.inbound_endpoints:
            path = endpoint.get("endpoint_path")
            if not path:
                continue
            
            # Normalize path (convert {id} to proper OpenAPI format)
            path = re.sub(r':(\w+)', r'{\1}', path)
            
            if path not in paths:
                paths[path] = {}
            
            # Determine HTTP method from rule or default to GET
            method = endpoint.get("metadata", {}).get("http_method", "get").lower()
            
            paths[path][method] = {
                "summary": f"Auto-discovered from {endpoint.get('path', 'unknown')}",
                "responses": {
                    "200": {"description": "Successful response"}
                }
            }
            
            # Add path parameters
            params = re.findall(r'\{(\w+)\}', path)
            if params:
                paths[path][method]["parameters"] = [
                    {"name": p, "in": "path", "required": True, "schema": {"type": "string"}}
                    for p in params
                ]
        
        return paths
    
    def _build_security_schemes(self) -> Dict[str, Any]:
        """Build security schemes from detected auth patterns."""
        schemes = {}
        
        auth_types = set()
        for auth in self.auth_vectors:
            auth_type = auth.get("metadata", {}).get("auth_type", "")
            if auth_type:
                auth_types.add(auth_type)
        
        if "bearer" in auth_types or "jwt" in auth_types:
            schemes["bearerAuth"] = {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            }
        
        if "api-key" in auth_types:
            schemes["apiKeyAuth"] = {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key"
            }
        
        if "basic" in auth_types:
            schemes["basicAuth"] = {
                "type": "http",
                "scheme": "basic"
            }
        
        if "oauth2" in auth_types or "oauth2-client" in auth_types:
            schemes["oauth2"] = {
                "type": "oauth2",
                "flows": {
                    "clientCredentials": {
                        "tokenUrl": "/oauth/token",
                        "scopes": {}
                    }
                }
            }
        
        return schemes
    
    # =========================================================================
    # Phase 4: Security Agent
    # =========================================================================
    def phase4_security(self) -> List[Dict]:
        """Assess security vulnerabilities for discovered endpoints."""
        logger.info("Phase 4: Security Agent - Vulnerability assessment")
        
        threat_matrix = []
        
        for endpoint in self.inbound_endpoints:
            path = endpoint.get("endpoint_path", endpoint.get("code", ""))
            vulnerabilities = []
            
            # Check for OWASP API Top 10 issues
            
            # API1: BOLA - paths with IDs
            if re.search(r'\{.*id.*\}|:\w+id', path, re.IGNORECASE):
                vulnerabilities.append({
                    "owasp_id": "API1:2023",
                    "title": "Potential Broken Object Level Authorization",
                    "severity": "HIGH",
                    "description": "Endpoint accepts resource ID - verify authorization checks"
                })
            
            # API2: Broken Auth - check if auth is present
            has_auth = any(
                auth.get("path") == endpoint.get("path")
                for auth in self.auth_vectors
            )
            if not has_auth:
                vulnerabilities.append({
                    "owasp_id": "API2:2023",
                    "title": "Potentially Missing Authentication",
                    "severity": "MEDIUM",
                    "description": "No authentication decorator/middleware detected"
                })
            
            # API7: SSRF - check outbound calls with dynamic URLs
            # (for matching files)
            
            if vulnerabilities:
                threat_matrix.append({
                    "endpoint": path,
                    "file": endpoint.get("path", ""),
                    "line": endpoint.get("line", 0),
                    "vulnerabilities": vulnerabilities,
                    "risk_score": self._calculate_risk_score(vulnerabilities)
                })
        
        # Run secrets scan for credential exposure
        self._run_secrets_scan()
        
        self.threat_matrix = threat_matrix
        
        # Save threat matrix
        with open(self.report_dir / f"{self.repo_name}_threat_matrix.json", 'w') as f:
            json.dump(threat_matrix, f, indent=2)
        
        logger.info(f"Security assessment complete: {len(threat_matrix)} endpoints analyzed")
        return threat_matrix
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate risk score based on vulnerabilities."""
        severity_scores = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 2, "INFO": 1}
        
        if not vulnerabilities:
            return 0.0
        
        total = sum(severity_scores.get(v.get("severity", "INFO"), 1) for v in vulnerabilities)
        return min(10.0, total)
    
    def _run_secrets_scan(self):
        """Run Gitleaks for credential discovery."""
        gitleaks_bin = shutil.which("gitleaks")
        if not gitleaks_bin:
            logger.warning("Gitleaks not installed, skipping secrets scan")
            return
        
        output_file = self.report_dir / f"{self.repo_name}_gitleaks.json"
        
        try:
            cmd = [
                gitleaks_bin, "detect",
                f"--source={self.repo_path}",
                "--report-format=json",
                f"--report-path={output_file}"
            ]
            subprocess.run(cmd, capture_output=True, timeout=300)
        except Exception as e:
            logger.error(f"Gitleaks scan failed: {e}")
    
    # =========================================================================
    # Generate Summary Report
    # =========================================================================
    def generate_report(self) -> str:
        """Generate markdown summary report."""
        report = f"""# API Security Audit Report: {self.repo_name}

**Generated:** {datetime.datetime.now().isoformat()}

## Executive Summary

| Metric | Value |
|--------|-------|
| Language | {self.fingerprint.get('language', 'Unknown')} |
| Frameworks | {', '.join(self.fingerprint.get('frameworks', [])) or 'None detected'} |
| HTTP Clients | {', '.join(self.fingerprint.get('http_clients', [])) or 'None detected'} |
| Config Sources | {len(self.fingerprint.get('config_sources', []))} files |
| API Servers Discovered | {len(self.openapi_spec.get('servers', []))} |
| Inbound Endpoints (Served) | {len(self.inbound_endpoints)} |
| Outbound Endpoints (Consumed) | {len(self.outbound_endpoints)} |
| Auth Patterns | {len(self.auth_vectors)} |
| Security Issues | {len(self.threat_matrix)} |

## Served APIs (Inbound)

APIs that this project **exposes** to consumers:

"""
        if self.inbound_endpoints:
            report += "| Endpoint | Method | File | Line |\n"
            report += "|----------|--------|------|------|\n"
            for ep in self.inbound_endpoints[:30]:
                endpoint = ep.get('endpoint_path', ep.get('code', '')[:50])
                method = ep.get('metadata', {}).get('http_method', 'ANY')
                file_path = Path(ep.get('path', '')).name
                line = ep.get('line', 0)
                report += f"| `{endpoint}` | {method} | {file_path} | {line} |\n"
        else:
            report += "*No served APIs detected*\n"
        
        # =====================================================================
        # CONSUMED APIs SECTION - Enhanced documentation
        # =====================================================================
        report += "\n## Consumed APIs (Outbound)\n\n"
        report += "APIs that this project **calls/consumes** from external services:\n\n"
        
        if self.outbound_endpoints:
            # Group by framework
            by_framework = {}
            for ep in self.outbound_endpoints:
                framework = ep.get('metadata', {}).get('framework', 'unknown')
                if framework not in by_framework:
                    by_framework[framework] = []
                by_framework[framework].append(ep)
            
            for framework, endpoints in by_framework.items():
                report += f"### {framework.title()} Client\n\n"
                report += "| Endpoint/URL | Method | File | Line |\n"
                report += "|--------------|--------|------|------|\n"
                
                for ep in endpoints[:20]:
                    # Try to extract URL/path from code or message
                    code = ep.get('code', '')[:60].replace('|', '\\|')
                    method = ep.get('metadata', {}).get('http_method', 'GET')
                    file_path = Path(ep.get('path', '')).name
                    line = ep.get('line', 0)
                    report += f"| `{code}` | {method} | {file_path} | {line} |\n"
                
                report += "\n"
        else:
            report += "*No consumed API endpoints detected*\n"
        
        # =====================================================================
        # DISCOVERED API SERVERS - Show server URLs from OpenAPI/Config
        # =====================================================================
        servers = self.openapi_spec.get('servers', [])
        if servers:
            report += "\n## Discovered API Servers\n\n"
            report += "**Server URLs extracted from configuration files:**\n\n"
            
            # Group by environment
            prod_servers = []
            stage_servers = []
            dev_servers = []
            other_servers = []
            
            for server in servers:
                url = server.get('url', '')
                url_lower = url.lower()
                if 'prod' in url_lower or ('api.' in url_lower and 'dev' not in url_lower and 'stage' not in url_lower and 'test' not in url_lower):
                    prod_servers.append(url)
                elif 'stage' in url_lower:
                    stage_servers.append(url)
                elif 'dev' in url_lower or 'test' in url_lower or 'qa' in url_lower or 'circle' in url_lower:
                    dev_servers.append(url)
                else:
                    other_servers.append(url)
            
            if prod_servers:
                report += "### Production\n"
                for url in prod_servers[:5]:
                    report += f"- `{url}`\n"
                report += "\n"
            
            if stage_servers:
                report += "### Staging\n"
                for url in stage_servers[:3]:
                    report += f"- `{url}`\n"
                report += "\n"
            
            if dev_servers:
                report += f"### Development/QA ({len(dev_servers)} servers)\n"
                for url in dev_servers[:5]:
                    report += f"- `{url}`\n"
                if len(dev_servers) > 5:
                    report += f"- *...and {len(dev_servers) - 5} more*\n"
                report += "\n"
            
            if other_servers:
                report += "### Other\n"
                for url in other_servers[:3]:
                    report += f"- `{url}`\n"
                report += "\n"
        
        # =====================================================================
        # Config Sources - Show where configuration was found
        # =====================================================================
        config_sources = self.fingerprint.get('config_sources', [])
        if config_sources:
            report += "\n## Configuration Sources\n\n"
            report += "Files where API configuration was discovered:\n\n"
            for source in config_sources[:10]:
                report += f"- `{source}`\n"
            report += "\n"
        
        # =====================================================================
        # Auth Patterns
        # =====================================================================
        report += "\n## Authentication Patterns\n\n"
        if self.auth_vectors:
            auth_types = set()
            for auth in self.auth_vectors:
                auth_type = auth.get('metadata', {}).get('auth_type', 'unknown')
                auth_types.add(auth_type)
            
            report += f"**Detected Auth Types:** {', '.join(auth_types)}\n\n"
            report += "| Pattern | File | Line |\n"
            report += "|---------|------|------|\n"
            for auth in self.auth_vectors[:15]:
                code = auth.get('code', '')[:50].replace('|', '\\|')
                file_path = Path(auth.get('path', '')).name
                line = auth.get('line', 0)
                report += f"| `{code}` | {file_path} | {line} |\n"
        else:
            report += "*No authentication patterns detected*\n"
        
        # =====================================================================
        # HARDCODED CREDENTIALS RISK ASSESSMENT
        # =====================================================================
        report += "\n## Hardcoded Credentials Risk Assessment\n\n"
        
        # Classify discovered secrets by risk level
        high_risk = []
        medium_risk = []
        low_risk = []
        
        for ep in self.outbound_endpoints:
            secret_type = ep.get('metadata', {}).get('secret_type', '')
            code = ep.get('code', '')
            path = ep.get('path', '')
            env = ep.get('metadata', {}).get('environment', '')
            
            # Skip non-secrets (just URLs)
            if 'api_url' in secret_type and 'key' not in code.lower() and 'secret' not in code.lower():
                continue
            
            finding = {
                'type': secret_type,
                'file': path,
                'line': ep.get('line', 0),
                'code': code[:80],
                'env': env
            }
            
            # Classify by risk
            if any(x in secret_type.lower() for x in ['azure_key', 'shared_key', 'secret', 'signature']):
                finding['severity'] = 'HIGH'
                finding['risk'] = 'May allow infrastructure access, push notifications, or service impersonation'
                high_risk.append(finding)
            elif any(x in secret_type.lower() for x in ['mixpanel', 'firebase', 'instabug', 'appcenter', 'api_key']):
                finding['severity'] = 'MEDIUM'
                finding['risk'] = 'Allows data injection, analytics pollution, or service abuse'
                medium_risk.append(finding)
            elif any(x in secret_type.lower() for x in ['client_id', 'cognito']):
                finding['severity'] = 'LOW'
                finding['risk'] = 'OAuth client IDs are typically public but useful for API enumeration'
                low_risk.append(finding)
        
        total_secrets = len(high_risk) + len(medium_risk) + len(low_risk)
        
        if total_secrets > 0:
            report += f"**Found {total_secrets} hardcoded credentials requiring review:**\n\n"
            report += "| Severity | Count | Examples |\n"
            report += "|----------|-------|----------|\n"
            if high_risk:
                report += f"| 🔴 **HIGH** | {len(high_risk)} | Azure keys, shared secrets |\n"
            if medium_risk:
                report += f"| 🟡 **MEDIUM** | {len(medium_risk)} | Mixpanel, Firebase, API tokens |\n"
            if low_risk:
                report += f"| 🟢 **LOW** | {len(low_risk)} | OAuth client IDs |\n"
            report += "\n"
            
            if high_risk:
                report += "### 🔴 High Risk Credentials\n\n"
                report += "**Impact:** May allow infrastructure access, push notifications abuse, or service impersonation.\n\n"
                report += "| Type | Environment | File | Code Sample |\n"
                report += "|------|-------------|------|-------------|\n"
                for f in high_risk[:10]:
                    code_sample = f['code'][:50].replace('|', '\\|')
                    report += f"| {f['type']} | {f['env']} | {Path(f['file']).name} | `{code_sample}...` |\n"
                report += "\n"
            
            if medium_risk:
                report += "### 🟡 Medium Risk Credentials\n\n"
                report += "**Impact:** Allows data injection, analytics pollution, quota exhaustion, or downstream automation abuse.\n\n"
                report += "| Type | Environment | File | Attack Vector |\n"
                report += "|------|-------------|------|---------------|\n"
                seen_types = set()
                for f in medium_risk:
                    if f['type'] not in seen_types:
                        seen_types.add(f['type'])
                        if 'mixpanel' in f['type'].lower():
                            attack = "Send fake analytics events, impersonate users"
                        elif 'firebase' in f['type'].lower():
                            attack = "Send push notifications, access Firebase services"
                        elif 'instabug' in f['type'].lower():
                            attack = "Submit fake bug reports, access crash data"
                        else:
                            attack = "API abuse, data injection"
                        report += f"| {f['type']} | {f['env']} | {Path(f['file']).name} | {attack} |\n"
                report += "\n"
            
            if low_risk:
                report += "### 🟢 Low Risk Credentials\n\n"
                report += "**Impact:** Public OAuth client IDs are expected in mobile apps but useful for API reconnaissance.\n\n"
                report += f"- Found {len(low_risk)} OAuth client IDs (Cognito, etc.)\n"
                report += "- These are typically public but confirm API surface\n\n"
            
            report += "### Remediation Recommendations\n\n"
            report += "1. **Rotate** any production credentials that may have been exposed\n"
            report += "2. **Monitor** third-party service logs for unusual API calls\n"
            report += "3. **Consider** moving sensitive keys to server-side configuration\n"
            report += "4. **Implement** API rate limiting on third-party services\n\n"
        else:
            report += "*No hardcoded credentials detected in properties files*\n"
        
        # =====================================================================
        # Security Findings
        # =====================================================================
        report += "\n## API Security Findings\n\n"
        if self.threat_matrix:
            for threat in self.threat_matrix[:20]:
                report += f"### {threat.get('endpoint', 'Unknown')}\n"
                report += f"**Risk Score:** {threat.get('risk_score', 0)}/10\n\n"
                for vuln in threat.get("vulnerabilities", []):
                    report += f"- **{vuln.get('owasp_id')}** [{vuln.get('severity')}]: {vuln.get('title')}\n"
                report += "\n"
        else:
            report += "*No API security issues detected*\n"
        
        report += "\n## Generated Artifacts\n\n"
        report += f"- OpenAPI Spec: `{self.repo_name}_openapi.yaml`\n"
        report += f"- Endpoints JSON: `{self.repo_name}_api_endpoints.json`\n"
        report += f"- Threat Matrix: `{self.repo_name}_threat_matrix.json`\n"
        report += f"- Consumed APIs: See `outbound_endpoints` in `{self.repo_name}_api_endpoints.json`\n"
        
        # Save report
        report_path = self.report_dir / f"{self.repo_name}_api_audit.md"
        with open(report_path, 'w') as f:
            f.write(report)
        
        # Also save a dedicated consumed APIs file
        self._save_consumed_apis_report()
        
        return report
    
    def _save_consumed_apis_report(self):
        """Generate a dedicated consumed APIs documentation file."""
        consumed_report = f"""# Consumed APIs Documentation: {self.repo_name}

**Generated:** {datetime.datetime.now().isoformat()}

This document lists all external APIs that {self.repo_name} consumes (calls).

## Overview

| Metric | Count |
|--------|-------|
| Total Consumed APIs | {len(self.outbound_endpoints)} |
| HTTP Clients Detected | {', '.join(self.fingerprint.get('http_clients', [])) or 'None'} |

## API Endpoints

"""
        # Group by framework
        by_framework = {}
        for ep in self.outbound_endpoints:
            framework = ep.get('metadata', {}).get('framework', 'unknown')
            if framework not in by_framework:
                by_framework[framework] = []
            by_framework[framework].append(ep)
        
        for framework, endpoints in by_framework.items():
            consumed_report += f"### {framework.title()}\n\n"
            
            for ep in endpoints:
                method = ep.get('metadata', {}).get('http_method', 'GET')
                code = ep.get('code', '')
                file_path = ep.get('path', '')
                line = ep.get('line', 0)
                message = ep.get('message', '')
                
                consumed_report += f"#### `{method}` {message or code[:60]}\n\n"
                consumed_report += f"- **File:** `{file_path}`\n"
                consumed_report += f"- **Line:** {line}\n"
                consumed_report += f"- **Code:**\n```\n{code}\n```\n\n"
        
        if not self.outbound_endpoints:
            consumed_report += "*No consumed APIs detected*\n"
        
        # Save
        report_path = self.report_dir / f"{self.repo_name}_consumed_apis.md"
        with open(report_path, 'w') as f:
            f.write(consumed_report)
    
    # =========================================================================
    # Main Execution
    # =========================================================================
    def run_full_scan(self) -> Dict[str, Any]:
        """Execute full 4-phase API security scan."""
        logger.info(f"Starting API security scan for {self.repo_name}")
        
        # Phase 1: Discovery
        self.phase1_discovery()
        
        # Phase 2: Extraction
        self.phase2_extraction()
        
        # Phase 3: Synthesis
        self.phase3_synthesis()
        
        # Phase 4: Security
        self.phase4_security()
        
        # Generate report
        self.generate_report()
        
        logger.info(f"API security scan complete for {self.repo_name}")
        
        return {
            "fingerprint": self.fingerprint,
            "inbound_count": len(self.inbound_endpoints),
            "outbound_count": len(self.outbound_endpoints),
            "threat_count": len(self.threat_matrix),
            "report_dir": str(self.report_dir),
        }


def main():
    parser = argparse.ArgumentParser(description="API Security Scanner")
    parser.add_argument("--path", required=True, help="Path to the repository")
    parser.add_argument("--name", required=True, help="Repository name")
    parser.add_argument("--output", required=True, help="Output directory")
    parser.add_argument("--phase", choices=["discovery", "extraction", "synthesis", "security", "all"],
                        default="all", help="Phase to run")
    parser.add_argument("--generate-openapi", action="store_true", help="Generate OpenAPI spec")
    parser.add_argument("--threat-matrix", action="store_true", help="Generate threat matrix")
    
    args = parser.parse_args()
    
    scanner = APIScanner(args.path, args.name, args.output)
    
    if args.phase == "all":
        result = scanner.run_full_scan()
    elif args.phase == "discovery":
        result = scanner.phase1_discovery()
    elif args.phase == "extraction":
        scanner.phase1_discovery()  # Need fingerprint first
        result = scanner.phase2_extraction()
    elif args.phase == "synthesis":
        scanner.phase1_discovery()
        scanner.phase2_extraction()
        result = scanner.phase3_synthesis()
    elif args.phase == "security":
        scanner.phase1_discovery()
        scanner.phase2_extraction()
        result = scanner.phase4_security()
    
    print(json.dumps(result, indent=2, default=str))
    return 0


def run_api_audit(
    repo_path: str,
    repo_name: str,
    output_dir: str,
    db_session=None,
    repository_id: str = None
) -> Dict[str, Any]:
    """
    Wrapper function to run API audit from scan_repos.py.
    
    Args:
        repo_path: Path to the repository
        repo_name: Name of the repository
        output_dir: Directory to save reports
        db_session: SQLAlchemy session for persisting results (optional)
        repository_id: UUID of the repository in database (optional)
    
    Returns:
        Dict with scan results
    """
    logger.info(f"Running API audit for {repo_name}")
    
    scanner = APIScanner(repo_path, repo_name, output_dir)
    result = scanner.run_full_scan()
    
    # Persist results to database if session provided
    if db_session and repository_id:
        try:
            _persist_to_database(
                db_session=db_session,
                repository_id=repository_id,
                scanner=scanner
            )
        except Exception as e:
            logger.error(f"Failed to persist API audit results to database: {e}")
    
    return result


def _persist_to_database(db_session, repository_id: str, scanner: APIScanner):
    """Persist API audit results to database."""
    try:
        # Import models here to avoid circular imports
        from src.api import models
        
        # Clear existing endpoints for this repository
        db_session.query(models.APIEndpoint).filter(
            models.APIEndpoint.repository_id == repository_id
        ).delete()
        
        # Add inbound endpoints
        for ep in scanner.inbound_endpoints:
            endpoint = models.APIEndpoint(
                repository_id=repository_id,
                endpoint_url=ep.get("endpoint_path", ep.get("code", "")[:200]),
                http_method=ep.get("metadata", {}).get("http_method", "GET"),
                direction="serves",
                auth_method=None,  # Will be filled from auth_vectors
                file_path=ep.get("path"),
                line_number=ep.get("line"),
                code_snippet=ep.get("code", "")[:500],
                framework=scanner.fingerprint.get("frameworks", [None])[0] if scanner.fingerprint.get("frameworks") else None,
                rule_id=ep.get("rule_id"),
                confidence="high"
            )
            db_session.add(endpoint)
        
        # Add outbound endpoints
        for ep in scanner.outbound_endpoints:
            endpoint = models.APIEndpoint(
                repository_id=repository_id,
                endpoint_url=ep.get("code", "")[:200],
                http_method="GET",
                direction="outbound",
                auth_method=None,
                file_path=ep.get("path"),
                line_number=ep.get("line"),
                code_snippet=ep.get("code", "")[:500],
                framework=None,
                rule_id=ep.get("rule_id"),
                confidence="medium"
            )
            db_session.add(endpoint)
        
        # Save OpenAPI spec if generated
        if scanner.openapi_spec:
            import yaml
            spec_content = yaml.dump(scanner.openapi_spec, default_flow_style=False)
            
            # Delete existing spec
            db_session.query(models.OpenAPISpec).filter(
                models.OpenAPISpec.repository_id == repository_id
            ).delete()
            
            spec = models.OpenAPISpec(
                repository_id=repository_id,
                spec_content=spec_content,
                spec_format="yaml",
                version="3.0.3",
                endpoint_count=len(scanner.inbound_endpoints)
            )
            db_session.add(spec)
        
        db_session.commit()
        logger.info(f"Persisted {len(scanner.inbound_endpoints)} inbound, {len(scanner.outbound_endpoints)} outbound endpoints to database")
        
    except ImportError as e:
        logger.warning(f"Could not import models for database persistence: {e}")
    except Exception as e:
        db_session.rollback()
        raise


if __name__ == "__main__":
    sys.exit(main())
