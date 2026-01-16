"""
Code Extractors for Architecture Preprocessing Pipeline

These extractors analyze source code to identify architectural components
without requiring full AST parsing - using regex patterns for speed and reliability.
"""

import os
import re
import json
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from collections import defaultdict


@dataclass
class APIEndpoint:
    path: str
    method: str
    function_name: str
    file_path: str
    line_number: int
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []


@dataclass
class DatabaseModel:
    name: str
    table_name: Optional[str]
    file_path: str
    fields: List[Dict[str, str]]
    relationships: List[str]


@dataclass
class ServiceDefinition:
    name: str
    type: str  # 'docker', 'kubernetes', 'process'
    port: Optional[int]
    image: Optional[str]
    depends_on: List[str]
    environment: Dict[str, str]
    volumes: List[str]


@dataclass
class ExternalConnection:
    name: str
    type: str  # 'database', 'api', 'cache', 'queue', 'storage'
    connection_string_pattern: str
    env_var: Optional[str]
    file_path: str


@dataclass
class ImportDependency:
    module: str
    imported_names: List[str]
    file_path: str
    is_local: bool


class APIRouteExtractor:
    """Extract API routes from various frameworks"""

    # Patterns for different frameworks
    PATTERNS = {
        'fastapi': [
            # @app.get("/path") or @router.get("/path")
            r'@(?:app|router)\.(get|post|put|delete|patch|options|head)\s*\(\s*["\']([^"\']+)["\']',
            # @app.api_route("/path", methods=["GET"])
            r'@(?:app|router)\.api_route\s*\(\s*["\']([^"\']+)["\'].*?methods\s*=\s*\[([^\]]+)\]',
        ],
        'flask': [
            # @app.route("/path", methods=["GET"])
            r'@(?:app|bp|blueprint)\s*\.\s*route\s*\(\s*["\']([^"\']+)["\'](?:.*?methods\s*=\s*\[([^\]]+)\])?',
        ],
        'express': [
            # app.get('/path', handler) or router.get('/path', handler)
            r'(?:app|router)\.(get|post|put|delete|patch|options|head)\s*\(\s*["\']([^"\']+)["\']',
        ],
        'spring': [
            # @GetMapping("/path") @PostMapping("/path")
            r'@(Get|Post|Put|Delete|Patch)Mapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',
            # @RequestMapping(value="/path", method=RequestMethod.GET)
            r'@RequestMapping\s*\([^)]*value\s*=\s*["\']([^"\']+)["\'][^)]*method\s*=\s*RequestMethod\.(\w+)',
        ],
        'django': [
            # path('route/', view)
            r'path\s*\(\s*["\']([^"\']+)["\']',
            # url(r'^route/$', view)
            r'url\s*\(\s*r?["\']([^"\']+)["\']',
        ],
        'gin': [
            # r.GET("/path", handler)
            r'(?:r|router|group)\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s*\(\s*["\']([^"\']+)["\']',
        ],
    }

    def extract(self, repo_path: str) -> List[APIEndpoint]:
        """Extract all API endpoints from repository"""
        endpoints = []

        for root, dirs, files in os.walk(repo_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in {
                'node_modules', '.git', '__pycache__', 'venv', 'env',
                '.venv', 'dist', 'build', 'target', 'vendor'
            }]

            for file in files:
                if self._is_source_file(file):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            endpoints.extend(self._extract_from_file(content, file_path, repo_path))
                    except Exception:
                        continue

        return endpoints

    def _is_source_file(self, filename: str) -> bool:
        """Check if file is a source code file"""
        extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php'}
        return Path(filename).suffix.lower() in extensions

    def _extract_from_file(self, content: str, file_path: str, repo_path: str) -> List[APIEndpoint]:
        """Extract endpoints from a single file"""
        endpoints = []
        lines = content.split('\n')
        rel_path = os.path.relpath(file_path, repo_path)

        # Detect framework from imports/content
        framework = self._detect_framework(content)

        if framework and framework in self.PATTERNS:
            for pattern in self.PATTERNS[framework]:
                for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                    # Find line number
                    pos = match.start()
                    line_num = content[:pos].count('\n') + 1

                    # Extract method and path based on pattern groups
                    groups = match.groups()
                    if framework in ['fastapi', 'express', 'gin']:
                        method = groups[0].upper()
                        path = groups[1]
                    elif framework == 'spring':
                        if 'Mapping' in pattern:
                            method = groups[0].upper()
                            path = groups[1]
                        else:
                            path = groups[0]
                            method = groups[1].upper()
                    else:
                        path = groups[0]
                        method = groups[1].upper() if len(groups) > 1 and groups[1] else 'GET'

                    # Try to find function name
                    func_name = self._find_function_name(lines, line_num - 1)

                    endpoints.append(APIEndpoint(
                        path=path,
                        method=method,
                        function_name=func_name,
                        file_path=rel_path,
                        line_number=line_num,
                        tags=self._infer_tags(path)
                    ))

        return endpoints

    def _detect_framework(self, content: str) -> Optional[str]:
        """Detect which framework is being used"""
        if 'from fastapi' in content or 'import fastapi' in content:
            return 'fastapi'
        elif 'from flask' in content or 'import flask' in content:
            return 'flask'
        elif 'express' in content and ('require' in content or 'import' in content):
            return 'express'
        elif '@GetMapping' in content or '@PostMapping' in content or '@RequestMapping' in content:
            return 'spring'
        elif 'from django' in content or 'urlpatterns' in content:
            return 'django'
        elif 'github.com/gin-gonic/gin' in content:
            return 'gin'
        return None

    def _find_function_name(self, lines: List[str], decorator_line: int) -> str:
        """Find the function name after a decorator"""
        for i in range(decorator_line + 1, min(decorator_line + 5, len(lines))):
            line = lines[i].strip()
            # Python: def function_name(
            match = re.match(r'(?:async\s+)?def\s+(\w+)\s*\(', line)
            if match:
                return match.group(1)
            # JavaScript/TypeScript: function name( or const name =
            match = re.match(r'(?:async\s+)?(?:function\s+)?(\w+)\s*[=(]', line)
            if match:
                return match.group(1)
        return 'unknown'

    def _infer_tags(self, path: str) -> List[str]:
        """Infer API tags from path"""
        tags = []
        path_parts = path.strip('/').split('/')
        if path_parts:
            # First significant part is often the resource
            for part in path_parts:
                if part and not part.startswith('{') and not part.startswith(':'):
                    tags.append(part)
                    break
        return tags


class DatabaseModelExtractor:
    """Extract database models from ORM definitions"""

    def extract(self, repo_path: str) -> List[DatabaseModel]:
        """Extract all database models"""
        models = []

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in {
                'node_modules', '.git', '__pycache__', 'venv', 'env',
                '.venv', 'dist', 'build', 'migrations', 'alembic'
            }]

            for file in files:
                if file.endswith(('.py', '.ts', '.js', '.java', '.prisma')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            models.extend(self._extract_from_file(content, file_path, repo_path))
                    except Exception:
                        continue

        return models

    def _extract_from_file(self, content: str, file_path: str, repo_path: str) -> List[DatabaseModel]:
        """Extract models from a single file"""
        models = []
        rel_path = os.path.relpath(file_path, repo_path)

        # SQLAlchemy models
        if 'sqlalchemy' in content.lower() or 'Base' in content:
            models.extend(self._extract_sqlalchemy(content, rel_path))

        # Django models
        if 'models.Model' in content:
            models.extend(self._extract_django(content, rel_path))

        # Prisma models
        if file_path.endswith('.prisma'):
            models.extend(self._extract_prisma(content, rel_path))

        # TypeORM entities
        if '@Entity' in content:
            models.extend(self._extract_typeorm(content, rel_path))

        return models

    def _extract_sqlalchemy(self, content: str, file_path: str) -> List[DatabaseModel]:
        """Extract SQLAlchemy models"""
        models = []

        # Match class definitions that inherit from Base or declarative_base
        pattern = r'class\s+(\w+)\s*\([^)]*(?:Base|DeclarativeBase|db\.Model)[^)]*\):'

        for match in re.finditer(pattern, content):
            class_name = match.group(1)
            class_start = match.end()

            # Find class body
            class_body = self._get_class_body(content, class_start)

            # Extract table name
            table_match = re.search(r'__tablename__\s*=\s*["\'](\w+)["\']', class_body)
            table_name = table_match.group(1) if table_match else class_name.lower()

            # Extract fields
            fields = []
            field_pattern = r'(\w+)\s*=\s*(?:Column|db\.Column)\s*\(\s*(\w+)'
            for field_match in re.finditer(field_pattern, class_body):
                fields.append({
                    'name': field_match.group(1),
                    'type': field_match.group(2)
                })

            # Extract relationships
            relationships = []
            rel_pattern = r'(\w+)\s*=\s*relationship\s*\(\s*["\'](\w+)["\']'
            for rel_match in re.finditer(rel_pattern, class_body):
                relationships.append(rel_match.group(2))

            models.append(DatabaseModel(
                name=class_name,
                table_name=table_name,
                file_path=file_path,
                fields=fields,
                relationships=relationships
            ))

        return models

    def _extract_django(self, content: str, file_path: str) -> List[DatabaseModel]:
        """Extract Django models"""
        models = []

        pattern = r'class\s+(\w+)\s*\(\s*models\.Model\s*\):'

        for match in re.finditer(pattern, content):
            class_name = match.group(1)
            class_start = match.end()
            class_body = self._get_class_body(content, class_start)

            fields = []
            field_pattern = r'(\w+)\s*=\s*models\.(\w+Field)'
            for field_match in re.finditer(field_pattern, class_body):
                fields.append({
                    'name': field_match.group(1),
                    'type': field_match.group(2)
                })

            relationships = []
            rel_pattern = r'(\w+)\s*=\s*models\.(ForeignKey|OneToOneField|ManyToManyField)\s*\(\s*["\']?(\w+)'
            for rel_match in re.finditer(rel_pattern, class_body):
                relationships.append(rel_match.group(3))

            models.append(DatabaseModel(
                name=class_name,
                table_name=class_name.lower(),
                file_path=file_path,
                fields=fields,
                relationships=relationships
            ))

        return models

    def _extract_prisma(self, content: str, file_path: str) -> List[DatabaseModel]:
        """Extract Prisma models"""
        models = []

        pattern = r'model\s+(\w+)\s*\{([^}]+)\}'

        for match in re.finditer(pattern, content):
            model_name = match.group(1)
            body = match.group(2)

            fields = []
            relationships = []

            for line in body.strip().split('\n'):
                line = line.strip()
                if not line or line.startswith('//') or line.startswith('@@'):
                    continue

                parts = line.split()
                if len(parts) >= 2:
                    field_name = parts[0]
                    field_type = parts[1].rstrip('?').rstrip('[]')

                    # Check if it's a relation (capitalized type that's not a primitive)
                    if field_type[0].isupper() and field_type not in {'String', 'Int', 'Float', 'Boolean', 'DateTime', 'Json', 'Bytes'}:
                        relationships.append(field_type)
                    else:
                        fields.append({'name': field_name, 'type': field_type})

            models.append(DatabaseModel(
                name=model_name,
                table_name=model_name,
                file_path=file_path,
                fields=fields,
                relationships=relationships
            ))

        return models

    def _extract_typeorm(self, content: str, file_path: str) -> List[DatabaseModel]:
        """Extract TypeORM entities"""
        models = []

        # Find @Entity decorated classes
        pattern = r'@Entity\s*\([^)]*\)\s*(?:export\s+)?class\s+(\w+)'

        for match in re.finditer(pattern, content):
            class_name = match.group(1)
            class_start = match.end()
            class_body = self._get_class_body(content, class_start)

            fields = []
            field_pattern = r'@Column\s*\([^)]*\)\s*(\w+)\s*[?:]?\s*:?\s*(\w+)?'
            for field_match in re.finditer(field_pattern, class_body):
                fields.append({
                    'name': field_match.group(1),
                    'type': field_match.group(2) or 'unknown'
                })

            relationships = []
            rel_pattern = r'@(?:ManyToOne|OneToMany|OneToOne|ManyToMany)\s*\([^)]*\)\s*(\w+)'
            for rel_match in re.finditer(rel_pattern, class_body):
                relationships.append(rel_match.group(1))

            models.append(DatabaseModel(
                name=class_name,
                table_name=class_name.lower(),
                file_path=file_path,
                fields=fields,
                relationships=relationships
            ))

        return models

    def _get_class_body(self, content: str, start_pos: int) -> str:
        """Extract class body using indentation"""
        lines = content[start_pos:].split('\n')
        body_lines = []
        base_indent = None

        for line in lines[1:]:  # Skip the first line (class definition)
            if not line.strip():
                body_lines.append(line)
                continue

            # Calculate indentation
            indent = len(line) - len(line.lstrip())

            if base_indent is None:
                base_indent = indent

            if indent >= base_indent:
                body_lines.append(line)
            else:
                break

        return '\n'.join(body_lines)


class ServiceExtractor:
    """Extract service definitions from Docker, Kubernetes, etc."""

    def extract(self, repo_path: str) -> List[ServiceDefinition]:
        """Extract all service definitions"""
        services = []

        # Docker Compose
        for compose_file in ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml']:
            compose_path = os.path.join(repo_path, compose_file)
            if os.path.exists(compose_path):
                services.extend(self._extract_docker_compose(compose_path))

        # Kubernetes manifests
        k8s_dirs = ['k8s', 'kubernetes', 'manifests', 'deploy', 'deployment']
        for k8s_dir in k8s_dirs:
            k8s_path = os.path.join(repo_path, k8s_dir)
            if os.path.isdir(k8s_path):
                services.extend(self._extract_kubernetes(k8s_path))

        # Also check root for k8s files
        services.extend(self._extract_kubernetes(repo_path, recursive=False))

        return services

    def _extract_docker_compose(self, file_path: str) -> List[ServiceDefinition]:
        """Extract services from docker-compose.yml"""
        services = []

        try:
            with open(file_path, 'r') as f:
                compose = yaml.safe_load(f)
        except Exception:
            return services

        if not compose or 'services' not in compose:
            return services

        for name, config in compose.get('services', {}).items():
            if not isinstance(config, dict):
                continue

            # Extract port
            port = None
            ports = config.get('ports', [])
            if ports and isinstance(ports, list):
                port_str = str(ports[0])
                # Parse "8080:80" or "8080"
                if ':' in port_str:
                    port = int(port_str.split(':')[0])
                else:
                    port = int(port_str.split('/')[0])

            # Extract environment variables (sanitized)
            env = {}
            env_config = config.get('environment', {})
            if isinstance(env_config, dict):
                for k, v in env_config.items():
                    # Don't include actual values, just note the variable exists
                    env[k] = '${' + k + '}' if v else 'unset'
            elif isinstance(env_config, list):
                for item in env_config:
                    if '=' in str(item):
                        k = item.split('=')[0]
                        env[k] = '${' + k + '}'

            services.append(ServiceDefinition(
                name=name,
                type='docker',
                port=port,
                image=config.get('image'),
                depends_on=config.get('depends_on', []),
                environment=env,
                volumes=config.get('volumes', [])
            ))

        return services

    def _extract_kubernetes(self, path: str, recursive: bool = True) -> List[ServiceDefinition]:
        """Extract services from Kubernetes manifests"""
        services = []

        if recursive:
            yaml_files = list(Path(path).rglob('*.yaml')) + list(Path(path).rglob('*.yml'))
        else:
            yaml_files = list(Path(path).glob('*.yaml')) + list(Path(path).glob('*.yml'))

        for yaml_file in yaml_files:
            try:
                with open(yaml_file, 'r') as f:
                    docs = list(yaml.safe_load_all(f))
            except Exception:
                continue

            for doc in docs:
                if not isinstance(doc, dict):
                    continue

                kind = doc.get('kind', '')
                if kind in ['Deployment', 'StatefulSet', 'DaemonSet', 'Service']:
                    metadata = doc.get('metadata', {})
                    name = metadata.get('name', 'unknown')

                    # Extract container info
                    port = None
                    image = None
                    env = {}

                    spec = doc.get('spec', {})
                    if kind == 'Service':
                        ports = spec.get('ports', [])
                        if ports:
                            port = ports[0].get('port')
                    else:
                        template = spec.get('template', {}).get('spec', {})
                        containers = template.get('containers', [])
                        if containers:
                            container = containers[0]
                            image = container.get('image')
                            container_ports = container.get('ports', [])
                            if container_ports:
                                port = container_ports[0].get('containerPort')
                            for env_var in container.get('env', []):
                                env[env_var.get('name', '')] = 'k8s-env'

                    services.append(ServiceDefinition(
                        name=name,
                        type='kubernetes',
                        port=port,
                        image=image,
                        depends_on=[],
                        environment=env,
                        volumes=[]
                    ))

        return services


class ExternalConnectionExtractor:
    """Extract external service connections from config and code"""

    # Patterns for detecting connection types
    CONNECTION_PATTERNS = {
        'database': [
            (r'DATABASE_URL|DB_URL|POSTGRES_|MYSQL_|MONGO_|REDIS_URL', 'env'),
            (r'postgresql://|mysql://|mongodb://|redis://', 'url'),
            (r'host\s*=.*(?:rds|cloudsql|database)', 'config'),
        ],
        'cache': [
            (r'REDIS_|MEMCACHED_|CACHE_URL', 'env'),
            (r'redis://|memcached://', 'url'),
        ],
        'queue': [
            (r'RABBITMQ_|AMQP_|SQS_|KAFKA_', 'env'),
            (r'amqp://|kafka://', 'url'),
        ],
        'storage': [
            (r'AWS_S3|AZURE_STORAGE|GCS_|MINIO_', 'env'),
            (r's3://|gs://|azure://', 'url'),
        ],
        'api': [
            (r'API_URL|API_KEY|API_SECRET', 'env'),
            (r'https?://api\.', 'url'),
        ],
        'auth': [
            (r'AUTH0_|OKTA_|COGNITO_|OAUTH_', 'env'),
        ],
        'monitoring': [
            (r'DATADOG_|NEWRELIC_|SENTRY_DSN|PROMETHEUS_', 'env'),
        ],
    }

    def extract(self, repo_path: str) -> List[ExternalConnection]:
        """Extract all external connections"""
        connections = []
        seen = set()

        # Check env files
        env_files = ['.env', '.env.example', '.env.sample', '.env.template']
        for env_file in env_files:
            env_path = os.path.join(repo_path, env_file)
            if os.path.exists(env_path):
                connections.extend(self._extract_from_env(env_path, repo_path, seen))

        # Check config files
        config_patterns = ['config.*', 'settings.*', '*.config.*']
        for pattern in config_patterns:
            for config_file in Path(repo_path).glob(pattern):
                if config_file.is_file():
                    connections.extend(self._extract_from_config(str(config_file), repo_path, seen))

        return connections

    def _extract_from_env(self, file_path: str, repo_path: str, seen: Set[str]) -> List[ExternalConnection]:
        """Extract connections from .env files"""
        connections = []
        rel_path = os.path.relpath(file_path, repo_path)

        try:
            with open(file_path, 'r') as f:
                content = f.read()
        except Exception:
            return connections

        for conn_type, patterns in self.CONNECTION_PATTERNS.items():
            for pattern, pattern_type in patterns:
                if pattern_type == 'env':
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        var_name = match.group(0)
                        key = f"{conn_type}:{var_name}"
                        if key not in seen:
                            seen.add(key)
                            connections.append(ExternalConnection(
                                name=var_name,
                                type=conn_type,
                                connection_string_pattern=pattern,
                                env_var=var_name,
                                file_path=rel_path
                            ))

        return connections

    def _extract_from_config(self, file_path: str, repo_path: str, seen: Set[str]) -> List[ExternalConnection]:
        """Extract connections from config files"""
        connections = []
        rel_path = os.path.relpath(file_path, repo_path)

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return connections

        for conn_type, patterns in self.CONNECTION_PATTERNS.items():
            for pattern, pattern_type in patterns:
                if pattern_type in ['url', 'config']:
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        matched = match.group(0)
                        key = f"{conn_type}:{matched[:30]}"
                        if key not in seen:
                            seen.add(key)
                            connections.append(ExternalConnection(
                                name=f"{conn_type}_connection",
                                type=conn_type,
                                connection_string_pattern=matched[:50] + '...' if len(matched) > 50 else matched,
                                env_var=None,
                                file_path=rel_path
                            ))

        return connections


class ImportGraphExtractor:
    """Extract import dependencies between modules"""

    def extract(self, repo_path: str, max_files: int = 100) -> Dict[str, List[ImportDependency]]:
        """Extract import graph from source files"""
        imports_by_file = {}
        file_count = 0

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in {
                'node_modules', '.git', '__pycache__', 'venv', 'env',
                '.venv', 'dist', 'build', 'target', 'vendor', 'test', 'tests'
            }]

            for file in files:
                if file_count >= max_files:
                    break

                if self._is_source_file(file):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, repo_path)

                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            imports = self._extract_imports(content, rel_path, repo_path)
                            if imports:
                                imports_by_file[rel_path] = imports
                                file_count += 1
                    except Exception:
                        continue

        return imports_by_file

    def _is_source_file(self, filename: str) -> bool:
        """Check if file is a source code file"""
        extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.java'}
        return Path(filename).suffix.lower() in extensions

    def _extract_imports(self, content: str, file_path: str, repo_path: str) -> List[ImportDependency]:
        """Extract imports from a file"""
        imports = []

        # Python imports
        if file_path.endswith('.py'):
            # from module import x, y
            for match in re.finditer(r'^from\s+([\w.]+)\s+import\s+(.+)$', content, re.MULTILINE):
                module = match.group(1)
                names = [n.strip().split(' as ')[0] for n in match.group(2).split(',')]
                imports.append(ImportDependency(
                    module=module,
                    imported_names=names,
                    file_path=file_path,
                    is_local=module.startswith('.')
                ))
            # import module
            for match in re.finditer(r'^import\s+([\w.]+)', content, re.MULTILINE):
                imports.append(ImportDependency(
                    module=match.group(1),
                    imported_names=[],
                    file_path=file_path,
                    is_local=False
                ))

        # JavaScript/TypeScript imports
        elif file_path.endswith(('.js', '.ts', '.jsx', '.tsx')):
            # import { x, y } from 'module'
            for match in re.finditer(r'import\s+(?:{([^}]+)}|\*\s+as\s+\w+|(\w+))\s+from\s+[\'"]([^\'"]+)[\'"]', content):
                names_str = match.group(1) or match.group(2) or ''
                names = [n.strip().split(' as ')[0] for n in names_str.split(',') if n.strip()]
                module = match.group(3)
                imports.append(ImportDependency(
                    module=module,
                    imported_names=names,
                    file_path=file_path,
                    is_local=module.startswith('.') or module.startswith('@/')
                ))
            # require('module')
            for match in re.finditer(r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)', content):
                imports.append(ImportDependency(
                    module=match.group(1),
                    imported_names=[],
                    file_path=file_path,
                    is_local=match.group(1).startswith('.')
                ))

        # Go imports
        elif file_path.endswith('.go'):
            for match in re.finditer(r'import\s+(?:\(\s*)?["\']([^"\']+)["\']', content):
                imports.append(ImportDependency(
                    module=match.group(1),
                    imported_names=[],
                    file_path=file_path,
                    is_local=not match.group(1).startswith('github.com') and '/' not in match.group(1)
                ))

        return imports


def extract_all(repo_path: str) -> Dict[str, Any]:
    """Run all extractors and return combined results"""

    api_extractor = APIRouteExtractor()
    db_extractor = DatabaseModelExtractor()
    service_extractor = ServiceExtractor()
    connection_extractor = ExternalConnectionExtractor()
    import_extractor = ImportGraphExtractor()

    # Run all extractors
    endpoints = api_extractor.extract(repo_path)
    models = db_extractor.extract(repo_path)
    services = service_extractor.extract(repo_path)
    connections = connection_extractor.extract(repo_path)
    imports = import_extractor.extract(repo_path)

    # Convert to serializable format
    return {
        'api_endpoints': [asdict(e) for e in endpoints],
        'database_models': [asdict(m) for m in models],
        'services': [asdict(s) for s in services],
        'external_connections': [asdict(c) for c in connections],
        'import_summary': {
            'total_files': len(imports),
            'local_imports': sum(1 for deps in imports.values() for d in deps if d.is_local),
            'external_imports': sum(1 for deps in imports.values() for d in deps if not d.is_local),
            'top_dependencies': _get_top_dependencies(imports)
        }
    }


def _get_top_dependencies(imports: Dict[str, List[ImportDependency]], limit: int = 20) -> List[Dict[str, Any]]:
    """Get the most commonly imported modules"""
    module_counts = defaultdict(int)

    for deps in imports.values():
        for dep in deps:
            if not dep.is_local:
                # Get root module name
                root_module = dep.module.split('/')[0].split('.')[0]
                module_counts[root_module] += 1

    sorted_modules = sorted(module_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    return [{'module': m, 'count': c} for m, c in sorted_modules]
