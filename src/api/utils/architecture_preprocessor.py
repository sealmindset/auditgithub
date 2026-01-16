"""
Architecture Preprocessing Pipeline

Multi-stage pipeline that:
1. Extracts architectural components using code extractors
2. Summarizes each domain using focused AI prompts
3. Produces structured JSON for accurate diagram generation
"""

import json
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

from .code_extractors import extract_all
from .repo_context import get_repo_context

logger = logging.getLogger(__name__)


@dataclass
class ArchitectureComponent:
    """A component in the architecture"""
    name: str
    type: str  # 'service', 'database', 'cache', 'queue', 'storage', 'api', 'external'
    technology: Optional[str]
    port: Optional[int]
    description: str
    connects_to: List[str]


@dataclass
class PreprocessedArchitecture:
    """Structured architecture data for diagram generation"""
    project_name: str
    project_type: str  # 'monolith', 'microservices', 'serverless', 'hybrid'
    cloud_provider: Optional[str]  # 'aws', 'azure', 'gcp', 'docker', 'kubernetes', None
    components: List[ArchitectureComponent]
    api_summary: Dict[str, Any]
    data_layer: Dict[str, Any]
    external_integrations: List[Dict[str, str]]
    tech_stack: Dict[str, List[str]]
    confidence_notes: List[str]  # Gaps and assumptions


class ArchitecturePreprocessor:
    """
    Orchestrates the preprocessing pipeline for architecture analysis.
    Uses code extractors for deterministic extraction, then AI for summarization.
    """

    def __init__(self, ai_provider):
        """
        Initialize with an AI provider instance.

        Args:
            ai_provider: An instance of BaseProvider (OpenAI, Claude, etc.)
        """
        self.ai_provider = ai_provider

    async def preprocess(self, repo_path: str, repo_name: str) -> PreprocessedArchitecture:
        """
        Run the full preprocessing pipeline.

        Args:
            repo_path: Local path to cloned repository
            repo_name: Name of the repository

        Returns:
            PreprocessedArchitecture with structured data for diagram generation
        """
        logger.info(f"Starting architecture preprocessing for {repo_name}")

        # Stage 1: Extract using deterministic extractors
        extracted_data = extract_all(repo_path)
        logger.info(f"Extracted: {len(extracted_data['api_endpoints'])} endpoints, "
                   f"{len(extracted_data['database_models'])} models, "
                   f"{len(extracted_data['services'])} services")

        # Also get traditional repo context for supplementary info
        structure, config_files = get_repo_context(repo_path)
        repo_context = {
            'structure': structure,
            'config_files': config_files
        }

        # Stage 2: AI summarization of each domain (parallel-capable)
        services_summary = await self._summarize_services(extracted_data, repo_context)
        api_summary = await self._summarize_api(extracted_data)
        data_summary = await self._summarize_data_layer(extracted_data)
        tech_stack = await self._identify_tech_stack(extracted_data, repo_context)

        # Stage 3: Build unified architecture model
        architecture = await self._build_architecture_model(
            repo_name=repo_name,
            services=services_summary,
            api=api_summary,
            data=data_summary,
            tech_stack=tech_stack,
            extracted=extracted_data,
            context=repo_context
        )

        logger.info(f"Preprocessing complete: {len(architecture.components)} components identified")
        return architecture

    async def _summarize_services(self, extracted: Dict, context: Dict) -> Dict[str, Any]:
        """Use AI to summarize and interpret service definitions"""

        services_data = extracted.get('services', [])
        connections = extracted.get('external_connections', [])

        if not services_data and not connections:
            return {'services': [], 'detected_pattern': 'unknown'}

        prompt = f"""Analyze these service definitions and external connections. Return a JSON summary.

Services from docker-compose/kubernetes:
{json.dumps(services_data, indent=2)[:3000]}

External connections detected:
{json.dumps(connections, indent=2)[:1500]}

Return JSON with this exact structure:
{{
    "services": [
        {{
            "name": "service name",
            "role": "api|web|worker|database|cache|queue|proxy|monitoring",
            "technology": "detected tech (e.g., FastAPI, PostgreSQL, Redis)",
            "port": port_number_or_null,
            "dependencies": ["list of services it connects to"]
        }}
    ],
    "detected_pattern": "monolith|microservices|serverless|unknown",
    "cloud_provider": "aws|azure|gcp|docker|kubernetes|null"
}}

Be concise. Only include services you have evidence for."""

        try:
            response = await self.ai_provider.chat(prompt, max_tokens=1500)
            return self._parse_json_response(response, {'services': [], 'detected_pattern': 'unknown'})
        except Exception as e:
            logger.error(f"Service summarization failed: {e}")
            return {'services': services_data, 'detected_pattern': 'unknown'}

    async def _summarize_api(self, extracted: Dict) -> Dict[str, Any]:
        """Use AI to categorize and summarize API endpoints"""

        endpoints = extracted.get('api_endpoints', [])

        if not endpoints:
            return {'domains': {}, 'total_endpoints': 0, 'api_style': 'unknown'}

        # Truncate if too many endpoints
        if len(endpoints) > 50:
            endpoints = endpoints[:50]

        prompt = f"""Analyze these API endpoints and categorize them by domain. Return a JSON summary.

API Endpoints:
{json.dumps(endpoints, indent=2)[:4000]}

Return JSON with this exact structure:
{{
    "domains": {{
        "domain_name": {{
            "description": "what this domain handles",
            "endpoints_count": number,
            "key_operations": ["list", "of", "main", "operations"]
        }}
    }},
    "total_endpoints": {len(endpoints)},
    "api_style": "REST|GraphQL|RPC|mixed",
    "authentication_detected": true|false
}}

Group related endpoints (e.g., /users/*, /auth/* -> "authentication", /repos/* -> "repositories").
Be concise."""

        try:
            response = await self.ai_provider.chat(prompt, max_tokens=1200)
            result = self._parse_json_response(response, {'domains': {}, 'total_endpoints': len(endpoints)})
            result['total_endpoints'] = len(extracted.get('api_endpoints', []))  # Use actual count
            return result
        except Exception as e:
            logger.error(f"API summarization failed: {e}")
            return {'domains': {}, 'total_endpoints': len(endpoints), 'api_style': 'unknown'}

    async def _summarize_data_layer(self, extracted: Dict) -> Dict[str, Any]:
        """Use AI to summarize database models and relationships"""

        models = extracted.get('database_models', [])
        connections = [c for c in extracted.get('external_connections', [])
                      if c.get('type') in ['database', 'cache']]

        if not models and not connections:
            return {'models': [], 'database_type': 'unknown', 'relationships': []}

        prompt = f"""Analyze these database models and connections. Return a JSON summary.

Database Models:
{json.dumps(models, indent=2)[:3000]}

Database Connections:
{json.dumps(connections, indent=2)[:1000]}

Return JSON with this exact structure:
{{
    "database_type": "postgresql|mysql|mongodb|sqlite|redis|unknown",
    "orm": "SQLAlchemy|Django|Prisma|TypeORM|unknown",
    "models_summary": [
        {{
            "name": "model name",
            "purpose": "brief description",
            "key_fields": ["important fields"],
            "relationships": ["related models"]
        }}
    ],
    "schema_pattern": "normalized|denormalized|document|unknown"
}}

Focus on the core entities. Be concise."""

        try:
            response = await self.ai_provider.chat(prompt, max_tokens=1200)
            return self._parse_json_response(response, {'models': [], 'database_type': 'unknown'})
        except Exception as e:
            logger.error(f"Data layer summarization failed: {e}")
            return {'models': models, 'database_type': 'unknown'}

    async def _identify_tech_stack(self, extracted: Dict, context: Dict) -> Dict[str, List[str]]:
        """Identify the technology stack from extracted data"""

        imports = extracted.get('import_summary', {})
        top_deps = imports.get('top_dependencies', [])
        config_files = context.get('config_files', {})

        # Build context string from config files (truncated)
        config_summary = []
        for filename, content in list(config_files.items())[:5]:
            config_summary.append(f"=== {filename} ===\n{content[:500]}")
        config_str = "\n".join(config_summary)

        prompt = f"""Identify the technology stack from this data. Return JSON.

Top imported dependencies:
{json.dumps(top_deps, indent=2)}

Config files preview:
{config_str[:2500]}

Return JSON with this exact structure:
{{
    "languages": ["primary language", "secondary if any"],
    "frameworks": ["web frameworks detected"],
    "databases": ["database technologies"],
    "caching": ["caching solutions"],
    "queues": ["message queue technologies"],
    "cloud_services": ["cloud services/platforms"],
    "ci_cd": ["CI/CD tools"],
    "containerization": ["Docker", "Kubernetes", etc.],
    "monitoring": ["monitoring/observability tools"]
}}

Only include technologies you have evidence for. Empty arrays are fine."""

        try:
            response = await self.ai_provider.chat(prompt, max_tokens=800)
            return self._parse_json_response(response, {'languages': [], 'frameworks': []})
        except Exception as e:
            logger.error(f"Tech stack identification failed: {e}")
            return {'languages': [], 'frameworks': []}

    async def _build_architecture_model(
        self,
        repo_name: str,
        services: Dict,
        api: Dict,
        data: Dict,
        tech_stack: Dict,
        extracted: Dict,
        context: Dict
    ) -> PreprocessedArchitecture:
        """Build the final architecture model from all summaries"""

        components = []
        confidence_notes = []

        # Add services as components
        for svc in services.get('services', []):
            components.append(ArchitectureComponent(
                name=svc.get('name', 'unknown'),
                type=self._map_role_to_type(svc.get('role', 'service')),
                technology=svc.get('technology'),
                port=svc.get('port'),
                description=svc.get('role', ''),
                connects_to=svc.get('dependencies', [])
            ))

        # Add database as component if detected
        db_type = data.get('database_type', 'unknown')
        if db_type != 'unknown':
            components.append(ArchitectureComponent(
                name=db_type,
                type='database',
                technology=db_type,
                port=self._default_port(db_type),
                description=f"Primary database ({data.get('orm', 'unknown')} ORM)",
                connects_to=[]
            ))

        # Add external integrations
        external = []
        for conn in extracted.get('external_connections', []):
            if conn.get('type') not in ['database', 'cache']:
                external.append({
                    'name': conn.get('name', 'external'),
                    'type': conn.get('type', 'api')
                })

        # Detect cloud provider
        cloud_provider = services.get('cloud_provider')
        if not cloud_provider:
            cloud_provider = self._detect_cloud_from_tech(tech_stack)

        # Determine project type
        project_type = services.get('detected_pattern', 'unknown')
        if project_type == 'unknown':
            if len(components) > 3:
                project_type = 'microservices'
            elif len(components) > 0:
                project_type = 'monolith'

        # Add confidence notes
        if not extracted.get('api_endpoints'):
            confidence_notes.append("No API endpoints were automatically detected - routes may use non-standard patterns")
        if not extracted.get('database_models'):
            confidence_notes.append("No ORM models detected - database schema inferred from connections only")
        if len(components) == 0:
            confidence_notes.append("No services detected - architecture inferred from config files only")
            # Add a generic API component
            frameworks = tech_stack.get('frameworks', [])
            if frameworks:
                components.append(ArchitectureComponent(
                    name='api',
                    type='service',
                    technology=frameworks[0] if frameworks else 'unknown',
                    port=8000,
                    description='Main application',
                    connects_to=[]
                ))

        return PreprocessedArchitecture(
            project_name=repo_name,
            project_type=project_type,
            cloud_provider=cloud_provider,
            components=components,
            api_summary=api,
            data_layer=data,
            external_integrations=external,
            tech_stack=tech_stack,
            confidence_notes=confidence_notes
        )

    def _map_role_to_type(self, role: str) -> str:
        """Map service role to component type"""
        mapping = {
            'api': 'service',
            'web': 'service',
            'worker': 'service',
            'database': 'database',
            'cache': 'cache',
            'queue': 'queue',
            'proxy': 'service',
            'monitoring': 'monitoring',
        }
        return mapping.get(role, 'service')

    def _default_port(self, db_type: str) -> Optional[int]:
        """Get default port for database type"""
        ports = {
            'postgresql': 5432,
            'mysql': 3306,
            'mongodb': 27017,
            'redis': 6379,
            'elasticsearch': 9200,
        }
        return ports.get(db_type.lower())

    def _detect_cloud_from_tech(self, tech_stack: Dict) -> Optional[str]:
        """Detect cloud provider from tech stack"""
        cloud_services = tech_stack.get('cloud_services', [])
        containerization = tech_stack.get('containerization', [])

        for service in cloud_services:
            service_lower = service.lower()
            if 'aws' in service_lower or 'amazon' in service_lower:
                return 'aws'
            if 'azure' in service_lower:
                return 'azure'
            if 'gcp' in service_lower or 'google' in service_lower:
                return 'gcp'

        if 'Kubernetes' in containerization:
            return 'kubernetes'
        if 'Docker' in containerization:
            return 'docker'

        return None

    def _parse_json_response(self, response: str, default: Dict) -> Dict:
        """Parse JSON from AI response, handling markdown code blocks"""
        try:
            # Try to extract JSON from markdown code block
            if '```json' in response:
                start = response.find('```json') + 7
                end = response.find('```', start)
                response = response[start:end].strip()
            elif '```' in response:
                start = response.find('```') + 3
                end = response.find('```', start)
                response = response[start:end].strip()

            return json.loads(response)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON response: {e}")
            return default

    def to_dict(self, architecture: PreprocessedArchitecture) -> Dict[str, Any]:
        """Convert PreprocessedArchitecture to dictionary for JSON serialization"""
        return {
            'project_name': architecture.project_name,
            'project_type': architecture.project_type,
            'cloud_provider': architecture.cloud_provider,
            'components': [asdict(c) for c in architecture.components],
            'api_summary': architecture.api_summary,
            'data_layer': architecture.data_layer,
            'external_integrations': architecture.external_integrations,
            'tech_stack': architecture.tech_stack,
            'confidence_notes': architecture.confidence_notes
        }


def build_diagram_prompt_from_preprocessed(architecture: PreprocessedArchitecture) -> str:
    """
    Build a focused diagram generation prompt from preprocessed architecture data.
    This replaces the raw file-based prompt with structured data.
    """

    components_desc = []
    for comp in architecture.components:
        conn_str = f" -> connects to: {', '.join(comp.connects_to)}" if comp.connects_to else ""
        components_desc.append(
            f"- {comp.name} ({comp.type}): {comp.technology or 'unknown tech'}"
            f"{f' on port {comp.port}' if comp.port else ''}{conn_str}"
        )

    api_domains = architecture.api_summary.get('domains', {})
    api_desc = []
    for domain, info in api_domains.items():
        api_desc.append(f"- {domain}: {info.get('description', '')} ({info.get('endpoints_count', 0)} endpoints)")

    external_desc = [f"- {ext['name']} ({ext['type']})" for ext in architecture.external_integrations]

    tech_desc = []
    for category, items in architecture.tech_stack.items():
        if items:
            tech_desc.append(f"- {category}: {', '.join(items)}")

    confidence_str = "\n".join(f"- {note}" for note in architecture.confidence_notes) if architecture.confidence_notes else "No major gaps identified."

    prompt = f"""Generate a Python architecture diagram using the `diagrams` library based on this VERIFIED architecture data.

## Project: {architecture.project_name}
- Type: {architecture.project_type}
- Cloud/Platform: {architecture.cloud_provider or 'Generic/Docker'}

## Components (VERIFIED):
{chr(10).join(components_desc) if components_desc else '- Main application service'}

## API Structure:
{chr(10).join(api_desc) if api_desc else '- API structure not fully detected'}
- Style: {architecture.api_summary.get('api_style', 'REST')}
- Total endpoints: {architecture.api_summary.get('total_endpoints', 'unknown')}

## Data Layer:
- Database: {architecture.data_layer.get('database_type', 'unknown')}
- ORM: {architecture.data_layer.get('orm', 'unknown')}
- Schema pattern: {architecture.data_layer.get('schema_pattern', 'unknown')}

## External Integrations:
{chr(10).join(external_desc) if external_desc else '- No external integrations detected'}

## Tech Stack:
{chr(10).join(tech_desc) if tech_desc else '- Tech stack not fully identified'}

## Confidence Notes:
{confidence_str}

---

**INSTRUCTIONS:**
1. Use `diagrams` library with appropriate provider modules:
   - Cloud: `diagrams.{architecture.cloud_provider or 'onprem'}.*`
   - Fallback to `diagrams.onprem.*` for generic components
2. Create clusters for logical groupings (e.g., "API Layer", "Data Layer", "External Services")
3. Show connections between components as indicated above
4. Use `graph_attr={{"splines": "ortho", "nodesep": "1.0", "ranksep": "1.0"}}` for clean layout
5. Add comments for any assumptions: `# ASSUMPTION: ...`

**IMPORTANT**:
- `Internet` is at `diagrams.onprem.network.Internet`
- Use `show=False, filename="architecture_diagram"`
- Return ONLY the Python code block, no explanations.

```python
# Your diagram code here
```"""

    return prompt
