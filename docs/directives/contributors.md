# Contributors Feature Enhancement Directive

## Objective

Enhance and improve the code and database for contributor tracking that identifies all contributors (people/members) for each repository, stores their contribution data in the database, and displays detailed contributor information in the UI at **Repositories > Project > Contributors (tab)**.

**Key Requirements:**
1. The complete list of folders, files, and languages are displayed in a **beautiful popup modal** when the analyst clicks on the **contributor's name**
2. For each file, include the **severity rating** based on security scan findings
3. Use **AI Agent** to bring all of these details together with intelligent analysis

---

## Requirements

For each contributor, track and display:

| Field | Description |
|-------|-------------|
| **Identity** | Name, email, GitHub username (if available) |
| **Files Contributed** | List of file paths with severity ratings from scans |
| **Folders Contributed** | Top-level directories they have modified |
| **Languages** | Programming languages worked with (inferred from file extensions) |
| **Total Commits** | Count of commits made by this contributor |
| **Last Activity** | Timestamp of their most recent commit |
| **Contribution %** | Their share of total repository commits |
| **Risk Score** | AI-calculated risk based on file severities and patterns |
| **AI Summary** | AI-generated analysis of contributor's security impact |

---

## Implementation Scope

### 1. Database Schema Enhancement

**File**: `src/api/models.py`

Enhance the `Contributor` model to track files with severity data:

```python
class Contributor(Base):
    __tablename__ = "contributors"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    repository_id = Column(UUID(as_uuid=True), ForeignKey("repositories.id"))
    name = Column(String, nullable=False)
    email = Column(String)
    github_username = Column(String)
    commits = Column(Integer, default=0)
    commit_percentage = Column(Numeric(5, 2))
    last_commit_at = Column(DateTime)
    languages = Column(JSONB)  # ["Python", "JavaScript", ...]

    # Enhanced file tracking with severity
    files_contributed = Column(JSONB)  # [{"path": "src/api.py", "severity": "high", "findings_count": 3}, ...]
    folders_contributed = Column(JSONB)  # ["src", "tests", "config", ...]

    # AI-enhanced fields
    risk_score = Column(Integer, default=0)  # 0-100 calculated risk
    ai_summary = Column(Text)  # AI-generated contributor analysis

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    repository = relationship("Repository", back_populates="contributors")
```

**Migration**: `migrations/add_contributor_enhancements.sql`

```sql
-- Enhance contributors table for file severity tracking and AI analysis
ALTER TABLE contributors
ADD COLUMN IF NOT EXISTS github_username VARCHAR(255),
ADD COLUMN IF NOT EXISTS commit_percentage NUMERIC(5, 2),
ADD COLUMN IF NOT EXISTS files_contributed JSONB DEFAULT '[]'::jsonb,
ADD COLUMN IF NOT EXISTS folders_contributed JSONB DEFAULT '[]'::jsonb,
ADD COLUMN IF NOT EXISTS ai_summary TEXT;

-- Update files_contributed to store severity data
COMMENT ON COLUMN contributors.files_contributed IS 'JSON array: [{"path": "file.py", "severity": "high", "findings_count": 2}, ...]';
COMMENT ON COLUMN contributors.ai_summary IS 'AI-generated analysis of contributor security impact';

-- Index for efficient queries
CREATE INDEX IF NOT EXISTS idx_contributors_repo_risk ON contributors(repository_id, risk_score DESC);
```

**Run Migration**:
```bash
cat migrations/add_contributor_enhancements.sql | docker-compose exec -T db psql -U auditgh -d auditgh_kb
```

---

### 2. Data Collection with Severity Mapping

**File**: `src/repo_intel.py`

Enhance contributor analysis to cross-reference files with security findings:

```python
def _analyze_contributors(self, findings_by_file: Dict[str, List[Dict]] = None) -> Dict[str, Any]:
    """
    Analyze repository contributors with file-level severity data.

    Args:
        findings_by_file: Dict mapping file paths to their security findings
                         e.g., {"src/api.py": [{"severity": "high", "type": "sast"}, ...]}

    Collects:
    - Contributor identity (name, email, github_username)
    - Total commits and percentage
    - Files contributed with severity ratings
    - Folders contributed
    - Languages inferred from file extensions
    """
    try:
        # Get detailed git log with file changes
        cmd = [
            'git', 'log',
            '--format=%H|%an|%ae|%aI',
            '--name-only',
            '--no-merges'
        ]
        result = subprocess.run(
            cmd,
            cwd=self.repo_path,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            return {"error": "Failed to analyze git history"}

        contributors = {}  # email -> contributor data
        total_commits = 0
        findings_by_file = findings_by_file or {}

        # Parse git log output
        current_commit = None
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue

            if '|' in line:
                # Commit header line
                parts = line.split('|')
                if len(parts) >= 4:
                    commit_hash, name, email, timestamp = parts[:4]
                    current_commit = {'name': name, 'email': email, 'timestamp': timestamp}
                    total_commits += 1

                    if email not in contributors:
                        contributors[email] = {
                            'name': name,
                            'email': email,
                            'github_username': self._extract_github_username(email),
                            'commits': 0,
                            'files': {},  # path -> {"count": N, "severity": "high"}
                            'folders': set(),
                            'languages': set(),
                            'last_commit_at': timestamp
                        }

                    contributors[email]['commits'] += 1
                    if timestamp > contributors[email]['last_commit_at']:
                        contributors[email]['last_commit_at'] = timestamp
            else:
                # File path line
                if current_commit and line.strip():
                    file_path = line.strip()
                    email = current_commit['email']

                    if email in contributors:
                        # Track file with severity
                        if file_path not in contributors[email]['files']:
                            # Get severity from findings
                            file_findings = findings_by_file.get(file_path, [])
                            max_severity = self._get_max_severity(file_findings)
                            findings_count = len(file_findings)

                            contributors[email]['files'][file_path] = {
                                'severity': max_severity,
                                'findings_count': findings_count
                            }

                        # Track folder
                        if '/' in file_path:
                            contributors[email]['folders'].add(file_path.split('/')[0])
                        else:
                            contributors[email]['folders'].add('(root)')

                        # Infer language
                        lang = self._infer_language(file_path)
                        if lang:
                            contributors[email]['languages'].add(lang)

        # Build result with file severity data
        result_contributors = []
        for email, data in contributors.items():
            percentage = (data['commits'] / total_commits * 100) if total_commits > 0 else 0

            # Convert files dict to list with severity
            files_with_severity = [
                {
                    'path': path,
                    'severity': info['severity'],
                    'findings_count': info['findings_count']
                }
                for path, info in data['files'].items()
            ]
            # Sort by severity (critical > high > medium > low > none)
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'none': 4, None: 5}
            files_with_severity.sort(key=lambda x: (severity_order.get(x['severity'], 5), x['path']))

            # Calculate risk score based on file severities
            risk_score = self._calculate_contributor_risk(files_with_severity)

            result_contributors.append({
                'name': data['name'],
                'email': data['email'],
                'github_username': data['github_username'],
                'commits': data['commits'],
                'commit_percentage': round(percentage, 2),
                'last_commit_at': data['last_commit_at'],
                'languages': sorted(list(data['languages'])),
                'files_contributed': files_with_severity[:200],  # Limit to 200 files
                'folders_contributed': sorted(list(data['folders'])),
                'risk_score': risk_score
            })

        # Sort by commits descending
        result_contributors.sort(key=lambda x: x['commits'], reverse=True)

        return {
            'total_contributors': len(result_contributors),
            'total_commits': total_commits,
            'bus_factor': self._calculate_bus_factor(result_contributors, total_commits),
            'top_contributors': result_contributors
        }

    except Exception as e:
        return {"error": str(e)}

def _get_max_severity(self, findings: List[Dict]) -> str:
    """Get the maximum severity from a list of findings."""
    if not findings:
        return None

    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    max_sev = None
    max_order = 999

    for finding in findings:
        sev = finding.get('severity', '').lower()
        if sev in severity_order and severity_order[sev] < max_order:
            max_order = severity_order[sev]
            max_sev = sev

    return max_sev

def _calculate_contributor_risk(self, files: List[Dict]) -> int:
    """
    Calculate contributor risk score (0-100) based on file severities.

    Scoring:
    - Critical finding: +25 points per file
    - High finding: +15 points per file
    - Medium finding: +5 points per file
    - Low finding: +1 point per file
    """
    score = 0
    severity_points = {'critical': 25, 'high': 15, 'medium': 5, 'low': 1}

    for file in files:
        sev = file.get('severity')
        if sev:
            score += severity_points.get(sev, 0)

    return min(100, score)  # Cap at 100

def _extract_github_username(self, email: str) -> Optional[str]:
    """Extract GitHub username from noreply email."""
    if 'noreply.github.com' in email:
        local_part = email.split('@')[0]
        if '+' in local_part:
            return local_part.split('+')[1]
        return local_part
    return None

def _infer_language(self, file_path: str) -> Optional[str]:
    """Infer programming language from file extension."""
    extension_map = {
        '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript',
        '.tsx': 'TypeScript', '.jsx': 'JavaScript', '.java': 'Java',
        '.go': 'Go', '.rs': 'Rust', '.rb': 'Ruby', '.php': 'PHP',
        '.cs': 'C#', '.cpp': 'C++', '.c': 'C', '.h': 'C/C++',
        '.swift': 'Swift', '.kt': 'Kotlin', '.scala': 'Scala',
        '.sql': 'SQL', '.sh': 'Shell', '.ps1': 'PowerShell',
        '.yaml': 'YAML', '.yml': 'YAML', '.json': 'JSON',
        '.tf': 'Terraform', '.md': 'Markdown'
    }

    if 'dockerfile' in file_path.lower():
        return 'Docker'

    ext = '.' + file_path.split('.')[-1].lower() if '.' in file_path else ''
    return extension_map.get(ext)
```

---

### 3. AI Agent Integration

**File**: `src/ai_agent/contributor_analyzer.py` (NEW)

Create an AI-powered contributor analyzer:

```python
"""
AI-powered contributor analysis for security insights.
"""
from typing import Dict, List, Optional
import json

class ContributorAnalyzer:
    """Analyzes contributor data using AI to generate security insights."""

    def __init__(self, ai_provider):
        """
        Initialize with an AI provider (OpenAI, Claude, etc.)

        Args:
            ai_provider: AI provider instance with generate() method
        """
        self.ai_provider = ai_provider

    async def analyze_contributor(
        self,
        contributor: Dict,
        repo_name: str,
        total_findings: int
    ) -> Dict:
        """
        Generate AI analysis for a contributor.

        Args:
            contributor: Contributor data with files and severities
            repo_name: Name of the repository
            total_findings: Total findings in the repository

        Returns:
            Dict with ai_summary and enhanced risk assessment
        """
        # Build context for AI
        critical_files = [f for f in contributor.get('files_contributed', [])
                        if f.get('severity') == 'critical']
        high_files = [f for f in contributor.get('files_contributed', [])
                     if f.get('severity') == 'high']

        prompt = f"""Analyze this contributor's security impact for repository "{repo_name}":

**Contributor:** {contributor.get('name')} ({contributor.get('email')})
**Commits:** {contributor.get('commits')} ({contributor.get('commit_percentage', 0):.1f}% of total)
**Last Active:** {contributor.get('last_commit_at', 'Unknown')}
**Languages:** {', '.join(contributor.get('languages', []))}
**Files Modified:** {len(contributor.get('files_contributed', []))}
**Folders:** {', '.join(contributor.get('folders_contributed', [])[:10])}

**Security Impact:**
- Critical severity files: {len(critical_files)}
- High severity files: {len(high_files)}
- Repository total findings: {total_findings}

**Critical Files:**
{json.dumps(critical_files[:5], indent=2) if critical_files else 'None'}

**High Severity Files:**
{json.dumps(high_files[:5], indent=2) if high_files else 'None'}

Provide a concise 2-3 sentence security analysis of this contributor:
1. Their code ownership risk (bus factor consideration)
2. Security debt they may have introduced
3. Priority recommendation for remediation

Format as a brief professional summary."""

        try:
            response = await self.ai_provider.generate(
                prompt=prompt,
                max_tokens=300,
                temperature=0.3
            )

            return {
                'ai_summary': response.text,
                'analysis_confidence': response.confidence if hasattr(response, 'confidence') else 0.8
            }

        except Exception as e:
            return {
                'ai_summary': f"Analysis unavailable: {str(e)}",
                'analysis_confidence': 0
            }

    async def generate_team_summary(
        self,
        contributors: List[Dict],
        repo_name: str
    ) -> str:
        """Generate an overall team security summary."""

        high_risk_contributors = [c for c in contributors if c.get('risk_score', 0) >= 50]
        total_commits = sum(c.get('commits', 0) for c in contributors)

        prompt = f"""Analyze the contributor team for repository "{repo_name}":

**Team Size:** {len(contributors)} contributors
**Total Commits:** {total_commits}
**High Risk Contributors (score >= 50):** {len(high_risk_contributors)}

**Top 5 Contributors by Commits:**
{json.dumps([{
    'name': c['name'],
    'commits': c['commits'],
    'risk_score': c.get('risk_score', 0),
    'critical_files': len([f for f in c.get('files_contributed', []) if f.get('severity') == 'critical'])
} for c in contributors[:5]], indent=2)}

Provide a brief team security assessment (3-4 sentences):
1. Bus factor risk
2. Security debt concentration
3. Recommended actions"""

        try:
            response = await self.ai_provider.generate(
                prompt=prompt,
                max_tokens=400,
                temperature=0.3
            )
            return response.text
        except Exception as e:
            return f"Team analysis unavailable: {str(e)}"
```

**Integration in scan_repos.py:**

```python
# After collecting contributor data, enhance with AI analysis
if AI_AGENT_AVAILABLE and ai_provider:
    from src.ai_agent.contributor_analyzer import ContributorAnalyzer
    analyzer = ContributorAnalyzer(ai_provider)

    for contributor in contributors_data:
        ai_result = await analyzer.analyze_contributor(
            contributor=contributor,
            repo_name=repo_name,
            total_findings=total_findings_count
        )
        contributor['ai_summary'] = ai_result.get('ai_summary', '')
```

---

### 4. Data Ingestion Enhancement

**File**: `ingest_scans.py`

Update ingestion to handle file severities and AI summaries:

```python
def ingest_contributors(db: Session, repo: models.Repository, report_path: Path):
    """Ingest enhanced contributor data with file severities and AI analysis."""
    intel_path = report_path.parent / f"{repo.name}_intel.json"

    if not intel_path.exists():
        logging.warning(f"No intel report found for {repo.name}")
        return

    try:
        with open(intel_path, 'r') as f:
            data = json.load(f)

        contributors_data = data.get('contributors', {}).get('top_contributors', [])

        if not contributors_data:
            logging.info(f"No contributors found for {repo.name}")
            return

        # Clear existing contributors
        db.query(models.Contributor).filter(
            models.Contributor.repository_id == repo.id
        ).delete()

        for c in contributors_data:
            last_commit = None
            if c.get('last_commit_at'):
                try:
                    last_commit = datetime.fromisoformat(
                        c['last_commit_at'].replace('Z', '+00:00')
                    )
                except ValueError:
                    pass

            contributor = models.Contributor(
                repository_id=repo.id,
                name=c.get('name', 'Unknown'),
                email=c.get('email', ''),
                github_username=c.get('github_username'),
                commits=c.get('commits', 0),
                commit_percentage=c.get('commit_percentage', 0),
                last_commit_at=last_commit,
                languages=c.get('languages', []),
                # Enhanced: files now include severity data
                files_contributed=c.get('files_contributed', []),  # [{"path": "", "severity": "", "findings_count": 0}]
                folders_contributed=c.get('folders_contributed', []),
                risk_score=c.get('risk_score', 0),
                ai_summary=c.get('ai_summary', '')
            )
            db.add(contributor)

        db.commit()
        logging.info(f"Ingested {len(contributors_data)} contributors for {repo.name}")

    except Exception as e:
        logging.error(f"Failed to ingest contributors for {repo.name}: {e}")
        db.rollback()
```

---

### 5. API Enhancement

**File**: `src/api/routers/projects.py`

Create enhanced API with contributor detail modal data:

```python
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

class FileWithSeverity(BaseModel):
    path: str
    severity: Optional[str]
    findings_count: int = 0

class ContributorDetail(BaseModel):
    """Full contributor details for modal display."""
    id: str
    name: str
    email: Optional[str]
    github_username: Optional[str]
    commits: int
    commit_percentage: Optional[float]
    last_commit_at: Optional[datetime]
    languages: List[str]
    files_contributed: List[FileWithSeverity]
    folders_contributed: List[str]
    risk_score: int
    ai_summary: Optional[str]

    # Computed stats for modal
    critical_files_count: int = 0
    high_files_count: int = 0
    medium_files_count: int = 0
    low_files_count: int = 0

    class Config:
        orm_mode = True


class ContributorSummary(BaseModel):
    """Summary for table display."""
    id: str
    name: str
    email: Optional[str]
    github_username: Optional[str]
    commits: int
    commit_percentage: Optional[float]
    last_commit_at: Optional[datetime]
    languages: List[str]
    files_count: int
    folders_count: int
    risk_score: int
    highest_severity: Optional[str]

    class Config:
        orm_mode = True


class ContributorsResponse(BaseModel):
    total_contributors: int
    total_commits: int
    bus_factor: int
    team_ai_summary: Optional[str]
    contributors: List[ContributorSummary]


@router.get("/{project_id}/contributors", response_model=ContributorsResponse)
def get_project_contributors(
    project_id: str,
    db: Session = Depends(get_db),
    limit: int = 100
):
    """Get all contributors with summary data for table display."""
    try:
        repo_uuid = uuid.UUID(project_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    repo = db.query(models.Repository).filter(models.Repository.id == repo_uuid).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    contributors = db.query(models.Contributor).filter(
        models.Contributor.repository_id == repo_uuid
    ).order_by(models.Contributor.commits.desc()).limit(limit).all()

    total_commits = sum(c.commits for c in contributors)

    # Calculate bus factor
    bus_factor = 0
    cumulative = 0
    threshold = total_commits * 0.5
    for i, c in enumerate(contributors, 1):
        cumulative += c.commits
        if cumulative >= threshold:
            bus_factor = i
            break

    # Build summary responses
    summaries = []
    for c in contributors:
        files = c.files_contributed or []

        # Get highest severity
        severities = [f.get('severity') for f in files if f.get('severity')]
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        highest = None
        if severities:
            highest = min(severities, key=lambda s: severity_order.get(s, 99))

        summaries.append(ContributorSummary(
            id=str(c.id),
            name=c.name,
            email=c.email,
            github_username=c.github_username,
            commits=c.commits,
            commit_percentage=float(c.commit_percentage) if c.commit_percentage else None,
            last_commit_at=c.last_commit_at,
            languages=c.languages or [],
            files_count=len(files),
            folders_count=len(c.folders_contributed or []),
            risk_score=c.risk_score or 0,
            highest_severity=highest
        ))

    return ContributorsResponse(
        total_contributors=len(contributors),
        total_commits=total_commits,
        bus_factor=bus_factor,
        team_ai_summary=None,  # Can be populated from repo-level AI analysis
        contributors=summaries
    )


@router.get("/{project_id}/contributors/{contributor_id}", response_model=ContributorDetail)
def get_contributor_detail(
    project_id: str,
    contributor_id: str,
    db: Session = Depends(get_db)
):
    """Get full contributor details for modal display."""
    try:
        repo_uuid = uuid.UUID(project_id)
        contrib_uuid = uuid.UUID(contributor_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid ID format")

    contributor = db.query(models.Contributor).filter(
        models.Contributor.id == contrib_uuid,
        models.Contributor.repository_id == repo_uuid
    ).first()

    if not contributor:
        raise HTTPException(status_code=404, detail="Contributor not found")

    files = contributor.files_contributed or []

    # Count files by severity
    critical_count = len([f for f in files if f.get('severity') == 'critical'])
    high_count = len([f for f in files if f.get('severity') == 'high'])
    medium_count = len([f for f in files if f.get('severity') == 'medium'])
    low_count = len([f for f in files if f.get('severity') == 'low'])

    return ContributorDetail(
        id=str(contributor.id),
        name=contributor.name,
        email=contributor.email,
        github_username=contributor.github_username,
        commits=contributor.commits,
        commit_percentage=float(contributor.commit_percentage) if contributor.commit_percentage else None,
        last_commit_at=contributor.last_commit_at,
        languages=contributor.languages or [],
        files_contributed=[FileWithSeverity(**f) for f in files],
        folders_contributed=contributor.folders_contributed or [],
        risk_score=contributor.risk_score or 0,
        ai_summary=contributor.ai_summary,
        critical_files_count=critical_count,
        high_files_count=high_count,
        medium_files_count=medium_count,
        low_files_count=low_count
    )
```

---

### 6. UI Enhancement - Beautiful Popup Modal

**File**: `src/web-ui/components/ContributorsView.tsx`

Create a beautiful contributor detail modal triggered by clicking the name:

```typescript
"use client"

import { useEffect, useState } from "react"
import {
    ColumnDef,
    flexRender,
    getCoreRowModel,
    getSortedRowModel,
    getFilteredRowModel,
    SortingState,
    useReactTable,
} from "@tanstack/react-table"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Loader2, Users, GitCommit, AlertTriangle, FolderOpen, FileCode, Shield, Brain, X } from "lucide-react"
import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Progress } from "@/components/ui/progress"
import { Separator } from "@/components/ui/separator"

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

// Types
interface FileWithSeverity {
    path: string
    severity: string | null
    findings_count: number
}

interface ContributorSummary {
    id: string
    name: string
    email: string | null
    github_username: string | null
    commits: number
    commit_percentage: number | null
    last_commit_at: string | null
    languages: string[]
    files_count: number
    folders_count: number
    risk_score: number
    highest_severity: string | null
}

interface ContributorDetail {
    id: string
    name: string
    email: string | null
    github_username: string | null
    commits: number
    commit_percentage: number | null
    last_commit_at: string | null
    languages: string[]
    files_contributed: FileWithSeverity[]
    folders_contributed: string[]
    risk_score: number
    ai_summary: string | null
    critical_files_count: number
    high_files_count: number
    medium_files_count: number
    low_files_count: number
}

interface ContributorsResponse {
    total_contributors: number
    total_commits: number
    bus_factor: number
    team_ai_summary: string | null
    contributors: ContributorSummary[]
}

// Severity badge component
function SeverityBadge({ severity }: { severity: string | null }) {
    if (!severity) return null

    const variants: Record<string, string> = {
        critical: "bg-red-600 text-white",
        high: "bg-orange-500 text-white",
        medium: "bg-yellow-500 text-black",
        low: "bg-blue-500 text-white"
    }

    return (
        <Badge className={`text-xs ${variants[severity] || "bg-gray-500"}`}>
            {severity.toUpperCase()}
        </Badge>
    )
}

// Contributor Detail Modal Component
function ContributorModal({
    contributorId,
    projectId,
    isOpen,
    onClose
}: {
    contributorId: string | null
    projectId: string
    isOpen: boolean
    onClose: () => void
}) {
    const [detail, setDetail] = useState<ContributorDetail | null>(null)
    const [loading, setLoading] = useState(false)

    useEffect(() => {
        if (isOpen && contributorId) {
            setLoading(true)
            fetch(`${API_BASE}/projects/${projectId}/contributors/${contributorId}`)
                .then(res => res.json())
                .then(data => setDetail(data))
                .catch(console.error)
                .finally(() => setLoading(false))
        }
    }, [isOpen, contributorId, projectId])

    if (!isOpen) return null

    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <DialogContent className="max-w-4xl max-h-[90vh] overflow-hidden">
                {loading ? (
                    <div className="flex items-center justify-center h-64">
                        <Loader2 className="h-8 w-8 animate-spin" />
                    </div>
                ) : detail ? (
                    <>
                        <DialogHeader>
                            <div className="flex items-center gap-4">
                                <Avatar className="h-16 w-16">
                                    {detail.github_username && (
                                        <AvatarImage
                                            src={`https://github.com/${detail.github_username}.png`}
                                            alt={detail.name}
                                        />
                                    )}
                                    <AvatarFallback className="text-xl">
                                        {detail.name.split(" ").map(n => n[0]).join("").toUpperCase().slice(0, 2)}
                                    </AvatarFallback>
                                </Avatar>
                                <div>
                                    <DialogTitle className="text-2xl">{detail.name}</DialogTitle>
                                    <div className="text-sm text-muted-foreground">
                                        {detail.email}
                                        {detail.github_username && (
                                            <span className="ml-2 text-blue-500">@{detail.github_username}</span>
                                        )}
                                    </div>
                                </div>
                                <div className="ml-auto flex items-center gap-2">
                                    <Badge variant={detail.risk_score >= 50 ? "destructive" : "secondary"}>
                                        Risk Score: {detail.risk_score}
                                    </Badge>
                                </div>
                            </div>
                        </DialogHeader>

                        {/* Stats Cards */}
                        <div className="grid grid-cols-4 gap-4 my-4">
                            <Card>
                                <CardContent className="pt-4">
                                    <div className="text-2xl font-bold">{detail.commits}</div>
                                    <div className="text-xs text-muted-foreground">
                                        Commits ({detail.commit_percentage?.toFixed(1)}%)
                                    </div>
                                </CardContent>
                            </Card>
                            <Card>
                                <CardContent className="pt-4">
                                    <div className="text-2xl font-bold text-red-600">{detail.critical_files_count}</div>
                                    <div className="text-xs text-muted-foreground">Critical Files</div>
                                </CardContent>
                            </Card>
                            <Card>
                                <CardContent className="pt-4">
                                    <div className="text-2xl font-bold text-orange-500">{detail.high_files_count}</div>
                                    <div className="text-xs text-muted-foreground">High Severity</div>
                                </CardContent>
                            </Card>
                            <Card>
                                <CardContent className="pt-4">
                                    <div className="text-2xl font-bold">{detail.files_contributed.length}</div>
                                    <div className="text-xs text-muted-foreground">Total Files</div>
                                </CardContent>
                            </Card>
                        </div>

                        {/* AI Summary */}
                        {detail.ai_summary && (
                            <Card className="mb-4 bg-gradient-to-r from-purple-50 to-blue-50 dark:from-purple-950 dark:to-blue-950">
                                <CardHeader className="pb-2">
                                    <CardTitle className="text-sm flex items-center gap-2">
                                        <Brain className="h-4 w-4" />
                                        AI Security Analysis
                                    </CardTitle>
                                </CardHeader>
                                <CardContent>
                                    <p className="text-sm">{detail.ai_summary}</p>
                                </CardContent>
                            </Card>
                        )}

                        {/* Tabs for Files, Folders, Languages */}
                        <Tabs defaultValue="files" className="flex-1">
                            <TabsList className="grid w-full grid-cols-3">
                                <TabsTrigger value="files">
                                    <FileCode className="h-4 w-4 mr-2" />
                                    Files ({detail.files_contributed.length})
                                </TabsTrigger>
                                <TabsTrigger value="folders">
                                    <FolderOpen className="h-4 w-4 mr-2" />
                                    Folders ({detail.folders_contributed.length})
                                </TabsTrigger>
                                <TabsTrigger value="languages">
                                    <Shield className="h-4 w-4 mr-2" />
                                    Languages ({detail.languages.length})
                                </TabsTrigger>
                            </TabsList>

                            <TabsContent value="files" className="mt-4">
                                <ScrollArea className="h-[300px] pr-4">
                                    <div className="space-y-1">
                                        {detail.files_contributed.map((file, idx) => (
                                            <div
                                                key={idx}
                                                className="flex items-center justify-between p-2 rounded hover:bg-muted"
                                            >
                                                <div className="flex items-center gap-2 flex-1 min-w-0">
                                                    <FileCode className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                                                    <span className="text-sm font-mono truncate">{file.path}</span>
                                                </div>
                                                <div className="flex items-center gap-2 flex-shrink-0">
                                                    {file.findings_count > 0 && (
                                                        <span className="text-xs text-muted-foreground">
                                                            {file.findings_count} findings
                                                        </span>
                                                    )}
                                                    <SeverityBadge severity={file.severity} />
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </ScrollArea>
                            </TabsContent>

                            <TabsContent value="folders" className="mt-4">
                                <ScrollArea className="h-[300px] pr-4">
                                    <div className="grid grid-cols-3 gap-2">
                                        {detail.folders_contributed.map((folder, idx) => (
                                            <div
                                                key={idx}
                                                className="flex items-center gap-2 p-3 rounded-lg bg-muted"
                                            >
                                                <FolderOpen className="h-5 w-5 text-yellow-500" />
                                                <span className="text-sm font-medium">{folder}</span>
                                            </div>
                                        ))}
                                    </div>
                                </ScrollArea>
                            </TabsContent>

                            <TabsContent value="languages" className="mt-4">
                                <div className="flex flex-wrap gap-3">
                                    {detail.languages.map((lang, idx) => (
                                        <Badge
                                            key={idx}
                                            variant="outline"
                                            className="text-base px-4 py-2"
                                        >
                                            {lang}
                                        </Badge>
                                    ))}
                                </div>
                            </TabsContent>
                        </Tabs>
                    </>
                ) : (
                    <div className="text-center text-muted-foreground">
                        Contributor not found
                    </div>
                )}
            </DialogContent>
        </Dialog>
    )
}

// Main Contributors View Component
export function ContributorsView({ projectId }: { projectId: string }) {
    const [data, setData] = useState<ContributorsResponse | null>(null)
    const [loading, setLoading] = useState(true)
    const [sorting, setSorting] = useState<SortingState>([])
    const [globalFilter, setGlobalFilter] = useState("")
    const [selectedContributor, setSelectedContributor] = useState<string | null>(null)
    const [modalOpen, setModalOpen] = useState(false)

    useEffect(() => {
        fetch(`${API_BASE}/projects/${projectId}/contributors`)
            .then(res => res.json())
            .then(data => setData(data))
            .catch(console.error)
            .finally(() => setLoading(false))
    }, [projectId])

    const handleContributorClick = (contributorId: string) => {
        setSelectedContributor(contributorId)
        setModalOpen(true)
    }

    const columns: ColumnDef<ContributorSummary>[] = [
        {
            accessorKey: "name",
            header: "Contributor",
            cell: ({ row }) => {
                const name = row.getValue("name") as string
                const email = row.original.email
                const github = row.original.github_username
                const initials = name.split(" ").map(n => n[0]).join("").toUpperCase().slice(0, 2)

                return (
                    <button
                        onClick={() => handleContributorClick(row.original.id)}
                        className="flex items-center gap-3 hover:bg-muted p-2 rounded-lg transition-colors w-full text-left"
                    >
                        <Avatar className="h-10 w-10">
                            {github && <AvatarImage src={`https://github.com/${github}.png`} alt={name} />}
                            <AvatarFallback>{initials}</AvatarFallback>
                        </Avatar>
                        <div>
                            <div className="font-medium text-primary hover:underline">{name}</div>
                            {email && <div className="text-xs text-muted-foreground">{email}</div>}
                        </div>
                    </button>
                )
            },
        },
        {
            accessorKey: "commits",
            header: "Commits",
            cell: ({ row }) => (
                <div className="text-center">
                    <div className="font-semibold">{row.getValue("commits")}</div>
                    <div className="text-xs text-muted-foreground">
                        {row.original.commit_percentage?.toFixed(1)}%
                    </div>
                </div>
            ),
        },
        {
            accessorKey: "files_count",
            header: "Files",
            cell: ({ row }) => (
                <Badge variant="secondary">{row.getValue("files_count")} files</Badge>
            ),
        },
        {
            accessorKey: "highest_severity",
            header: "Severity",
            cell: ({ row }) => <SeverityBadge severity={row.getValue("highest_severity")} />,
        },
        {
            accessorKey: "risk_score",
            header: "Risk",
            cell: ({ row }) => {
                const score = row.getValue("risk_score") as number
                return (
                    <div className="flex items-center gap-2">
                        <Progress value={score} className="w-16 h-2" />
                        <span className={`text-sm font-medium ${score >= 50 ? 'text-red-500' : ''}`}>
                            {score}
                        </span>
                    </div>
                )
            },
        },
        {
            accessorKey: "languages",
            header: "Languages",
            cell: ({ row }) => {
                const languages = row.getValue("languages") as string[]
                return (
                    <div className="flex flex-wrap gap-1">
                        {languages.slice(0, 3).map(lang => (
                            <Badge key={lang} variant="outline" className="text-xs">{lang}</Badge>
                        ))}
                        {languages.length > 3 && (
                            <Badge variant="secondary" className="text-xs">+{languages.length - 3}</Badge>
                        )}
                    </div>
                )
            },
        },
    ]

    const table = useReactTable({
        data: data?.contributors || [],
        columns,
        getCoreRowModel: getCoreRowModel(),
        getSortedRowModel: getSortedRowModel(),
        getFilteredRowModel: getFilteredRowModel(),
        onSortingChange: setSorting,
        onGlobalFilterChange: setGlobalFilter,
        state: { sorting, globalFilter },
    })

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
        )
    }

    if (!data || data.contributors.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                <Users className="h-12 w-12 mb-4" />
                <p>No contributor data available</p>
                <p className="text-sm">Run a scan to collect contributor information</p>
            </div>
        )
    }

    return (
        <div className="space-y-6">
            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Card>
                    <CardHeader className="pb-2">
                        <CardTitle className="text-sm font-medium flex items-center gap-2">
                            <Users className="h-4 w-4" /> Total Contributors
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{data.total_contributors}</div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader className="pb-2">
                        <CardTitle className="text-sm font-medium flex items-center gap-2">
                            <GitCommit className="h-4 w-4" /> Total Commits
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">{data.total_commits.toLocaleString()}</div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader className="pb-2">
                        <CardTitle className="text-sm font-medium flex items-center gap-2">
                            <AlertTriangle className="h-4 w-4" /> Bus Factor
                        </CardTitle>
                        <CardDescription className="text-xs">
                            Contributors needed for 50% of commits
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">
                            {data.bus_factor}
                            {data.bus_factor <= 2 && (
                                <Badge variant="destructive" className="ml-2 text-xs">Risk</Badge>
                            )}
                        </div>
                    </CardContent>
                </Card>
            </div>

            {/* Search */}
            <div className="flex items-center gap-4">
                <Input
                    placeholder="Search contributors..."
                    value={globalFilter}
                    onChange={(e) => setGlobalFilter(e.target.value)}
                    className="max-w-sm"
                />
                <p className="text-sm text-muted-foreground">
                    Click on a contributor name to view full details
                </p>
            </div>

            {/* Contributors Table */}
            <div className="rounded-md border">
                <Table>
                    <TableHeader>
                        {table.getHeaderGroups().map(headerGroup => (
                            <TableRow key={headerGroup.id}>
                                {headerGroup.headers.map(header => (
                                    <TableHead key={header.id}>
                                        {header.isPlaceholder ? null : flexRender(
                                            header.column.columnDef.header,
                                            header.getContext()
                                        )}
                                    </TableHead>
                                ))}
                            </TableRow>
                        ))}
                    </TableHeader>
                    <TableBody>
                        {table.getRowModel().rows?.length ? (
                            table.getRowModel().rows.map(row => (
                                <TableRow key={row.id}>
                                    {row.getVisibleCells().map(cell => (
                                        <TableCell key={cell.id}>
                                            {flexRender(cell.column.columnDef.cell, cell.getContext())}
                                        </TableCell>
                                    ))}
                                </TableRow>
                            ))
                        ) : (
                            <TableRow>
                                <TableCell colSpan={columns.length} className="h-24 text-center">
                                    No contributors found.
                                </TableCell>
                            </TableRow>
                        )}
                    </TableBody>
                </Table>
            </div>

            {/* Contributor Detail Modal */}
            <ContributorModal
                contributorId={selectedContributor}
                projectId={projectId}
                isOpen={modalOpen}
                onClose={() => setModalOpen(false)}
            />
        </div>
    )
}
```

---

## Verification Checklist

After implementation, verify:

- [ ] Migration adds new columns (`ai_summary`, enhanced `files_contributed` with severity)
- [ ] `repo_intel.py` collects files with severity data from findings
- [ ] AI Agent generates contributor analysis summaries
- [ ] API returns file severity data and AI summaries
- [ ] **Clicking contributor name** opens the beautiful modal
- [ ] Modal displays tabs for Files (with severity badges), Folders, Languages
- [ ] AI Summary card appears in modal with gradient styling
- [ ] Severity badges show correct colors (critical=red, high=orange, medium=yellow, low=blue)
- [ ] Risk score progress bar visualizes contributor risk
- [ ] Search filters contributors in table

---

## Performance Considerations

1. **File Severity Mapping**: Cross-reference files at scan time, not runtime
2. **AI Summary Caching**: Store AI summaries in database, regenerate only on new scans
3. **Lazy Modal Loading**: Fetch contributor detail only when modal opens
4. **File List Pagination**: Limit to 200 files per contributor, paginate in modal if needed

---

## AI Agent Prompts

### Contributor Analysis Prompt
```
Analyze this contributor's security impact:
- Name, commits, percentage of codebase
- Critical/High severity files they own
- Languages and folders they work in

Provide: Risk assessment, code ownership concerns, remediation priority
```

### Team Summary Prompt
```
Analyze the contributor team:
- Bus factor risk
- Security debt concentration by contributor
- Recommended actions for risk mitigation
```

---

## Deployment & Troubleshooting

### Pre-Deployment Setup

Run these commands in order before using the Contributors feature:

```bash
# 1. Run the database migration to add new columns
cat migrations/add_contributor_enhancements.sql | docker-compose exec -T db psql -U auditgh -d auditgh_kb

# 2. Restart the API to pick up model changes
docker-compose restart api

# 3. Restart the web UI to pick up component changes
docker-compose restart web-ui
```

### Verification Commands

Use these commands to verify the setup is correct:

```bash
# Check if migration was applied (columns should exist)
docker-compose exec db psql -U auditgh -d auditgh_kb -c "\d contributors"

# Check if contributors table has data
docker-compose exec db psql -U auditgh -d auditgh_kb -c "SELECT COUNT(*) as total FROM contributors;"

# Check sample contributor data
docker-compose exec db psql -U auditgh -d auditgh_kb -c "SELECT name, commits, risk_score FROM contributors LIMIT 5;"

# Test the API endpoint (replace PROJECT_ID with actual UUID)
curl http://localhost:8000/projects/PROJECT_ID/contributors

# Check API logs for errors
docker-compose logs api --tail 50
```

### Common Issues & Solutions

| Issue | Symptom | Solution |
|-------|---------|----------|
| **"No contributor data available"** | UI shows empty state | Run a scan: `docker-compose run --rm auditgh --repo="REPO_NAME" --overridescan` |
| **API returns 500 error** | Console shows HTTP error | Check API logs: `docker-compose logs api --tail 50` |
| **Missing columns error** | API throws column error | Run migration: `cat migrations/add_contributor_enhancements.sql \| docker-compose exec -T db psql -U auditgh -d auditgh_kb` |
| **Old API response format** | `data.contributors` undefined | Restart API: `docker-compose restart api` |
| **UI not updating** | Old component showing | Restart web-ui: `docker-compose restart web-ui` |
| **Empty files_contributed** | Files array is empty | Re-run scan to collect file data with severity mapping |

### Populating Contributor Data

If the contributors table is empty, you need to scan a repository:

```bash
# Scan a specific repository
docker-compose run --rm auditgh --repo="YOUR_REPO_NAME" --overridescan

# Or scan all repositories in the organization
docker-compose run --rm auditgh --org YOUR_ORG --overridescan
```

The scan will:
1. Clone the repository
2. Analyze git history for contributors
3. Cross-reference files with security findings for severity data
4. Store results in the database
5. The Contributors tab will then show data

### Database Schema Verification

Ensure the contributors table has all required columns:

```sql
-- Run this query to check table structure
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'contributors'
ORDER BY ordinal_position;
```

Expected columns:
- `id` (uuid)
- `repository_id` (uuid)
- `name` (character varying)
- `email` (character varying)
- `github_username` (character varying)
- `commits` (integer)
- `commit_percentage` (numeric)
- `last_commit_at` (timestamp)
- `languages` (jsonb)
- `files_contributed` (jsonb)
- `folders_contributed` (jsonb)
- `risk_score` (integer)
- `ai_summary` (text)
- `created_at` (timestamp)
- `updated_at` (timestamp)

### API Response Format

The `/projects/{id}/contributors` endpoint returns:

```json
{
  "total_contributors": 10,
  "total_commits": 500,
  "bus_factor": 2,
  "team_ai_summary": null,
  "contributors": [
    {
      "id": "uuid",
      "name": "John Doe",
      "email": "john@example.com",
      "github_username": "johndoe",
      "commits": 150,
      "commit_percentage": 30.0,
      "last_commit_at": "2024-01-15T10:30:00",
      "languages": ["Python", "JavaScript"],
      "files_count": 45,
      "folders_count": 8,
      "risk_score": 25,
      "highest_severity": "high"
    }
  ]
}
```

If the API returns an array instead of this object format, the API service needs to be restarted to pick up the new endpoint code.

---

## Known Issues & Fixes

### Issue 1: Missing Contributors (Shallow Clone Problem)

**Symptom:** Only one contributor is shown even though the repository has multiple contributors.

**Root Cause:** Repositories are cloned with `--depth 1` (shallow clone), which only retrieves the most recent commit. The `git fetch --unshallow` command was failing silently (logged at DEBUG level) with no fallback mechanism.

**Location:** `scan_repos.py` lines 480 (shallow clone) and 1823-1869 (unshallow logic)

**Fix Applied:**

```python
# Run Repo Intelligence (OSINT)
if PROGRESS_MONITOR_AVAILABLE:
    # Unshallow the repository to get full git history for contributor analysis
    unshallow_success = False
    try:
        logging.info(f"Unshallowing repository {repo_name} for contributor analysis...")
        unshallow_result = subprocess.run(
            ["git", "fetch", "--unshallow"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        if unshallow_result.returncode == 0:
            logging.info(f"Successfully unshallowed {repo_name}")
            unshallow_success = True
        else:
            # Check if it's already complete (not a shallow repo) - that's OK
            if "not a shallow repository" in unshallow_result.stderr.lower():
                logging.info(f"Repository {repo_name} is already complete (not shallow)")
                unshallow_success = True
            else:
                logging.warning(f"Unshallow failed for {repo_name}: {unshallow_result.stderr.strip()}")
    except subprocess.TimeoutExpired:
        logging.warning(f"Unshallow timeout for {repo_name}")
    except Exception as e:
        logging.warning(f"Could not unshallow {repo_name}: {e}")

    # Fallback: fetch more history if unshallow failed
    if not unshallow_success:
        try:
            logging.info(f"Fetching deeper history for {repo_name} (depth=500)...")
            fetch_result = subprocess.run(
                ["git", "fetch", "--depth=500"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=120
            )
            if fetch_result.returncode == 0:
                logging.info(f"Fetched deeper history for {repo_name}")
            else:
                logging.warning(f"Could not fetch deeper history for {repo_name}: {fetch_result.stderr.strip()}")
        except Exception as e:
            logging.warning(f"Fallback fetch failed for {repo_name}: {e}, contributor data may be incomplete")

    repo_intel_result = analyze_repo(repo_path, repo_name, repo_report_dir)
```

**Key Improvements:**
1. Changed unshallow failure logging from DEBUG to WARNING level
2. Added detection for "not a shallow repository" case (which is OK)
3. Added fallback: `git fetch --depth=500` if unshallow fails
4. Better error messages to identify why contributor data is incomplete

**Verification:**

After re-scanning, logs should show:
```
INFO: Unshallowing repository REPO_NAME for contributor analysis...
INFO: Successfully unshallowed REPO_NAME
```

Or if fallback is used:
```
WARNING: Unshallow failed for REPO_NAME: <reason>
INFO: Fetching deeper history for REPO_NAME (depth=500)...
INFO: Fetched deeper history for REPO_NAME
```

---

### Issue 2: DialogTitle Accessibility Warning

**Symptom:** Browser console shows:
```
`DialogContent` requires a `DialogTitle` for the component to be accessible for screen reader users.
```

**Root Cause:** The `DialogContent` component was missing `DialogTitle` in loading and error states.

**Location:** `src/web-ui/components/ContributorsView.tsx` - ContributorModal component

**Fix Applied:**

```typescript
// In the loading state, add DialogTitle for accessibility
{loading ? (
    <div className="flex items-center justify-center h-64">
        <DialogHeader>
            <DialogTitle className="sr-only">Loading contributor details</DialogTitle>
        </DialogHeader>
        <Loader2 className="h-8 w-8 animate-spin" />
    </div>
) : detail ? (
    // ... existing detail content with visible DialogTitle ...
) : (
    <div className="text-center text-muted-foreground">
        <DialogHeader>
            <DialogTitle className="sr-only">Contributor not found</DialogTitle>
        </DialogHeader>
        Contributor not found
    </div>
)}
```

**Key Points:**
- `sr-only` class makes the title visually hidden but accessible to screen readers
- Each conditional branch now has a `DialogTitle`
- The visible DialogTitle in the detail view remains unchanged

---

### Issue 3: Null Check for Contributors Data

**Symptom:** `TypeError: undefined is not an object (evaluating 'data.contributors.length')`

**Root Cause:** Missing null check before accessing `data.contributors.length`.

**Location:** `src/web-ui/components/ContributorsView.tsx` - ContributorsView component

**Fix Applied:**

```typescript
// Before (buggy)
if (!data || data.contributors.length === 0) {

// After (fixed)
if (!data || !data.contributors || data.contributors.length === 0) {
```

---

## Re-scanning for Complete Contributor Data

If repositories were scanned before these fixes were applied, contributor data may be incomplete. Re-scan affected repositories:

```bash
# Re-scan a specific repository
python scan_repos.py --repo="REPO_NAME" --org YOUR_ORG

# For repos with names starting with hyphen, use = syntax
python scan_repos.py --repo="-REPO-NAME" --org YOUR_ORG
```

The scan will now:
1. Clone repository with `--depth 1` (fast initial clone)
2. Unshallow to get full history OR fallback to `--depth 500`
3. Analyze complete git log for all contributors
4. Store all contributor data in database
