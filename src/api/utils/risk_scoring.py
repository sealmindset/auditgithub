"""
Risk Scoring Utility

Calculates a composite risk score (0-100) for findings based on multiple factors.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, Optional


# Severity base weights
SEVERITY_WEIGHTS = {
    'critical': 40,
    'high': 30,
    'medium': 15,
    'low': 5,
    'info': 2,
    'warning': 3
}


def calculate_risk_score(
    finding: Any,
    repository: Optional[Any] = None
) -> tuple[int, Dict[str, Any]]:
    """
    Calculate a composite risk score for a finding.
    
    Returns:
        tuple: (score: int 0-100, factors: dict with breakdown)
    """
    factors = {}
    score = 0
    
    # 1. Severity Base Score (0-40 points)
    severity = (finding.severity or 'medium').lower()
    severity_score = SEVERITY_WEIGHTS.get(severity, 10)
    factors['severity'] = {
        'value': severity,
        'points': severity_score,
        'max': 40
    }
    score += severity_score
    
    # 2. Exposure Score (0-20 points)
    exposure_score = 0
    exposure_reasons = []
    
    if repository:
        # Public repo = higher risk
        if repository.visibility == 'public' or not repository.is_private:
            exposure_score += 15
            exposure_reasons.append('public_repo')
        
        # High star count = more visible
        if (repository.stargazers_count or 0) > 100:
            exposure_score += 5
            exposure_reasons.append('popular_repo')
    
    # Active secret = critical exposure
    if getattr(finding, 'is_validated_active', None) is True:
        exposure_score = min(exposure_score + 20, 25)
        exposure_reasons.append('active_secret')
    elif getattr(finding, 'is_verified_by_scanner', None) is True:
        exposure_score = min(exposure_score + 10, 25)
        exposure_reasons.append('verified_secret')
    
    factors['exposure'] = {
        'reasons': exposure_reasons,
        'points': min(exposure_score, 25),
        'max': 25
    }
    score += min(exposure_score, 25)
    
    # 3. Age Score (0-20 points) - older = higher risk
    age_score = 0
    first_seen = getattr(finding, 'first_seen_at', None) or getattr(finding, 'created_at', None)
    
    if first_seen:
        if isinstance(first_seen, str):
            first_seen = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
        
        # Calculate days old
        now = datetime.utcnow()
        if first_seen.tzinfo:
            from datetime import timezone
            now = datetime.now(timezone.utc)
        
        try:
            age_days = (now - first_seen).days
        except TypeError:
            # Handle naive/aware datetime mismatch
            age_days = (datetime.utcnow() - first_seen.replace(tzinfo=None)).days
        
        if age_days > 180:
            age_score = 20
        elif age_days > 90:
            age_score = 15
        elif age_days > 30:
            age_score = 10
        elif age_days > 7:
            age_score = 5
        
        factors['age'] = {
            'days': age_days,
            'points': age_score,
            'max': 20
        }
    else:
        factors['age'] = {'days': 0, 'points': 0, 'max': 20}
    
    score += age_score
    
    # 4. Context Score (0-15 points)
    context_score = 0
    context_reasons = []
    
    # Check if repo is archived (lower priority)
    if repository and getattr(repository, 'is_archived', False):
        context_score -= 10
        context_reasons.append('archived_repo')
    
    # Check file path for sensitive locations
    file_path = getattr(finding, 'file_path', '') or ''
    sensitive_paths = ['config', 'secret', 'credential', 'password', 'key', 'token', '.env', 'prod']
    for sp in sensitive_paths:
        if sp in file_path.lower():
            context_score += 10
            context_reasons.append(f'sensitive_path:{sp}')
            break
    
    # Check for infrastructure code
    infra_indicators = ['terraform', 'cloudformation', 'kubernetes', 'k8s', 'docker', 'ansible']
    for ind in infra_indicators:
        if ind in file_path.lower():
            context_score += 5
            context_reasons.append('infrastructure_code')
            break
    
    factors['context'] = {
        'reasons': context_reasons,
        'points': max(0, min(context_score, 15)),
        'max': 15
    }
    score += max(0, min(context_score, 15))
    
    # Ensure score is within 0-100
    final_score = max(0, min(score, 100))
    
    factors['total'] = {
        'raw_score': score,
        'final_score': final_score,
        'max': 100
    }
    
    return final_score, factors


def get_risk_level(score: int) -> str:
    """Convert numeric score to risk level label."""
    if score >= 75:
        return 'critical'
    elif score >= 50:
        return 'high'
    elif score >= 25:
        return 'medium'
    else:
        return 'low'


def batch_calculate_risk_scores(findings: list, repositories_map: dict = None) -> list:
    """
    Calculate risk scores for a batch of findings.
    
    Args:
        findings: List of Finding objects
        repositories_map: Optional dict mapping repository_id -> Repository
        
    Returns:
        List of (finding, score, factors) tuples
    """
    results = []
    repositories_map = repositories_map or {}
    
    for finding in findings:
        repo = None
        if hasattr(finding, 'repository'):
            repo = finding.repository
        elif hasattr(finding, 'repository_id') and finding.repository_id:
            repo = repositories_map.get(str(finding.repository_id))
        
        score, factors = calculate_risk_score(finding, repo)
        results.append((finding, score, factors))
    
    return results
