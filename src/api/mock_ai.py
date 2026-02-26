"""
Mock AI provider for the sandbox environment.

Returns canned responses for all AI endpoints so that the sandbox operates
without any external AI API keys.  Responses are realistic enough to
demonstrate the UI and API contract.
"""

MOCK_ARCHITECTURE = {
    "summary": "The repository follows a layered microservice architecture with a FastAPI backend, React frontend, and PostgreSQL datastore.",
    "components": [
        {"name": "API Gateway", "type": "service", "language": "Python", "risk": "medium"},
        {"name": "Auth Service", "type": "service", "language": "Go", "risk": "high"},
        {"name": "Database", "type": "datastore", "language": "SQL", "risk": "low"},
        {"name": "Message Queue", "type": "infrastructure", "language": "N/A", "risk": "low"},
        {"name": "Frontend SPA", "type": "client", "language": "TypeScript", "risk": "medium"},
    ],
    "data_flows": [
        {"from": "Frontend SPA", "to": "API Gateway", "protocol": "HTTPS", "data": "User requests"},
        {"from": "API Gateway", "to": "Auth Service", "protocol": "gRPC", "data": "Token validation"},
        {"from": "API Gateway", "to": "Database", "protocol": "TCP/TLS", "data": "CRUD operations"},
        {"from": "API Gateway", "to": "Message Queue", "protocol": "AMQP", "data": "Async events"},
    ],
    "recommendations": [
        "Enable mutual TLS between internal services",
        "Add rate limiting to the API Gateway",
        "Implement database connection pooling",
    ],
}

MOCK_REMEDIATION = {
    "finding": "Hardcoded AWS access key in config.py",
    "severity": "critical",
    "remediation_steps": [
        "Immediately rotate the exposed AWS access key in the IAM console.",
        "Remove the hardcoded key from config.py and all git history (use git-filter-repo).",
        "Store credentials in AWS Secrets Manager or environment variables.",
        "Add config.py patterns to .gitignore and configure pre-commit hooks with gitleaks.",
        "Enable AWS CloudTrail to audit any unauthorized usage of the leaked key.",
    ],
    "code_fix": (
        "# Before (INSECURE)\n"
        "AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n\n"
        "# After (SECURE)\n"
        "import os\n"
        "AWS_ACCESS_KEY = os.environ['AWS_ACCESS_KEY_ID']"
    ),
    "references": [
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    ],
    "estimated_effort": "2-4 hours",
}

MOCK_EXECUTIVE_SUMMARY = {
    "overall_risk": "medium-high",
    "risk_score": 72,
    "total_findings": 540,
    "critical": 54,
    "high": 108,
    "medium": 162,
    "low": 108,
    "info": 108,
    "top_risks": [
        "Hardcoded credentials detected in 18 repositories across all organizations.",
        "32 container images running as root without security contexts.",
        "SQL injection vulnerabilities in 12 API endpoints.",
    ],
    "trend": "improving",
    "trend_detail": "Critical findings decreased 15% month-over-month after remediation push.",
    "recommendations": [
        "Prioritize credential rotation for the 54 critical secret findings.",
        "Enforce non-root container policies in CI/CD pipelines.",
        "Schedule targeted semgrep scans for injection patterns.",
    ],
}

MOCK_TRIAGE = {
    "finding": "SQL injection in user search endpoint",
    "verdict": "true_positive",
    "confidence": 0.95,
    "reasoning": (
        "The user-supplied search parameter is concatenated directly into "
        "a raw SQL query without parameterization. An attacker could inject "
        "arbitrary SQL to extract or modify data."
    ),
    "priority": "P1",
    "suggested_assignee": "backend-security-team",
}

MOCK_ZERO_DAY = {
    "cve_id": "CVE-2024-SANDBOX",
    "affected_repos": 12,
    "affected_components": ["lodash@4.17.20", "express@4.17.1"],
    "exploitability": "high",
    "assessment": (
        "This vulnerability allows remote code execution via prototype "
        "pollution in lodash versions prior to 4.17.21. Twelve repositories "
        "in the organization use affected versions."
    ),
    "immediate_actions": [
        "Upgrade lodash to >= 4.17.21 across all affected repositories.",
        "Deploy WAF rules to block known exploitation payloads.",
        "Run targeted scans to identify any indicators of compromise.",
    ],
}

MOCK_CHAT_RESPONSE = (
    "Based on the security analysis of your repositories, here are the key insights:\n\n"
    "1. **Critical findings** are concentrated in the `backend-api` and `payment-gateway` services.\n"
    "2. The most common vulnerability type is **hardcoded credentials** (gitleaks).\n"
    "3. Your container security posture could be improved by enforcing non-root policies.\n\n"
    "Would you like me to drill down into any specific area?"
)


# ============================================================================
# Public API
# ============================================================================

def get_mock_response(endpoint_type: str, **kwargs) -> dict | str:
    """
    Return a canned AI response for the given endpoint type.

    Parameters
    ----------
    endpoint_type : str
        One of: architecture, remediation, executive_summary, triage,
        zero_day, chat, or a fallback generic.
    **kwargs : dict
        Ignored — present for API compatibility with real AI providers.
    """
    responses = {
        "architecture": MOCK_ARCHITECTURE,
        "remediation": MOCK_REMEDIATION,
        "executive_summary": MOCK_EXECUTIVE_SUMMARY,
        "triage": MOCK_TRIAGE,
        "zero_day": MOCK_ZERO_DAY,
        "chat": MOCK_CHAT_RESPONSE,
    }
    return responses.get(endpoint_type, {
        "message": f"[Sandbox mock] No specific mock for '{endpoint_type}'.",
        "note": "This is a sandbox environment — AI responses are pre-generated.",
    })
