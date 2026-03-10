"""
Tool category definitions for API key scoping.

Categories group related security tools. API keys can be scoped to
specific categories and/or individual tools.
"""

TOOL_CATEGORIES = {
    "sast": {
        "display_name": "Static Analysis (SAST)",
        "tools": ["semgrep", "bandit"]
    },
    "secrets": {
        "display_name": "Secrets Detection",
        "tools": ["gitleaks", "trufflehog", "whispers"]
    },
    "dependencies": {
        "display_name": "Dependency Scanning",
        "tools": ["grype", "trivy", "osv"]
    },
    "iac": {
        "display_name": "Infrastructure as Code",
        "tools": ["checkov", "trivy_iac", "terrascan"]
    },
    "containers": {
        "display_name": "Container Security",
        "tools": ["dockle", "trivy_container"]
    },
    "go_security": {
        "display_name": "Go Security",
        "tools": ["gosec", "govulncheck"]
    },
    "api_discovery": {
        "display_name": "API Discovery",
        "tools": ["api_scanner", "ai_api_discovery"]
    }
}

# Flat lookup: tool_name -> category
TOOL_TO_CATEGORY = {}
for cat, config in TOOL_CATEGORIES.items():
    for tool in config["tools"]:
        TOOL_TO_CATEGORY[tool] = cat

ALL_TOOL_NAMES = list(TOOL_TO_CATEGORY.keys())
ALL_CATEGORY_NAMES = list(TOOL_CATEGORIES.keys())
