#!/usr/bin/env python3
"""
Script to add RBAC dependencies to all API routers.
This systematically updates all router files with appropriate permission checks.
"""

import re
from pathlib import Path

# Router directory
ROUTER_DIR = Path("/Users/rob.vance@sleepnumber.com/Documents/GitHub/auditgithub/src/api/routers")

# Permission mappings based on the plan
PERMISSION_MAPPINGS = {
    # Findings endpoints
    "findings.py": {
        "GET": "findings:read",
        "POST": "findings:write",
        "PATCH": "findings:write",
        "PUT": "findings:write",
        "DELETE": "findings:delete",
    },
    # Scans endpoints
    "scans.py": {
        "GET": "scans:read",
        "POST": "scans:execute",
        "PATCH": "scans:write",
        "PUT": "scans:write",
        "DELETE": "scans:delete",
    },
    # Repositories endpoints
    "repositories.py": {
        "GET": "repositories:read",
        "POST": "repositories:write",
        "PATCH": "repositories:write",
        "PUT": "repositories:write",
        "DELETE": "repositories:delete",
    },
    # Organizations endpoints
    "organizations.py": {
        "GET": "organizations:read",
        "POST": "organizations:admin",  # Create is admin
        "PATCH": "organizations:write",
        "PUT": "organizations:write",
        "DELETE": "organizations:admin",  # Delete is admin
    },
    # Projects endpoints
    "projects.py": {
        "GET": "projects:read",
        "POST": "projects:write",
        "PATCH": "projects:write",
        "PUT": "projects:write",
        "DELETE": "projects:delete",
    },
    # Analytics endpoints
    "analytics.py": {
        "GET": "reports:read",
        "POST": "reports:read",
    },
    # API Audit endpoints
    "api_audit.py": {
        "GET": "admin:manage",  # Admin only
        "POST": "admin:manage",
    },
    # Attack paths endpoints
    "attack_paths.py": {
        "GET": "findings:read",
        "POST": "findings:write",
    },
    # Attack surface endpoints
    "attack_surface.py": {
        "GET": "findings:read",
        "POST": "findings:write",
    },
    # AI endpoints
    "ai.py": {
        "GET": "findings:read",
        "POST": "findings:write",
    },
    # Contributor profiles endpoints
    "contributor_profiles.py": {
        "GET": "projects:read",
        "POST": "projects:write",
    },
    # Cribl endpoints (admin integration)
    "cribl.py": {
        "GET": "admin:manage",
        "POST": "admin:manage",
    },
    # Feedback endpoints
    "feedback.py": {
        "GET": "projects:read",
        "POST": "projects:write",
    },
    # GitHub sync endpoints
    "github_sync.py": {
        "GET": "repositories:read",
        "POST": "repositories:write",
    },
    # JIRA endpoints
    "jira.py": {
        "GET": "findings:read",
        "POST": "findings:write",
    },
    # Scheduler endpoints (admin)
    "scheduler.py": {
        "GET": "admin:manage",
        "POST": "admin:manage",
        "DELETE": "admin:manage",
    },
    # Secrets endpoints
    "secrets.py": {
        "GET": "findings:read",
        "POST": "findings:write",
        "DELETE": "findings:delete",
    },
    # Settings endpoints (admin)
    "settings.py": {
        "GET": "admin:manage",
        "POST": "admin:manage",
        "PATCH": "admin:manage",
        "PUT": "admin:manage",
    },
    # SLA endpoints
    "sla.py": {
        "GET": "reports:read",
        "POST": "admin:manage",
        "PATCH": "admin:manage",
        "PUT": "admin:manage",
    },
    # Tenants endpoints (admin)
    "tenants.py": {
        "GET": "admin:manage",
        "POST": "admin:manage",
        "PATCH": "admin:manage",
        "PUT": "admin:manage",
        "DELETE": "admin:manage",
    },
    # Auth endpoints - NO RBAC (auth happens before RBAC)
    "auth.py": {
        "SKIP": True
    },
}


def add_import_if_missing(content: str) -> str:
    """Add RBAC import if not present."""
    if "from src.rbac.dependencies import require_permissions" in content:
        return content

    # Find the last import line
    import_pattern = r"(from .+ import .+\n)"
    imports = list(re.finditer(import_pattern, content))

    if imports:
        last_import = imports[-1]
        insert_pos = last_import.end()
        return (
            content[:insert_pos] +
            "from src.rbac.dependencies import require_permissions\n" +
            content[insert_pos:]
        )

    return content


def extract_http_method(decorator_line: str) -> str:
    """Extract HTTP method from decorator."""
    if "@router.get(" in decorator_line:
        return "GET"
    elif "@router.post(" in decorator_line:
        return "POST"
    elif "@router.patch(" in decorator_line:
        return "PATCH"
    elif "@router.put(" in decorator_line:
        return "PUT"
    elif "@router.delete(" in decorator_line:
        return "DELETE"
    return None


def add_dependency_to_decorator(decorator: str, permission: str) -> str:
    """Add dependencies parameter to a router decorator."""
    # Check if dependencies already exists
    if "dependencies=" in decorator:
        return decorator  # Already has dependencies, skip

    # Find where to insert dependencies parameter
    # Pattern: @router.method("path", <other params>)
    # Insert dependencies after path, before other params or closing paren

    # Find the closing parenthesis
    close_paren_idx = decorator.rfind(")")
    if close_paren_idx == -1:
        return decorator

    # Check if there are existing parameters after the path
    # Pattern: @router.get("/path"<HERE>, response_model=...)
    path_end = decorator.find('",', decorator.find("("))

    if path_end != -1:
        # Has other parameters, insert before them
        insert_pos = path_end + 2  # After ","
        return (
            decorator[:insert_pos] +
            f'\n    dependencies=[Depends(require_permissions("{permission}"))], ' +
            decorator[insert_pos:]
        )
    else:
        # No other parameters, insert before closing paren
        # Check if path ends with just quote
        quote_idx = decorator.rfind('"', 0, close_paren_idx)
        if quote_idx != -1:
            insert_pos = quote_idx + 1
            return (
                decorator[:insert_pos] +
                f',\n    dependencies=[Depends(require_permissions("{permission}"))]' +
                decorator[insert_pos:]
            )

    return decorator


def process_router_file(file_path: Path, permissions: dict):
    """Process a single router file to add RBAC dependencies."""
    print(f"Processing {file_path.name}...")

    # Skip auth router
    if permissions.get("SKIP"):
        print(f"  Skipping {file_path.name} (no RBAC required)")
        return

    content = file_path.read_text()

    # Add import
    content = add_import_if_missing(content)

    # Find all route decorators
    lines = content.split("\n")
    modified = False

    for i, line in enumerate(lines):
        if line.strip().startswith("@router."):
            method = extract_http_method(line)
            if method and method in permissions:
                permission = permissions[method]

                # Check if next lines are continuation of decorator (multi-line)
                full_decorator = line
                j = i + 1
                while j < len(lines) and not lines[j].strip().startswith("def ") and not lines[j].strip().startswith("async def"):
                    if lines[j].strip() and not lines[j].strip().startswith("@"):
                        full_decorator += "\n" + lines[j]
                        j += 1
                    else:
                        break

                # Check if dependencies already present
                if "dependencies=" not in full_decorator:
                    # Add dependency parameter
                    modified_decorator = add_dependency_to_decorator(full_decorator, permission)

                    # Replace in lines
                    if modified_decorator != full_decorator:
                        lines[i] = modified_decorator
                        modified = True
                        print(f"  Added {permission} to {method} endpoint")

    if modified:
        file_path.write_text("\n".join(lines))
        print(f"  ✓ Updated {file_path.name}")
    else:
        print(f"  - No changes needed for {file_path.name}")


def main():
    """Main execution function."""
    print("Starting RBAC dependency updates...\n")

    for router_file, permissions in PERMISSION_MAPPINGS.items():
        file_path = ROUTER_DIR / router_file
        if file_path.exists():
            try:
                process_router_file(file_path, permissions)
            except Exception as e:
                print(f"  ✗ Error processing {router_file}: {e}")
        else:
            print(f"  ! File not found: {router_file}")

    print("\n✓ RBAC dependency updates complete!")


if __name__ == "__main__":
    main()
