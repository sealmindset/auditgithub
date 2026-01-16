# RBAC (Role-Based Access Control) Module

Comprehensive role-based access control system with audit logging for the AuditGH platform.

## Overview

This module implements a 5-tier role hierarchy with tenant-scoped user assignments and comprehensive audit logging for security monitoring and compliance (SOC2/GDPR).

## Role Hierarchy

Roles are numbered 1-5, where lower numbers have higher privileges:

1. **Super Admin** - Platform-wide administration
2. **Admin** - Tenant administration and user management
3. **Analyst** - Security analysis and findings management
4. **Manager** - View and reporting capabilities
5. **User** - Basic read-only access

## Components

### Models (`models.py`)
- `Role` - Role definitions with hierarchical levels
- `Permission` - Fine-grained permission strings (e.g., "findings:read")
- `RolePermission` - Many-to-many mapping between roles and permissions
- `UserRole` - Tenant-scoped user role assignments

### Dependencies (`dependencies.py`)
FastAPI dependency functions for protecting API routes:

#### `require_permissions(*permissions)`
Checks if user has required permissions before route execution.

```python
@router.get("/findings", dependencies=[Depends(require_permissions("findings:read"))])
async def list_findings(user: User = Depends(get_current_user)):
    return {"findings": [...]}
```

#### `require_role(min_role_level)`
Checks if user has required role level (or higher privilege).

```python
@router.post("/admin/users", dependencies=[Depends(require_role(2))])  # Admin and above
async def create_user(user: User = Depends(get_current_user)):
    return {"user_id": "..."}
```

#### `require_tenant_access(resource_id, resource_type, user, tenant_id, session)`
Helper function for verifying resource belongs to user's tenant.

```python
@router.get("/findings/{finding_id}")
async def get_finding(
    finding_id: str,
    user: User = Depends(get_current_user),
    request: Request = None,
    session: Session = Depends(get_db)
):
    tenant_id = get_tenant_id_from_request(request)
    await require_tenant_access(finding_id, "finding", user, tenant_id, session)
    return await get_finding_from_db(finding_id)
```

### Audit Logging (`audit.py`)

Comprehensive audit logging for all authorization decisions and data access.

#### Event Types

1. **authorization.granted** - Authorization check succeeded
2. **authorization.denied** - Authorization check failed (potential attack)
3. **data.access** - Read access to sensitive resources
4. **data.modification** - Create/update/delete operations
5. **admin.action** - Privileged administrative operations
6. **role.assignment** - Role granted or revoked

#### Audit Functions

##### `audit_authorization(user, tenant_id, resource, action, granted, ...)`
Logs all authorization decisions (automatic in dependencies).

```python
audit_authorization(
    user=current_user,
    tenant_id="tenant_123",
    resource="findings",
    action="read",
    granted=True,
    required_permissions=["findings:read"],
    user_permissions=["findings:read", "findings:write"]
)
```

##### `audit_data_access(user, tenant_id, resource_type, resource_id, action, ...)`
Logs data access to sensitive resources.

```python
# Single resource
audit_data_access(user, tenant_id, "finding", "finding_123", "read")

# List operation
audit_data_access(user, tenant_id, "finding", None, "list",
                 metadata={"filters": {"status": "open"}})
```

##### `audit_data_modification(user, tenant_id, resource_type, resource_id, action, changes)`
Logs create/update/delete operations.

```python
# Update
audit_data_modification(
    user, tenant_id, "finding", finding_id, "update",
    changes={"status": "resolved", "assignee": "user@example.com"}
)

# Delete
audit_data_modification(user, tenant_id, "scan", scan_id, "delete")
```

##### `audit_admin_action(user, tenant_id, action, target, details)`
Logs privileged administrative operations.

```python
audit_admin_action(
    user, tenant_id, "assign_role",
    target="user@example.com",
    details={"role": "admin", "reason": "promotion"}
)
```

##### `audit_role_assignment(admin_user, tenant_id, target_user_sub, role_name, action)`
Logs role assignments and revocations.

```python
audit_role_assignment(
    admin_user, tenant_id, "user_sub_123", "Admin", "assigned"
)
```

#### When to Call Audit Functions

**Automatic Auditing (No Action Required):**
- All authorization checks via `require_permissions()` and `require_role()` dependencies
- Resource-level tenant access checks via `require_tenant_access()`

**Manual Auditing Required:**
```python
# After data access (in route handlers)
@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str, ...):
    finding = await db.get_finding(finding_id)
    audit_data_access(user, tenant_id, "finding", finding_id, "read")
    return finding

# Before data modification
@router.put("/findings/{finding_id}")
async def update_finding(finding_id: str, update: FindingUpdate, ...):
    old_finding = await db.get_finding(finding_id)
    new_finding = await db.update_finding(finding_id, update)
    audit_data_modification(
        user, tenant_id, "finding", finding_id, "update",
        changes={"status": f"{old_finding.status} -> {new_finding.status}"}
    )
    return new_finding

# For admin actions
@router.post("/admin/users/{user_id}/roles")
async def assign_role(user_id: str, role: str, ...):
    await db.assign_role(user_id, role)
    audit_role_assignment(admin_user, tenant_id, user_id, role, "assigned")
    return {"success": True}
```

## Cribl Integration

Audit events are automatically forwarded to Cribl Stream (if enabled) for centralized log management and SIEM integration.

### Configuration

In `.env`:
```bash
# Enable Cribl integration (set to false for local dev)
CRIBL_ENABLED=true

# Minimum log level for audit events
AUDIT_LOG_LEVEL=INFO
```

### Local Development Without Cribl

When `CRIBL_ENABLED=false`, audit events are logged to stdout in JSON format:
```json
[AuditLog] {"event_type": "authorization.granted", "timestamp": "2024-01-01T12:00:00", ...}
```

### Production Cribl Setup

1. Configure Cribl HTTP Event Collector endpoint in database
2. Set `CRIBL_ENABLED=true` in environment
3. Audit events are batched and sent to Cribl with "audit" tag
4. Configure SIEM alerts on audit event patterns

## Security Best Practices

### Authorization Checks
- Always use dependencies for route protection (not manual checks)
- Dependencies run BEFORE route handlers (prevents timing attacks)
- Authorization failures return 403 (not 404) for routes

### Tenant Isolation
- NEVER default to a tenant - always require explicit context
- Use `require_tenant_access()` for resource-level checks
- Return 404 (not 403) for missing resources (prevents enumeration)

### Audit Logging
- ALL authorization decisions are logged (success AND failure)
- Authorization failures use WARNING level (triggers SIEM alerts)
- NEVER log sensitive data (passwords, tokens, PII)
- Include complete context for forensics (user, tenant, resource, action)

### Compliance
- SOC2 requires audit trails for all data access and authorization
- GDPR requires logging of personal data access
- Admin actions require special logging for accountability
- Audit logs must be tamper-proof (external system, not app DB)

## Permission String Format

Permissions follow the format: `resource:action`

Examples:
- `findings:read` - Read findings
- `findings:write` - Create/update findings
- `findings:delete` - Delete findings
- `scans:execute` - Execute scans
- `users:manage` - Manage users
- `roles:assign` - Assign roles

## Common Patterns

### Protecting an API Route
```python
@router.get(
    "/findings",
    dependencies=[Depends(require_permissions("findings:read"))]
)
async def list_findings(user: User = Depends(get_current_user)):
    # Authorization already verified by dependency
    findings = await db.get_findings_for_tenant(tenant_id)

    # Audit data access
    audit_data_access(user, tenant_id, "finding", None, "list")

    return findings
```

### Resource-Level Access Control
```python
@router.get(
    "/findings/{finding_id}",
    dependencies=[Depends(require_permissions("findings:read"))]
)
async def get_finding(
    finding_id: str,
    user: User = Depends(get_current_user),
    request: Request = None,
    session: Session = Depends(get_db)
):
    tenant_id = get_tenant_id_from_request(request)

    # Verify resource belongs to tenant
    await require_tenant_access(finding_id, "finding", user, tenant_id, session)

    # Get resource
    finding = await db.get_finding(finding_id)

    # Audit data access
    audit_data_access(user, tenant_id, "finding", finding_id, "read")

    return finding
```

### Admin-Only Endpoint
```python
@router.post(
    "/admin/users",
    dependencies=[Depends(require_role(2))]  # Admin and above
)
async def create_user(
    user_data: UserCreate,
    admin_user: User = Depends(get_current_user)
):
    new_user = await db.create_user(user_data)

    # Audit admin action
    audit_admin_action(
        admin_user, tenant_id, "create_user",
        target=new_user.email,
        details={"role": user_data.role}
    )

    return new_user
```

## Testing

### Unit Tests
```python
def test_require_permissions_granted():
    # Test permission check passes for authorized user
    pass

def test_require_permissions_denied():
    # Test permission check fails for unauthorized user
    # Verify audit_authorization called with granted=False
    pass
```

### Integration Tests
```python
async def test_api_route_protection():
    # Test protected route returns 403 without permission
    response = await client.get("/findings")
    assert response.status_code == 403

    # Verify audit log contains authorization failure
    assert "authorization.denied" in audit_logs
```

## Future Enhancements

- [ ] Rate limiting integration (track failed auth attempts)
- [ ] Anomaly detection (unusual access patterns)
- [ ] Automated alerts for high-risk events
- [ ] Audit log retention policies
- [ ] Export audit logs for compliance reporting
