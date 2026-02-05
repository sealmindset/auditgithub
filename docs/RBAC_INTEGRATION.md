# RBAC Integration Guide

## Overview

This document explains how the new user-based RBAC system (implemented in Phase 1-4) integrates with the existing permission-based RBAC system.

## Two RBAC Systems

### Existing System (src/rbac/)
The codebase already has a permission-based RBAC system:
- **Location**: `src/rbac/dependencies.py`, `src/rbac/permissions.py`
- **Database**: `roles` table (separate from users)
- **Model**: Permission strings (e.g., `"findings:read"`, `"scans:execute"`)
- **Usage**: `@router.get("/findings", dependencies=[Depends(require_permissions("findings:read"))])`
- **Features**:
  - Fine-grained permission checking
  - Role levels (1-5)
  - Tenant/organization access verification
  - Audit logging for authorization

### New System (src/auth/)
The new invitation-based RBAC system:
- **Location**: `src/auth/dependencies.py`, `src/auth/invitations.py`
- **Database**: `users` table with role column
- **Model**: Role names (e.g., `"super_admin"`, `"analyst"`, `"developer"`)
- **Usage**: `@router.post("/invitations", current_user: User = Depends(require_admin))`
- **Features**:
  - User invitation system
  - Break glass authentication
  - Access type controls (UI/API/Both)
  - Repository-level access control
  - Authentication middleware

## Integration Strategy

### Option 1: Keep Both Systems (Recommended)
Use both systems together for different purposes:

**New System**: User management and authentication
- Invitation flow
- Break glass access
- Access type enforcement (UI vs API)
- Repository assignments
- User role management

**Existing System**: API endpoint protection
- Fine-grained permissions on endpoints
- Resource-level access control
- Tenant isolation

**Example**:
```python
@router.delete("/findings/{finding_id}")
async def delete_finding(
    finding_id: UUID,
    # New system: Check user role
    user: User = Depends(require_role('analyst', 'admin', 'super_admin')),
    # Existing system: Check specific permission
    _: None = Depends(require_permissions("findings:delete")),
    db: Session = Depends(get_db)
):
    # Both checks pass before handler executes
    pass
```

### Option 2: Map New Roles to Existing Permissions
Create a mapping between new user roles and existing permissions:

**File**: `src/rbac/role_mapping.py`
```python
"""
Map new user roles to existing permission strings.
"""
from typing import List

ROLE_PERMISSIONS = {
    'super_admin': ['*'],  # All permissions
    'admin': ['*'],  # All permissions
    'manager': [
        'findings:read',
        'findings:write',
        'scans:read',
        'scans:execute',
        'projects:read',
        'projects:write'
    ],
    'analyst': [
        'findings:read',
        'findings:write',
        'findings:delete',
        'scans:read',
        'scans:execute',
        'jira:submit'
    ],
    'developer': [
        'findings:read',
        'scans:read',
        'scans:execute',
        'projects:read'
    ],
    'user': [
        'findings:read',
        'scans:read',
        'projects:read'
    ]
}

def get_permissions_for_role(role: str) -> List[str]:
    """Get all permissions for a given role."""
    return ROLE_PERMISSIONS.get(role, [])

def has_permission_for_role(role: str, permission: str) -> bool:
    """Check if role has specific permission."""
    perms = ROLE_PERMISSIONS.get(role, [])
    return '*' in perms or permission in perms
```

Then modify `src/rbac/dependencies.py`:
```python
from src.auth.dependencies import get_db_user
from src.rbac.role_mapping import has_permission_for_role

def require_permissions(*required_perms: str) -> Callable:
    """
    Modified to use new user roles.
    """
    def permission_checker(
        request: Request,
        user: User = Depends(get_db_user),  # Use new system
        db: Session = Depends(get_db)
    ):
        # Check if user's role has required permissions
        for perm in required_perms:
            if not has_permission_for_role(user.role, perm):
                raise HTTPException(
                    status_code=403,
                    detail=f"Permission denied: {perm} required"
                )
        return None

    return permission_checker
```

### Option 3: Migrate to New System Only
Gradually replace existing permission checks with new role checks:

**Before** (existing system):
```python
@router.delete("/findings/{finding_id}",
               dependencies=[Depends(require_permissions("findings:delete"))])
```

**After** (new system):
```python
@router.delete("/findings/{finding_id}")
async def delete_finding(
    finding_id: UUID,
    user: User = Depends(require_role('analyst', 'admin', 'super_admin')),
    db: Session = Depends(get_db)
):
    # Check repository access
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    # Use new check_repository_access dependency
    check_repository_access(finding.repository_id, 'delete_finding')(user, db)

    # Delete finding
    db.delete(finding)
    db.commit()
```

## Current State

### What's Implemented
✅ **New RBAC System** (Phases 1-4):
- User table with role, access_type, auth_provider
- Invitation system with email validation
- Break glass authentication
- RBAC dependencies (require_admin, require_role, check_repository_access)
- User management API
- Admin UI
- Authentication middleware

✅ **Existing RBAC System**:
- Permission-based endpoint protection on scans and findings
- Role levels (1-5)
- Tenant access verification
- Audit logging

### What's Not Integrated
⏳ **Permission Mapping**:
- No automatic mapping between new user roles and existing permissions
- Endpoints still use old `require_permissions()` dependency
- No repository access checks on scan/finding endpoints

⏳ **User Role Usage**:
- Existing endpoints don't check user.role from new system
- No access type enforcement (UI vs API) on existing endpoints

## Recommended Next Steps

### Immediate (For Testing)
1. **Keep both systems** - They don't conflict
2. **Test new features**:
   - Login with break glass
   - Send invitations
   - Manage users in admin panel
3. **Existing endpoints continue to work** with old permission system

### Short-term (1-2 weeks)
1. **Implement Option 2** - Map new roles to existing permissions
2. **Update `require_permissions()`** to check new user.role
3. **Add repository access checks** to scan/finding endpoints
4. **Test integration** - Verify both systems work together

### Long-term (1-2 months)
1. **Gradually migrate to Option 3** - Replace permission strings with roles
2. **Deprecate roles table** - Move entirely to users.role
3. **Simplify RBAC** - Single source of truth for permissions

## Code Examples

### Using Both Systems Together
```python
from src.auth.dependencies import get_db_user, require_admin
from src.rbac.dependencies import require_permissions

# Admin-only endpoint with fine-grained permission
@router.post("/admin/reset-database")
async def reset_database(
    admin_user: User = Depends(require_admin),  # New system: Check role
    _: None = Depends(require_permissions("admin:reset")),  # Old system: Extra check
    db: Session = Depends(get_db)
):
    # Both admin role AND specific permission required
    pass

# Analyst endpoint with repository access
@router.post("/findings/{finding_id}/mark-exception")
async def mark_exception(
    finding_id: UUID,
    user: User = Depends(require_role('analyst', 'admin')),  # New system
    db: Session = Depends(get_db)
):
    # Get finding to check repository
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404)

    # Check repository access (new system)
    check_repository_access(finding.repository_id, 'mark_exception')(user, db)

    # Mark as exception
    finding.is_exception = True
    db.commit()
```

### Updating Existing Endpoint
**Before**:
```python
@router.post("/scans", dependencies=[Depends(require_permissions("scans:execute"))])
async def trigger_scan(
    body: ScanRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Old permission check only
    pass
```

**After**:
```python
@router.post("/scans")
async def trigger_scan(
    body: ScanRequest,
    user: User = Depends(get_db_user),  # Use new user model with role
    db: Session = Depends(get_db)
):
    # Check if user can perform 'run_scan' action
    if not can_perform_action(user.role, 'run_scan'):
        raise HTTPException(403, f"Role {user.role} cannot trigger scans")

    # Check repository access
    has_access = db.query(UserRepositoryAccess).filter(
        UserRepositoryAccess.user_id == user.id,
        UserRepositoryAccess.repository_id == body.repository_id
    ).first()

    if not has_access and user.role not in ['admin', 'super_admin']:
        raise HTTPException(403, "No access to this repository")

    # Trigger scan
    pass
```

## Testing Integration

### Test Scenario 1: Admin User
1. Login as admin (rob.vance@sleepnumber.com)
2. Try to delete a finding:
   - ✅ New system: Admin role check passes
   - ✅ Old system: `findings:delete` permission check passes
3. Result: Both systems allow, finding deleted

### Test Scenario 2: Developer User
1. Login as developer (invited user)
2. Try to delete a finding:
   - ❌ New system: Developer role doesn't have delete permission
   - ❌ Old system: No `findings:delete` permission
3. Result: Both systems block, 403 error returned

### Test Scenario 3: Analyst with Repository Access
1. Login as analyst (invited user)
2. Assigned to repository "my-app"
3. Try to trigger scan on "my-app":
   - ✅ New system: Analyst can run scans
   - ✅ New system: Has repository access
   - ✅ Old system: `scans:execute` permission
4. Result: Scan triggered

## Migration Checklist

- [ ] Document existing permission strings
- [ ] Create role-to-permission mapping
- [ ] Update `require_permissions()` to check user.role
- [ ] Add repository access checks to scan endpoints
- [ ] Add repository access checks to finding endpoints
- [ ] Test all endpoints with different roles
- [ ] Update API documentation
- [ ] Train users on new role system

## Conclusion

The new RBAC system is **fully functional** for:
- User invitation and onboarding
- Break glass authentication
- User management
- Access type controls
- Repository assignments

Integration with existing endpoints is **optional** and can be done gradually using one of the three strategies above. The current state allows both systems to coexist without conflicts.

**Recommended approach**: Start with Option 1 (keep both systems) and gradually move to Option 2 (map roles to permissions) over time.
