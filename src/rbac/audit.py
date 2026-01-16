"""
Structured audit logging module for authorization decisions and data access events.

This module provides comprehensive audit trails for SOC2/GDPR compliance, security
monitoring, and incident investigation. All audit events are logged as structured
JSON for integration with SIEM tools (Cribl, Splunk, ELK).

Event Types:
    - authorization.granted: Authorization decision allowed
    - authorization.denied: Authorization decision denied (potential attack indicator)
    - data.access: Read access to sensitive resources
    - data.modification: Write/update/delete operations on resources
    - admin.action: Privileged administrative operations
    - role.assignment: Role granted or revoked

Security Best Practices:
    - Log ALL authorization decisions (both success and failure)
    - Log failures at WARNING level for security alerting
    - Never log sensitive data (passwords, tokens, PII)
    - Use structured JSON for SIEM parsing
    - Include complete context (user, tenant, resource, action)
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
from loguru import logger
from src.auth.models import User
import json
import os

# Import Cribl logger for audit event forwarding
try:
    from src.api.utils.cribl_logger import log_audit_event
    CRIBL_AVAILABLE = True
except ImportError:
    CRIBL_AVAILABLE = False
    # Fallback if Cribl logger not available
    def log_audit_event(event_type: str, event_data: Dict[str, Any]) -> None:
        print(f"[AuditLog] {json.dumps(event_data)}")


# Audit event type constants
AUTHORIZATION_GRANTED = "authorization.granted"
AUTHORIZATION_DENIED = "authorization.denied"
DATA_ACCESS = "data.access"
DATA_MODIFICATION = "data.modification"
ADMIN_ACTION = "admin.action"
ROLE_ASSIGNMENT = "role.assignment"


def _send_to_cribl(event: Dict[str, Any]) -> None:
    """
    Internal helper to send audit event to Cribl logger.

    This function extracts the event type and forwards the event to Cribl
    (if enabled) or logs to stdout (local dev mode). This enables centralized
    log management and SIEM integration.

    Args:
        event: Complete audit event dict with event_type field
    """
    event_type = event.get("event_type", "unknown")
    log_audit_event(event_type, event)


def audit_authorization(
    user: User,
    tenant_id: str,
    resource: str,
    action: str,
    granted: bool,
    reason: Optional[str] = None,
    required_permissions: Optional[List[str]] = None,
    user_permissions: Optional[List[str]] = None
) -> None:
    """
    Log an authorization decision (success or failure).

    This function logs all authorization checks to create a complete audit trail.
    Authorization failures are logged at WARNING level because they may indicate
    attack attempts (e.g., privilege escalation, unauthorized access).

    Args:
        user: Authenticated user making the request
        tenant_id: Tenant/organization ID context
        resource: Resource being accessed (e.g., "findings", "api", "admin")
        action: Action being performed (e.g., "read", "write", "request")
        granted: Whether authorization was granted
        reason: Human-readable reason for the decision
        required_permissions: Permissions required for this action
        user_permissions: Permissions the user actually has

    Example:
        audit_authorization(
            user=current_user,
            tenant_id="tenant_123",
            resource="findings",
            action="read",
            granted=True,
            required_permissions=["findings:read"],
            user_permissions=["findings:read", "findings:write"]
        )

    Security:
        - Logging failures helps detect privilege escalation attacks
        - Complete permission context enables forensic analysis
        - WARNING level for failures triggers SIEM alerts
    """
    event = {
        "event_type": AUTHORIZATION_GRANTED if granted else AUTHORIZATION_DENIED,
        "timestamp": datetime.utcnow().isoformat(),
        "user": {
            "sub": user.sub,
            "email": user.email,
            "provider": user.provider
        },
        "tenant_id": tenant_id,
        "resource": resource,
        "action": action,
        "granted": granted,
        "reason": reason,
        "required_permissions": required_permissions,
        "user_permissions": user_permissions
    }

    # Send to Cribl for centralized logging
    _send_to_cribl(event)

    # Use appropriate log level based on outcome
    if granted:
        logger.info(
            f"Authorization granted for {user.email}: {action} on {resource}",
            extra={"audit_event": event}
        )
    else:
        logger.warning(
            f"Authorization DENIED for {user.email}: {action} on {resource}",
            extra={"audit_event": event}
        )


def audit_data_access(
    user: User,
    tenant_id: str,
    resource_type: str,
    resource_id: Optional[str],
    action: str,
    metadata: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log data access to sensitive resources.

    This function creates an audit trail for all data access operations. This is
    critical for compliance (SOC2, GDPR) and incident investigation. Logs include
    the specific resource accessed and any relevant metadata.

    Args:
        user: Authenticated user accessing data
        tenant_id: Tenant/organization ID context
        resource_type: Type of resource (e.g., "finding", "scan", "repository")
        resource_id: Specific resource ID (None for list operations)
        action: Action performed (e.g., "read", "list", "access_check")
        metadata: Additional context (e.g., query parameters, filters)

    Examples:
        # Single resource access
        audit_data_access(user, tenant_id, "finding", "finding_123", "read")

        # List operation
        audit_data_access(user, tenant_id, "finding", None, "list",
                         metadata={"filters": {"status": "open"}})

        # Access verification
        audit_data_access(user, tenant_id, "scan", scan_id, "access_check")

    Compliance:
        - SOC2 requires audit trails for all data access
        - GDPR requires logging of personal data access
        - Enables "who accessed what when" forensics
    """
    event = {
        "event_type": DATA_ACCESS,
        "timestamp": datetime.utcnow().isoformat(),
        "user": {
            "sub": user.sub,
            "email": user.email
        },
        "tenant_id": tenant_id,
        "resource": {
            "type": resource_type,
            "id": resource_id,
            "action": action
        },
        "metadata": metadata
    }

    # Send to Cribl for centralized logging
    _send_to_cribl(event)

    logger.info(
        f"Data access by {user.email}: {action} {resource_type}/{resource_id or 'list'}",
        extra={"audit_event": event}
    )


def audit_data_modification(
    user: User,
    tenant_id: str,
    resource_type: str,
    resource_id: str,
    action: str,
    changes: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log data modification operations (create, update, delete).

    This function creates an audit trail for all data modification operations.
    Recording changes enables rollback and forensic analysis. For updates, the
    changes dict should contain before/after values or a summary of modifications.

    Args:
        user: Authenticated user modifying data
        tenant_id: Tenant/organization ID context
        resource_type: Type of resource being modified
        resource_id: Specific resource ID
        action: Action performed (e.g., "create", "update", "delete")
        changes: Summary of changes made (avoid logging sensitive data)

    Examples:
        # Create operation
        audit_data_modification(user, tenant_id, "finding", finding_id, "create")

        # Update with changes
        audit_data_modification(
            user, tenant_id, "finding", finding_id, "update",
            changes={"status": "resolved", "assignee": "user@example.com"}
        )

        # Delete operation
        audit_data_modification(user, tenant_id, "scan", scan_id, "delete")

    Security:
        - Enables detection of unauthorized modifications
        - Provides audit trail for compliance
        - Changes dict enables rollback/forensics
        - DO NOT log sensitive data in changes dict
    """
    event = {
        "event_type": DATA_MODIFICATION,
        "timestamp": datetime.utcnow().isoformat(),
        "user": {
            "sub": user.sub,
            "email": user.email
        },
        "tenant_id": tenant_id,
        "resource": {
            "type": resource_type,
            "id": resource_id,
            "action": action
        },
        "changes": changes
    }

    # Send to Cribl for centralized logging
    _send_to_cribl(event)

    logger.info(
        f"Data modification by {user.email}: {action} {resource_type}/{resource_id}",
        extra={"audit_event": event}
    )


def audit_admin_action(
    user: User,
    tenant_id: str,
    action: str,
    target: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log privileged administrative actions.

    This function provides accountability for high-privilege operations. Admin
    actions are logged at WARNING level for higher visibility and alerting.
    These logs are critical for detecting insider threats and unauthorized
    administrative access.

    Args:
        user: Admin user performing the action
        tenant_id: Tenant/organization ID context
        action: Admin action performed (e.g., "assign_role", "revoke_access")
        target: Target of the action (e.g., user email, resource ID)
        details: Additional context about the action

    Examples:
        # Role assignment
        audit_admin_action(
            user, tenant_id, "assign_role",
            target="user@example.com",
            details={"role": "admin", "reason": "promotion"}
        )

        # Access revocation
        audit_admin_action(
            user, tenant_id, "revoke_access",
            target="user@example.com",
            details={"reason": "user left organization"}
        )

        # Configuration change
        audit_admin_action(
            user, tenant_id, "update_config",
            details={"setting": "require_mfa", "value": True}
        )

    Security:
        - WARNING level ensures high visibility
        - Provides accountability for privileged operations
        - Enables detection of insider threats
        - Critical for compliance (SOC2 requires admin action logs)
    """
    event = {
        "event_type": ADMIN_ACTION,
        "timestamp": datetime.utcnow().isoformat(),
        "user": {
            "sub": user.sub,
            "email": user.email
        },
        "tenant_id": tenant_id,
        "action": action,
        "target": target,
        "details": details
    }

    # Send to Cribl for centralized logging
    _send_to_cribl(event)

    logger.warning(
        f"ADMIN ACTION by {user.email}: {action}",
        extra={"audit_event": event}
    )


def audit_role_assignment(
    admin_user: User,
    tenant_id: str,
    target_user_sub: str,
    role_name: str,
    action: str
) -> None:
    """
    Log role assignment or revocation operations.

    This function provides a specialized audit trail for role changes. Role
    assignments are security-sensitive operations that affect authorization
    decisions. These logs are critical for compliance and security monitoring.

    Args:
        admin_user: Admin user making the role change
        tenant_id: Tenant/organization ID context
        target_user_sub: Subject claim of the user receiving/losing the role
        role_name: Name of the role (e.g., "Admin", "Analyst", "User")
        action: "assigned" or "revoked"

    Examples:
        # Assign role
        audit_role_assignment(
            admin_user, tenant_id, "user_sub_123", "Admin", "assigned"
        )

        # Revoke role
        audit_role_assignment(
            admin_user, tenant_id, "user_sub_123", "Admin", "revoked"
        )

    Security:
        - WARNING level for security visibility
        - Enables detection of privilege escalation
        - Required for compliance (SOC2, GDPR)
        - Provides accountability for role changes
    """
    event = {
        "event_type": ROLE_ASSIGNMENT,
        "timestamp": datetime.utcnow().isoformat(),
        "admin_user": {
            "sub": admin_user.sub,
            "email": admin_user.email
        },
        "tenant_id": tenant_id,
        "target_user_sub": target_user_sub,
        "role_name": role_name,
        "action": action
    }

    # Send to Cribl for centralized logging
    _send_to_cribl(event)

    logger.warning(
        f"Role {action} by {admin_user.email}: {role_name} for user {target_user_sub}",
        extra={"audit_event": event}
    )
