"""
User Management API

Endpoints for admins to manage users, roles, and repository access.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from sqlalchemy.orm import Session

from src.api.database import get_db
from src.api.models import User, UserRepositoryAccess, Repository, AuthAuditLog
from src.auth.dependencies import require_admin, get_db_user, require_super_admin
from loguru import logger

router = APIRouter(prefix="/api/users", tags=["user-management"])


# =========================================================================
# Request/Response Models
# =========================================================================

class UserResponse(BaseModel):
    """Response model for user."""
    id: str
    email: str
    username: str
    full_name: Optional[str]
    role: str
    access_type: str
    auth_provider: str
    is_active: bool
    is_invited: bool
    last_login_at: Optional[datetime]
    created_at: datetime

    class Config:
        schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "email": "developer@example.com",
                "username": "developer",
                "full_name": "John Developer",
                "role": "developer",
                "access_type": "both",
                "auth_provider": "entra",
                "is_active": True,
                "is_invited": True,
                "last_login_at": "2025-02-04T10:00:00Z",
                "created_at": "2025-02-01T10:00:00Z"
            }
        }


class UpdateRoleRequest(BaseModel):
    """Request body for updating user role."""
    role: str

    class Config:
        schema_extra = {
            "example": {
                "role": "analyst"
            }
        }


class UpdateAccessTypeRequest(BaseModel):
    """Request body for updating user access type."""
    access_type: str

    class Config:
        schema_extra = {
            "example": {
                "access_type": "both"
            }
        }


class AssignRepositoryRequest(BaseModel):
    """Request body for assigning repository to user."""
    repository_id: UUID

    class Config:
        schema_extra = {
            "example": {
                "repository_id": "123e4567-e89b-12d3-a456-426614174000"
            }
        }


class UserRepositoryResponse(BaseModel):
    """Response model for user repository assignment."""
    repository_id: str
    repository_name: str
    organization_name: str
    assigned_at: datetime
    assigned_by_email: str

    class Config:
        schema_extra = {
            "example": {
                "repository_id": "123e4567-e89b-12d3-a456-426614174000",
                "repository_name": "my-api-service",
                "organization_name": "sleepnumberinc",
                "assigned_at": "2025-02-04T10:00:00Z",
                "assigned_by_email": "admin@example.com"
            }
        }


# =========================================================================
# Endpoints
# =========================================================================

@router.get("", response_model=List[UserResponse])
async def list_users(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
    include_inactive: bool = False
):
    """
    List all users.

    Only admins can view user list.

    Args:
        current_user: Current admin user (from dependency)
        db: Database session
        include_inactive: Whether to include inactive users (default: False)

    Returns:
        List of users
    """
    query = db.query(User)

    if not include_inactive:
        query = query.filter(User.is_active == True)

    users = query.order_by(User.created_at.desc()).all()

    return [
        UserResponse(
            id=str(user.id),
            email=user.email,
            username=user.username,
            full_name=user.full_name,
            role=user.role,
            access_type=user.access_type,
            auth_provider=user.auth_provider,
            is_active=user.is_active,
            is_invited=user.is_invited or False,
            last_login_at=user.last_login_at,
            created_at=user.created_at
        )
        for user in users
    ]


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    current_user: User = Depends(get_db_user),
    db: Session = Depends(get_db)
):
    """
    Get user details.

    Users can view their own details.
    Admins can view any user's details.

    Args:
        user_id: User UUID
        current_user: Current user (from dependency)
        db: Database session

    Returns:
        User details

    Raises:
        HTTPException 403: If user tries to view another user's details without admin access
        HTTPException 404: If user not found
    """
    # Users can see their own details, admins can see anyone's
    if current_user.id != user_id and current_user.role not in ['admin', 'super_admin']:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot view other users' details"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return UserResponse(
        id=str(user.id),
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        role=user.role,
        access_type=user.access_type,
        auth_provider=user.auth_provider,
        is_active=user.is_active,
        is_invited=user.is_invited or False,
        last_login_at=user.last_login_at,
        created_at=user.created_at
    )


@router.patch("/{user_id}/role", response_model=UserResponse)
async def update_user_role(
    user_id: UUID,
    body: UpdateRoleRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Update user role.

    Admins can update roles except Super Admins.
    Only Super Admins can modify Super Admin roles.

    Args:
        user_id: User UUID
        body: New role
        current_user: Current admin user (from dependency)
        db: Database session

    Returns:
        Updated user details

    Raises:
        HTTPException 403: If admin tries to modify Super Admin
        HTTPException 404: If user not found
        HTTPException 400: If role is invalid
    """
    # Validate role
    valid_roles = ['user', 'developer', 'analyst', 'manager', 'admin', 'super_admin']
    if body.role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}"
        )

    # Find user
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Admins cannot modify Super Admins (only Super Admins can)
    if user.role == 'super_admin' and current_user.role != 'super_admin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot modify Super Admin users"
        )

    # Only Super Admins can assign super_admin role
    if body.role == 'super_admin' and current_user.role != 'super_admin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only Super Admins can assign super_admin role"
        )

    # Update role
    old_role = user.role
    user.role = body.role
    db.commit()
    db.refresh(user)

    # Audit log
    audit_log = AuthAuditLog(
        user_id=user.id,
        email=user.email,
        event_type='role_changed',
        success=True,
        extra_data={
            'old_role': old_role,
            'new_role': body.role,
            'changed_by': current_user.email
        }
    )
    db.add(audit_log)
    db.commit()

    logger.info(
        f"Role updated for {user.email}: {old_role} -> {body.role} "
        f"(by {current_user.email})"
    )

    return UserResponse(
        id=str(user.id),
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        role=user.role,
        access_type=user.access_type,
        auth_provider=user.auth_provider,
        is_active=user.is_active,
        is_invited=user.is_invited or False,
        last_login_at=user.last_login_at,
        created_at=user.created_at
    )


@router.patch("/{user_id}/access-type", response_model=UserResponse)
async def update_user_access_type(
    user_id: UUID,
    body: UpdateAccessTypeRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Update user access type (UI only, API only, or both).

    Args:
        user_id: User UUID
        body: New access type
        current_user: Current admin user (from dependency)
        db: Database session

    Returns:
        Updated user details

    Raises:
        HTTPException 404: If user not found
        HTTPException 400: If access type is invalid
    """
    # Validate access type
    valid_access_types = ['ui_only', 'api_only', 'both']
    if body.access_type not in valid_access_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid access type. Must be one of: {', '.join(valid_access_types)}"
        )

    # Find user
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Update access type
    user.access_type = body.access_type
    db.commit()
    db.refresh(user)

    logger.info(
        f"Access type updated for {user.email}: {body.access_type} "
        f"(by {current_user.email})"
    )

    return UserResponse(
        id=str(user.id),
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        role=user.role,
        access_type=user.access_type,
        auth_provider=user.auth_provider,
        is_active=user.is_active,
        is_invited=user.is_invited or False,
        last_login_at=user.last_login_at,
        created_at=user.created_at
    )


@router.post("/{user_id}/repositories", status_code=status.HTTP_201_CREATED)
async def assign_repository(
    user_id: UUID,
    body: AssignRepositoryRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Assign repository to user.

    Args:
        user_id: User UUID
        body: Repository ID to assign
        current_user: Current admin user (from dependency)
        db: Database session

    Returns:
        Success message

    Raises:
        HTTPException 404: If user or repository not found
        HTTPException 400: If repository already assigned
    """
    # Find user
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Find repository
    repo = db.query(Repository).filter(Repository.id == body.repository_id).first()
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )

    # Check if already assigned
    existing = db.query(UserRepositoryAccess).filter(
        UserRepositoryAccess.user_id == user_id,
        UserRepositoryAccess.repository_id == body.repository_id
    ).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Repository already assigned to user"
        )

    # Create assignment
    access = UserRepositoryAccess(
        user_id=user_id,
        repository_id=body.repository_id,
        organization_id=repo.organization_id,
        assigned_by=current_user.id
    )

    db.add(access)
    db.commit()

    logger.info(
        f"Repository {repo.name} assigned to {user.email} by {current_user.email}"
    )

    return {"message": "Repository assigned successfully"}


@router.delete("/{user_id}/repositories/{repository_id}", status_code=status.HTTP_204_NO_CONTENT)
async def unassign_repository(
    user_id: UUID,
    repository_id: UUID,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Unassign repository from user.

    Args:
        user_id: User UUID
        repository_id: Repository UUID
        current_user: Current admin user (from dependency)
        db: Database session

    Returns:
        204 No Content on success

    Raises:
        HTTPException 404: If assignment not found
    """
    # Find assignment
    access = db.query(UserRepositoryAccess).filter(
        UserRepositoryAccess.user_id == user_id,
        UserRepositoryAccess.repository_id == repository_id
    ).first()

    if not access:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository assignment not found"
        )

    # Delete assignment
    db.delete(access)
    db.commit()

    logger.info(
        f"Repository {repository_id} unassigned from {user_id} by {current_user.email}"
    )

    return None  # 204 No Content


@router.get("/{user_id}/repositories", response_model=List[UserRepositoryResponse])
async def list_user_repositories(
    user_id: UUID,
    current_user: User = Depends(get_db_user),
    db: Session = Depends(get_db)
):
    """
    List repositories assigned to user.

    Users can view their own repositories.
    Admins can view any user's repositories.

    Args:
        user_id: User UUID
        current_user: Current user (from dependency)
        db: Database session

    Returns:
        List of repository assignments

    Raises:
        HTTPException 403: If user tries to view another user's repositories without admin access
    """
    # Users can see their own, admins can see anyone's
    if current_user.id != user_id and current_user.role not in ['admin', 'super_admin']:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot view other users' repositories"
        )

    assignments = db.query(UserRepositoryAccess).filter(
        UserRepositoryAccess.user_id == user_id
    ).all()

    return [
        UserRepositoryResponse(
            repository_id=str(a.repository_id),
            repository_name=a.repository.name,
            organization_name=a.repository.organization.name,
            assigned_at=a.assigned_at,
            assigned_by_email=a.assigner.email
        )
        for a in assignments
    ]
