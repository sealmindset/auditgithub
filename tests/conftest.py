"""
Pytest fixtures for RBAC integration tests.

Provides test database, test client, and test users with various roles for
verifying role-based access control enforcement across API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
import uuid

# Import application components
from src.api.main import app
from src.api.database import Base, get_db
from src.auth.models import User
from src.rbac.models import Role, Permission, RolePermission, UserRole
from src.api.models import Organization


# Test database configuration
TEST_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="function")
def test_db():
    """
    Create a fresh test database for each test function.

    Yields:
        Session: SQLAlchemy database session
    """
    # Create all tables
    Base.metadata.create_all(bind=test_engine)

    db = TestingSessionLocal()

    try:
        # Seed with basic RBAC data
        seed_rbac_data(db)
        yield db
    finally:
        db.close()
        # Drop all tables after test
        Base.metadata.drop_all(bind=test_engine)


def seed_rbac_data(db: Session):
    """Seed database with RBAC roles and permissions."""

    # Create permissions
    permissions = [
        Permission(id=uuid.uuid4(), name="*:*", description="Wildcard - all permissions"),
        Permission(id=uuid.uuid4(), name="findings:read", description="Read findings"),
        Permission(id=uuid.uuid4(), name="findings:write", description="Write findings"),
        Permission(id=uuid.uuid4(), name="findings:delete", description="Delete findings"),
        Permission(id=uuid.uuid4(), name="scans:read", description="Read scans"),
        Permission(id=uuid.uuid4(), name="scans:execute", description="Execute scans"),
        Permission(id=uuid.uuid4(), name="repositories:read", description="Read repositories"),
        Permission(id=uuid.uuid4(), name="repositories:write", description="Write repositories"),
        Permission(id=uuid.uuid4(), name="organizations:read", description="Read organizations"),
        Permission(id=uuid.uuid4(), name="organizations:write", description="Write organizations"),
        Permission(id=uuid.uuid4(), name="organizations:admin", description="Admin organizations"),
        Permission(id=uuid.uuid4(), name="projects:read", description="Read projects"),
        Permission(id=uuid.uuid4(), name="reports:read", description="Read reports"),
        Permission(id=uuid.uuid4(), name="admin:manage", description="Manage system"),
    ]

    for perm in permissions:
        db.add(perm)
    db.commit()

    # Create roles
    super_admin = Role(
        id=uuid.uuid4(),
        name="super_admin",
        description="Super Administrator",
        level=1,
        is_system=True
    )
    admin = Role(
        id=uuid.uuid4(),
        name="admin",
        description="Administrator",
        level=2,
        is_system=True
    )
    analyst = Role(
        id=uuid.uuid4(),
        name="analyst",
        description="Security Analyst",
        level=3,
        is_system=True
    )
    manager = Role(
        id=uuid.uuid4(),
        name="manager",
        description="Manager",
        level=4,
        is_system=True
    )
    user = Role(
        id=uuid.uuid4(),
        name="user",
        description="Basic User",
        level=5,
        is_system=True
    )

    db.add_all([super_admin, admin, analyst, manager, user])
    db.commit()

    # Assign permissions to roles
    # Super Admin gets wildcard
    db.add(RolePermission(
        role_id=super_admin.id,
        permission_id=next(p.id for p in permissions if p.name == "*:*")
    ))

    # Admin gets most permissions
    admin_perms = ["findings:read", "findings:write", "findings:delete", "scans:read", "scans:execute",
                   "repositories:read", "repositories:write", "organizations:read", "organizations:write",
                   "projects:read", "reports:read", "admin:manage"]
    for perm_name in admin_perms:
        perm_id = next(p.id for p in permissions if p.name == perm_name)
        db.add(RolePermission(role_id=admin.id, permission_id=perm_id))

    # Analyst gets read/write for findings and scans
    analyst_perms = ["findings:read", "findings:write", "scans:read", "scans:execute",
                     "repositories:read", "projects:read", "reports:read"]
    for perm_name in analyst_perms:
        perm_id = next(p.id for p in permissions if p.name == perm_name)
        db.add(RolePermission(role_id=analyst.id, permission_id=perm_id))

    # Manager gets read-only
    manager_perms = ["findings:read", "scans:read", "repositories:read",
                     "organizations:read", "projects:read", "reports:read"]
    for perm_name in manager_perms:
        perm_id = next(p.id for p in permissions if p.name == perm_name)
        db.add(RolePermission(role_id=manager.id, permission_id=perm_id))

    # User gets minimal read
    user_perms = ["findings:read", "projects:read"]
    for perm_name in user_perms:
        perm_id = next(p.id for p in permissions if p.name == perm_name)
        db.add(RolePermission(role_id=user.id, permission_id=perm_id))

    db.commit()


@pytest.fixture(scope="function")
def test_client(test_db):
    """
    Create a test client with database session override.

    Args:
        test_db: Test database session fixture

    Yields:
        TestClient: FastAPI test client
    """
    # Override database dependency
    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db

    client = TestClient(app)

    yield client

    # Clean up
    app.dependency_overrides.clear()


@pytest.fixture
def test_tenant(test_db):
    """Create a test organization/tenant."""
    org = Organization(
        id=uuid.uuid4(),
        name="test-org",
        display_name="Test Organization",
        github_org="test-github-org",
        is_active=True
    )
    test_db.add(org)
    test_db.commit()
    test_db.refresh(org)
    return org


@pytest.fixture
def test_user_super_admin(test_db, test_tenant):
    """Create a test user with super_admin role."""
    user_data = {
        "email": "super@test.com",
        "name": "Super Admin",
        "sub": f"test-super-{uuid.uuid4()}",
        "provider": "test"
    }

    # Assign super_admin role
    role = test_db.query(Role).filter(Role.name == "super_admin").first()
    user_role = UserRole(
        user_sub=user_data["sub"],
        tenant_id=str(test_tenant.id),
        role_id=role.id
    )
    test_db.add(user_role)
    test_db.commit()

    # Create token for authentication (mock)
    user_data["token"] = "test-token-super-admin"

    return User(**user_data)


@pytest.fixture
def test_user_analyst(test_db, test_tenant):
    """Create a test user with analyst role."""
    user_data = {
        "email": "analyst@test.com",
        "name": "Test Analyst",
        "sub": f"test-analyst-{uuid.uuid4()}",
        "provider": "test"
    }

    # Assign analyst role
    role = test_db.query(Role).filter(Role.name == "analyst").first()
    user_role = UserRole(
        user_sub=user_data["sub"],
        tenant_id=str(test_tenant.id),
        role_id=role.id
    )
    test_db.add(user_role)
    test_db.commit()

    user_data["token"] = "test-token-analyst"

    return User(**user_data)


@pytest.fixture
def test_user_manager(test_db, test_tenant):
    """Create a test user with manager role."""
    user_data = {
        "email": "manager@test.com",
        "name": "Test Manager",
        "sub": f"test-manager-{uuid.uuid4()}",
        "provider": "test"
    }

    # Assign manager role
    role = test_db.query(Role).filter(Role.name == "manager").first()
    user_role = UserRole(
        user_sub=user_data["sub"],
        tenant_id=str(test_tenant.id),
        role_id=role.id
    )
    test_db.add(user_role)
    test_db.commit()

    user_data["token"] = "test-token-manager"

    return User(**user_data)


@pytest.fixture
def test_user_no_role(test_db, test_tenant):
    """Create a test user without any role assignment."""
    user_data = {
        "email": "norole@test.com",
        "name": "No Role User",
        "sub": f"test-norole-{uuid.uuid4()}",
        "provider": "test"
    }

    # No role assignment
    user_data["token"] = "test-token-no-role"

    return User(**user_data)


@pytest.fixture
def test_user_admin(test_db, test_tenant):
    """Create a test user with admin role."""
    user_data = {
        "email": "admin@test.com",
        "name": "Test Admin",
        "sub": f"test-admin-{uuid.uuid4()}",
        "provider": "test"
    }

    # Assign admin role
    role = test_db.query(Role).filter(Role.name == "admin").first()
    user_role = UserRole(
        user_sub=user_data["sub"],
        tenant_id=str(test_tenant.id),
        role_id=role.id
    )
    test_db.add(user_role)
    test_db.commit()

    user_data["token"] = "test-token-admin"

    return User(**user_data)
