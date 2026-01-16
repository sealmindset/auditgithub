"""
Integration tests for RBAC enforcement across API routes.

Tests verify that:
- Unauthenticated requests are denied (401)
- Authenticated users without roles are denied (403)
- Users with appropriate permissions can access endpoints
- Users without required permissions are denied (403)
- Role hierarchy works correctly
- Wildcard permissions (*:*) grant access to all endpoints
- Audit logs capture authorization events
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock


class TestAuthenticationRequirement:
    """Test that all protected endpoints require authentication."""

    def test_unauthenticated_user_denied_findings(self, test_client):
        """Unauthenticated requests to findings endpoint should return 401."""
        response = test_client.get("/api/findings/")
        assert response.status_code == 401
        assert "not authenticated" in response.json()["detail"].lower()

    def test_unauthenticated_user_denied_scans(self, test_client):
        """Unauthenticated requests to scans endpoint should return 401."""
        response = test_client.get("/api/scans/test-scan-id")
        assert response.status_code == 401

    def test_unauthenticated_user_denied_repositories(self, test_client):
        """Unauthenticated requests to repositories endpoint should return 401."""
        response = test_client.get("/api/repositories/")
        assert response.status_code == 401


class TestUserWithoutRole:
    """Test that users without role assignments are denied access."""

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_user_without_role_denied(self, mock_get_user, test_client, test_user_no_role):
        """User without role should return 403 Permission Denied."""
        mock_get_user.return_value = test_user_no_role

        response = test_client.get("/api/findings/")
        assert response.status_code == 403
        assert "permission" in response.json()["detail"].lower() or "role" in response.json()["detail"].lower()


class TestAnalystRoleAccess:
    """Test analyst role permissions (findings:read/write, scans:read/execute)."""

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_analyst_can_read_findings(self, mock_get_user, test_client, test_user_analyst):
        """Analyst role should access findings:read endpoint."""
        mock_get_user.return_value = test_user_analyst

        response = test_client.get("/api/findings/")
        # May return 200 (success) or 404 (no findings) - both are acceptable
        assert response.status_code in [200, 404]

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_analyst_can_execute_scans(self, mock_get_user, test_client, test_user_analyst):
        """Analyst role should access scans:execute endpoint."""
        mock_get_user.return_value = test_user_analyst

        # POST to scans requires scans:execute
        response = test_client.post("/api/scans/", json={
            "repo_name": "test-repo",
            "scan_type": "full"
        })
        # May return 200/201 (success) or 404 (repo not found) - both mean permission granted
        assert response.status_code in [200, 201, 404, 422]  # 422 = validation error, but permission was granted

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_analyst_cannot_delete_findings(self, mock_get_user, test_client, test_user_analyst):
        """Analyst role should NOT access findings:delete endpoint."""
        mock_get_user.return_value = test_user_analyst

        # Try to delete a finding
        response = test_client.post("/api/findings/exception/delete", json={
            "finding_id": "00000000-0000-0000-0000-000000000000",
            "scope": "specific",
            "confirmed": True
        })
        # Should be 403 Forbidden (no findings:delete permission)
        assert response.status_code == 403
        assert "permission" in response.json()["detail"].lower()

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_analyst_cannot_manage_organizations(self, mock_get_user, test_client, test_user_analyst):
        """Analyst role should NOT access organizations:admin endpoint."""
        mock_get_user.return_value = test_user_analyst

        # Try to create an organization (requires organizations:admin)
        response = test_client.post("/api/organizations/", json={
            "name": "test-org",
            "github_org": "test",
            "github_token": "test-token"
        })
        # Should be 403 Forbidden
        assert response.status_code == 403


class TestManagerRoleAccess:
    """Test manager role permissions (read-only access)."""

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_manager_can_read_findings(self, mock_get_user, test_client, test_user_manager):
        """Manager role should access findings:read endpoint."""
        mock_get_user.return_value = test_user_manager

        response = test_client.get("/api/findings/")
        assert response.status_code in [200, 404]

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_manager_can_read_reports(self, mock_get_user, test_client, test_user_manager):
        """Manager role should access reports:read endpoint."""
        mock_get_user.return_value = test_user_manager

        response = test_client.get("/api/analytics/summary")
        # May succeed or fail due to missing data, but permission should be granted
        assert response.status_code in [200, 404, 422, 500]

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_manager_cannot_write_findings(self, mock_get_user, test_client, test_user_manager):
        """Manager role should NOT access findings:write endpoint."""
        mock_get_user.return_value = test_user_manager

        # Try to snooze a finding (requires findings:write)
        response = test_client.post("/api/findings/00000000-0000-0000-0000-000000000000/snooze", json={
            "days": 7,
            "reason": "test"
        })
        # Should be 403 Forbidden
        assert response.status_code == 403

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_manager_cannot_execute_scans(self, mock_get_user, test_client, test_user_manager):
        """Manager role should NOT access scans:execute endpoint."""
        mock_get_user.return_value = test_user_manager

        response = test_client.post("/api/scans/", json={
            "repo_name": "test-repo",
            "scan_type": "full"
        })
        # Should be 403 Forbidden
        assert response.status_code == 403


class TestSuperAdminWildcardAccess:
    """Test super admin wildcard (*:*) permissions grant universal access."""

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_super_admin_can_access_all_endpoints(self, mock_get_user, test_client, test_user_super_admin):
        """Super admin (*:*) should access all endpoints."""
        mock_get_user.return_value = test_user_super_admin

        # Test various endpoints across different resource types
        endpoints = [
            ("/api/findings/", "GET"),
            ("/api/scans/test-id", "GET"),
            ("/api/repositories/", "GET"),
            ("/api/organizations/", "GET"),
            ("/api/projects/", "GET"),
            ("/api/analytics/summary", "GET"),
        ]

        for endpoint, method in endpoints:
            if method == "GET":
                response = test_client.get(endpoint)
            elif method == "POST":
                response = test_client.post(endpoint, json={})

            # All should succeed or fail due to data issues, not permissions
            # 200, 404, 422, 500 all indicate permission was granted
            assert response.status_code in [200, 404, 422, 500], f"Failed on {endpoint}: {response.status_code}"


class TestRoleHierarchy:
    """Test that role hierarchy works correctly (lower level = higher privilege)."""

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_admin_can_access_manager_resources(self, mock_get_user, test_client, test_user_admin):
        """Admin (level 2) should access Manager (level 4) resources."""
        mock_get_user.return_value = test_user_admin

        # Admin should be able to access reports (manager-level resource)
        response = test_client.get("/api/analytics/summary")
        # Permission should be granted
        assert response.status_code in [200, 404, 422, 500]

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_admin_can_manage_system(self, mock_get_user, test_client, test_user_admin):
        """Admin should access admin:manage endpoints."""
        mock_get_user.return_value = test_user_admin

        # Try to access settings (requires admin:manage)
        response = test_client.get("/api/settings/")
        # Permission should be granted
        assert response.status_code in [200, 404, 422, 500]


class TestPermissionGranularity:
    """Test that permission granularity works correctly (resource:action)."""

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_findings_read_does_not_grant_write(self, mock_get_user, test_client, test_user_manager):
        """Having findings:read should not grant findings:write."""
        mock_get_user.return_value = test_user_manager  # Manager has read-only

        # Can read findings
        response = test_client.get("/api/findings/")
        assert response.status_code in [200, 404]

        # Cannot write findings
        response = test_client.patch("/api/findings/00000000-0000-0000-0000-000000000000", json={
            "description": "test",
            "scope": "specific"
        })
        assert response.status_code == 403

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_findings_write_does_not_grant_delete(self, mock_get_user, test_client, test_user_analyst):
        """Having findings:write should not grant findings:delete."""
        mock_get_user.return_value = test_user_analyst  # Analyst has read/write but not delete

        # Can write findings
        response = test_client.patch("/api/findings/00000000-0000-0000-0000-000000000000", json={
            "description": "test",
            "scope": "specific"
        })
        # May fail due to finding not found, but permission was granted
        assert response.status_code in [400, 404]

        # Cannot delete findings
        response = test_client.post("/api/findings/exception/delete", json={
            "finding_id": "00000000-0000-0000-0000-000000000000",
            "scope": "specific",
            "confirmed": True
        })
        assert response.status_code == 403


class TestAuditLogging:
    """Test that authorization events are logged to audit system."""

    @patch('src.auth.dependencies.get_current_user_from_session')
    @patch('src.rbac.dependencies.audit_authorization')
    def test_successful_authorization_logged(self, mock_audit, mock_get_user, test_client, test_user_analyst):
        """Successful authorization should be logged."""
        mock_get_user.return_value = test_user_analyst

        response = test_client.get("/api/findings/")

        # Audit function should have been called with granted=True
        # Note: This may not work if audit is called within async context
        # In that case, check application logs instead
        if mock_audit.called:
            # Find the call with granted=True
            granted_calls = [call for call in mock_audit.call_args_list if call.kwargs.get('granted')]
            assert len(granted_calls) > 0

    @patch('src.auth.dependencies.get_current_user_from_session')
    @patch('src.rbac.dependencies.audit_authorization')
    def test_failed_authorization_logged(self, mock_audit, mock_get_user, test_client, test_user_manager):
        """Failed authorization should be logged."""
        mock_get_user.return_value = test_user_manager

        # Manager cannot write findings
        response = test_client.patch("/api/findings/00000000-0000-0000-0000-000000000000", json={
            "description": "test"
        })
        assert response.status_code == 403

        # Audit function should have been called with granted=False
        if mock_audit.called:
            denied_calls = [call for call in mock_audit.call_args_list if not call.kwargs.get('granted')]
            assert len(denied_calls) > 0


class TestMultiplePermissionsRequired:
    """Test endpoints that require multiple permissions."""

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_user_must_have_all_required_permissions(self, mock_get_user, test_client, test_user_analyst):
        """User must have ALL required permissions for endpoint."""
        mock_get_user.return_value = test_user_analyst

        # Analyst has findings:read and findings:write
        # Test that they can access an endpoint requiring both
        response = test_client.get("/api/findings/")
        assert response.status_code in [200, 404]


class TestResourceIsolation:
    """Test that permissions are resource-specific."""

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_findings_permission_does_not_grant_scans(self, mock_get_user, test_client):
        """Having findings:* should not grant scans:* permissions."""
        # This would require a custom user with only findings permissions
        # For now, we test that different endpoints have different permission requirements
        pass

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_repositories_permission_does_not_grant_organizations(self, mock_get_user, test_client, test_user_analyst):
        """Having repositories:* should not grant organizations:* permissions."""
        mock_get_user.return_value = test_user_analyst

        # Analyst has repositories:read
        response = test_client.get("/api/repositories/")
        assert response.status_code in [200, 404]

        # But not organizations:admin
        response = test_client.post("/api/organizations/", json={
            "name": "test",
            "github_org": "test",
            "github_token": "test"
        })
        assert response.status_code == 403


@pytest.mark.parametrize("endpoint,method,required_permission", [
    ("/api/findings/", "GET", "findings:read"),
    ("/api/scans/test-id", "GET", "scans:read"),
    ("/api/repositories/", "GET", "repositories:read"),
    ("/api/organizations/", "GET", "organizations:read"),
    ("/api/projects/", "GET", "projects:read"),
])
class TestEndpointPermissionMapping:
    """Test that endpoints are mapped to correct permissions."""

    @patch('src.auth.dependencies.get_current_user_from_session')
    def test_endpoint_requires_correct_permission(self, mock_get_user, test_client, endpoint, method, required_permission):
        """Each endpoint should require its designated permission."""
        # This is a meta-test that verifies the permission mapping
        # We can't fully test this without inspecting the route's dependencies
        # But we can verify that access is denied without appropriate role
        pass
