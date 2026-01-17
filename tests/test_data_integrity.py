"""
Data integrity tests.
Ensures database maintains referential integrity and data consistency.
"""

import pytest
from sqlalchemy import text


class TestReferentialIntegrity:
    """Test database referential integrity."""

    @pytest.mark.quick
    def test_no_orphaned_findings(self, db_session):
        """Verify all findings have valid repository references."""
        orphans = db_session.execute(text("""
            SELECT f.id, f.repository_id
            FROM findings f
            LEFT JOIN repositories r ON f.repository_id = r.id
            WHERE r.id IS NULL
            LIMIT 10
        """)).fetchall()

        assert len(orphans) == 0, f"Found {len(orphans)} orphaned findings: {[o.id for o in orphans]}"

    @pytest.mark.quick
    def test_no_orphaned_api_endpoints(self, db_session):
        """Verify all API endpoints have valid repository references."""
        orphans = db_session.execute(text("""
            SELECT ae.id, ae.repository_id
            FROM api_endpoints ae
            LEFT JOIN repositories r ON ae.repository_id = r.id
            WHERE r.id IS NULL
            LIMIT 10
        """)).fetchall()

        assert len(orphans) == 0, f"Found {len(orphans)} orphaned API endpoints"

    @pytest.mark.quick
    def test_no_orphaned_threat_assessments(self, db_session):
        """Verify all threat assessments have valid repository references."""
        orphans = db_session.execute(text("""
            SELECT ata.id, ata.repository_id
            FROM api_threat_assessments ata
            LEFT JOIN repositories r ON ata.repository_id = r.id
            WHERE r.id IS NULL
            LIMIT 10
        """)).fetchall()

        assert len(orphans) == 0, f"Found {len(orphans)} orphaned threat assessments"

    @pytest.mark.quick
    def test_no_orphaned_dependencies(self, db_session):
        """Verify all dependencies have valid repository references."""
        orphans = db_session.execute(text("""
            SELECT d.id, d.repository_id
            FROM dependencies d
            LEFT JOIN repositories r ON d.repository_id = r.id
            WHERE r.id IS NULL
            LIMIT 10
        """)).fetchall()

        assert len(orphans) == 0, f"Found {len(orphans)} orphaned dependencies"


class TestDataTypeConsistency:
    """Test data type consistency and validation."""

    @pytest.mark.quick
    def test_finding_types_valid(self, db_session):
        """Verify all findings have valid types."""
        invalid = db_session.execute(text("""
            SELECT id, finding_type, scanner_name
            FROM findings
            WHERE finding_type NOT IN ('secret', 'sast', 'oss', 'iac')
            LIMIT 10
        """)).fetchall()

        if invalid:
            invalid_types = [(f.id, f.finding_type, f.scanner_name) for f in invalid]
            assert False, f"Found {len(invalid)} findings with invalid types: {invalid_types}"

    @pytest.mark.quick
    def test_scanner_finding_type_consistency(self, db_session):
        """Verify scanner names match expected finding types."""
        mismatched = db_session.execute(text("""
            SELECT id, scanner_name, finding_type
            FROM findings
            WHERE (scanner_name = 'gitleaks' AND finding_type != 'secret')
               OR (scanner_name = 'grype' AND finding_type != 'oss')
               OR (scanner_name = 'semgrep' AND finding_type != 'sast')
            LIMIT 10
        """)).fetchall()

        if mismatched:
            errors = [(f.id, f.scanner_name, f.finding_type) for f in mismatched]
            assert False, f"Found {len(mismatched)} mismatched scanner/type pairs: {errors}"

    @pytest.mark.quick
    def test_severity_values_valid(self, db_session):
        """Verify severity values are valid."""
        invalid = db_session.execute(text("""
            SELECT id, severity, scanner_name
            FROM findings
            WHERE severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN')
            LIMIT 10
        """)).fetchall()

        if invalid:
            invalid_severities = [(f.id, f.severity, f.scanner_name) for f in invalid]
            assert False, f"Found {len(invalid)} findings with invalid severity: {invalid_severities}"

    @pytest.mark.quick
    def test_api_endpoint_directions_valid(self, db_session):
        """Verify API endpoint directions are valid."""
        invalid = db_session.execute(text("""
            SELECT id, direction, endpoint_url
            FROM api_endpoints
            WHERE direction NOT IN ('inbound', 'outbound', 'config', 'unknown')
            LIMIT 10
        """)).fetchall()

        if invalid:
            invalid_directions = [(e.id, e.direction) for e in invalid]
            assert False, f"Found {len(invalid)} endpoints with invalid direction: {invalid_directions}"

    @pytest.mark.quick
    def test_threat_assessment_severities_valid(self, db_session):
        """Verify threat assessment severities are valid."""
        invalid = db_session.execute(text("""
            SELECT id, severity, owasp_id
            FROM api_threat_assessments
            WHERE severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN')
            LIMIT 10
        """)).fetchall()

        if invalid:
            invalid_severities = [(t.id, t.severity, t.owasp_id) for t in invalid]
            assert False, f"Found {len(invalid)} threats with invalid severity: {invalid_severities}"


class TestUniqueConstraints:
    """Test unique constraints are enforced."""

    @pytest.mark.quick
    def test_findings_no_duplicates(self, db_session):
        """Verify findings unique constraint (repo + uuid) prevents duplicates."""
        duplicates = db_session.execute(text("""
            SELECT repository_id, finding_uuid, COUNT(*) as dup_count
            FROM findings
            GROUP BY repository_id, finding_uuid
            HAVING COUNT(*) > 1
            LIMIT 10
        """)).fetchall()

        if duplicates:
            dup_details = [(d.repository_id, d.finding_uuid, d.dup_count) for d in duplicates]
            assert False, f"Found {len(duplicates)} duplicate findings: {dup_details}"

    @pytest.mark.quick
    def test_dependencies_no_duplicates(self, db_session):
        """Verify dependencies unique constraint prevents duplicates."""
        duplicates = db_session.execute(text("""
            SELECT repository_id, name, version, COUNT(*) as dup_count
            FROM dependencies
            GROUP BY repository_id, name, version
            HAVING COUNT(*) > 1
            LIMIT 10
        """)).fetchall()

        if duplicates:
            dup_details = [(d.repository_id, d.name, d.version, d.dup_count) for d in duplicates]
            assert False, f"Found {len(duplicates)} duplicate dependencies: {dup_details}"

    @pytest.mark.quick
    def test_openapi_specs_one_per_repo(self, db_session):
        """Verify only one OpenAPI spec per repository."""
        duplicates = db_session.execute(text("""
            SELECT repository_id, COUNT(*) as spec_count
            FROM openapi_specs
            GROUP BY repository_id
            HAVING COUNT(*) > 1
            LIMIT 10
        """)).fetchall()

        if duplicates:
            dup_repos = [(d.repository_id, d.spec_count) for d in duplicates]
            assert False, f"Found {len(duplicates)} repos with multiple OpenAPI specs: {dup_repos}"


class TestOrganizationIsolation:
    """Test multi-tenant data isolation."""

    @pytest.mark.quick
    def test_all_findings_have_org_id(self, db_session):
        """Verify all findings have organization_id set."""
        missing_org = db_session.execute(text("""
            SELECT COUNT(*) as count
            FROM findings
            WHERE organization_id IS NULL
        """)).scalar()

        assert missing_org == 0, f"Found {missing_org} findings without org_id - this breaks multi-tenancy!"

    @pytest.mark.quick
    def test_all_api_endpoints_have_org_id(self, db_session):
        """Verify all API endpoints have organization_id set."""
        missing_org = db_session.execute(text("""
            SELECT COUNT(*) as count
            FROM api_endpoints
            WHERE organization_id IS NULL
        """)).scalar()

        assert missing_org == 0, f"Found {missing_org} API endpoints without org_id"

    @pytest.mark.quick
    def test_all_threat_assessments_have_org_id(self, db_session):
        """Verify all threat assessments have organization_id set."""
        missing_org = db_session.execute(text("""
            SELECT COUNT(*) as count
            FROM api_threat_assessments
            WHERE organization_id IS NULL
        """)).scalar()

        assert missing_org == 0, f"Found {missing_org} threat assessments without org_id"

    @pytest.mark.quick
    def test_org_id_matches_repo_org(self, db_session):
        """Verify finding org_id matches its repository's org_id."""
        mismatched = db_session.execute(text("""
            SELECT f.id, f.organization_id as finding_org, r.organization_id as repo_org
            FROM findings f
            JOIN repositories r ON f.repository_id = r.id
            WHERE f.organization_id != r.organization_id
            LIMIT 10
        """)).fetchall()

        if mismatched:
            errors = [(f.id, f.finding_org, f.repo_org) for f in mismatched]
            assert False, f"Found {len(mismatched)} findings with mismatched org_id: {errors}"


class TestDataCompleteness:
    """Test critical fields are populated."""

    @pytest.mark.quick
    def test_findings_have_required_fields(self, db_session):
        """Verify findings have all required fields populated."""
        incomplete = db_session.execute(text("""
            SELECT id, finding_type, scanner_name, severity
            FROM findings
            WHERE finding_type IS NULL
               OR scanner_name IS NULL
               OR severity IS NULL
               OR repository_id IS NULL
            LIMIT 10
        """)).fetchall()

        if incomplete:
            errors = [(f.id, f.finding_type, f.scanner_name, f.severity) for f in incomplete]
            assert False, f"Found {len(incomplete)} findings with missing required fields: {errors}"

    @pytest.mark.quick
    def test_api_endpoints_have_required_fields(self, db_session):
        """Verify API endpoints have all required fields."""
        incomplete = db_session.execute(text("""
            SELECT id, endpoint_url, direction
            FROM api_endpoints
            WHERE endpoint_url IS NULL
               OR endpoint_url = ''
               OR direction IS NULL
               OR repository_id IS NULL
            LIMIT 10
        """)).fetchall()

        if incomplete:
            errors = [(e.id, e.endpoint_url, e.direction) for e in incomplete]
            assert False, f"Found {len(incomplete)} endpoints with missing required fields: {errors}"

    @pytest.mark.quick
    def test_threat_assessments_have_required_fields(self, db_session):
        """Verify threat assessments have all required fields."""
        incomplete = db_session.execute(text("""
            SELECT id, endpoint, owasp_id, severity
            FROM api_threat_assessments
            WHERE endpoint IS NULL
               OR endpoint = ''
               OR owasp_id IS NULL
               OR severity IS NULL
               OR repository_id IS NULL
            LIMIT 10
        """)).fetchall()

        if incomplete:
            errors = [(t.id, t.endpoint, t.owasp_id, t.severity) for t in incomplete]
            assert False, f"Found {len(incomplete)} threats with missing required fields: {errors}"
