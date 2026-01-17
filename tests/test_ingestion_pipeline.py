"""
Tests for ingestion pipeline functions.
Ensures all ingestion functions maintain data integrity and deduplication.
"""

import pytest
import json
from pathlib import Path
from sqlalchemy import text
from datetime import datetime


class TestGitleaksIngestion:
    """Test gitleaks ingestion functionality."""

    @pytest.fixture
    def sample_gitleaks_report(self, tmp_path):
        """Create sample gitleaks report."""
        report = tmp_path / "test_repo_gitleaks.json"
        report.write_text(json.dumps([
            {
                "Description": "Generic API Key",
                "StartLine": 10,
                "EndLine": 10,
                "StartColumn": 5,
                "EndColumn": 45,
                "Match": "api_key=sk_test_1234567890",
                "Secret": "sk_test_1234567890",
                "File": "config.py",
                "SymlinkFile": "",
                "Commit": "abc123",
                "Entropy": 3.5,
                "Author": "test@example.com",
                "Email": "test@example.com",
                "Date": "2026-01-17T10:00:00Z",
                "Message": "Add config",
                "Tags": [],
                "RuleID": "generic-api-key",
                "Fingerprint": "abc123:config.py:generic-api-key:10"
            }
        ]))
        return report

    @pytest.mark.quick
    def test_gitleaks_creates_secret_finding(self, db_session, sample_gitleaks_report):
        """Test gitleaks ingestion creates finding with correct type."""
        from ingest_reports import ingest_gitleaks

        repo_id = "test-repo-id-gitleaks"
        org_id = "test-org-id"

        count = ingest_gitleaks(db_session, repo_id, org_id, sample_gitleaks_report)

        assert count == 1, "Should ingest 1 finding"

        # Verify finding in database
        finding = db_session.execute(
            text("SELECT * FROM findings WHERE repository_id = :repo_id"),
            {"repo_id": repo_id}
        ).fetchone()

        assert finding is not None, "Finding should exist"
        assert finding.finding_type == "secret", f"Type should be 'secret', got '{finding.finding_type}'"
        assert finding.scanner_name == "gitleaks"
        assert finding.organization_id == org_id
        assert finding.severity is not None

    @pytest.mark.quick
    def test_gitleaks_deduplication(self, db_session, sample_gitleaks_report):
        """Test gitleaks doesn't create duplicates on re-ingestion."""
        from ingest_reports import ingest_gitleaks

        repo_id = "test-repo-id-gitleaks-dedup"
        org_id = "test-org-id"

        # First ingestion
        count1 = ingest_gitleaks(db_session, repo_id, org_id, sample_gitleaks_report)
        assert count1 == 1, "First ingestion should create 1 finding"

        # Second ingestion (should skip duplicate)
        count2 = ingest_gitleaks(db_session, repo_id, org_id, sample_gitleaks_report)
        assert count2 == 0, "Second ingestion should not create duplicate"

        # Verify only one finding exists
        total = db_session.execute(
            text("SELECT COUNT(*) FROM findings WHERE repository_id = :repo_id"),
            {"repo_id": repo_id}
        ).scalar()

        assert total == 1, f"Should have exactly 1 finding, got {total}"


class TestAPIEndpointIngestion:
    """Test API endpoint ingestion functionality."""

    @pytest.fixture
    def sample_api_endpoints(self, tmp_path):
        """Create sample API endpoints file."""
        api_file = tmp_path / "test_repo_api_endpoints.json"
        api_file.write_text(json.dumps({
            "inbound_endpoints": [
                {
                    "category": "inbound",
                    "endpoint_path": "/api/v1/users",
                    "http_method": "GET",
                    "path": "routes/users.js",
                    "line": 10,
                    "metadata": {"framework": "express"}
                }
            ],
            "outbound_endpoints": [
                {
                    "category": "outbound",
                    "endpoint_path": "https://api.example.com/data",
                    "http_method": "POST",
                    "path": "services/api.js",
                    "line": 25,
                    "metadata": {"framework": "axios"}
                }
            ]
        }))
        return api_file

    @pytest.mark.quick
    def test_api_endpoint_ingestion(self, db_session, sample_api_endpoints):
        """Test API endpoint ingestion creates correct records."""
        from ingest_reports import ingest_api_endpoints

        repo_id = "test-repo-id-api"
        org_id = "test-org-id"

        count = ingest_api_endpoints(db_session, repo_id, org_id, sample_api_endpoints)

        assert count == 2, f"Should ingest 2 endpoints, got {count}"

        # Verify endpoints
        endpoints = db_session.execute(
            text("SELECT * FROM api_endpoints WHERE repository_id = :repo_id ORDER BY direction"),
            {"repo_id": repo_id}
        ).fetchall()

        assert len(endpoints) == 2, f"Should have 2 endpoints in DB, got {len(endpoints)}"

        # Check directions
        directions = [e.direction for e in endpoints]
        assert "inbound" in directions, "Should have inbound endpoint"
        assert "outbound" in directions, "Should have outbound endpoint"

        # Check specific endpoint data
        inbound = next(e for e in endpoints if e.direction == "inbound")
        assert inbound.endpoint_url == "/api/v1/users"
        assert inbound.http_method == "GET"

    @pytest.mark.quick
    def test_api_endpoint_deduplication(self, db_session, sample_api_endpoints):
        """Test API endpoint deduplication."""
        from ingest_reports import ingest_api_endpoints

        repo_id = "test-repo-id-api-dedup"
        org_id = "test-org-id"

        # First ingestion
        count1 = ingest_api_endpoints(db_session, repo_id, org_id, sample_api_endpoints)
        assert count1 == 2, "First ingestion should create 2 endpoints"

        # Second ingestion (should skip duplicates)
        count2 = ingest_api_endpoints(db_session, repo_id, org_id, sample_api_endpoints)
        assert count2 == 0, "Second ingestion should not create duplicates"

        # Verify only 2 endpoints exist
        total = db_session.execute(
            text("SELECT COUNT(*) FROM api_endpoints WHERE repository_id = :repo_id"),
            {"repo_id": repo_id}
        ).scalar()

        assert total == 2, f"Should have exactly 2 endpoints, got {total}"


class TestThreatAssessmentIngestion:
    """Test AI threat assessment ingestion functionality."""

    @pytest.fixture
    def sample_threats(self, tmp_path):
        """Create sample threat matrix file."""
        threat_file = tmp_path / "test_repo_threat_matrix.json"
        threat_file.write_text(json.dumps([
            {
                "endpoint": "/api/admin",
                "file": "/tmp/scan/routes/admin.js",
                "line": 15,
                "vulnerabilities": [
                    {
                        "owasp_id": "API2:2023",
                        "title": "Broken Authentication",
                        "severity": "HIGH",
                        "description": "No authentication check detected"
                    }
                ],
                "risk_score": 8
            },
            {
                "endpoint": "/api/users/:id",
                "file": "/tmp/scan/routes/users.js",
                "line": 42,
                "vulnerabilities": [
                    {
                        "owasp_id": "API1:2023",
                        "title": "Broken Object Level Authorization",
                        "severity": "MEDIUM",
                        "description": "No authorization check"
                    }
                ],
                "risk_score": 6
            }
        ]))
        return threat_file

    @pytest.mark.quick
    def test_threat_assessment_ingestion(self, db_session, sample_threats):
        """Test AI threat assessment ingestion."""
        from ingest_reports import ingest_threat_assessments

        repo_id = "test-repo-id-threats"
        org_id = "test-org-id"

        count = ingest_threat_assessments(db_session, repo_id, org_id, sample_threats)

        assert count == 2, f"Should ingest 2 threat assessments, got {count}"

        # Verify threats in database
        threats = db_session.execute(
            text("SELECT * FROM api_threat_assessments WHERE repository_id = :repo_id ORDER BY risk_score DESC"),
            {"repo_id": repo_id}
        ).fetchall()

        assert len(threats) == 2, f"Should have 2 threats in DB, got {len(threats)}"

        # Check high-risk threat
        high_risk = threats[0]
        assert high_risk.owasp_id == "API2:2023"
        assert high_risk.severity == "HIGH"
        assert high_risk.risk_score == 8
        assert high_risk.endpoint == "/api/admin"

        # Check medium-risk threat
        medium_risk = threats[1]
        assert medium_risk.owasp_id == "API1:2023"
        assert medium_risk.severity == "MEDIUM"
        assert medium_risk.risk_score == 6

    @pytest.mark.quick
    def test_threat_assessment_deduplication(self, db_session, sample_threats):
        """Test threat assessment deduplication."""
        from ingest_reports import ingest_threat_assessments

        repo_id = "test-repo-id-threats-dedup"
        org_id = "test-org-id"

        # First ingestion
        count1 = ingest_threat_assessments(db_session, repo_id, org_id, sample_threats)
        assert count1 == 2, "First ingestion should create 2 assessments"

        # Second ingestion (should skip duplicates)
        count2 = ingest_threat_assessments(db_session, repo_id, org_id, sample_threats)
        assert count2 == 0, "Second ingestion should not create duplicates"

        # Verify only 2 assessments exist
        total = db_session.execute(
            text("SELECT COUNT(*) FROM api_threat_assessments WHERE repository_id = :repo_id"),
            {"repo_id": repo_id}
        ).scalar()

        assert total == 2, f"Should have exactly 2 assessments, got {total}"


class TestOpenAPISpecIngestion:
    """Test OpenAPI specification ingestion functionality."""

    @pytest.fixture
    def sample_openapi_spec(self, tmp_path):
        """Create sample OpenAPI spec file."""
        spec_file = tmp_path / "test_repo_openapi.json"
        spec_file.write_text(json.dumps({
            "openapi": "3.0.0",
            "info": {
                "title": "Test API",
                "version": "1.0.0"
            },
            "paths": {
                "/users": {
                    "get": {"summary": "Get users"}
                },
                "/users/{id}": {
                    "get": {"summary": "Get user by ID"}
                }
            }
        }))
        return spec_file

    @pytest.mark.quick
    def test_openapi_spec_ingestion(self, db_session, sample_openapi_spec):
        """Test OpenAPI spec ingestion."""
        from ingest_reports import ingest_openapi_specs

        repo_id = "test-repo-id-openapi"
        org_id = "test-org-id"

        count = ingest_openapi_specs(db_session, repo_id, org_id, sample_openapi_spec)

        assert count == 1, f"Should ingest 1 OpenAPI spec, got {count}"

        # Verify spec in database
        spec = db_session.execute(
            text("SELECT * FROM openapi_specs WHERE repository_id = :repo_id"),
            {"repo_id": repo_id}
        ).fetchone()

        assert spec is not None, "OpenAPI spec should exist"
        assert spec.spec_format == "json"
        assert spec.version == "1.0.0"
        assert spec.endpoint_count == 2
        assert "Test API" in spec.spec_content

    @pytest.mark.quick
    def test_openapi_spec_update(self, db_session, sample_openapi_spec, tmp_path):
        """Test OpenAPI spec updates existing record."""
        from ingest_reports import ingest_openapi_specs

        repo_id = "test-repo-id-openapi-update"
        org_id = "test-org-id"

        # First ingestion
        count1 = ingest_openapi_specs(db_session, repo_id, org_id, sample_openapi_spec)
        assert count1 == 1, "First ingestion should create 1 spec"

        # Create updated spec
        updated_spec = tmp_path / "test_repo_openapi_v2.json"
        updated_spec.write_text(json.dumps({
            "openapi": "3.0.0",
            "info": {
                "title": "Test API",
                "version": "2.0.0"
            },
            "paths": {
                "/users": {"get": {"summary": "Get users"}},
                "/users/{id}": {"get": {"summary": "Get user by ID"}},
                "/products": {"get": {"summary": "Get products"}}
            }
        }))

        # Second ingestion (should update existing)
        count2 = ingest_openapi_specs(db_session, repo_id, org_id, updated_spec)
        assert count2 == 1, "Second ingestion should update existing spec"

        # Verify only one spec exists with updated data
        total = db_session.execute(
            text("SELECT COUNT(*) FROM openapi_specs WHERE repository_id = :repo_id"),
            {"repo_id": repo_id}
        ).scalar()
        assert total == 1, f"Should have exactly 1 spec, got {total}"

        spec = db_session.execute(
            text("SELECT * FROM openapi_specs WHERE repository_id = :repo_id"),
            {"repo_id": repo_id}
        ).fetchone()
        assert spec.version == "2.0.0", "Version should be updated"
        assert spec.endpoint_count == 3, "Endpoint count should be updated"
