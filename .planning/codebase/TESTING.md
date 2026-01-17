# Testing Patterns

**Analysis Date:** 2026-01-17

## Test Framework

**Runner:**
- pytest 7.4.0+
- Config: `pytest.ini` in project root

**Assertion Library:**
- pytest built-in assert
- SQLAlchemy text() for raw SQL assertions

**Run Commands:**
```bash
pytest                              # Run all tests
pytest -v                           # Verbose output
pytest tests/test_file.py           # Single file
pytest -m quick                     # Run quick-marked tests only
pytest --cov                        # Coverage report
```

## Test File Organization

**Location:**
- All tests in `tests/` directory
- Separate from source code (not co-located)

**Naming:**
- `test_*.py` for all test files
- Classes: `Test*` (e.g., `TestGitleaksIngestion`, `TestAuthenticationRequirement`)
- Functions: `test_*` (e.g., `test_no_orphaned_findings`)

**Structure:**
```
tests/
├── conftest.py                    # Shared fixtures
├── test_data_integrity.py         # Database integrity tests
├── test_ingestion_pipeline.py     # Ingestion tests
├── test_rbac_enforcement.py       # RBAC tests
├── test_tenant_isolation.py       # Multi-tenant tests
└── test_scan_repos_bugfixes.py    # Regression tests
```

## Test Structure

**Suite Organization:**
```python
import pytest
from sqlalchemy import text

class TestGitleaksIngestion:
    """Test gitleaks ingestion functionality."""

    @pytest.fixture
    def sample_gitleaks_report(self, tmp_path):
        """Create sample gitleaks report."""
        # fixture setup
        return report

    @pytest.mark.quick
    def test_gitleaks_creates_secret_finding(self, db_session, sample_gitleaks_report):
        """Test gitleaks ingestion creates finding with correct type."""
        # arrange
        repo_id = "test-repo-id"

        # act
        count = ingest_gitleaks(db_session, repo_id, org_id, sample_gitleaks_report)

        # assert
        assert count == 1, "Should ingest 1 finding"
```

**Patterns:**
- Class-based test organization with descriptive names
- `@pytest.fixture` for test data setup
- `@pytest.mark.quick` for fast tests
- Docstrings explain test purpose
- Explicit arrange/act/assert structure

## Mocking

**Framework:**
- unittest.mock (`from unittest.mock import patch, MagicMock`)
- pytest fixtures for database mocking

**Patterns:**
```python
from unittest.mock import patch, MagicMock

@patch('module.external_function')
def test_with_mock(mock_func):
    mock_func.return_value = 'mocked'
    # test code
    mock_func.assert_called_once_with('expected_arg')
```

**What to Mock:**
- External APIs (GitHub, AI providers)
- File system operations
- Database sessions (via fixtures)
- Environment variables

**What NOT to Mock:**
- Internal business logic
- SQLAlchemy models
- Pydantic validators

## Fixtures and Factories

**Test Data:**
```python
# conftest.py
@pytest.fixture
def db_session():
    """Create a fresh test database for each test function."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

@pytest.fixture
def test_user_analyst(db_session, test_tenant):
    """Create analyst user with limited permissions."""
    user = User(email="analyst@test.com", tenant_id=test_tenant.id)
    # assign analyst role
    return user
```

**Location:**
- `tests/conftest.py` - Shared fixtures for all tests
- Test-specific fixtures defined in test files

**Available Fixtures:**
- `db_session` - In-memory SQLite session
- `test_client` - FastAPI TestClient
- `test_tenant` - Test tenant for multi-tenant tests
- `test_user_super_admin`, `test_user_analyst`, `test_user_manager`, `test_user_no_role`, `test_user_admin`

## Coverage

**Requirements:**
- No enforced coverage target
- Coverage tracked for awareness
- Focus on critical paths (RBAC, tenant isolation, ingestion)

**Configuration:**
- pytest-cov 4.1.0+
- Run: `pytest --cov`

**View Coverage:**
```bash
pytest --cov=src --cov-report=html
open htmlcov/index.html
```

## Test Types

**Unit Tests:**
- Scope: Test single function/class in isolation
- Mocking: Mock external dependencies
- Examples: `test_data_integrity.py`

**Integration Tests:**
- Scope: Test multiple modules together
- Database: In-memory SQLite
- Examples: `test_rbac_enforcement.py`, `test_tenant_isolation.py`

**RBAC Tests:**
- Scope: Test permission enforcement across API routes
- Patterns: 401 (unauthenticated), 403 (insufficient permissions), 200 (authorized)
- Example: `test_analyst_cannot_delete_findings()`

**E2E Tests:**
- Not currently implemented
- CLI integration tested manually

## Common Patterns

**Async Testing:**
```python
@pytest.mark.asyncio
async def test_async_operation():
    result = await async_function()
    assert result == expected
```

**Database Testing:**
```python
def test_finding_exists(db_session):
    finding = db_session.execute(
        text("SELECT * FROM findings WHERE repository_id = :repo_id"),
        {"repo_id": repo_id}
    ).fetchone()

    assert finding is not None, "Finding should exist"
    assert finding.finding_type == "secret"
```

**Error Testing:**
```python
def test_raises_on_invalid_input():
    with pytest.raises(ValueError, match="Invalid input"):
        function_that_should_raise()
```

**Deduplication Testing:**
```python
def test_no_duplicates_on_reingestion(db_session, sample_report):
    # First ingestion
    count1 = ingest(db_session, sample_report)
    assert count1 == 1

    # Second ingestion (should skip duplicate)
    count2 = ingest(db_session, sample_report)
    assert count2 == 0
```

## Test Statistics

- Total test code: 1,593 lines across test files
- Test files: 10 files in `tests/`
- Async support: pytest-asyncio 0.21.0+

## Gaps

**Not Tested:**
- TypeScript/React components (no Jest/Vitest setup)
- E2E user flows
- Individual router endpoints (only integration tested)
- All 12 Stripe webhook event types (only 3 tested)

---

*Testing analysis: 2026-01-17*
*Update when test patterns change*
