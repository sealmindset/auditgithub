# Testing Patterns

**Analysis Date:** 2026-01-12

## Test Framework

**Runner:**
- **No formal test framework configured**
- No Jest, Vitest, Pytest, or similar test runner setup
- No `jest.config.js`, `vitest.config.ts`, or `pytest.ini` found

**Manual Testing Only:**
- Ad-hoc test scripts at root level:
  - `test_ai_providers.py` - AI provider connectivity tests
  - `test_script.py` - General testing
  - `test_zda_enhancements.py` - Zero-day assessment feature tests

**Run Commands:**
```bash
# No standardized test command
python test_ai_providers.py     # Manual AI provider testing
python test_script.py           # Ad-hoc testing
```

## Test File Organization

**Location:**
- Test files at **root level only** (not in dedicated test directory)
- No `tests/` directory structure
- No `__tests__/` directories
- No test files co-located with source in `src/`

**Naming:**
- `test_*.py` pattern for Python (root level only)
- No TypeScript/React test files found

**Structure:**
```
auditgithub/
├── test_ai_providers.py    # AI connectivity tests
├── test_script.py          # Ad-hoc tests
├── test_zda_enhancements.py # Feature tests
└── (no other test files)
```

## Test Structure

**Python Test Pattern** (from `test_ai_providers.py`):
```python
def test_openai() -> Tuple[bool, str]:
    """Test OpenAI API connection"""
    try:
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            return False, "OPENAI_API_KEY not set"

        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Test"}],
            max_tokens=10
        )
        return True, f"Success: {response.choices[0].message.content}"
    except Exception as e:
        return False, f"Error: {str(e)}"
```

**Test Characteristics:**
- Manual execution (no test runner)
- Integration tests (real API calls, no mocking)
- Return tuples for success/failure
- Color-coded terminal output using ANSI codes

**No Unit Tests:**
- No isolated function testing
- No mocking framework detected
- No test fixtures or factories
- All tests are integration tests

## Mocking

**Framework:**
- **None** - No mocking library (pytest-mock, unittest.mock, Vitest vi)

**Patterns:**
- Tests call real external services (GitHub, OpenAI, Claude, Ollama)
- No mock patterns detected
- No test doubles or stubs

## Fixtures and Factories

**Test Data:**
- No test fixtures directory
- No factory pattern implementations
- No shared test data files
- Tests use environment variables for real credentials

**Location:**
- Not applicable - no test data infrastructure

## Coverage

**Requirements:**
- No coverage targets defined
- No coverage measurement tools configured

**Configuration:**
- No coverage.py configuration
- No pytest-cov setup
- No Istanbul/Vitest coverage for frontend

**View Coverage:**
- Not applicable - no coverage tracking

## Test Types

**Integration Tests:**
- Scope: Full system integration (real APIs, real database)
- Examples: `test_ai_providers.py` (OpenAI, Claude, Gemini, Ollama connectivity)
- Speed: Slow (network calls to external services)
- Mocking: None

**Unit Tests:**
- **Not present** - No isolated unit tests

**E2E Tests:**
- **Not present** - No Playwright, Cypress, or similar

## API Validation

**Runtime Validation:**
- Pydantic models provide automatic request/response validation - `src/api/models.py`
- FastAPI automatically validates inputs and returns 422 for validation errors
- TypeScript provides compile-time type checking - `src/web-ui/tsconfig.json`

**This provides implicit testing:**
- Invalid API requests rejected automatically
- Type errors caught at compile time (frontend)
- Schema validation via Pydantic (backend)

## Pre-commit Hooks

**Husky Configuration** (mentioned in `CONTRIBUTING.md`):
```bash
npm run typecheck      # TypeScript validation
npm run build          # Full build validation
```

**These provide build-time validation:**
- TypeScript compilation errors fail commit
- Next.js build errors block commits
- ESLint errors block commits

## Common Patterns

**Async Testing:**
- No async test patterns (no test framework)

**Error Testing:**
- Try/catch in manual tests
- Return failure tuples

**Example from `test_ai_providers.py`:**
```python
def test_claude() -> Tuple[bool, str]:
    """Test Claude API connection"""
    try:
        api_key = os.getenv('ANTHROPIC_API_KEY')
        if not api_key:
            return False, "ANTHROPIC_API_KEY not set"
        # ... test logic ...
        return True, "Success"
    except Exception as e:
        return False, f"Error: {str(e)}"
```

## Testing Gaps

**Critical Missing Coverage:**
1. **Unit tests** - No isolated function testing
2. **Router tests** - API endpoints not tested
3. **Database tests** - ORM operations not tested
4. **Scanner tests** - Security scanner plugins not tested
5. **Frontend tests** - React components not tested
6. **Integration tests** - Only AI provider connectivity tested
7. **E2E tests** - No user flow testing

**Impact:**
- Unknown test coverage percentage
- Regression risk when refactoring
- No automated test suite in CI/CD
- Manual testing burden on developers

## Recommendations

**To Establish Testing:**
1. **Backend:**
   - Add **Pytest** - `pip install pytest pytest-cov pytest-asyncio`
   - Create `tests/` directory structure mirroring `src/`
   - Add `pytest.ini` configuration
   - Write unit tests for:
     - `src/api/utils/risk_scoring.py`
     - `src/ai_agent/agent.py`
     - `src/api/routers/findings.py`

2. **Frontend:**
   - Add **Vitest** or **Jest** - `npm install --save-dev vitest @testing-library/react`
   - Add `vitest.config.ts`
   - Write component tests for:
     - `src/web-ui/components/AskAIDialog.tsx`
     - `src/web-ui/components/data-table.tsx`

3. **E2E:**
   - Add **Playwright** - `npm install --save-dev @playwright/test`
   - Write user flow tests for critical paths

4. **CI/CD:**
   - Add GitHub Actions workflow to run tests on PR
   - Block merges on test failures
   - Enforce minimum coverage threshold (70%+)

---

*Testing analysis: 2026-01-12*
*Update when test patterns change*
