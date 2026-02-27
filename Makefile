# =============================================================================
# AuditGH Makefile — Sandbox & Developer Workflow Targets
# =============================================================================

.PHONY: sandbox-up sandbox-down sandbox-reset sandbox-export \
        sandbox-sdk-python sandbox-sdk-typescript sandbox-validate \
        sandbox-logs sandbox-status

# -----------------------------------------------------------------------------
# Sandbox lifecycle
# -----------------------------------------------------------------------------

## Start the sandbox environment (API on :8001, Swagger Editor on :8080)
sandbox-up:
	@echo "Initializing sandbox database..."
	POSTGRES_HOST=localhost python scripts/init_sandbox_db.py || true
	@echo "Starting sandbox services..."
	docker compose --profile sandbox up -d sandbox swagger-editor
	@echo ""
	@echo "Sandbox API:       http://localhost:8001"
	@echo "Swagger Editor:    http://localhost:8080"
	@echo "Developer Portal:  http://localhost:8001/"
	@echo ""

## Stop sandbox services
sandbox-down:
	docker compose --profile sandbox down

## Reset sandbox data (requires admin key)
sandbox-reset:
	curl -s -X POST http://localhost:8001/api/sandbox/reset \
	  -H "X-API-Key: agh_sandbox_admin" | python -m json.tool

## Export the sandbox OpenAPI spec to a file
sandbox-export:
	curl -s http://localhost:8001/openapi.json | python -m json.tool > openapi-sandbox.json
	@echo "Exported to openapi-sandbox.json"

## Show sandbox status
sandbox-status:
	curl -s http://localhost:8001/api/sandbox/status | python -m json.tool

## Tail sandbox logs
sandbox-logs:
	docker compose --profile sandbox logs -f sandbox

# -----------------------------------------------------------------------------
# SDK Generation (requires openapi-generator-cli or similar)
# -----------------------------------------------------------------------------

## Generate Python SDK from sandbox OpenAPI spec
sandbox-sdk-python:
	@echo "Exporting OpenAPI spec..."
	curl -s http://localhost:8001/openapi.json > /tmp/auditgh-sandbox.json
	@echo "Generating Python SDK..."
	docker run --rm -v /tmp:/specs -v $(PWD)/sdks/python:/out \
	  openapitools/openapi-generator-cli generate \
	  -i /specs/auditgh-sandbox.json -g python -o /out \
	  --additional-properties=packageName=auditgh_sdk
	@echo "Python SDK generated in sdks/python/"

## Generate TypeScript SDK from sandbox OpenAPI spec
sandbox-sdk-typescript:
	@echo "Exporting OpenAPI spec..."
	curl -s http://localhost:8001/openapi.json > /tmp/auditgh-sandbox.json
	@echo "Generating TypeScript SDK..."
	docker run --rm -v /tmp:/specs -v $(PWD)/sdks/typescript:/out \
	  openapitools/openapi-generator-cli generate \
	  -i /specs/auditgh-sandbox.json -g typescript-fetch -o /out \
	  --additional-properties=npmName=@auditgh/sdk
	@echo "TypeScript SDK generated in sdks/typescript/"

# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------

## Validate the OpenAPI spec with spectral or openapi-generator
sandbox-validate:
	@echo "Fetching sandbox OpenAPI spec..."
	curl -s http://localhost:8001/openapi.json > /tmp/auditgh-sandbox.json
	@echo "Validating..."
	docker run --rm -v /tmp:/specs stoplight/spectral lint /specs/auditgh-sandbox.json || \
	  python scripts/check_openapi_coverage.py --spec /tmp/auditgh-sandbox.json
	@echo "Validation complete"
