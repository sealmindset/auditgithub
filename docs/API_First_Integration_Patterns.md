# Integration Patterns

**Source:** [API_First.md](API_First.md) - Section 9

---

## 9.1 Outbound Integrations (API as Client)

| Integration | Protocol | Authentication | Purpose |
|-------------|----------|----------------|---------|
| **GitHub API** | REST | PAT (per-org) | Repository metadata sync, file commits, workflow runs |
| **Jira** | REST v3 | Basic Auth (API token) | Create security tickets, sync status updates |
| **AI Providers** | REST | API keys | Claude, GPT-4, Gemini, Ollama for analysis |
| **Cribl Stream** | HTTP | Token-based | Forward structured logs for SIEM correlation |
| **MinIO (S3)** | S3 API | Access key/secret | Log storage, report archival |

## 9.2 Inbound Integrations (API as Server)

| Integration | Mechanism | Endpoint |
|-------------|-----------|----------|
| **Jira Webhooks** | POST webhook | `/integrations/jira/webhook` |
| **CI/CD Pipelines** | REST calls | `/scans/*`, `/findings/*` |
| **GitHub Actions** | REST calls | `/cicd/sync` |
| **External Scripts** | REST calls | Any endpoint with Bearer token |

## 9.3 Instrumentation Pattern

All external service calls are instrumented:

```python
@instrument_external_call(service_name="jira", operation="create_issue", endpoint=url)
async def create_jira_ticket(finding):
    # Automatically logs:
    # - EXTERNAL_CALL_START (service, operation, endpoint)
    # - EXTERNAL_CALL_END (duration_ms, perf_category)
    # - EXTERNAL_CALL_ERROR (exception details, if failed)
    # Performance categories: FAST(<200ms), NORMAL, SLOW(1-5s), CRITICAL(>5s)
```
