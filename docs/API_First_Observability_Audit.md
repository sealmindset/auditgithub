# Observability and Audit

**Source:** [API_First.md](API_First.md) - Section 10

---

## 10.1 Structured Logging

Every request generates structured JSON logs sent to Cribl Stream (with MinIO fallback):

```json
{
    "timestamp": "2026-02-26T14:30:00.000Z",
    "level": "INFO",
    "event_type": "REQUEST_END",
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "method": "GET",
    "path": "/findings",
    "status_code": 200,
    "duration_ms": 45.2,
    "perf_category": "FAST",
    "app_context": {
        "org_id": "uuid-of-org",
        "org_name": "example-org",
        "user_id": "user@example-org.com",
        "session_id": "abc123"
    },
    "client_ip": "10.0.1.50",
    "user_agent": "Mozilla/5.0..."
}
```

## 10.2 Audit Trail

Three audit log types capture security-relevant events:

| Audit Log | Table | Events |
|-----------|-------|--------|
| **Auth Audit** | `auth_audit_log` | login, logout, token refresh, device approval, break-glass access |
| **Authorization Audit** | via Cribl logger | permission granted/denied, role assignment changes |
| **Data Access Audit** | via Cribl logger | resource reads, writes, deletes with user and tenant context |

## 10.3 Health Monitoring

The `/health` endpoint checks all dependencies:

```json
{
    "status": "healthy",
    "timestamp": "2026-02-26T14:30:00.000Z",
    "checks": {
        "database": "healthy",
        "redis": "healthy"
    },
    "multi_tenant": true
}
```

Docker Compose health checks poll this endpoint every 30 seconds with 3 retries.
