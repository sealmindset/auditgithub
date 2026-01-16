# Cribl Log Management Integration - Implementation Specification

## Overview

This document specifies the implementation of centralized log management for the AuditGitHub platform, integrating with Cribl Stream for log collection, processing, and routing.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AuditGitHub Platform                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐                     │
│  │   Scanner    │   │     API      │   │   Web-UI     │                     │
│  │  (Python)    │   │  (FastAPI)   │   │  (Next.js)   │                     │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘                     │
│         │                  │                  │                              │
│         │    Loguru + HTTP Transport          │  Pino/Winston                │
│         │                  │                  │                              │
│         └──────────────────┼──────────────────┘                              │
│                            │                                                 │
│                            ▼                                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     Next.js API Route                                │    │
│  │                   POST /api/log (Proxy)                              │    │
│  │   - Adds Auth Token (server-side, not exposed to client)            │    │
│  │   - Forwards to Cribl or MinIO                                       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                            │                                                 │
└────────────────────────────┼────────────────────────────────────────────────┘
                             │
          ┌──────────────────┴──────────────────┐
          │                                     │
          ▼                                     ▼
┌──────────────────────┐             ┌──────────────────────┐
│      MinIO           │             │    Cribl Stream      │
│  (Log Storage)       │             │   (External)         │
│  - S3-compatible     │◄────────────│   - Pull from MinIO  │
│  - Local dev/test    │  Collector  │   - Process & Route  │
│  - Backup storage    │             │   - SIEM/Analytics   │
└──────────────────────┘             └──────────────────────┘
```

## Components

### 1. MinIO Log Storage Container

**Purpose**: S3-compatible object storage for centralized log collection. Acts as:
- Local log aggregation point for development/testing
- Backup storage when Cribl is unavailable
- Source for Cribl's pull-based collection

**Docker Service Configuration**:
```yaml
minio:
  image: minio/minio:latest
  container_name: auditgh_minio
  ports:
    - "9000:9000"   # S3 API
    - "9001:9001"   # Console UI
  environment:
    - MINIO_ROOT_USER=${MINIO_ROOT_USER:-auditgh}
    - MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD:-auditgh_logs_2024}
  volumes:
    - minio-data:/data
  command: server /data --console-address ":9001"
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
    interval: 30s
    timeout: 10s
    retries: 3
```

### 2. Database Schema

**Table**: `cribl_config`

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| api_id | BIGSERIAL | PostgREST numeric ID |
| ingest_url | VARCHAR(500) | Cribl HTTP/S endpoint URL |
| auth_token | VARCHAR(500) | Bearer token for authentication |
| verify_ssl | BOOLEAN | Whether to validate SSL certificates |
| enabled | BOOLEAN | Master switch for Cribl forwarding |
| log_levels | VARCHAR[] | Log levels to forward (INFO, WARNING, ERROR, etc.) |
| include_app_context | BOOLEAN | Include org_id, user_id, request_id |
| include_security_audit | BOOLEAN | Include action, resource, outcome fields |
| minio_fallback | BOOLEAN | Store in MinIO when Cribl unavailable |
| last_test_at | TIMESTAMP | Last successful connection test |
| last_test_status | VARCHAR(50) | SUCCESS, FAILED, PENDING |
| last_test_message | TEXT | Detailed test result message |
| created_at | TIMESTAMP | Record creation time |
| updated_at | TIMESTAMP | Last modification time |

### 3. API Endpoints

**Router**: `/cribl`

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/cribl/config` | Get current Cribl configuration |
| POST | `/cribl/config` | Save/update Cribl configuration |
| POST | `/cribl/test` | Test connection to Cribl endpoint |
| GET | `/cribl/status` | Get current logging status and stats |
| POST | `/cribl/toggle` | Enable/disable Cribl forwarding |

### 4. Log Format (NDJSON)

Each log entry follows this structure:

```json
{
  "timestamp": "2024-12-24T18:30:00.000Z",
  "level": "INFO",
  "message": "User authenticated successfully",
  "source": "api",
  "host": "auditgh_api",
  
  "app_context": {
    "org_id": "uuid-of-organization",
    "org_name": "sleepnumberlabs",
    "user_id": "uuid-of-user",
    "request_id": "uuid-of-request",
    "session_id": "session-identifier"
  },
  
  "security_audit": {
    "action": "authenticate",
    "resource": "user",
    "resource_id": "user-uuid",
    "outcome": "success",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0..."
  },
  
  "extra": {
    "duration_ms": 45,
    "endpoint": "/api/v1/login",
    "method": "POST"
  }
}
```

### 5. Logging Implementation

#### Python (API/Scanner) - Loguru

```python
from loguru import logger
import httpx
import json

class CriblSink:
    """Custom Loguru sink that forwards logs to Cribl via HTTP."""
    
    def __init__(self, config: CriblConfig):
        self.config = config
        self.client = httpx.AsyncClient(verify=config.verify_ssl)
    
    async def write(self, message: str):
        if not self.config.enabled:
            return
        
        record = message.record
        log_entry = self._format_log(record)
        
        try:
            await self.client.post(
                self.config.ingest_url,
                json=log_entry,
                headers={"Authorization": f"Bearer {self.config.auth_token}"}
            )
        except Exception as e:
            if self.config.minio_fallback:
                await self._store_in_minio(log_entry)
    
    def _format_log(self, record) -> dict:
        return {
            "timestamp": record["time"].isoformat(),
            "level": record["level"].name,
            "message": record["message"],
            "source": "api",
            # ... additional fields
        }
```

#### Next.js (Web-UI) - Pino

```typescript
import pino from 'pino';

const logger = pino({
  level: 'info',
  transport: {
    target: 'pino-http-send',
    options: {
      url: '/api/log',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }
  }
});
```

### 6. UI Components

#### Settings Page - Cribl Tab

Location: `src/web-ui/app/settings/page.tsx`

**Form Fields**:
- **Ingest URL**: Text input for Cribl endpoint (e.g., `https://cribl.example.com:20000`)
- **Auth Token**: Password input for Bearer token
- **Verify SSL**: Toggle switch
- **Enable Cribl Logging**: Master toggle
- **Log Levels**: Multi-select checkboxes (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- **Include App Context**: Toggle (org_id, user_id, request_id)
- **Include Security Audit**: Toggle (action, resource, outcome)
- **MinIO Fallback**: Toggle for storing logs when Cribl unavailable

**Actions**:
- **Test Configuration**: Button to verify connectivity
- **Save Changes**: Persist configuration to database

### 7. Next.js API Route (Log Proxy)

Location: `src/web-ui/app/api/log/route.ts`

```typescript
import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  const logEntry = await request.json();
  
  // Get Cribl config from API
  const configRes = await fetch(`${process.env.API_BASE}/cribl/config`);
  const config = await configRes.json();
  
  if (!config.enabled) {
    return NextResponse.json({ status: 'disabled' });
  }
  
  // Add server-side auth token (not exposed to client)
  const response = await fetch(config.ingest_url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${config.auth_token}`,
      'X-Forwarded-For': request.headers.get('x-forwarded-for') || ''
    },
    body: JSON.stringify(logEntry)
  });
  
  return NextResponse.json({ status: 'forwarded' });
}
```

## Implementation Order

1. **Database Migration** (`migrations/013_cribl_config.sql`)
2. **SQLAlchemy Model** (`src/api/models.py`)
3. **API Router** (`src/api/routers/cribl.py`)
4. **Register Router** (`src/api/main.py`)
5. **MinIO Docker Service** (`docker-compose.yml`)
6. **Loguru HTTP Sink** (`src/api/utils/cribl_logger.py`)
7. **Settings UI Tab** (`src/web-ui/app/settings/page.tsx`)
8. **Next.js Log Proxy** (`src/web-ui/app/api/log/route.ts`)
9. **Update CHANGELOG.md**

## Environment Variables

```bash
# MinIO Configuration
MINIO_ROOT_USER=auditgh
MINIO_ROOT_PASSWORD=auditgh_logs_2024
MINIO_ENDPOINT=http://minio:9000
MINIO_BUCKET=auditgh-logs

# Cribl Configuration (optional, can be set via UI)
CRIBL_INGEST_URL=
CRIBL_AUTH_TOKEN=
CRIBL_VERIFY_SSL=true
CRIBL_ENABLED=false
```

## Security Considerations

1. **Auth Token Storage**: Stored encrypted in database, never exposed to client-side code
2. **Log Proxy**: All client logs route through server-side proxy to add auth token
3. **SSL Verification**: Configurable but defaults to enabled
4. **Sensitive Data**: Log entries should NOT contain credentials, passwords, or PII
5. **Rate Limiting**: Consider implementing rate limiting on log proxy endpoint

## Testing

1. **Unit Tests**: Test log formatting, Cribl sink, MinIO fallback
2. **Integration Tests**: Test full flow from log generation to Cribl/MinIO
3. **UI Tests**: Test configuration form validation and save/load
4. **Connection Test**: Verify test button correctly validates connectivity
