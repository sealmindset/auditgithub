"""
Cribl Logger - Structured logging with HTTP transport to Cribl Stream

This module provides a Loguru-based logging system that forwards logs to:
1. Cribl Stream (when configured and enabled)
2. MinIO (as fallback when Cribl is unavailable)
3. Standard output (always)

Log entries include:
- Standard fields: timestamp, level, message, source
- App context: org_id, user_id, request_id (when available)
- Security audit: action, resource, outcome (when applicable)
"""

import os
import sys
import json
import asyncio
import threading
from datetime import datetime
from typing import Optional, Dict, Any
from contextlib import contextmanager
import queue

from .redaction import redact_string, redact_dict

try:
    from loguru import logger as loguru_logger
except ImportError:
    loguru_logger = None

try:
    import httpx
except ImportError:
    httpx = None

try:
    from minio import Minio
except ImportError:
    Minio = None


# Thread-local storage for request context
import contextvars

_request_context: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar(
    'request_context', default={}
)


class CriblLoggerConfig:
    """Configuration for Cribl logger, loaded from database or environment."""

    def __init__(self):
        self.enabled = False
        self.ingest_url = ""
        self.auth_token = ""
        self.verify_ssl = True
        self.log_levels = ["INFO", "WARNING", "ERROR", "CRITICAL"]
        self.include_app_context = True
        self.include_security_audit = True
        self.minio_fallback = True
        self.minio_endpoint = os.environ.get("MINIO_ENDPOINT", "http://minio:9000")
        self.minio_bucket = os.environ.get("MINIO_BUCKET", "auditgh-logs")
        self.minio_access_key = os.environ.get("MINIO_ROOT_USER", "auditgh")
        self.minio_secret_key = os.environ.get("MINIO_ROOT_PASSWORD", "auditgh_logs_2024")
        self.redact_sensitive_data = os.environ.get("CRIBL_REDACT_SENSITIVE", "true").lower() == "true"
        self._last_refresh = None
    
    def load_from_db(self):
        """Load configuration from database."""
        try:
            from ..database import SessionLocal
            from .. import models
            
            db = SessionLocal()
            try:
                config = db.query(models.CriblConfig).first()
                if config:
                    self.enabled = config.enabled or False
                    self.ingest_url = config.ingest_url or ""
                    self.auth_token = config.auth_token or ""
                    self.verify_ssl = config.verify_ssl if config.verify_ssl is not None else True
                    self.log_levels = config.log_levels or ["INFO", "WARNING", "ERROR", "CRITICAL"]
                    self.include_app_context = config.include_app_context if config.include_app_context is not None else True
                    self.include_security_audit = config.include_security_audit if config.include_security_audit is not None else True
                    self.minio_fallback = config.minio_fallback if config.minio_fallback is not None else True
                    if config.minio_endpoint:
                        self.minio_endpoint = config.minio_endpoint
                    if config.minio_bucket:
                        self.minio_bucket = config.minio_bucket
                    if config.minio_access_key:
                        self.minio_access_key = config.minio_access_key
                    if config.minio_secret_key:
                        self.minio_secret_key = config.minio_secret_key
                self._last_refresh = datetime.utcnow()
            finally:
                db.close()
        except Exception as e:
            print(f"[CriblLogger] Failed to load config from DB: {e}")
    
    def should_refresh(self) -> bool:
        """Check if config should be refreshed (every 60 seconds)."""
        if self._last_refresh is None:
            return True
        return (datetime.utcnow() - self._last_refresh).total_seconds() > 60


class CriblLogSink:
    """
    Custom Loguru sink that forwards logs to Cribl Stream.
    
    Uses a background thread with a queue to avoid blocking the main thread.
    Falls back to MinIO storage when Cribl is unavailable.
    """
    
    def __init__(self, config: CriblLoggerConfig):
        self.config = config
        self._queue: queue.Queue = queue.Queue(maxsize=10000)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._minio_client: Optional[Any] = None
    
    def start(self):
        """Start the background log forwarding thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._process_queue, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Stop the background thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def write(self, message):
        """Called by Loguru for each log message."""
        if not self.config.enabled:
            return
        
        record = message.record
        level_name = record["level"].name
        
        if level_name not in self.config.log_levels:
            return
        
        log_entry = self._format_log_entry(record)
        
        try:
            self._queue.put_nowait(log_entry)
        except queue.Full:
            pass
    
    def _format_log_entry(self, record) -> Dict[str, Any]:
        """Format a log record into the standard log entry structure."""
        entry = {
            "timestamp": record["time"].isoformat(),
            "level": record["level"].name,
            "message": str(record["message"]),
            "source": "api",
            "host": os.environ.get("HOSTNAME", "auditgh_api"),
            "module": record["module"],
            "function": record["function"],
            "line": record["line"]
        }

        if self.config.include_app_context:
            ctx = _request_context.get()
            if ctx:
                entry["app_context"] = {
                    "org_id": ctx.get("org_id"),
                    "org_name": ctx.get("org_name"),
                    "user_id": ctx.get("user_id"),
                    "request_id": ctx.get("request_id"),
                    "session_id": ctx.get("session_id")
                }

        if self.config.include_security_audit:
            extra = record.get("extra", {})
            if any(k in extra for k in ["action", "resource", "outcome"]):
                entry["security_audit"] = {
                    "action": extra.get("action"),
                    "resource": extra.get("resource"),
                    "resource_id": extra.get("resource_id"),
                    "outcome": extra.get("outcome"),
                    "ip_address": extra.get("ip_address"),
                    "user_agent": extra.get("user_agent")
                }

        extra = record.get("extra", {})
        filtered_extra = {k: v for k, v in extra.items()
                         if k not in ["action", "resource", "resource_id", "outcome", "ip_address", "user_agent"]}
        if filtered_extra:
            entry["extra"] = filtered_extra

        # Apply redaction if enabled
        if self.config.redact_sensitive_data:
            try:
                entry["message"] = redact_string(str(entry["message"]))
                if "app_context" in entry:
                    entry["app_context"] = redact_dict(entry["app_context"])
                if "security_audit" in entry:
                    entry["security_audit"] = redact_dict(entry["security_audit"])
                if "extra" in entry:
                    entry["extra"] = redact_dict(entry["extra"])
            except Exception as e:
                print(f"[CriblLogger] Redaction failed: {e}")

        return entry
    
    def _process_queue(self):
        """Background thread that processes the log queue."""
        batch = []
        batch_size = 100
        flush_interval = 5.0
        last_flush = datetime.utcnow()
        
        while self._running or not self._queue.empty():
            try:
                entry = self._queue.get(timeout=1.0)
                batch.append(entry)
                
                should_flush = (
                    len(batch) >= batch_size or
                    (datetime.utcnow() - last_flush).total_seconds() >= flush_interval
                )
                
                if should_flush and batch:
                    self._send_batch(batch)
                    batch = []
                    last_flush = datetime.utcnow()
                    
            except queue.Empty:
                if batch:
                    self._send_batch(batch)
                    batch = []
                    last_flush = datetime.utcnow()
            except Exception as e:
                print(f"[CriblLogger] Queue processing error: {e}")
        
        if batch:
            self._send_batch(batch)
    
    def _send_batch(self, batch: list):
        """Send a batch of log entries to Cribl or MinIO."""
        if not batch:
            return
        
        if self.config.should_refresh():
            self.config.load_from_db()
        
        if self.config.ingest_url and self.config.enabled:
            success = self._send_to_cribl(batch)
            if success:
                return
        
        if self.config.minio_fallback:
            self._store_in_minio(batch)
    
    def _send_to_cribl(self, batch: list) -> bool:
        """Send log batch to Cribl Stream via HTTP."""
        if not httpx:
            return False
        
        try:
            headers = {"Content-Type": "application/x-ndjson"}
            if self.config.auth_token:
                headers["Authorization"] = f"Bearer {self.config.auth_token}"
            
            ndjson_payload = "\n".join(json.dumps(entry) for entry in batch)
            
            with httpx.Client(verify=self.config.verify_ssl, timeout=30.0) as client:
                response = client.post(
                    self.config.ingest_url,
                    content=ndjson_payload,
                    headers=headers
                )
            
            return response.status_code in [200, 201, 202, 204]
            
        except Exception as e:
            print(f"[CriblLogger] Failed to send to Cribl: {e}")
            return False
    
    def _store_in_minio(self, batch: list):
        """Store log batch in MinIO as fallback."""
        if not Minio:
            return
        
        try:
            if not self._minio_client:
                endpoint = self.config.minio_endpoint.replace("http://", "").replace("https://", "")
                secure = self.config.minio_endpoint.startswith("https://")
                self._minio_client = Minio(
                    endpoint,
                    access_key=self.config.minio_access_key,
                    secret_key=self.config.minio_secret_key,
                    secure=secure
                )
                
                if not self._minio_client.bucket_exists(self.config.minio_bucket):
                    self._minio_client.make_bucket(self.config.minio_bucket)
            
            timestamp = datetime.utcnow()
            object_name = f"logs/{timestamp.strftime('%Y/%m/%d/%H')}/{timestamp.strftime('%Y%m%d_%H%M%S_%f')}.ndjson"
            
            ndjson_content = "\n".join(json.dumps(entry) for entry in batch)
            
            from io import BytesIO
            data = BytesIO(ndjson_content.encode('utf-8'))
            data_length = len(ndjson_content.encode('utf-8'))
            
            self._minio_client.put_object(
                self.config.minio_bucket,
                object_name,
                data,
                data_length,
                content_type="application/x-ndjson"
            )
            
        except Exception as e:
            print(f"[CriblLogger] Failed to store in MinIO: {e}")


_cribl_config: Optional[CriblLoggerConfig] = None
_cribl_sink: Optional[CriblLogSink] = None


def setup_cribl_logger():
    """
    Set up the Cribl logger with Loguru.

    Call this during application startup to configure logging.
    """
    global _cribl_config, _cribl_sink

    if not loguru_logger:
        print("[CriblLogger] Loguru not installed, skipping Cribl logger setup")
        return

    _cribl_config = CriblLoggerConfig()
    _cribl_config.load_from_db()

    _cribl_sink = CriblLogSink(_cribl_config)
    _cribl_sink.start()

    # Get minimum log level from environment (default: INFO)
    min_level = os.environ.get("AUDIT_LOG_LEVEL", "INFO").upper()

    loguru_logger.add(
        _cribl_sink.write,
        format="{message}",
        level=min_level,
        enqueue=False
    )

    loguru_logger.info(f"Cribl logger initialized (enabled={_cribl_config.enabled}, min_level={min_level})")
    print(f"[CriblLogger] Initialized (enabled={_cribl_config.enabled}, min_level={min_level})")


def shutdown_cribl_logger():
    """Shutdown the Cribl logger gracefully."""
    global _cribl_sink
    if _cribl_sink:
        _cribl_sink.stop()
        print("[CriblLogger] Shutdown complete")


@contextmanager
def log_context(**kwargs):
    """
    Context manager to set request-scoped logging context.
    
    Usage:
        with log_context(org_id="uuid", user_id="uuid", request_id="uuid"):
            logger.info("This log will include the context")
    """
    token = _request_context.set(kwargs)
    try:
        yield
    finally:
        _request_context.reset(token)


def set_log_context(**kwargs):
    """Set logging context for the current request."""
    current = _request_context.get()
    updated = {**current, **kwargs}
    _request_context.set(updated)


def clear_log_context():
    """Clear the logging context."""
    _request_context.set({})


def log_audit_event(event_type: str, event_data: Dict[str, Any]) -> None:
    """
    Log a structured audit event to Cribl with special "audit" tag for filtering.

    This function sends audit events to Cribl (if enabled) with a special tag that
    enables filtering and alerting on audit events. If Cribl is disabled, events
    are logged to stdout for local development.

    Args:
        event_type: Type of audit event (e.g., "authorization.granted")
        event_data: Complete audit event data dict with all fields

    Example:
        log_audit_event("authorization.granted", {
            "timestamp": "2024-01-01T12:00:00",
            "user": {"email": "user@example.com"},
            "tenant_id": "tenant_123",
            "resource": "findings",
            "action": "read",
            "granted": True
        })

    Environment:
        CRIBL_ENABLED: Set to "false" for local dev without Cribl
        AUDIT_LOG_LEVEL: Minimum log level for audit events (default: INFO)
    """
    global _cribl_config, _cribl_sink

    # Add audit tag for Cribl filtering
    tagged_event = {
        **event_data,
        "tags": ["audit", event_type.split(".")[0]]  # e.g., ["audit", "authorization"]
    }

    # If Cribl is enabled and configured, send to Cribl
    if _cribl_config and _cribl_config.enabled and _cribl_sink:
        try:
            _cribl_sink._queue.put_nowait(tagged_event)
        except Exception as e:
            # Fallback to stdout if queue is full or other error
            print(f"[AuditLog] {json.dumps(tagged_event)}")
    else:
        # Local dev mode - log to stdout
        print(f"[AuditLog] {json.dumps(tagged_event)}")


def audit_log(action: str, resource: str, outcome: str, **extra):
    """
    Log a security audit event.

    Args:
        action: The action performed (e.g., "authenticate", "create", "delete")
        resource: The resource type (e.g., "user", "finding", "repository")
        outcome: The outcome (e.g., "success", "failure", "denied")
        **extra: Additional fields (resource_id, ip_address, user_agent, etc.)
    """
    if loguru_logger:
        loguru_logger.bind(
            action=action,
            resource=resource,
            outcome=outcome,
            **extra
        ).info(f"AUDIT: {action} {resource} - {outcome}")


if loguru_logger:
    logger = loguru_logger
else:
    import logging
    logger = logging.getLogger("auditgh")
