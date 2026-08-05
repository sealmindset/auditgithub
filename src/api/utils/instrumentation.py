"""Performance instrumentation utilities for external service calls."""
import time
from contextlib import contextmanager
from typing import Optional
from loguru import logger


@contextmanager
def instrument_external_call(service_name: str, operation: str, endpoint: Optional[str] = None):
    """
    Context manager to instrument external service calls with duration logging.

    Usage:
        with instrument_external_call("github", "get_repos", "https://api.github.com/orgs/foo/repos"):
            response = requests.get(url, timeout=30)

    Logs:
        - EXTERNAL_CALL_START with service, operation, endpoint
        - EXTERNAL_CALL_END with duration_ms and performance category
        - EXTERNAL_CALL_ERROR on exception
    """
    start_time = time.time()

    logger.bind(
        event_type="EXTERNAL_CALL_START",
        service=service_name,
        operation=operation,
        endpoint=endpoint
    ).debug(f"External call started: {service_name}.{operation}")

    try:
        yield
        duration_ms = int((time.time() - start_time) * 1000)

        # Categorize performance
        if duration_ms < 200:
            perf = "FAST"
        elif duration_ms < 1000:
            perf = "NORMAL"
        elif duration_ms < 5000:
            perf = "SLOW"
        else:
            perf = "CRITICAL"

        logger.bind(
            event_type="EXTERNAL_CALL_END",
            service=service_name,
            operation=operation,
            duration_ms=duration_ms,
            perf_category=perf
        ).info(f"External call completed: {service_name}.{operation} ({duration_ms}ms, {perf})")

        if perf in ["SLOW", "CRITICAL"]:
            logger.bind(
                event_type="SLOW_EXTERNAL_CALL",
                service=service_name,
                duration_ms=duration_ms
            ).warning(f"Slow external call: {service_name}.{operation} took {duration_ms}ms")

    except Exception as e:
        duration_ms = int((time.time() - start_time) * 1000)
        logger.bind(
            event_type="EXTERNAL_CALL_ERROR",
            service=service_name,
            operation=operation,
            duration_ms=duration_ms,
            error=str(e)
        ).error(f"External call failed: {service_name}.{operation} - {str(e)}")
        raise
