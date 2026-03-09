"""
Structured logging configuration for ML Security RBAC Platform.

Provides centralized logging with structured output, security event
tagging, and configurable log levels per module.

Author: Gabriel Demetrios Lafis
"""

import logging
import logging.handlers
import json
import sys
import os
from datetime import datetime, timezone
from typing import Any, Optional
from pathlib import Path


class StructuredFormatter(logging.Formatter):
    """JSON-structured log formatter for security audit compliance."""

    def __init__(self, service_name: str = "ml-security-rbac"):
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": self.service_name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }

        if hasattr(record, "user_id"):
            log_entry["user_id"] = record.user_id
        if hasattr(record, "action"):
            log_entry["action"] = record.action
        if hasattr(record, "resource"):
            log_entry["resource"] = record.resource
        if hasattr(record, "ip_address"):
            log_entry["ip_address"] = record.ip_address
        if hasattr(record, "security_event"):
            log_entry["security_event"] = record.security_event

        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
            }

        return json.dumps(log_entry, default=str)


class SecurityLogFilter(logging.Filter):
    """Filter that enriches log records with security context."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "security_event"):
            record.security_event = None
        if not hasattr(record, "user_id"):
            record.user_id = None
        if not hasattr(record, "ip_address"):
            record.ip_address = None
        return True


def get_logger(
    name: str,
    level: Optional[str] = None,
    log_file: Optional[str] = None,
) -> logging.Logger:
    """
    Create a configured logger instance.

    Args:
        name: Logger name (typically module name).
        level: Log level override. Defaults to LOG_LEVEL env var or INFO.
        log_file: Optional file path for file-based logging.

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    log_level = level or os.getenv("LOG_LEVEL", "INFO")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    formatter = StructuredFormatter()
    security_filter = SecurityLogFilter()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(security_filter)
    logger.addHandler(console_handler)

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            filename=str(log_path),
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(security_filter)
        logger.addHandler(file_handler)

    logger.propagate = False
    return logger


def log_security_event(
    logger: logging.Logger,
    event_type: str,
    message: str,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    extra: Optional[dict[str, Any]] = None,
) -> None:
    """
    Log a security-relevant event with structured metadata.

    Args:
        logger: Logger instance.
        event_type: Category of security event (e.g., AUTH_FAILURE, ACCESS_DENIED).
        message: Human-readable event description.
        user_id: Associated user identifier.
        ip_address: Client IP address.
        extra: Additional context fields.
    """
    log_extra = {
        "security_event": event_type,
        "user_id": user_id or "anonymous",
        "ip_address": ip_address or "unknown",
    }
    if extra:
        log_extra.update(extra)

    logger.warning(message, extra=log_extra)
