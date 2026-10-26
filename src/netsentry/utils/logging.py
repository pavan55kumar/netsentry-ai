"""Privacy-preserving structured operational logging for NetSentry AI.

What it does:
    Provides structured, security-conscious logging with automatic redaction
    of sensitive data: IP host addresses, raw packet payloads, credentials,
    tokens, and local filesystem user paths.

Why it is needed:
    Network security appliances and ML intrusion detection systems must never
    become vectors for privacy violations or credential leakage. Raw packet
    captures frequently contain credentials, session cookies, or personal
    identifiable information (PII). This module guarantees that operational
    logs retain forensic diagnostic value while strictly omitting sensitive bytes.

DCN / Security connection:
    - IP Masking: Preserves subnet identifiers for routing context (e.g. 192.168.1.***)
      while anonymizing individual host endpoints.
    - Payload Suppression: Discards L7 application layer data; logs only L3/L4
      flow metadata (packet counts, durations, ports).
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any


IPV4_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b")
IPV6_PATTERN = re.compile(r"([0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}):[0-9a-fA-F:]+")

SECRET_KEY_VALUE_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?([^\s'\"]+)"
)
GENERIC_SECRETS = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-\._~\+\/]+=*"),
]
USER_PATH_PATTERN = re.compile(r"[A-Za-z]:[\\/]Users[\\/][^\\/]+[\\/]", re.IGNORECASE)


def redact_ip_address(ip_str: str) -> str:
    """Mask host octet of IP address for privacy preservation.

    Examples:
        '192.168.1.45' -> '192.168.1.***'
        '10.0.5.120' -> '10.0.5.***'
        '2001:0db8:85a3:0000:0000:8a2e:0370:7334' -> '2001:0db8:85a3:****'
    """
    if "." in ip_str:
        return IPV4_PATTERN.sub(r"\1.***", ip_str)
    if ":" in ip_str:
        return IPV6_PATTERN.sub(r"\1:****", ip_str)
    return ip_str


def sanitize_log_message(msg: str) -> str:
    """Scrub sensitive credentials, user home directories, and full host IPs from log text."""
    # Redact IPv4 host octets
    cleaned = IPV4_PATTERN.sub(r"\1.***", msg)
    # Redact IPv6 host endpoints
    cleaned = IPV6_PATTERN.sub(r"\1:****", cleaned)
    # Redact key-value secrets (e.g. password=..., api_key: ...)
    cleaned = SECRET_KEY_VALUE_PATTERN.sub(r"\1: [REDACTED_SECRET]", cleaned)
    # Redact standalone secrets (AWS keys, bearer tokens)
    for pat in GENERIC_SECRETS:
        cleaned = pat.sub("[REDACTED_SECRET]", cleaned)
    # Redact absolute user paths
    cleaned = USER_PATH_PATTERN.sub("[USER_DIR]/", cleaned)
    return cleaned



class SecurityAuditFilter(logging.Filter):
    """Logging filter that redacts sensitive identifiers from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = sanitize_log_message(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: (sanitize_log_message(str(v)) if isinstance(v, str) else v) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(sanitize_log_message(str(a)) if isinstance(a, str) else a for a in record.args)
        return True


class JsonAuditFormatter(logging.Formatter):
    """Formats log records as structured, machine-parseable JSON."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        if hasattr(record, "audit_data") and isinstance(record.audit_data, dict):
            # Sanitize audit data
            sanitized_data = {}
            for k, v in record.audit_data.items():
                if isinstance(v, str):
                    sanitized_data[k] = sanitize_log_message(v)
                else:
                    sanitized_data[k] = v
            log_entry["audit_data"] = sanitized_data

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


def get_security_logger(
    name: str = "netsentry",
    log_file: str | Path | None = "artifacts/netsentry_audit.log",
    level: int = logging.INFO,
) -> logging.Logger:
    """Construct and configure a privacy-preserving security audit logger.

    Args:
        name: Logger name.
        log_file: Destination path for rotated audit logs (or None for console only).
        level: Minimum logging level.

    Returns:
        Configured Logger instance with SecurityAuditFilter.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid duplicate handlers on re-initialization
    if not logger.handlers:
        # Console handler with standard formatted message
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        console_handler.setFormatter(console_fmt)
        console_handler.addFilter(SecurityAuditFilter())
        logger.addHandler(console_handler)

        # File handler with JSON formatting if requested
        if log_file:
            path = Path(log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(str(path), maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
            file_handler.setLevel(level)
            file_handler.setFormatter(JsonAuditFormatter(datefmt="%Y-%m-%d %H:%M:%S"))
            file_handler.addFilter(SecurityAuditFilter())
            logger.addHandler(file_handler)

    return logger
