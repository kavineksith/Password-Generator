"""
Non-blocking accountability logging subsystem.

Uses logging.handlers.QueueHandler / QueueListener so that log I/O never
blocks the async event loop or generation workers. Two sinks are attached
to the listener:

  1. Console sink  -- human-readable, ANSI-colored, for interactive use.
  2. JSON-lines sink -- machine-parseable audit trail on disk, one JSON
     object per log record, suitable for accountability / compliance
     review of every generation event.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import queue
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from passforge.core.exceptions import LogInitializationError

_RESET = "\x1b[0m"
_COLORS = {
    logging.DEBUG: "\x1b[36m",     # cyan
    logging.INFO: "\x1b[32m",      # green
    logging.WARNING: "\x1b[33m",   # yellow
    logging.ERROR: "\x1b[31m",     # red
    logging.CRITICAL: "\x1b[41m",  # red background
}


class ConsoleFormatter(logging.Formatter):
    """ANSI-colored, human-readable console formatter."""

    def format(self, record: logging.LogRecord) -> str:
        color = _COLORS.get(record.levelno, "")
        base = f"[{self.formatTime(record, '%H:%M:%S')}] {record.levelname:<8}"
        message = record.getMessage()
        event_type = getattr(record, "event_type", None)
        suffix = f" ({event_type})" if event_type else ""
        return f"{color}{base}{_RESET} {message}{suffix}"


class JsonLinesFormatter(logging.Formatter):
    """Structured JSON-lines formatter for the on-disk audit trail."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "event_type": getattr(record, "event_type", None),
            "context": getattr(record, "context", {}),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class AccountabilityLogger:
    """Owns a QueueListener wiring one QueueHandler to two real sinks.

    Supports use as a context manager to guarantee the background
    listener thread is always stopped and flushed cleanly.
    """

    def __init__(
        self,
        name: str = "passforge",
        log_dir: str = "logs",
        level: int = logging.INFO,
        console: bool = True,
    ) -> None:
        self.name = name
        self.log_dir = Path(log_dir)
        self.level = level
        self._console_enabled = console
        self._queue: "queue.Queue" = queue.Queue(-1)
        self._listener: Optional[logging.handlers.QueueListener] = None
        self._logger = logging.getLogger(name)
        self._started = False

    def start(self) -> logging.Logger:
        """Initialize handlers, wire the QueueListener, and return the logger."""
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            audit_path = self.log_dir / f"{self.name}_audit.jsonl"

            file_handler = logging.FileHandler(audit_path, encoding="utf-8")
            file_handler.setFormatter(JsonLinesFormatter())
            file_handler.setLevel(self.level)

            handlers = [file_handler]

            if self._console_enabled:
                console_handler = logging.StreamHandler()
                console_handler.setFormatter(ConsoleFormatter())
                console_handler.setLevel(self.level)
                handlers.append(console_handler)

            self._listener = logging.handlers.QueueListener(
                self._queue, *handlers, respect_handler_level=True
            )
            self._listener.start()

            queue_handler = logging.handlers.QueueHandler(self._queue)
            self._logger.handlers.clear()
            self._logger.addHandler(queue_handler)
            self._logger.setLevel(self.level)
            self._logger.propagate = False

            self._started = True
            return self._logger
        except OSError as exc:
            raise LogInitializationError(
                f"Failed to initialize accountability logger: {exc}",
                context={"log_dir": str(self.log_dir)},
            ) from exc

    def stop(self) -> None:
        """Stop the background listener thread, flushing pending records."""
        if self._listener is not None and self._started:
            self._listener.stop()
            self._started = False

    def __enter__(self) -> logging.Logger:
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()

    def __repr__(self) -> str:
        return f"AccountabilityLogger(name={self.name!r}, log_dir={str(self.log_dir)!r})"


def log_event(
    logger: logging.Logger,
    level: int,
    message: str,
    event_type: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
) -> None:
    """Convenience helper to emit a structured log record with extras."""
    logger.log(
        level,
        message,
        extra={"event_type": event_type, "context": context or {}},
    )
