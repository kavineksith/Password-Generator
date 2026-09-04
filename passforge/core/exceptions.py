"""
Custom exception hierarchy for passforge.

Every exception carries a project-prefixed error code (PFG-xxxx), a
severity classification, a UTC timestamp, and a structured context
payload so that failures are fully auditable from log output alone.
"""

from __future__ import annotations

import pickle
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from passforge.core.enums import ErrorSeverity


class PassforgeError(Exception):
    """Base exception for all passforge errors.

    Attributes:
        message: Human-readable description of the failure.
        error_code: Project-prefixed structured code, e.g. ``PFG-1000``.
        severity: ErrorSeverity classification.
        context: Arbitrary structured payload describing failure context.
        timestamp: UTC timestamp of when the exception was created.
    """

    error_code: str = "PFG-1000"
    default_severity: ErrorSeverity = ErrorSeverity.ERROR

    def __init__(
        self,
        message: str,
        *,
        error_code: Optional[str] = None,
        severity: Optional[ErrorSeverity] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.message = message
        self.error_code = error_code or type(self).error_code
        self.severity = severity or type(self).default_severity
        self.context: Dict[str, Any] = context or {}
        self.timestamp = datetime.now(timezone.utc)
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the exception into a structured, log-friendly dict."""
        return {
            "error_code": self.error_code,
            "exception_type": type(self).__name__,
            "message": self.message,
            "severity": str(self.severity),
            "timestamp": self.timestamp.isoformat(),
            "context": self.context,
        }

    def __str__(self) -> str:
        return f"[{self.error_code}] {self.message}"

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(message={self.message!r}, "
            f"error_code={self.error_code!r}, severity={self.severity!r}, "
            f"context={self.context!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PassforgeError):
            return NotImplemented
        return (
            self.error_code == other.error_code
            and self.message == other.message
            and self.context == other.context
        )

    def __hash__(self) -> int:
        return hash((self.error_code, self.message))

    def __bool__(self) -> bool:
        # An exception instance is always "truthy" -- explicit for clarity
        # and to avoid accidental reliance on default object truthiness.
        return True

    def __len__(self) -> int:
        return len(self.context)

    def __contains__(self, key: str) -> bool:
        return key in self.context

    def __getitem__(self, key: str) -> Any:
        return self.context[key]

    def __iter__(self):
        return iter(self.context.items())

    def __reduce__(self):
        # Enables pickling despite custom __init__ signature.
        return (
            _rebuild_exception,
            (type(self), self.message, self.error_code, self.severity, self.context),
        )


def _rebuild_exception(cls, message, error_code, severity, context):
    """Helper used by __reduce__ to reconstruct exceptions when unpickling."""
    return cls(message, error_code=error_code, severity=severity, context=context)


# --------------------------------------------------------------------------
# Input & validation errors (PFG-11xx)
# --------------------------------------------------------------------------

class InputValidationError(PassforgeError):
    """Raised when user-supplied input fails validation."""

    error_code = "PFG-1100"
    default_severity = ErrorSeverity.WARNING


class InvalidLengthError(InputValidationError):
    """Raised when requested length/word-count is out of allowed range."""

    error_code = "PFG-1101"


class InvalidCategoryError(InputValidationError):
    """Raised when an unrecognized password category is requested."""

    error_code = "PFG-1102"


class InvalidStrengthError(InputValidationError):
    """Raised when an unrecognized strength level is requested."""

    error_code = "PFG-1103"


class InvalidCountError(InputValidationError):
    """Raised when the requested generation count is invalid."""

    error_code = "PFG-1104"


class InvalidExclusionSetError(InputValidationError):
    """Raised when an exclusion character set empties a required pool."""

    error_code = "PFG-1105"


# --------------------------------------------------------------------------
# Policy errors (PFG-12xx)
# --------------------------------------------------------------------------

class PolicyError(PassforgeError):
    """Base class for password-policy related errors."""

    error_code = "PFG-1200"


class PolicyViolationError(PolicyError):
    """Raised when a generated candidate cannot satisfy the active policy."""

    error_code = "PFG-1201"


class PolicyConfigurationError(PolicyError):
    """Raised when a PasswordPolicy itself is internally inconsistent."""

    error_code = "PFG-1202"


class GenerationExhaustedError(PolicyError):
    """Raised when the maximum retry budget is exhausted without success."""

    error_code = "PFG-1203"
    default_severity = ErrorSeverity.CRITICAL


# --------------------------------------------------------------------------
# Character pool errors (PFG-13xx)
# --------------------------------------------------------------------------

class CharacterPoolError(PassforgeError):
    """Base class for character-pool construction errors."""

    error_code = "PFG-1300"


class EmptyCharacterPoolError(CharacterPoolError):
    """Raised when exclusions reduce a required character pool to empty."""

    error_code = "PFG-1301"
    default_severity = ErrorSeverity.CRITICAL


# --------------------------------------------------------------------------
# Wordlist errors (PFG-14xx)
# --------------------------------------------------------------------------

class WordlistError(PassforgeError):
    """Base class for EFF wordlist loading errors."""

    error_code = "PFG-1400"


class WordlistNotFoundError(WordlistError):
    """Raised when the configured wordlist file does not exist."""

    error_code = "PFG-1401"
    default_severity = ErrorSeverity.CRITICAL


class WordlistFormatError(WordlistError):
    """Raised when the wordlist file is empty or malformed."""

    error_code = "PFG-1402"


class WordlistReadError(WordlistError):
    """Raised on I/O failure while reading the wordlist file."""

    error_code = "PFG-1403"


# --------------------------------------------------------------------------
# Export / persistence errors (PFG-15xx)
# --------------------------------------------------------------------------

class ExportError(PassforgeError):
    """Base class for output/export errors."""

    error_code = "PFG-1500"


class UnsupportedExportFormatError(ExportError):
    """Raised when an unsupported export file extension is requested."""

    error_code = "PFG-1501"


class ExportWriteError(ExportError):
    """Raised when writing generated results to disk fails."""

    error_code = "PFG-1502"
    default_severity = ErrorSeverity.CRITICAL


class ExportPathError(ExportError):
    """Raised when the destination path is invalid or unwritable."""

    error_code = "PFG-1503"


# --------------------------------------------------------------------------
# Concurrency errors (PFG-16xx)
# --------------------------------------------------------------------------

class ConcurrencyError(PassforgeError):
    """Base class for errors arising from parallel generation tasks."""

    error_code = "PFG-1600"


class TaskPoolError(ConcurrencyError):
    """Raised when one or more concurrent generation tasks fail."""

    error_code = "PFG-1601"
    default_severity = ErrorSeverity.CRITICAL


class SemaphoreConfigurationError(ConcurrencyError):
    """Raised when concurrency limits are configured invalidly."""

    error_code = "PFG-1602"


# --------------------------------------------------------------------------
# Logging subsystem errors (PFG-17xx)
# --------------------------------------------------------------------------

class LoggingError(PassforgeError):
    """Base class for accountability-logging subsystem errors."""

    error_code = "PFG-1700"


class LogInitializationError(LoggingError):
    """Raised when the dual-sink logger fails to initialize."""

    error_code = "PFG-1701"
    default_severity = ErrorSeverity.CRITICAL


class LogWriteError(LoggingError):
    """Raised when a log record cannot be persisted to its sink."""

    error_code = "PFG-1702"


# --------------------------------------------------------------------------
# CLI errors (PFG-18xx)
# --------------------------------------------------------------------------

class CLIError(PassforgeError):
    """Base class for CLI/interactive-mode errors."""

    error_code = "PFG-1800"
    default_severity = ErrorSeverity.WARNING


class InteractiveAbortError(CLIError):
    """Raised when the user cancels an interactive session."""

    error_code = "PFG-1801"
    default_severity = ErrorSeverity.INFO


class ArgumentParsingError(CLIError):
    """Raised when command-line argument parsing fails semantically."""

    error_code = "PFG-1802"
