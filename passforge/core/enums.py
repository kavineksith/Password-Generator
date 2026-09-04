"""Core enumerations shared across passforge."""

from __future__ import annotations

from enum import Enum


class PasswordCategory(Enum):
    """Supported password generation categories."""

    ALPHANUMERIC = "alphanumeric"
    COMPLEX = "complex"
    PASSPHRASE = "passphrase"

    def __str__(self) -> str:
        return self.value


class PasswordStrength(Enum):
    """Password strength / security tiers.

    Ordering is defined at module level (see _STRENGTH_ORDER) because a
    class-level ordering dict inside an Enum body gets shadowed by the
    enum's own member machinery.
    """

    BASIC = "basic"
    STRONG = "strong"
    PARANOID = "paranoid"

    def __str__(self) -> str:
        return self.value

    def __lt__(self, other: "PasswordStrength") -> bool:
        if not isinstance(other, PasswordStrength):
            return NotImplemented
        return _STRENGTH_ORDER[self] < _STRENGTH_ORDER[other]

    def __le__(self, other: "PasswordStrength") -> bool:
        if not isinstance(other, PasswordStrength):
            return NotImplemented
        return _STRENGTH_ORDER[self] <= _STRENGTH_ORDER[other]

    def __gt__(self, other: "PasswordStrength") -> bool:
        if not isinstance(other, PasswordStrength):
            return NotImplemented
        return _STRENGTH_ORDER[self] > _STRENGTH_ORDER[other]

    def __ge__(self, other: "PasswordStrength") -> bool:
        if not isinstance(other, PasswordStrength):
            return NotImplemented
        return _STRENGTH_ORDER[self] >= _STRENGTH_ORDER[other]


# Module-level ordering map -- MUST stay outside the Enum class body.
_STRENGTH_ORDER = {
    PasswordStrength.BASIC: 0,
    PasswordStrength.STRONG: 1,
    PasswordStrength.PARANOID: 2,
}


class ErrorSeverity(Enum):
    """Severity classification attached to every PassforgeError."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

    def __str__(self) -> str:
        return self.value


class LogEventType(Enum):
    """Categorizes accountability log events."""

    GENERATION_REQUEST = "generation_request"
    GENERATION_SUCCESS = "generation_success"
    GENERATION_FAILURE = "generation_failure"
    POLICY_VIOLATION = "policy_violation"
    EXPORT_SUCCESS = "export_success"
    EXPORT_FAILURE = "export_failure"
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    VALIDATION_ERROR = "validation_error"

    def __str__(self) -> str:
        return self.value
