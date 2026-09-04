"""Password policy configuration model."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict

from passforge.core.exceptions import PolicyConfigurationError


@dataclass
class PasswordPolicy:
    """Configuration governing password generation constraints.

    Validation happens explicitly via ``validate()`` rather than in
    ``__post_init__``. Keeping validation out of the constructor means a
    policy object can still be freely reconstructed (e.g. from a stored
    JSON config or historical audit record) even if it momentarily holds
    values that a stricter service-layer check would reject.
    """

    min_length: int = 12
    max_length: int = 128
    min_digits: int = 2
    min_special: int = 2
    min_upper: int = 1
    min_lower: int = 1
    exclude_chars: str = ""
    exclude_similar: bool = True
    max_generation_attempts: int = 100

    def validate(self) -> None:
        """Validate internal consistency of the policy.

        Raises:
            PolicyConfigurationError: If the policy is self-contradictory.
        """
        errors = []
        if self.min_length < 1:
            errors.append("min_length must be >= 1")
        if self.max_length < self.min_length:
            errors.append("max_length must be >= min_length")
        if self.min_digits < 0 or self.min_special < 0:
            errors.append("min_digits and min_special must be >= 0")
        if self.min_upper < 0 or self.min_lower < 0:
            errors.append("min_upper and min_lower must be >= 0")
        required_minimum = self.min_digits + self.min_special + self.min_upper + self.min_lower
        if required_minimum > self.max_length:
            errors.append(
                "sum of minimum character-class requirements exceeds max_length"
            )
        if self.max_generation_attempts < 1:
            errors.append("max_generation_attempts must be >= 1")

        if errors:
            raise PolicyConfigurationError(
                "Invalid password policy configuration",
                context={"errors": errors, "policy": asdict(self)},
            )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def __str__(self) -> str:
        return (
            f"PasswordPolicy(length={self.min_length}-{self.max_length}, "
            f"digits>={self.min_digits}, special>={self.min_special}, "
            f"upper>={self.min_upper}, lower>={self.min_lower})"
        )
