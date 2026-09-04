"""Generated-password result model."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterator

from passforge.core.enums import PasswordCategory, PasswordStrength


@dataclass
class GeneratedPassword:
    """Represents a single generated password/passphrase and its metadata.

    Implements a full dunder suite so instances behave naturally in
    collections, comparisons, and serialization contexts.
    """

    value: str
    category: PasswordCategory
    strength: PasswordStrength
    charset_size: int = 0
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def entropy_bits(self) -> float:
        """Estimate Shannon entropy in bits given charset size and length."""
        if self.charset_size <= 1 or len(self.value) == 0:
            return 0.0
        return len(self.value) * math.log2(self.charset_size)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "category": str(self.category),
            "strength": str(self.strength),
            "length": len(self.value),
            "entropy_bits": round(self.entropy_bits, 2),
            "generated_at": self.generated_at.isoformat(),
        }

    # -- dunder suite ------------------------------------------------

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return (
            f"GeneratedPassword(category={self.category!r}, "
            f"strength={self.strength!r}, length={len(self.value)}, "
            f"entropy_bits={self.entropy_bits:.1f})"
        )

    def __eq__(self, other: object) -> bool:
        if isinstance(other, GeneratedPassword):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.value)

    def __len__(self) -> int:
        return len(self.value)

    def __bool__(self) -> bool:
        return len(self.value) > 0

    def __iter__(self) -> Iterator[str]:
        return iter(self.value)

    def __contains__(self, item: str) -> bool:
        return item in self.value

    def __getitem__(self, index):
        return self.value[index]

    def __lt__(self, other: "GeneratedPassword") -> bool:
        if not isinstance(other, GeneratedPassword):
            return NotImplemented
        return self.entropy_bits < other.entropy_bits

    def __le__(self, other: "GeneratedPassword") -> bool:
        if not isinstance(other, GeneratedPassword):
            return NotImplemented
        return self.entropy_bits <= other.entropy_bits

    def __gt__(self, other: "GeneratedPassword") -> bool:
        if not isinstance(other, GeneratedPassword):
            return NotImplemented
        return self.entropy_bits > other.entropy_bits

    def __ge__(self, other: "GeneratedPassword") -> bool:
        if not isinstance(other, GeneratedPassword):
            return NotImplemented
        return self.entropy_bits >= other.entropy_bits
