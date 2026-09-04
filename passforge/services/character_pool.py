"""Secure character pool construction and policy-compliance checks."""

from __future__ import annotations

import string
from typing import Dict

from passforge.core.enums import PasswordCategory
from passforge.core.exceptions import EmptyCharacterPoolError, InvalidExclusionSetError
from passforge.models.policy import PasswordPolicy

_SIMILAR_CHARS = "l1IoO0"


class CharacterPool:
    """Builds and exposes the character sets used during generation."""

    def __init__(self, policy: PasswordPolicy) -> None:
        self.policy = policy
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.special = string.punctuation
        self._apply_exclusions()
        self._validate_non_empty()

    def _apply_exclusions(self) -> None:
        if self.policy.exclude_similar:
            for char in _SIMILAR_CHARS:
                self.lowercase = self.lowercase.replace(char.lower(), "")
                self.uppercase = self.uppercase.replace(char.upper(), "")
                self.digits = self.digits.replace(char, "")

        if self.policy.exclude_chars:
            for char in self.policy.exclude_chars:
                self.lowercase = self.lowercase.replace(char.lower(), "")
                self.uppercase = self.uppercase.replace(char.upper(), "")
                self.digits = self.digits.replace(char, "")
                self.special = self.special.replace(char, "")

    def _validate_non_empty(self) -> None:
        if self.policy.min_digits > 0 and not self.digits:
            raise InvalidExclusionSetError(
                "Exclusion set removed all digit characters but policy "
                "requires min_digits > 0",
                context={"min_digits": self.policy.min_digits},
            )
        if self.policy.min_upper > 0 and not self.uppercase:
            raise InvalidExclusionSetError(
                "Exclusion set removed all uppercase characters but policy "
                "requires min_upper > 0",
                context={"min_upper": self.policy.min_upper},
            )
        if self.policy.min_lower > 0 and not self.lowercase:
            raise InvalidExclusionSetError(
                "Exclusion set removed all lowercase characters but policy "
                "requires min_lower > 0",
                context={"min_lower": self.policy.min_lower},
            )
        if self.policy.min_special > 0 and not self.special:
            raise InvalidExclusionSetError(
                "Exclusion set removed all special characters but policy "
                "requires min_special > 0",
                context={"min_special": self.policy.min_special},
            )

    def get_character_set(self, category: PasswordCategory) -> str:
        if category == PasswordCategory.ALPHANUMERIC:
            pool = self.lowercase + self.uppercase + self.digits
        elif category == PasswordCategory.COMPLEX:
            pool = self.lowercase + self.uppercase + self.digits + self.special
        elif category == PasswordCategory.PASSPHRASE:
            pool = self.lowercase + self.uppercase
        else:
            raise ValueError(f"Unsupported category: {category}")

        if not pool:
            raise EmptyCharacterPoolError(
                "Character pool is empty after exclusions",
                context={"category": str(category)},
            )
        return pool

    def validate_policy_compliance(self, password: str, category: PasswordCategory) -> bool:
        if not (self.policy.min_length <= len(password) <= self.policy.max_length):
            return False

        counts: Dict[str, int] = {"digit": 0, "special": 0, "upper": 0, "lower": 0}
        for char in password:
            if char in self.digits:
                counts["digit"] += 1
            elif char in self.special:
                counts["special"] += 1
            elif char in self.uppercase:
                counts["upper"] += 1
            elif char in self.lowercase:
                counts["lower"] += 1

        if category == PasswordCategory.ALPHANUMERIC:
            return (
                counts["digit"] >= self.policy.min_digits
                and counts["upper"] >= self.policy.min_upper
                and counts["lower"] >= self.policy.min_lower
            )
        if category == PasswordCategory.COMPLEX:
            return (
                counts["digit"] >= self.policy.min_digits
                and counts["special"] >= self.policy.min_special
                and counts["upper"] >= self.policy.min_upper
                and counts["lower"] >= self.policy.min_lower
            )
        if category == PasswordCategory.PASSPHRASE:
            return counts["upper"] >= self.policy.min_upper and counts["lower"] >= self.policy.min_lower
        return False

    def __repr__(self) -> str:
        return (
            f"CharacterPool(lower={len(self.lowercase)}, upper={len(self.uppercase)}, "
            f"digits={len(self.digits)}, special={len(self.special)})"
        )
