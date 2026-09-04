"""Async password/passphrase generation service."""

from __future__ import annotations

import asyncio
import logging
import random
import secrets
from typing import List, Optional

from passforge.core.enums import LogEventType, PasswordCategory, PasswordStrength
from passforge.core.exceptions import (
    GenerationExhaustedError,
    InputValidationError,
    InvalidCountError,
    PolicyViolationError,
    SemaphoreConfigurationError,
    TaskPoolError,
)
from passforge.core.logger import log_event
from passforge.models.password import GeneratedPassword
from passforge.models.policy import PasswordPolicy
from passforge.services.character_pool import CharacterPool
from passforge.services.wordlist_service import WordlistService

_DEFAULT_MAX_CONCURRENCY = 16


class PasswordGeneratorService:
    """Industrial-grade async password generator with policy enforcement.

    Single-password generation is CPU-bound and effectively instant, so
    each candidate attempt runs synchronously; bulk generation fans out
    across a bounded worker pool via ``asyncio.gather`` + a semaphore
    (each unit of work offloaded to a thread with ``asyncio.to_thread``)
    so a large ``--count`` request is not serialized behind a single
    event-loop turn.
    """

    def __init__(
        self,
        policy: Optional[PasswordPolicy] = None,
        wordlist_service: Optional[WordlistService] = None,
        logger: Optional[logging.Logger] = None,
        max_concurrency: int = _DEFAULT_MAX_CONCURRENCY,
    ) -> None:
        self.policy = policy or PasswordPolicy()
        self.policy.validate()
        self.character_pool = CharacterPool(self.policy)
        self.wordlist_service = wordlist_service or WordlistService()
        self.logger = logger or logging.getLogger("passforge")

        if max_concurrency < 1:
            raise SemaphoreConfigurationError(
                "max_concurrency must be >= 1", context={"max_concurrency": max_concurrency}
            )
        self.max_concurrency = max_concurrency

    _MAX_PASSPHRASE_WORDS = 64

    def _validate_length(self, length: int, category: PasswordCategory) -> None:
        if not isinstance(length, int) or length < 1:
            raise InputValidationError(
                "Length/word-count must be a positive integer",
                context={"length": length},
            )

        if category == PasswordCategory.PASSPHRASE:
            # Word count is independent of the character-length policy,
            # which governs fixed-charset passwords, not word counts.
            if length > self._MAX_PASSPHRASE_WORDS:
                raise InputValidationError(
                    f"Word count must not exceed {self._MAX_PASSPHRASE_WORDS}",
                    context={"length": length, "max_words": self._MAX_PASSPHRASE_WORDS},
                )
            return

        if not self.policy.min_length <= length <= self.policy.max_length:
            raise InputValidationError(
                f"Length must be between {self.policy.min_length} and "
                f"{self.policy.max_length}",
                context={
                    "length": length,
                    "min_length": self.policy.min_length,
                    "max_length": self.policy.max_length,
                },
            )

    def _random_source(self, strength: PasswordStrength):
        return random.choice if strength == PasswordStrength.BASIC else secrets.choice

    def _generate_fixed_password_sync(
        self, length: int, category: PasswordCategory, strength: PasswordStrength
    ) -> GeneratedPassword:
        characters = self.character_pool.get_character_set(category)
        chooser = self._random_source(strength)

        for _ in range(self.policy.max_generation_attempts):
            candidate = "".join(chooser(characters) for _ in range(length))
            if self.character_pool.validate_policy_compliance(candidate, category):
                return GeneratedPassword(
                    value=candidate,
                    category=category,
                    strength=strength,
                    charset_size=len(characters),
                )

        raise GenerationExhaustedError(
            f"Could not satisfy policy after {self.policy.max_generation_attempts} attempts",
            context={"category": str(category), "strength": str(strength), "length": length},
        )

    async def _generate_passphrase_async(
        self, word_count: int, strength: PasswordStrength
    ) -> GeneratedPassword:
        wordlist = await self.wordlist_service.load()
        chooser = self._random_source(strength)

        words = [chooser(wordlist) for _ in range(word_count)]

        if strength == PasswordStrength.STRONG:
            for i in range(len(words)):
                if secrets.randbelow(2):
                    words[i] = words[i].capitalize()
            words.append(secrets.choice(self.character_pool.digits))
        elif strength == PasswordStrength.PARANOID:
            words = [w.capitalize() for w in words]
            words.append(secrets.choice(self.character_pool.digits))
            words.append(secrets.choice(self.character_pool.special))
            secrets.SystemRandom().shuffle(words)

        separator = (
            secrets.choice(["-", "_", ".", " ", ""])
            if strength != PasswordStrength.BASIC
            else " "
        )
        value = separator.join(words)
        charset_size = len(set("".join(words))) or 1
        return GeneratedPassword(
            value=value, category=PasswordCategory.PASSPHRASE, strength=strength, charset_size=charset_size
        )

    async def generate_one(
        self,
        length: int,
        category: PasswordCategory,
        strength: PasswordStrength = PasswordStrength.STRONG,
    ) -> GeneratedPassword:
        """Generate a single password/passphrase, fully async end-to-end."""
        self._validate_length(length, category)

        log_event(
            self.logger,
            logging.INFO,
            "Generation requested",
            event_type=str(LogEventType.GENERATION_REQUEST),
            context={"category": str(category), "strength": str(strength), "length": length},
        )

        try:
            if category == PasswordCategory.PASSPHRASE:
                result = await self._generate_passphrase_async(length, strength)
            else:
                result = await asyncio.to_thread(
                    self._generate_fixed_password_sync, length, category, strength
                )
        except PolicyViolationError:
            raise
        except GenerationExhaustedError as exc:
            log_event(
                self.logger,
                logging.ERROR,
                "Generation exhausted retry budget",
                event_type=str(LogEventType.GENERATION_FAILURE),
                context=exc.context,
            )
            raise

        log_event(
            self.logger,
            logging.INFO,
            "Generation succeeded",
            event_type=str(LogEventType.GENERATION_SUCCESS),
            context={"category": str(category), "strength": str(strength), "entropy_bits": round(result.entropy_bits, 2)},
        )
        return result

    async def generate_many(
        self,
        count: int,
        length: int,
        category: PasswordCategory,
        strength: PasswordStrength = PasswordStrength.STRONG,
    ) -> List[GeneratedPassword]:
        """Concurrently generate ``count`` passwords using a bounded worker pool."""
        if not isinstance(count, int) or count < 1:
            raise InvalidCountError("count must be a positive integer", context={"count": count})

        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def _worker() -> GeneratedPassword:
            async with semaphore:
                return await self.generate_one(length, category, strength)

        results = await asyncio.gather(
            *(_worker() for _ in range(count)), return_exceptions=True
        )

        successes: List[GeneratedPassword] = []
        failures = []
        for item in results:
            if isinstance(item, GeneratedPassword):
                successes.append(item)
            else:
                failures.append(item)

        if failures and not successes:
            raise TaskPoolError(
                f"All {len(failures)} concurrent generation tasks failed",
                context={"failure_count": len(failures), "sample_error": str(failures[0])},
            )

        return successes

    def __repr__(self) -> str:
        return f"PasswordGeneratorService(policy={self.policy!r}, max_concurrency={self.max_concurrency})"
