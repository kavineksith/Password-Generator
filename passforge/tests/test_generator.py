import asyncio
from pathlib import Path

import pytest

from passforge.core.enums import PasswordCategory, PasswordStrength
from passforge.core.exceptions import InputValidationError, InvalidCountError, SemaphoreConfigurationError
from passforge.models.policy import PasswordPolicy
from passforge.services.generator import PasswordGeneratorService
from passforge.services.wordlist_service import WordlistService

FIXTURE = Path(__file__).parent / "fixtures_wordlist.txt"


def _service(**policy_kwargs) -> PasswordGeneratorService:
    policy = PasswordPolicy(**policy_kwargs)
    return PasswordGeneratorService(policy=policy, wordlist_service=WordlistService(str(FIXTURE)))


class TestGenerateOne:
    def test_alphanumeric_respects_length(self):
        service = _service(min_length=10, max_length=20)
        result = asyncio.run(service.generate_one(12, PasswordCategory.ALPHANUMERIC))
        assert len(result) == 12

    def test_complex_contains_special_char(self):
        service = _service(min_length=10, max_length=20, min_special=1)
        result = asyncio.run(service.generate_one(12, PasswordCategory.COMPLEX))
        assert any(not c.isalnum() for c in result.value)

    def test_passphrase_uses_wordlist(self):
        service = _service()
        result = asyncio.run(
            service.generate_one(4, PasswordCategory.PASSPHRASE, PasswordStrength.BASIC)
        )
        assert len(result.value.split(" ")) == 4

    def test_invalid_length_raises(self):
        service = _service(min_length=10, max_length=20)
        with pytest.raises(InputValidationError):
            asyncio.run(service.generate_one(2, PasswordCategory.ALPHANUMERIC))

    def test_passphrase_word_count_ignores_char_length_policy(self):
        # Default policy has min_length=12, but a 4-word passphrase must
        # not be validated against character-length bounds.
        service = _service()
        result = asyncio.run(
            service.generate_one(4, PasswordCategory.PASSPHRASE, PasswordStrength.BASIC)
        )
        assert len(result.value.split(" ")) == 4

    def test_passphrase_word_count_upper_bound_enforced(self):
        service = _service()
        with pytest.raises(InputValidationError):
            asyncio.run(service.generate_one(1000, PasswordCategory.PASSPHRASE))

    def test_zero_max_concurrency_rejected(self):
        with pytest.raises(SemaphoreConfigurationError):
            PasswordGeneratorService(max_concurrency=0)


class TestGenerateMany:
    def test_generates_requested_count(self):
        service = _service(min_length=10, max_length=20)
        results = asyncio.run(service.generate_many(5, 12, PasswordCategory.ALPHANUMERIC))
        assert len(results) == 5

    def test_results_are_unique_with_high_probability(self):
        service = _service(min_length=14, max_length=20)
        results = asyncio.run(service.generate_many(10, 16, PasswordCategory.COMPLEX))
        values = {r.value for r in results}
        assert len(values) == 10

    def test_invalid_count_raises(self):
        service = _service()
        with pytest.raises(InvalidCountError):
            asyncio.run(service.generate_many(0, 12, PasswordCategory.ALPHANUMERIC))

    def test_respects_max_concurrency_bound(self):
        service = _service(min_length=10, max_length=20)
        service.max_concurrency = 2
        results = asyncio.run(service.generate_many(6, 12, PasswordCategory.ALPHANUMERIC))
        assert len(results) == 6
