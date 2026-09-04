import pytest

from passforge.core.enums import PasswordCategory
from passforge.core.exceptions import EmptyCharacterPoolError, InvalidExclusionSetError
from passforge.models.policy import PasswordPolicy
from passforge.services.character_pool import CharacterPool


class TestCharacterPool:
    def test_excludes_similar_by_default(self):
        pool = CharacterPool(PasswordPolicy())
        for ch in "l1IoO0":
            assert ch not in pool.lowercase + pool.uppercase + pool.digits

    def test_exclude_similar_disabled(self):
        pool = CharacterPool(PasswordPolicy(exclude_similar=False))
        assert "1" in pool.digits

    def test_custom_exclusions_removed_everywhere(self):
        pool = CharacterPool(PasswordPolicy(exclude_chars="xyz", exclude_similar=False))
        combined = pool.lowercase + pool.uppercase + pool.digits + pool.special
        for ch in "xyzXYZ":
            assert ch not in combined

    def test_exclusion_emptying_required_pool_raises(self):
        digits = "0123456789"
        with pytest.raises(InvalidExclusionSetError):
            CharacterPool(PasswordPolicy(exclude_chars=digits, min_digits=1, exclude_similar=False))

    def test_get_character_set_alphanumeric_excludes_special(self):
        pool = CharacterPool(PasswordPolicy())
        charset = pool.get_character_set(PasswordCategory.ALPHANUMERIC)
        assert not any(c in pool.special for c in charset)

    def test_get_character_set_complex_includes_special(self):
        pool = CharacterPool(PasswordPolicy())
        charset = pool.get_character_set(PasswordCategory.COMPLEX)
        assert any(c in pool.special for c in charset)

    def test_validate_policy_compliance_rejects_short_password(self):
        pool = CharacterPool(PasswordPolicy(min_length=12))
        assert pool.validate_policy_compliance("Ab1!", PasswordCategory.COMPLEX) is False

    def test_validate_policy_compliance_accepts_good_password(self):
        policy = PasswordPolicy(min_length=8, min_digits=1, min_special=1, min_upper=1, min_lower=1)
        pool = CharacterPool(policy)
        assert pool.validate_policy_compliance("Abcdef2!", PasswordCategory.COMPLEX) is True
