from passforge.core.enums import PasswordCategory, PasswordStrength


class TestPasswordStrengthOrdering:
    def test_basic_less_than_strong(self):
        assert PasswordStrength.BASIC < PasswordStrength.STRONG

    def test_strong_less_than_paranoid(self):
        assert PasswordStrength.STRONG < PasswordStrength.PARANOID

    def test_paranoid_is_greatest(self):
        assert PasswordStrength.PARANOID > PasswordStrength.BASIC
        assert PasswordStrength.PARANOID >= PasswordStrength.PARANOID

    def test_le_ge_reflexive(self):
        assert PasswordStrength.STRONG <= PasswordStrength.STRONG
        assert PasswordStrength.STRONG >= PasswordStrength.STRONG

    def test_str_returns_value(self):
        assert str(PasswordStrength.BASIC) == "basic"
        assert str(PasswordCategory.COMPLEX) == "complex"

    def test_comparison_against_non_enum_raises_type_error(self):
        import pytest

        with pytest.raises(TypeError):
            PasswordStrength.BASIC < 5
