import pytest

from passforge.core.exceptions import PolicyConfigurationError
from passforge.models.policy import PasswordPolicy


class TestPasswordPolicy:
    def test_default_policy_is_valid(self):
        PasswordPolicy().validate()

    def test_max_less_than_min_is_invalid(self):
        with pytest.raises(PolicyConfigurationError):
            PasswordPolicy(min_length=20, max_length=10).validate()

    def test_negative_min_length_is_invalid(self):
        with pytest.raises(PolicyConfigurationError):
            PasswordPolicy(min_length=0).validate()

    def test_requirements_exceeding_max_length_is_invalid(self):
        with pytest.raises(PolicyConfigurationError):
            PasswordPolicy(
                max_length=4, min_digits=2, min_special=2, min_upper=2, min_lower=2
            ).validate()

    def test_zero_attempts_is_invalid(self):
        with pytest.raises(PolicyConfigurationError):
            PasswordPolicy(max_generation_attempts=0).validate()

    def test_historical_reconstruction_without_validate_does_not_raise(self):
        # Simulates rebuilding a policy from a stored/historical record;
        # constructor must not itself enforce validation.
        policy = PasswordPolicy(min_length=50, max_length=10)
        assert policy.min_length == 50

    def test_to_dict_roundtrip_keys(self):
        d = PasswordPolicy().to_dict()
        assert set(d.keys()) == {
            "min_length", "max_length", "min_digits", "min_special",
            "min_upper", "min_lower", "exclude_chars", "exclude_similar",
            "max_generation_attempts",
        }
