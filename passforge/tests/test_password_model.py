from passforge.core.enums import PasswordCategory, PasswordStrength
from passforge.models.password import GeneratedPassword


def _make(value="Ab3!xyZ9", charset_size=94):
    return GeneratedPassword(
        value=value,
        category=PasswordCategory.COMPLEX,
        strength=PasswordStrength.STRONG,
        charset_size=charset_size,
    )


class TestGeneratedPassword:
    def test_str_is_raw_value(self):
        p = _make("hello")
        assert str(p) == "hello"

    def test_repr_contains_metadata(self):
        p = _make("hello")
        assert "GeneratedPassword" in repr(p)

    def test_equality_with_string(self):
        p = _make("hello")
        assert p == "hello"
        assert p != "world"

    def test_equality_between_instances(self):
        assert _make("same") == _make("same")

    def test_hash_usable_in_set(self):
        s = {_make("a"), _make("a"), _make("b")}
        assert len(s) == 2

    def test_len_matches_value(self):
        assert len(_make("abcdef")) == 6

    def test_bool_false_for_empty(self):
        assert bool(_make("")) is False
        assert bool(_make("x")) is True

    def test_iteration_yields_chars(self):
        assert list(_make("abc")) == ["a", "b", "c"]

    def test_contains(self):
        assert "b" in _make("abc")

    def test_getitem(self):
        assert _make("abc")[1] == "b"

    def test_entropy_positive_for_nonempty(self):
        assert _make("abcdef", charset_size=26).entropy_bits > 0

    def test_entropy_zero_for_empty(self):
        assert _make("", charset_size=26).entropy_bits == 0.0

    def test_ordering_by_entropy(self):
        weak = _make("ab", charset_size=2)
        strong = _make("abcdefgh", charset_size=94)
        assert weak < strong
        assert strong > weak
        assert weak <= weak
        assert strong >= strong

    def test_to_dict_shape(self):
        d = _make("abc").to_dict()
        assert d["value"] == "abc"
        assert d["length"] == 3
        assert "entropy_bits" in d
