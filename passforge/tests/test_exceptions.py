import pickle

import pytest

from passforge.core.enums import ErrorSeverity
from passforge.core.exceptions import (
    InvalidLengthError,
    PassforgeError,
    PolicyViolationError,
)


class TestPassforgeError:
    def test_default_error_code(self):
        err = PassforgeError("boom")
        assert err.error_code == "PFG-1000"

    def test_str_includes_code(self):
        err = PassforgeError("boom")
        assert str(err) == "[PFG-1000] boom"

    def test_repr_contains_class_name(self):
        err = InvalidLengthError("bad length")
        assert "InvalidLengthError" in repr(err)

    def test_equality(self):
        a = PassforgeError("x", error_code="PFG-9999", context={"k": 1})
        b = PassforgeError("x", error_code="PFG-9999", context={"k": 1})
        c = PassforgeError("y", error_code="PFG-9999", context={"k": 1})
        assert a == b
        assert a != c
        assert a != "not an error"

    def test_hash_stable(self):
        a = PassforgeError("x", error_code="PFG-1")
        assert hash(a) == hash(a)

    def test_bool_always_true(self):
        assert bool(PassforgeError("x")) is True

    def test_len_matches_context(self):
        err = PassforgeError("x", context={"a": 1, "b": 2})
        assert len(err) == 2

    def test_contains_and_getitem(self):
        err = PassforgeError("x", context={"a": 1})
        assert "a" in err
        assert err["a"] == 1

    def test_iter_yields_context_items(self):
        err = PassforgeError("x", context={"a": 1})
        assert dict(iter(err)) == {"a": 1}

    def test_to_dict_shape(self):
        err = InvalidLengthError("bad", context={"length": -1})
        d = err.to_dict()
        assert d["error_code"] == "PFG-1101"
        assert d["exception_type"] == "InvalidLengthError"
        assert d["context"] == {"length": -1}
        assert "timestamp" in d

    def test_pickle_roundtrip(self):
        err = PolicyViolationError("cannot satisfy", context={"attempts": 5})
        restored = pickle.loads(pickle.dumps(err))
        assert restored == err
        assert restored.context == err.context

    def test_severity_default_by_subclass(self):
        assert InvalidLengthError("x").severity == ErrorSeverity.WARNING
        assert PolicyViolationError("x").severity == ErrorSeverity.ERROR

    def test_raises_and_catchable_as_base(self):
        with pytest.raises(PassforgeError):
            raise InvalidLengthError("bad")
