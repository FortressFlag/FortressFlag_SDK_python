"""The decode edges the vectors cannot reach: hostile shapes that never leave the backend
but must still fail closed here."""

import math

from fortressflag._ruleset import MISSING, decode_value


def test_absent_and_null_are_both_no_value_and_neither_collapses_to_false() -> None:
    assert decode_value(MISSING, "boolean") == (None, False)
    assert decode_value(None, "boolean") == (None, False)


def test_an_explicit_false_is_a_value() -> None:
    assert decode_value(False, "boolean") == (False, True)


def test_kind_mismatch_is_no_value_not_a_coercion() -> None:
    assert decode_value("true", "boolean")[1] is False
    assert decode_value(1, "boolean")[1] is False
    assert decode_value(True, "string")[1] is False
    assert decode_value("5", "number")[1] is False


def test_bool_is_not_a_number_the_isinstance_trap() -> None:
    # isinstance(True, int) is True — the recorded trap. JSON true must not become 1.0.
    assert decode_value(True, "number")[1] is False


def test_unknown_kind_is_no_value() -> None:
    assert decode_value(True, "datetime")[1] is False


def test_non_finite_numbers_are_hostile_not_values() -> None:
    assert decode_value(math.nan, "number")[1] is False
    assert decode_value(math.inf, "number")[1] is False
