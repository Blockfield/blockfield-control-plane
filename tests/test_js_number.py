"""Stats digests must match the site's JSON.stringify for every double."""

import pytest

from cpv2.core import _js_number

# Expected strings are what node prints for JSON.stringify(x).
CASES = [
    (123456789012345680000.0, "123456789012345680000"),
    (9007199254740994.0, "9007199254740994"),
    (2.0**60, "1152921504606847000"),
    (1e20, "100000000000000000000"),
    (1e21, "1e+21"),
    (1e-7, "1e-7"),
    (0.0000012, "0.0000012"),
    (123.0, "123"),
    (-0.5, "-0.5"),
]


@pytest.mark.parametrize(("value", "expected"), CASES)
def test_js_number_matches_javascript(value, expected):
    assert _js_number(value) == expected
