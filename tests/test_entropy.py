"""Sanity tests for the Shannon entropy helper."""

from __future__ import annotations

import pytest

from detlab.entropy import shannon_entropy


def test_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_single_char_is_zero():
    assert shannon_entropy("aaaaaa") == 0.0


def test_uniform_two_chars_is_one_bit():
    assert shannon_entropy("ababab") == pytest.approx(1.0)


def test_random_base32_string_is_high():
    s = "abcdefghijklmnopqrstuvwxyz012345"  # 32 unique chars, max entropy = 5
    assert shannon_entropy(s) == pytest.approx(5.0)


def test_english_word_is_low():
    assert shannon_entropy("hello") < 2.5
