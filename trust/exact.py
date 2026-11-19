"""Exact numbers for configuration values and policy comparisons.

A configured number is read as the decimal (or rational) the author wrote: the float 0.1 means 1/10, the string "1/3" means one third.
Weights, thresholds and fused scores are therefore compared without binary rounding, so strict inequality at a threshold is exact.
"""
from decimal import Decimal
from fractions import Fraction
import math

from trust.errors import ConfigError


def to_fraction(value, name):
    """A finite int, float (shortest round-trip decimal), Decimal, Fraction or numeric string as an exact Fraction."""
    if value is None or isinstance(value, bool):
        raise ConfigError(f"{name}: a number is required")
    if isinstance(value, Fraction):
        return value
    if isinstance(value, int):
        return Fraction(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ConfigError(f"{name}: a finite number is required")
        return Fraction(repr(value))
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ConfigError(f"{name}: a finite number is required")
        return Fraction(value)
    if isinstance(value, str):
        try:
            return Fraction(value.strip())
        except (ValueError, ZeroDivisionError):
            raise ConfigError(f"{name}: not a number: {value!r}") from None
    raise ConfigError(f"{name}: unsupported number type {type(value).__name__}")
