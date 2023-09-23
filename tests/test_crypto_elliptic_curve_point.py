import pytest

from btctoy.crypto import (
    EllipcCurvePoint,
)


def test_ne() -> None:
    a = EllipcCurvePoint(x=3, y=-7, a=5, b=7)
    b = EllipcCurvePoint(x=18, y=77, a=5, b=7)
    assert a != b
    assert (a != a) is False


def test_on_curve() -> None:
    with pytest.raises(ValueError, match="is not on the elliptic curve"):
        EllipcCurvePoint(x=-2, y=4, a=5, b=7)
    # these should not raise an error
    EllipcCurvePoint(x=3, y=-7, a=5, b=7)
    EllipcCurvePoint(x=18, y=77, a=5, b=7)


def test_add0() -> None:
    a = EllipcCurvePoint(x=None, y=None, a=5, b=7)
    b = EllipcCurvePoint(x=2, y=5, a=5, b=7)
    c = EllipcCurvePoint(x=2, y=-5, a=5, b=7)
    assert a + b == b
    assert b + a == b
    assert b + c == a


def test_add1() -> None:
    a = EllipcCurvePoint(x=3, y=7, a=5, b=7)
    b = EllipcCurvePoint(x=-1, y=-1, a=5, b=7)
    assert a + b == EllipcCurvePoint(x=2, y=-5, a=5, b=7)


def test_add2() -> None:
    a = EllipcCurvePoint(x=-1, y=1, a=5, b=7)
    assert a + a == EllipcCurvePoint(x=18, y=-77, a=5, b=7)
