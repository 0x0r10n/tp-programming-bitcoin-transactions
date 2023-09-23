import pytest

from btctoy.crypto import (
    EllipcCurvePoint,
    ModularFieldInteger,
)


def test_on_curve() -> None:
    # tests the following points whether they are on the curve or not
    # on curve y^2=x^3-7 over F_223:
    # (192,105) (17,56) (200,119) (1,193) (42,99)
    # the ones that aren't should raise a ValueError
    prime = 223
    a = ModularFieldInteger(0, prime)
    b = ModularFieldInteger(7, prime)

    valid_points = ((192, 105), (17, 56), (1, 193))
    invalid_points = ((200, 119), (42, 99))

    # iterate over valid points
    for x_raw, y_raw in valid_points:
        x = ModularFieldInteger(x_raw, prime)
        y = ModularFieldInteger(y_raw, prime)
        EllipcCurvePoint(x, y, a, b)

    # iterate over invalid points
    for x_raw, y_raw in invalid_points:
        x = ModularFieldInteger(x_raw, prime)
        y = ModularFieldInteger(y_raw, prime)
        with pytest.raises(ValueError, match="is not on the elliptic curve"):
            EllipcCurvePoint(x, y, a, b)


def test_add():
    # tests the following additions on curve y^2=x^3-7 over F_223:
    # (192,105) + (17,56)
    # (47,71) + (117,141)
    # (143,98) + (76,66)
    prime = 223
    a = ModularFieldInteger(0, prime)
    b = ModularFieldInteger(7, prime)

    additions = (
        # (x1, y1, x2, y2, x3, y3)
        (192, 105, 17, 56, 170, 142),
        (47, 71, 117, 141, 60, 139),
        (143, 98, 76, 66, 47, 71),
    )
    # iterate over the additions
    for x1_raw, y1_raw, x2_raw, y2_raw, x3_raw, y3_raw in additions:
        x1 = ModularFieldInteger(x1_raw, prime)
        y1 = ModularFieldInteger(y1_raw, prime)
        p1 = EllipcCurvePoint(x1, y1, a, b)
        x2 = ModularFieldInteger(x2_raw, prime)
        y2 = ModularFieldInteger(y2_raw, prime)
        p2 = EllipcCurvePoint(x2, y2, a, b)
        x3 = ModularFieldInteger(x3_raw, prime)
        y3 = ModularFieldInteger(y3_raw, prime)
        p3 = EllipcCurvePoint(x3, y3, a, b)
        # check that p1 + p2 == p3
        assert p1 + p2 == p3


def test_rmul():
    # tests the following scalar multiplications
    # 2*(192,105)
    # 2*(143,98)
    # 2*(47,71)
    # 4*(47,71)
    # 8*(47,71)
    # 21*(47,71)
    prime = 223
    a = ModularFieldInteger(0, prime)
    b = ModularFieldInteger(7, prime)

    multiplications = (
        # (coefficient, x1, y1, x2, y2)
        (2, 192, 105, 49, 71),
        (2, 143, 98, 64, 168),
        (2, 47, 71, 36, 111),
        (4, 47, 71, 194, 51),
        (8, 47, 71, 116, 55),
        (21, 47, 71, None, None),
    )

    # iterate over the multiplications
    for s, x1_raw, y1_raw, x2_raw, y2_raw in multiplications:
        x1 = ModularFieldInteger(x1_raw, prime)
        y1 = ModularFieldInteger(y1_raw, prime)
        p1 = EllipcCurvePoint(x1, y1, a, b)
        # initialize the second point based on whether it's the point at infinity
        if x2_raw is None:
            p2 = EllipcCurvePoint(None, None, a, b)
        else:
            x2 = ModularFieldInteger(x2_raw, prime)
            y2 = ModularFieldInteger(y2_raw, prime)
            p2 = EllipcCurvePoint(x2, y2, a, b)

        # check that the product is equal to the expected point
        assert s * p1 == p2
