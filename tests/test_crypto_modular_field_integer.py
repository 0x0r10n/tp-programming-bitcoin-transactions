from btctoy.crypto import (
    ModularFieldInteger,
)


def test_ne() -> None:
    a = ModularFieldInteger(2, 31)
    b = ModularFieldInteger(2, 31)
    c = ModularFieldInteger(15, 31)
    assert a == b
    assert a != c
    assert (a != b) is False


def test_add() -> None:
    a = ModularFieldInteger(2, 31)
    b = ModularFieldInteger(15, 31)
    assert a + b == ModularFieldInteger(17, 31)
    a = ModularFieldInteger(17, 31)
    b = ModularFieldInteger(21, 31)
    assert a + b == ModularFieldInteger(7, 31)


def test_sub() -> None:
    a = ModularFieldInteger(29, 31)
    b = ModularFieldInteger(4, 31)
    assert a - b == ModularFieldInteger(25, 31)
    a = ModularFieldInteger(15, 31)
    b = ModularFieldInteger(30, 31)
    assert a - b == ModularFieldInteger(16, 31)


def test_mul() -> None:
    a = ModularFieldInteger(24, 31)
    b = ModularFieldInteger(19, 31)
    assert a * b == ModularFieldInteger(22, 31)


def test_rmul() -> None:
    a = ModularFieldInteger(24, 31)
    b = 2
    assert b * a == a + a


def test_pow() -> None:
    a = ModularFieldInteger(17, 31)
    assert a**3 == ModularFieldInteger(15, 31)
    a = ModularFieldInteger(5, 31)
    b = ModularFieldInteger(18, 31)
    assert a**5 * b == ModularFieldInteger(16, 31)


def test_div() -> None:
    a = ModularFieldInteger(3, 31)
    b = ModularFieldInteger(24, 31)
    assert a / b == ModularFieldInteger(4, 31)
    a = ModularFieldInteger(17, 31)
    assert a**-3 == ModularFieldInteger(29, 31)
    a = ModularFieldInteger(4, 31)
    b = ModularFieldInteger(11, 31)
    assert a**-4 * b == ModularFieldInteger(13, 31)
