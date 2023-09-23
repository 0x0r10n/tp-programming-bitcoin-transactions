from btctoy.crypto import (
    EC_A,
    EC_B,
    EC_PRIME,
    G_ORDER,
    G_X,
    G_Y,
    ModularFieldInteger,
    is_on_elliptic_curve,
    is_prime,
)


def test_is_prime() -> None:
    assert is_prime(0) is False
    assert is_prime(1) is False
    assert is_prime(2)
    assert is_prime(3)
    assert is_prime(7)
    assert is_prime(4) is False
    assert is_prime(150) is False
    assert is_prime(EC_PRIME)
    assert is_prime(EC_PRIME + 2) is False
    assert is_prime(G_ORDER)


def test_is_on_elliptic_curve() -> None:
    a = 12345
    b = 98765
    x = 42
    y = (x**3 + a * x + b) ** 0.5
    assert is_on_elliptic_curve(x, y, a, b)
    assert is_on_elliptic_curve(x, -y, a, b)

    assert is_on_elliptic_curve(
        ModularFieldInteger(G_X, EC_PRIME),
        ModularFieldInteger(G_Y, EC_PRIME),
        ModularFieldInteger(EC_A, EC_PRIME),
        ModularFieldInteger(EC_B, EC_PRIME),
    )
