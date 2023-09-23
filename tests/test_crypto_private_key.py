from secrets import (
    randbelow,
)

from btctoy.crypto import (
    G_ORDER,
    PrivateKey,
)


def test_sign() -> None:
    pk = PrivateKey(randbelow(G_ORDER))
    z = randbelow(2**256)
    sig = pk.sign(z)
    assert pk.point.verify(z, sig)


def test_wif() -> None:
    pk = PrivateKey(2**256 - 2**199)
    expected = "L5oLkpV3aqBJ4BgssVAsax1iRa77G5CVYnv9adQ6Z87te7TyUdSC"
    assert pk.wif(compressed=True, testnet=False) == expected
    pk = PrivateKey(2**256 - 2**201)
    expected = "93XfLeifX7Jx7n7ELGMAf1SUR6f9kgQs8Xke8WStMwUtrDucMzn"
    assert pk.wif(compressed=False, testnet=True) == expected
    pk = PrivateKey(0x0DBA685B4511DBD3D368E5C4358A1277DE9486447AF7B3604A69B8D9D8B7889D)
    expected = "5HvLFPDVgFZRK9cd4C5jcWki5Skz6fmKqi1GQJf5ZoMofid2Dty"
    assert pk.wif(compressed=False, testnet=False) == expected
    pk = PrivateKey(0x1CCA23DE92FD1862FB5B76E5F4F50EB082165E5191E116C18ED1A6B24BE6A53F)
    expected = "cNYfWuhDpbNM1JWc3c6JTrtrFVxU4AGhUKgw5f93NP2QaBqmxKkg"
    assert pk.wif(compressed=True, testnet=True) == expected
