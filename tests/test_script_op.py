from btctoy.script.op import (
    decode_num,
    op_checksig,
    op_hash160,
)


def test_op_hash160() -> None:
    stack = [b"hello world"]
    assert op_hash160(stack) is True
    assert stack[0].hex() == "d7d5ee7824ff93f94c3055af9382c86c68b5ca92"


def test_op_checksig() -> None:
    z = 0x7C076FF316692A3D7EB3C3BB0F8B1488CF72E1AFCD929E29307032997A838A3D
    sec = bytes.fromhex(
        "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34"
    )
    sig = bytes.fromhex(
        "3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601"
    )
    stack = [sig, sec]
    assert op_checksig(stack, z) is True
    assert decode_num(stack[0]) == 1
