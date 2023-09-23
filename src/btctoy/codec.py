from typing import (
    BinaryIO,
)

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encode_base58(s: bytes) -> str:
    # determine how many 0 bytes (b'\x00') s starts with
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    # convert to big endian integer
    num = int.from_bytes(s, "big")
    prefix = "1" * count
    result = ""
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def decode_base58(s: str) -> bytes:
    num = 0
    for c in s:
        num *= 58
        num += BASE58_ALPHABET.index(c)
    return num.to_bytes(25, byteorder="big")


def encode_base58_checksum(s: bytes) -> str:
    from btctoy.crypto import (
        hash256,
    )

    checksum = hash256(s)[:4]
    return encode_base58(s + checksum)


def decode_base58_checksum(s: str) -> bytes:
    from btctoy.crypto import (
        hash256,
    )

    combined = decode_base58(s)
    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError(
            "Bad address: {} {}".format(checksum, hash256(combined[:-4])[:4])
        )
    return combined[1:-4]


def little_endian_to_int(b: bytes) -> int:
    """little_endian_to_int takes byte sequence as a little-endian number.
    Returns an integer"""
    return int.from_bytes(b, "little")


def int_to_little_endian(n: int, length: int) -> bytes:
    """endian_to_little_endian takes an integer and returns the little-endian
    byte sequence of length"""
    return n.to_bytes(length, "little")


def read_varint(s: BinaryIO) -> int:
    """read_varint reads a variable integer from a stream"""
    i = s.read(1)[0]
    if i == 0xFD:
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xFE:
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xFF:
        # 0xff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i


def encode_varint(i: int) -> bytes:
    """encodes an integer as a varint"""
    if i < 0xFD:
        return bytes([i])
    elif i < 0x10000:
        return b"\xfd" + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b"\xfe" + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b"\xff" + int_to_little_endian(i, 8)
    else:
        raise ValueError("integer too large: {}".format(i))
