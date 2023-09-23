from io import (
    BytesIO,
)

from btctoy.script import (
    Script,
)


def test_parse() -> None:
    script_pubkey = BytesIO(
        bytes.fromhex(
            "6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937"
        )
    )
    script = Script.parse(script_pubkey)
    want = bytes.fromhex(
        "304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601"
    )
    assert script.cmds[0].hex() == want.hex()
    want = bytes.fromhex(
        "035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937"
    )
    assert script.cmds[1] == want


def test_serialize() -> None:
    want = "6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937"
    script_pubkey = BytesIO(bytes.fromhex(want))
    script = Script.parse(script_pubkey)
    assert script.serialize().hex() == want
