from typing import TYPE_CHECKING

from trezor.crypto import hashlib
from trezor.wire.errors import DataError

from apps.common.keychain import with_slip44_keychain

from . import CURVE, PATTERNS, SLIP44_ID, find_coin_by_chain_type

if TYPE_CHECKING:
    from trezor.messages import MessageSignature, MintlayerSignMessage

    from apps.common.keychain import Keychain


@with_slip44_keychain(*PATTERNS, curve=CURVE, slip44_id=SLIP44_ID, allow_testnet=True)
async def sign_message(
    msg: MintlayerSignMessage, keychain: Keychain
) -> MessageSignature:
    from trezor.crypto.bech32 import Encoding, bech32_encode, convertbits
    from trezor.crypto.curve import bip340
    from trezor.enums import MintlayerAddressType
    from trezor.messages import MessageSignature
    from trezor.ui.layouts import confirm_signverify

    from apps.common import paths

    coin_info = find_coin_by_chain_type(msg.chain_type)
    message = msg.message
    address_n = msg.address_n
    MESSAGE_MAGIC_PREFIX = b"===MINTLAYER MESSAGE BEGIN===\n"
    MESSAGE_MAGIC_SUFFIX = b"\n===MINTLAYER MESSAGE END==="

    node = keychain.derive(address_n)
    pubkey = node.public_key()
    if msg.address_type == MintlayerAddressType.PUBLIC_KEY:
        data = convertbits(bytes([2]) + pubkey, 8, 5)
        address = bech32_encode(coin_info.prefixes.public_key, data, Encoding.BECH32M)
    elif msg.address_type == MintlayerAddressType.PUBLIC_KEY_HASH:
        pkh = hashlib.blake2b(bytes([0]) + pubkey).digest()[:20]
        data = convertbits(bytes([1]) + pkh, 8, 5)
        address = bech32_encode(
            coin_info.prefixes.public_key_hash, data, Encoding.BECH32M
        )
    else:
        raise DataError(f"Unknown Address type {msg.address_type}")

    await confirm_signverify(
        decode_message_if_ascii(message),
        address,
        verify=False,
        account=paths.get_account_name(
            coin_info.coin_shortcut, msg.address_n, PATTERNS, coin_info.slip44
        ),
        path=paths.address_n_to_str(address_n),
        chunkify=False,
    )

    msg2 = MESSAGE_MAGIC_PREFIX + message + MESSAGE_MAGIC_SUFFIX
    digest = hashlib.blake2b(msg2).digest()[:32]
    digest = hashlib.blake2b(digest).digest()[:32]

    other_sig = bip340.sign(node.private_key(), digest)

    return MessageSignature(signature=other_sig, address=address)


# Note: initially we were using `apps.common.signverify.decode_message` instead of this function,
# which first tries to do `bytes(message).decode()`, and if that raises an exception, it then converts
# the message to hex. There are a few problems with this:
# 1) In Mycropython, `bytes.decode` seems to allow overlong utf-8 (where a character is encoded
#    with more bytes than necessary). E.g. `bytes([0xc1, 0x82]).decode()` will raise an exception
#    in normal Python, but will succeed when run in the firmware.
#    However, when such a string is passed to `confirm_signverify` (whose internals are
#    implemented in Rust), it will raise an exception.
#    The possible solution for this could be to add our own utility function written in Rust
#    to check byte arrays for valid utf-8.
# 2) Even if the bytes are valid utf-8, they may still be non-printable, so the user won't
#    know for sure what they're signing.
# So we just check if the entire string consists only of printable ascii characters; if not, we
# convert it to hex.
def decode_message_if_ascii(message: bytes) -> str:
    from ubinascii import hexlify

    if is_printable_ascii(message):
        return bytes(message).decode()
    else:
        return f"hex({hexlify(message).decode()})"


def is_printable_ascii(byte_string: bytes) -> bool:
    return all(32 <= byte <= 126 for byte in byte_string)
