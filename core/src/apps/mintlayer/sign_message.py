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
    from apps.common.signverify import decode_message

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
        decode_message(message),
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
