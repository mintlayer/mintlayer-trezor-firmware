from typing import TYPE_CHECKING

from trezor.crypto import hashlib

from apps.common.keychain import with_slip44_keychain

from . import CURVE, PATTERNS, SLIP44_ID

if TYPE_CHECKING:
    from trezor.messages import MessageSignature, MintlayerSignMessage

    from apps.common.keychain import Keychain


@with_slip44_keychain(*PATTERNS, curve=CURVE, slip44_id=SLIP44_ID)
async def sign_message(
    msg: MintlayerSignMessage, keychain: Keychain
) -> MessageSignature:
    from trezor.crypto.curve import bip340
    from trezor.messages import MessageSignature
    from trezor.ui.layouts import confirm_signverify

    from apps.common.signverify import decode_message

    message = msg.message
    address_n = msg.address_n
    MESSAGE_MAGIC_PREFIX = b"===MINTLAYER MESSAGE BEGIN===\n"
    MESSAGE_MAGIC_SUFFIX = b"\n===MINTLAYER MESSAGE END==="

    await confirm_signverify(
        decode_message(message),
        msg.address,
        verify=False,
        account=None,
        path=None,
        chunkify=False,
    )
    node = keychain.derive(address_n)

    msg2 = MESSAGE_MAGIC_PREFIX + message + MESSAGE_MAGIC_SUFFIX
    digest = hashlib.blake2b(msg2).digest()[:32]
    digest = hashlib.blake2b(digest).digest()[:32]

    other_sig = bip340.sign(node.private_key(), digest)

    return MessageSignature(signature=other_sig, address=msg.address)
