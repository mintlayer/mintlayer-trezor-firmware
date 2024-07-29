from typing import TYPE_CHECKING
from apps.common.keychain import auto_keychain

from trezor.crypto import hashlib

if TYPE_CHECKING:
    from trezor.enums import InputScriptType
    from trezor.messages import MessageSignature, MintlayerSignMessage

    from apps.common.keychain import Keychain


@auto_keychain(__name__)
async def sign_message(msg: MintlayerSignMessage, keychain: Keychain) -> MessageSignature:
    from trezor import TR, utils
    from trezor.crypto.curve import bip340
    from trezor.enums import InputScriptType
    from trezor.messages import Success
    from trezor.ui.layouts import confirm_signverify, show_success
    from trezor.wire import ProcessError
    from trezor.messages import MessageSignature

    from apps.common import coins
    from apps.common.signverify import decode_message, message_digest

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
    pubkey = bip340.publickey(node.private_key())

    msg2 = MESSAGE_MAGIC_PREFIX + message + MESSAGE_MAGIC_SUFFIX
    digest = hashlib.blake2b(msg2).digest()[:32]
    digest = hashlib.blake2b(digest).digest()[:32]
    print(f"digest {digest}")

    other_sig = bip340.sign(node.private_key(), digest)
    print(f"other sig: {len(other_sig)} {other_sig}")

    correct = bip340.verify(pubkey, other_sig, digest)
    print(f"verify self: {correct}")

    correct = bip340.verify_publickey(pubkey)
    print(f"verify pk: {correct}")

    return MessageSignature(signature=other_sig, address="")

