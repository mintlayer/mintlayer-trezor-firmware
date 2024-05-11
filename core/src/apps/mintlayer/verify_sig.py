from typing import TYPE_CHECKING
from apps.common.keychain import auto_keychain

from trezor.crypto import hashlib

if TYPE_CHECKING:
    from trezor.enums import InputScriptType
    from trezor.messages import Success, MintlayerVerifySig

    from apps.common.keychain import Keychain


@auto_keychain(__name__)
async def verify_sig(msg: MintlayerVerifySig, keychain: Keychain) -> Success:
    from trezor import TR, utils
    from trezor.crypto.curve import bip340
    from trezor.enums import InputScriptType
    from trezor.messages import Success
    from trezor.ui.layouts import confirm_signverify, show_success
    from trezor.wire import ProcessError

    from apps.common import coins
    from apps.common.signverify import decode_message, message_digest

    message = msg.message
    address_n = msg.address_n
    signature = msg.signature

    node = keychain.derive(address_n)
    pubkey = node.public_key()

    # digest = message_digest(coin, message)
    digest = message
    msg2 = bytes([141, 246, 62, 11, 137, 75, 1, 173, 157, 218, 61, 108, 3, 21, 251, 144, 237, 220, 224, 196, 81, 17, 81, 241, 69, 237, 70, 214, 41, 159, 45, 165])
    digest2 = hashlib.blake2b(msg2).digest()
    print(f"digest: {digest}")
    print(f"digest2: {digest2}")

    other_sig = bip340.sign(node.private_key(), digest)
    print(f"other sig: {len(other_sig)} {other_sig}")
    print(f"ML sig: {len(signature)} {signature}")

    correct = bip340.verify(pubkey, signature, digest)
    print(f"verify ML: {correct}")

    correct = bip340.verify(pubkey, other_sig, digest)
    print(f"verify self: {correct}")

    correct = bip340.verify_publickey(pubkey)
    print(f"verify pk: {correct}")

    # ============= other pubkey
    print(f"pk: {len(pubkey)} {pubkey}")
    pubkey = bip340.publickey(node.private_key())
    print(f"pk: {len(pubkey)} {pubkey}")

    correct = bip340.verify_publickey(pubkey)
    print(f"verify pk: {correct}")

    correct = bip340.verify(pubkey, signature, digest)
    print(f"verify ML: {correct}")

    correct = bip340.verify(pubkey, other_sig, digest)
    print(f"verify self: {correct}")

    # TODO: if not correct show error

    await show_success("verify_message", TR.bitcoin__valid_signature)
    return Success(message="Message verified")

