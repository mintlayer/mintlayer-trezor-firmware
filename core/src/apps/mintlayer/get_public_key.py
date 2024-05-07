from typing import TYPE_CHECKING

from apps.common.keychain import auto_keychain

if TYPE_CHECKING:
    from trezor.messages import MintlayerGetPublicKey, MintlayerPublicKey

    from apps.common.keychain import Keychain


@auto_keychain(__name__)
async def get_public_key(
    msg: MintlayerGetPublicKey, keychain: Keychain
) -> MintlayerPublicKey:
    from ubinascii import hexlify

    from trezor.messages import MintlayerPublicKey
    from trezor.ui.layouts import show_pubkey

    from apps.common import paths
    print("inside get pk of mintlayer")

    await paths.validate_path(keychain, msg.address_n)
    node = keychain.derive(msg.address_n)
    pubkey = node.public_key()

    if msg.show_display:
        from . import PATTERN, SLIP44_ID

        path = paths.address_n_to_str(msg.address_n)
        await show_pubkey(
            hexlify(pubkey).decode(),
            account=paths.get_account_name("BNB", msg.address_n, PATTERN, SLIP44_ID),
            path=path,
        )

    return MintlayerPublicKey(public_key=pubkey)

