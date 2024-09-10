from typing import TYPE_CHECKING

from apps.common.keychain import with_slip44_keychain
from . import CURVE, SLIP44_ID, PATTERNS

if TYPE_CHECKING:
    from trezor.messages import MintlayerAddress, MintlayerGetAddress

    from apps.common.keychain import Keychain


@with_slip44_keychain(*PATTERNS, curve=CURVE, slip44_id=SLIP44_ID)
async def get_address(msg: MintlayerGetAddress, keychain: Keychain) -> MintlayerAddress:
    from trezor.messages import MintlayerAddress
    from trezor.ui.layouts import show_address

    from apps.common import paths

    from trezor.crypto.bech32 import bech32_encode, Encoding

    HRP = "mtc"
    address_n = msg.address_n  # local_cache_attribute

    await paths.validate_path(keychain, address_n)

    node = keychain.derive(address_n)
    pubkey = node.public_key()
    address = bech32_encode(HRP, pubkey, Encoding.BECH32M)
    if msg.show_display:
        await show_address(
            address,
            path=paths.address_n_to_str(address_n),
            account=None,
            chunkify=bool(msg.chunkify),
        )

    return MintlayerAddress(address=address)

