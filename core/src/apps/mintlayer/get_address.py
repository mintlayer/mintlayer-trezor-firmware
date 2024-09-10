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

    from .helpers import address_from_public_key

    HRP = "bnb"
    address_n = msg.address_n  # local_cache_attribute

    await paths.validate_path(keychain, address_n)

    node = keychain.derive(address_n)
    pubkey = node.public_key()
    address = address_from_public_key(pubkey, HRP)
    if msg.show_display:
        await show_address(
            address,
            path=paths.address_n_to_str(address_n),
            account=paths.get_account_name("BNB", address_n, PATTERNS[0], SLIP44_ID),
            chunkify=bool(msg.chunkify),
        )

    return MintlayerAddress(address=address)

