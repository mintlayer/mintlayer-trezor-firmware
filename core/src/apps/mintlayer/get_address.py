from typing import TYPE_CHECKING

from trezor.crypto import hashlib
from trezor.enums import InputScriptType

from apps.common.keychain import with_slip44_keychain

from ..bitcoin.keychain import validate_path_against_script_type
from . import CURVE, PATTERNS, SLIP44_ID, find_coin_by_name

if TYPE_CHECKING:
    from trezor.messages import MintlayerAddress, MintlayerGetAddress

    from apps.common.keychain import Keychain


@with_slip44_keychain(*PATTERNS, curve=CURVE, slip44_id=SLIP44_ID, allow_testnet=True)
async def get_address(msg: MintlayerGetAddress, keychain: Keychain) -> MintlayerAddress:
    from trezor.crypto.bech32 import Encoding, bech32_encode, convertbits
    from trezor.messages import MintlayerAddress
    from trezor.ui.layouts import show_address

    from apps.common import paths

    coin_info = find_coin_by_name(msg.coin_name)
    address_n = msg.address_n  # local_cache_attribute

    await paths.validate_path(
        keychain,
        address_n,
        validate_path_against_script_type(
            coin_info, address_n=msg.address_n, script_type=InputScriptType.SPENDADDRESS
        ),
    )

    node = keychain.derive(address_n)
    pubkey = node.public_key()
    pkh = hashlib.blake2b(bytes([0]) + pubkey).digest()[:20]
    data = convertbits(bytes([1]) + pkh, 8, 5)
    address = bech32_encode(coin_info.prefixes.public_key_hash, data, Encoding.BECH32M)
    if msg.show_display:
        await show_address(
            address,
            path=paths.address_n_to_str(address_n),
            account=paths.get_account_name(
                coin_info.coin_shortcut, msg.address_n, PATTERNS, coin_info.slip44
            ),
            chunkify=bool(msg.chunkify),
        )

    return MintlayerAddress(address=address)
