# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import pytest

from trezorlib import messages, mintlayer
from trezorlib.debuglink import TrezorClientDebugLink as Client
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

from ...input_flows import InputFlowShowXpubQRCode

GET_PUBLIC_KEY_VECTORS = [
    (
        1,
        "03bf6f8d52dade77f95e9c6c9488fd8492a99c09ff23095caffb2e6409d1746ade",
        "0ae454a1024d0ddb9e10d23479cf8ef39fb400727fabd17844bd8362b1c70d7d",
    ),
    (
        2,
        "02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6",
        "f33f3a6035684e404902a47c25cad7269a1afdba22c6b02167f43f09125f37f2",
    ),
    (
        3,
        "02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6",
        "f33f3a6035684e404902a47c25cad7269a1afdba22c6b02167f43f09125f37f2",
    ),
    (
        4,
        "02a7451395735369f2ecdfc829c0f774e88ef1303dfe5b2f04dbaab30a535dfdd6",
        "f33f3a6035684e404902a47c25cad7269a1afdba22c6b02167f43f09125f37f2",
    ),
]

CHAIN_TYPE_TO_COIN = {1: 19788, 2: 1, 3: 1, 4: 1}


@pytest.mark.altcoin
@pytest.mark.mintlayer
@pytest.mark.setup_client(
    mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)
@pytest.mark.parametrize("chain_type, pub_key, chain_code", GET_PUBLIC_KEY_VECTORS)
def test_mintlayer_get_public_key(
    client: Client, chain_type: int, pub_key: str, chain_code: str
):
    coin = CHAIN_TYPE_TO_COIN[chain_type]
    with client:
        IF = InputFlowShowXpubQRCode(client)
        client.set_input_flow(IF.get())
        result = mintlayer.get_public_key(
            client,
            chain_type=1,
            address_n=parse_path(f"m/44h/{coin}h/0h/0/0"),
            show_display=True,
        )
        if isinstance(result, messages.MintlayerPublicKey):
            # m/44'/coin'/0'/0/0 for MNEMONIC
            assert result.public_key.hex() == pub_key
            assert result.chain_code.hex() == chain_code
        else:
            assert False


CHAIN_TYPES = [1, 2, 3, 4]


@pytest.mark.altcoin
@pytest.mark.mintlayer
@pytest.mark.setup_client(
    mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)
@pytest.mark.parametrize("chain_type", CHAIN_TYPES)
def test_mintlayer_get_public_key_forbidden_path(client: Client, chain_type: int):
    coin = CHAIN_TYPE_TO_COIN[chain_type]
    with client:
        # invalid coin
        with pytest.raises(TrezorFailure, match="Forbidden key path"):
            mintlayer.get_public_key(
                client,
                chain_type=chain_type,
                address_n=parse_path(f"m/44h/{coin + 1}h/0h/0/0"),
                show_display=True,
            )

        # invalid bip44
        with pytest.raises(TrezorFailure, match="Forbidden key path"):
            mintlayer.get_public_key(
                client,
                chain_type=chain_type,
                address_n=parse_path(f"m/43h/{coin}h/0h/0/0"),
                show_display=True,
            )

        # short path
        with pytest.raises(TrezorFailure, match="Forbidden key path"):
            mintlayer.get_public_key(
                client,
                chain_type=chain_type,
                address_n=parse_path(f"m/44h/{coin}h"),
                show_display=True,
            )

        # short path
        with pytest.raises(TrezorFailure, match="Forbidden key path"):
            mintlayer.get_public_key(
                client,
                chain_type=chain_type,
                address_n=parse_path("m/44h"),
                show_display=True,
            )
