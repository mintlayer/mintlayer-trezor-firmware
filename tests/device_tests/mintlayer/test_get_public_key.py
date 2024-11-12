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
from trezorlib.tools import parse_path

from ...input_flows import InputFlowShowXpubQRCode

MINTLAYER_PATH = parse_path("m/44h/19788h/0h/0/0")


@pytest.mark.altcoin
@pytest.mark.mintlayer
@pytest.mark.setup_client(
    mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)
def test_mintlayer_get_public_key(client: Client):
    with client:
        IF = InputFlowShowXpubQRCode(client)
        client.set_input_flow(IF.get())
        result = mintlayer.get_public_key(client, MINTLAYER_PATH, show_display=True)
        if isinstance(result, messages.MintlayerPublicKey):
            # m/44'/19788'/0'/0/0 for MNEMONIC
            assert (
                result.public_key.hex()
                == "03bf6f8d52dade77f95e9c6c9488fd8492a99c09ff23095caffb2e6409d1746ade"
            )
            assert (
                result.chain_code.hex()
                == "0ae454a1024d0ddb9e10d23479cf8ef39fb400727fabd17844bd8362b1c70d7d"
            )
        else:
            assert False
