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

from trezorlib import mintlayer
from trezorlib.debuglink import TrezorClientDebugLink as Client
from trezorlib.tools import parse_path


@pytest.mark.altcoin
@pytest.mark.mintlayer
@pytest.mark.setup_client(
    mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)
def test_mintlayer_get_address(client: Client):
    with client:
        assert (
            mintlayer.get_address(
                client,
                coin_name="Mainnet",
                address_n=parse_path("m/44h/19788h/0h/0/0"),
                show_display=True,
            )
            == "mtc1qyumjs84s5nqgcp6nw9kwde9mn7akph6hgtulsdk"
        )

        assert (
            mintlayer.get_address(
                client,
                coin_name="Testnet",
                address_n=parse_path("m/44h/1h/0h/0/0"),
                show_display=True,
            )
            == "tmt1qx5p4r2en7c99mpmg2tz9hucxfarf4k6dyyvsahr"
        )
