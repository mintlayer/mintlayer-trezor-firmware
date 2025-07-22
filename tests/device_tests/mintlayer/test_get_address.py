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
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

from . import pytestmark  # noqa

GET_ADDRESS_VECTORS = [
    (1, "mtc1qyumjs84s5nqgcp6nw9kwde9mn7akph6hgtulsdk"),
    (2, "tmt1qx5p4r2en7c99mpmg2tz9hucxfarf4k6dyyvsahr"),
    (3, "rmt1qx5p4r2en7c99mpmg2tz9hucxfarf4k6dypq388a"),
    (4, "smt1qx5p4r2en7c99mpmg2tz9hucxfarf4k6dy5zamcc"),
]

CHAIN_TYPE_TO_COIN = {1: 19788, 2: 1, 3: 1, 4: 1}


@pytest.mark.parametrize("chain_type, address", GET_ADDRESS_VECTORS)
def test_mintlayer_get_address(client: Client, chain_type: int, address: str):
    with client:
        assert (
            mintlayer.get_address(
                client,
                chain_type=chain_type,
                address_n=parse_path(f"m/44h/{CHAIN_TYPE_TO_COIN[chain_type]}h/0h/0/0"),
                show_display=True,
            )
            == address
        )


CHAIN_TYPES = [1, 2, 3, 4]


@pytest.mark.parametrize("chain_type", CHAIN_TYPES)
def test_mintlayer_get_address_forbidden_path(client: Client, chain_type: int):
    coin = CHAIN_TYPE_TO_COIN[chain_type]
    with client:
        # invalid coin
        with pytest.raises(TrezorFailure, match="Forbidden key path"):
            mintlayer.get_address(
                client,
                chain_type=chain_type,
                address_n=parse_path(f"m/44h/{coin + 1}h/0h/0/0"),
                show_display=True,
            )

        # invalid bip44
        with pytest.raises(TrezorFailure, match="Forbidden key path"):
            mintlayer.get_address(
                client,
                chain_type=chain_type,
                address_n=parse_path(f"m/43h/{coin}h/0h/0/0"),
                show_display=True,
            )

        # short path
        with pytest.raises(TrezorFailure, match="Forbidden key path"):
            mintlayer.get_address(
                client,
                chain_type=chain_type,
                address_n=parse_path(f"m/44h/{coin}h"),
                show_display=True,
            )

        # short path
        with pytest.raises(TrezorFailure, match="Forbidden key path"):
            mintlayer.get_address(
                client,
                chain_type=chain_type,
                address_n=parse_path("m/44h"),
                show_display=True,
            )
