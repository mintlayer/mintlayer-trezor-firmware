# This file is part of the Trezor project.
#
# Copyright (C) 2012-2022 SatoshiLabs and contributors
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

from typing import TYPE_CHECKING, Optional

from . import messages
from .protobuf import dict_to_proto
from .tools import expect, session

if TYPE_CHECKING:
    from .client import TrezorClient
    from .protobuf import MessageType
    from .tools import Address


@expect(messages.MintlayerAddress, field="address", ret_type=str)
def get_address(
    client: "TrezorClient",
    address_n: "Address",
    show_display: bool = False,
    chunkify: bool = False,
) -> "MessageType":
    return client.call(
        messages.MintlayerGetAddress(
            address_n=address_n, show_display=show_display, chunkify=chunkify
        )
    )


@expect(messages.MintlayerPublicKey, field="public_key", ret_type=bytes)
def get_public_key(
    client: "TrezorClient", address_n: "Address", show_display: bool = False
) -> "MessageType":
    return client.call(
        messages.MintlayerGetPublicKey(address_n=address_n, show_display=show_display)
    )

def verify_sig(
    client: "TrezorClient",
    address_n: "Address",
    signature: bytes,
    message: bytes,
) -> bool:
    try:
        resp = client.call(
            messages.MintlayerVerifySig(
                address_n=address_n,
                signature=signature,
                message=message
            )
        )
    # TODO: add exceptions like btc
    # except exceptions.TrezorFailure:
    except:
        print("got exception in verify sig Mintlayer")
        return False
    return isinstance(resp, messages.Success)

@session
def sign_tx(
        client: "TrezorClient", outputs_count: int, inputs_count: int,
        version: Optional["int"] = 1,
        serialize: Optional["bool"] = True,
        chunkify: Optional["bool"] = None,
):
    return client.call(
        messages.MintlayerSignTx(
            outputs_count=outputs_count,
            inputs_count=inputs_count,
            version=version,
            serialize=serialize,
            chunkify=chunkify,
        )
    )
