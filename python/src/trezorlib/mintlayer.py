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

from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Optional

from . import messages
from .tools import expect, session

if TYPE_CHECKING:
    from .client import TrezorClient
    from .protobuf import MessageType
    from .tools import Address


@expect(messages.MintlayerAddress, field="address", ret_type=str)
def get_address(
    client: "TrezorClient",
    address_n: "Address",
    chain_type: int,
    show_display: bool = False,
    chunkify: bool = False,
) -> "MessageType":

    return client.call(
        messages.MintlayerGetAddress(
            address_n=address_n,
            chain_type=messages.MintlayerChainType(chain_type),
            show_display=show_display,
            chunkify=chunkify,
        )
    )


def get_public_key(
    client: "TrezorClient",
    address_n: "Address",
    chain_type: int,
    show_display: bool = False,
) -> "MessageType":
    return client.call(
        messages.MintlayerGetPublicKey(
            address_n=address_n,
            chain_type=messages.MintlayerChainType(chain_type),
            show_display=show_display,
        )
    )


def sign_message(
    client: "TrezorClient",
    address_n: "Address",
    chain_type: int,
    address_type: str,
    message: bytes,
) -> "MessageType":
    if address_type == "PUBLIC_KEY":
        addr_type = messages.MintlayerAddressType.PUBLIC_KEY
    elif address_type == "PUBLIC_KEY_HASH":
        addr_type = messages.MintlayerAddressType.PUBLIC_KEY_HASH
    else:
        raise ValueError(f"Invalid address type {address_type}")

    return client.call(
        messages.MintlayerSignMessage(
            chain_type=messages.MintlayerChainType(chain_type),
            address_type=addr_type,
            address_n=address_n,
            message=message,
        )
    )


Input = messages.MintlayerTxInput
Output = messages.MintlayerTxOutput
TxHash = bytes


@dataclass
class Tx:
    inputs: List[Input]
    outputs: List[Output]


@session
def sign_tx(
    client: "TrezorClient",
    chain_type: int,
    inputs: List[Input],
    outputs: List[Output],
    prev_txs: Dict[TxHash, Dict[int, Output]],
    version: Optional["int"] = 1,
    serialize: Optional["bool"] = True,
    chunkify: Optional["bool"] = None,
) -> List[messages.MintlayerSignaturesForInput]:
    res = client.call(
        messages.MintlayerSignTx(
            outputs_count=len(outputs),
            inputs_count=len(inputs),
            chain_type=messages.MintlayerChainType(chain_type),
            version=version,
            serialize=serialize,
            chunkify=chunkify,
        )
    )

    R = messages.MintlayerRequestType
    while isinstance(res, messages.MintlayerTxRequest):
        if res.request_type == R.TXFINISHED:
            if res.serialized:
                return list(res.serialized.signatures)
            else:
                return []

        if res.request_type == R.TXINPUT and res.details is not None:
            assert res.details.request_index is not None
            msg = inputs[res.details.request_index]
            msg = messages.MintlayerTxAckUtxoInput(input=msg)
            res = client.call(msg)
        elif res.request_type == R.TXOUTPUT and res.details is not None:
            assert res.details is not None
            assert res.details.request_index is not None
            if res.details.tx_hash:
                out = prev_txs[res.details.tx_hash][res.details.request_index]
            else:
                out = outputs[res.details.request_index]
            msg = messages.MintlayerTxAckOutput(output=out)
            res = client.call(msg)

    raise Exception("Invalid response from trezor")
