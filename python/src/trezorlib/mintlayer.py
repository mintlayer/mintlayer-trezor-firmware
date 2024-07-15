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
        inputs: List[Input],
        outputs: List[Output],
        prev_txs: Dict[TxHash, Tx],
        version: Optional["int"] = 1,
        serialize: Optional["bool"] = True,
        chunkify: Optional["bool"] = None,
):
    res = client.call(
        messages.MintlayerSignTx(
            outputs_count=len(outputs),
            inputs_count=len(inputs),
            version=version,
            serialize=serialize,
            chunkify=chunkify,
        )
    )

    R = messages.MintlayerRequestType
    while isinstance(res, messages.MintlayerTxRequest):
        if res.request_type == R.TXFINISHED:
            return res

        if res.request_type == R.TXINPUT:
            msg = messages.MintlayerTxAckInputWrapper(input=inputs[res.details.request_index])
            msg = messages.MintlayerTxAckUtxoInput(tx=msg)
            res = client.call(msg)
        elif res.request_type == R.TXOUTPUT:
            assert res.details is not None
            if res.details.tx_hash:
                outs = prev_txs[res.details.tx_hash].outputs
            else:
                outs = outputs
            msg = messages.MintlayerTxAckOutputWrapper(output=outs[res.details.request_index])
            msg = messages.MintlayerTxAckOutput(tx=msg)
            res = client.call(msg)

    raise Exception("Invalid response from trezor")
