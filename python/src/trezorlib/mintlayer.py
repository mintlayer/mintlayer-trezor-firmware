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

from typing import TYPE_CHECKING, Dict, List, Optional

from . import messages
from .tools import workflow

if TYPE_CHECKING:
    from .client import Session
    from .protobuf import MessageType
    from .tools import Address


@workflow(capability=messages.Capability.Mintlayer)
def get_firmware_info(session: "Session") -> messages.MintlayerFirmwareInfo:
    return session.call(
        messages.MintlayerGetFirmwareInfo(),
        expect=messages.MintlayerFirmwareInfo,
    )


@workflow(capability=messages.Capability.Mintlayer)
def get_address(
    session: "Session",
    address_n: "Address",
    chain_type: int,
    show_display: bool = False,
    chunkify: bool = False,
) -> str:
    return session.call(
        messages.MintlayerGetAddress(
            address_n=address_n,
            chain_type=messages.MintlayerChainType(chain_type),
            show_display=show_display,
            chunkify=chunkify,
        ),
        expect=messages.MintlayerAddress,
    ).address


@workflow(capability=messages.Capability.Mintlayer)
def get_public_key(
    session: "Session",
    address_n: "Address",
    chain_type: int,
    show_display: bool = False,
) -> "MessageType":
    return session.call(
        messages.MintlayerGetPublicKey(
            address_n=address_n,
            chain_type=messages.MintlayerChainType(chain_type),
            show_display=show_display,
        )
    )


@workflow(capability=messages.Capability.Mintlayer)
def sign_message(
    session: "Session",
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

    return session.call(
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


@workflow(capability=messages.Capability.Mintlayer)
def sign_tx(
    session: "Session",
    chain_type: int,
    inputs: List[Input],
    outputs: List[Output],
    prev_txs: Dict[TxHash, Dict[int, Output]],
    input_commitments_version: int = 0,
    version: Optional["int"] = 1,
    chunkify: Optional["bool"] = None,
) -> List[messages.MintlayerSignaturesForInput]:
    res = session.call(
        messages.MintlayerSignTx(
            outputs_count=len(outputs),
            inputs_count=len(inputs),
            chain_type=messages.MintlayerChainType(chain_type),
            input_commitments_version=input_commitments_version,
            version=version,
            chunkify=chunkify,
        )
    )

    while isinstance(res, messages.MintlayerTxRequest):
        if res.signing_finished:
            return list(res.signing_finished.signatures)

        if res.input_request:
            msg = inputs[res.input_request.input_index]
            msg = messages.MintlayerTxAck(input=msg)
            res = session.call(msg)
        elif res.output_request:
            if res.output_request.tx_hash:
                out = prev_txs[res.output_request.tx_hash][
                    res.output_request.output_index
                ]
            else:
                out = outputs[res.output_request.output_index]
            msg = messages.MintlayerTxAck(output=out)
            res = session.call(msg)

    raise Exception("Invalid response from trezor")
