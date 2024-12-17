from typing import TYPE_CHECKING

from apps.common.keychain import with_slip44_keychain

from .. import CURVE, PATTERNS, SLIP44_ID

if TYPE_CHECKING:
    from trezor.messages import (
        MintlayerSignTx,
        MintlayerTxAckOutput,
        MintlayerTxAckUtxoInput,
        MintlayerTxRequest,
    )

    from apps.common.keychain import Keychain

    TxAckType = MintlayerTxAckOutput | MintlayerTxAckUtxoInput


@with_slip44_keychain(*PATTERNS, curve=CURVE, slip44_id=SLIP44_ID)
async def sign_tx(
    msg: MintlayerSignTx,
    keychain: Keychain,
) -> MintlayerTxRequest:
    from trezor.enums import MintlayerRequestType
    from trezor.messages import MintlayerTxRequest
    from trezor.wire import DataError
    from trezor.wire.context import call

    from . import helpers
    from .signer import Mintlayer

    if msg.inputs_count == 0:
        raise DataError("Cannot sign a transaction with 0 inputs")

    x = Mintlayer(msg, keychain)
    progress = x.progress
    signer = x.signer()

    res: TxAckType | bool | None = None
    while True:
        req = signer.send(res)
        if isinstance(req, tuple):
            request_class, req = req
            assert MintlayerTxRequest.is_type_of(req)
            if req.request_type == MintlayerRequestType.TXFINISHED:
                return req
            res = await call(req, request_class)
        elif isinstance(req, helpers.UiConfirm):
            res = await req.confirm_dialog()
            progress.report_init()
        else:
            raise TypeError("Invalid signing instruction")
