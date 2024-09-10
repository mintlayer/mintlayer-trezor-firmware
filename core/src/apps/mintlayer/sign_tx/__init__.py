from typing import TYPE_CHECKING

from apps.common.keychain import with_slip44_keychain
from .. import CURVE, SLIP44_ID, PATTERNS

if TYPE_CHECKING:
    from typing import Protocol

    from trezor.messages import (
        MintlayerSignTx,
        TxAckInput,
        TxAckOutput,
        TxAckPrevExtraData,
        TxAckPrevInput,
        TxAckPrevMeta,
        TxAckPrevOutput,
        MintlayerTxRequest,
    )

    from apps.common.coininfo import CoinInfo
    from apps.common.keychain import Keychain

    # from ..authorization import CoinJoinAuthorization
    # from . import approvers

    TxAckType = (
        TxAckInput
        | TxAckOutput
        | TxAckPrevMeta
        | TxAckPrevInput
        | TxAckPrevOutput
        | TxAckPrevExtraData
    )

    class SignerClass(Protocol):
        def __init__(  # pylint: disable=super-init-not-called
            self,
            tx: MintlayerSignTx,
            keychain: Keychain,
            coin: CoinInfo,
            # approver: approvers.Approver | None,
        ) -> None: ...

        async def signer(self) -> None: ...


@with_slip44_keychain(*PATTERNS, curve=CURVE, slip44_id=SLIP44_ID)
async def sign_tx(
    msg: MintlayerSignTx,
    keychain: Keychain,
) -> MintlayerTxRequest:
    from trezor.wire import DataError
    from trezor.enums import MintlayerRequestType
    from trezor.messages import MintlayerTxRequest
    from trezor.wire.context import call

    from . import progress
    from .signer import Mintlayer
    from . import helpers


    if msg.inputs_count == 0:
        raise DataError("Cannot sign a transaction with 0 inputs")

    signer = Mintlayer(msg, keychain).signer()

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
            progress.progress.report_init()
        else:

            print("invalid instruction", req, isinstance(req, helpers.UiConfirmTotal), isinstance(req, helpers.UiConfirm))
            raise TypeError("Invalid signing instruction")

