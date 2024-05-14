from typing import TYPE_CHECKING

from apps.common.keychain import auto_keychain

if TYPE_CHECKING:
    from typing import Protocol

    from trezor.messages import (
        SignTx,
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
            tx: SignTx,
            keychain: Keychain,
            coin: CoinInfo,
            # approver: approvers.Approver | None,
        ) -> None: ...

        async def signer(self) -> None: ...


@auto_keychain(__name__)
async def sign_tx(
    msg: SignTx,
    keychain: Keychain,
) -> MintlayerTxRequest:
    from trezor.enums import MintlayerRequestType
    from trezor.messages import MintlayerTxRequest
    from trezor.wire.context import call

    from . import progress
    from .signer import Mintlayer
    from ...bitcoin.sign_tx import helpers


    # approver: approvers.Approver | None = None
    approver = None

    # FIXME  handle 0 input & output tx

    signer = Mintlayer(msg, keychain).signer()

    res: TxAckType | bool | None = None
    while True:
        req = signer.send(res)
        if isinstance(req, tuple):
            request_class, req = req
            assert MintlayerTxRequest.is_type_of(req)
            if req.request_type == MintlayerRequestType.TXFINISHED:
                return req
            print('sending and waiting for response')
            res = await call(req, request_class)
            print('got response', res)
        elif isinstance(req, helpers.UiConfirm):
            res = await req.confirm_dialog()
            progress.progress.report_init()
        else:
            raise TypeError("Invalid signing instruction")

