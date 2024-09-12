from micropython import const
from typing import TYPE_CHECKING, Tuple

from trezor import utils
from trezor.enums import MintlayerRequestType
from trezor.wire import DataError

from . import layout

if TYPE_CHECKING:
    from typing import Any, Awaitable

    from trezor.messages import (
        MintlayerOutputTimeLock,
        MintlayerTxInput,
        MintlayerTxOutput,
        MintlayerTxRequest,
        PrevTx,
        SignTx,
    )

    from apps.common.coininfo import CoinInfo

TX_HASH_SIZE = const(32)

# Machine instructions
# ===


class UiConfirm:
    def confirm_dialog(self) -> Awaitable[Any]:
        raise NotImplementedError

    __eq__ = utils.obj_eq


class UiConfirmOutput(UiConfirm):
    def __init__(
        self,
        output: MintlayerTxOutput,
        coin: CoinInfo,
        output_index: int,
        chunkify: bool,
    ):
        self.output = output
        self.coin = coin
        self.output_index = output_index
        self.chunkify = chunkify

    def confirm_dialog(self) -> Awaitable[Any]:
        return layout.confirm_output(
            self.output,
            self.coin,
            self.output_index,
            self.chunkify,
        )


class UiConfirmTotal(UiConfirm):
    def __init__(
        self,
        spending: int,
        fee: int,
        fee_rate: float,
        coin: CoinInfo,
    ):
        self.spending = spending
        self.fee = fee
        self.fee_rate = fee_rate
        self.coin = coin

    def confirm_dialog(self) -> Awaitable[Any]:
        return layout.confirm_total(
            self.spending,
            self.fee,
            self.fee_rate,
            self.coin,
        )


class UiConfirmChangeCountOverThreshold(UiConfirm):
    def __init__(self, change_count: int):
        self.change_count = change_count

    def confirm_dialog(self) -> Awaitable[Any]:
        return layout.confirm_change_count_over_threshold(self.change_count)


class UiConfirmUnverifiedExternalInput(UiConfirm):
    def confirm_dialog(self) -> Awaitable[Any]:
        return layout.confirm_unverified_external_input()


class UiConfirmForeignAddress(UiConfirm):
    def __init__(self, address_n: list):
        self.address_n = address_n

    def confirm_dialog(self) -> Awaitable[Any]:
        from apps.common import paths

        return paths.show_path_warning(self.address_n)


class UiConfirmMultipleAccounts(UiConfirm):
    def confirm_dialog(self) -> Awaitable[Any]:
        return layout.confirm_multiple_accounts()


def confirm_output(output: MintlayerTxOutput, coin: CoinInfo, output_index: int, chunkify: bool) -> Awaitable[None]:  # type: ignore [awaitable-return-type]
    return (
        yield UiConfirmOutput(  # type: ignore [awaitable-return-type]
            output, coin, output_index, chunkify
        )
    )


def confirm_total(spending: int, fee: int, fee_rate: float, coin: CoinInfo) -> Awaitable[None]:  # type: ignore [awaitable-return-type]
    return (yield UiConfirmTotal(spending, fee, fee_rate, coin))  # type: ignore [awaitable-return-type]


def confirm_change_count_over_threshold(change_count: int) -> Awaitable[Any]:  # type: ignore [awaitable-return-type]
    return (yield UiConfirmChangeCountOverThreshold(change_count))  # type: ignore [awaitable-return-type]


def confirm_unverified_external_input() -> Awaitable[Any]:  # type: ignore [awaitable-return-type]
    return (yield UiConfirmUnverifiedExternalInput())  # type: ignore [awaitable-return-type]


def confirm_foreign_address(address_n: list) -> Awaitable[Any]:  # type: ignore [awaitable-return-type]
    return (yield UiConfirmForeignAddress(address_n))  # type: ignore [awaitable-return-type]


def confirm_multiple_accounts() -> Awaitable[Any]:  # type: ignore [awaitable-return-type]
    return (yield UiConfirmMultipleAccounts())  # type: ignore [awaitable-return-type]


def request_tx_input(tx_req: MintlayerTxRequest, i: int) -> Awaitable[MintlayerTxInput]:  # type: ignore [awaitable-return-type]
    from trezor.messages import MintlayerTxAckUtxoInput

    assert tx_req.details is not None
    tx_req.request_type = MintlayerRequestType.TXINPUT
    tx_req.details.request_index = i
    ack = yield MintlayerTxAckUtxoInput, tx_req  # type: ignore [awaitable-return-type]
    _clear_tx_request(tx_req)
    return _sanitize_tx_input(ack.tx.input)


def request_tx_output(tx_req: MintlayerTxRequest, i: int, tx_hash: bytes | None = None) -> Awaitable[MintlayerTxOutput]:  # type: ignore [awaitable-return-type]
    from trezor.messages import MintlayerTxAckOutput

    assert tx_req.details is not None
    if tx_hash:
        tx_req.request_type = MintlayerRequestType.TXOUTPUT
        tx_req.details.tx_hash = tx_hash
    else:
        tx_req.request_type = MintlayerRequestType.TXOUTPUT
    tx_req.details.request_index = i
    ack = yield MintlayerTxAckOutput, tx_req  # type: ignore [awaitable-return-type]
    _clear_tx_request(tx_req)
    return _sanitize_tx_output(ack.tx.output)


def request_tx_finish(tx_req: MintlayerTxRequest) -> Awaitable[None]:  # type: ignore [awaitable-return-type]
    tx_req.request_type = MintlayerRequestType.TXFINISHED
    yield None, tx_req  # type: ignore [awaitable-return-type]q
    _clear_tx_request(tx_req)


def _clear_tx_request(tx_req: MintlayerTxRequest) -> None:
    details = tx_req.details  # local_cache_attribute
    serialized = tx_req.serialized  # local_cache_attribute

    assert details is not None
    assert serialized is not None
    # assert serialized.serialized_tx is not None
    tx_req.request_type = None
    details.request_index = None
    details.tx_hash = None
    serialized = []
    # serialized.signature = None
    # serialized.signature_index = None


# Data sanitizers
# ===


def sanitize_sign_tx(tx: SignTx, coin: CoinInfo) -> SignTx:
    if coin.decred or coin.overwintered:
        tx.expiry = tx.expiry if tx.expiry is not None else 0
    elif tx.expiry:
        raise DataError("Expiry not enabled on this coin.")

    if coin.timestamp and not tx.timestamp:
        raise DataError("Timestamp must be set.")
    elif not coin.timestamp and tx.timestamp:
        raise DataError("Timestamp not enabled on this coin.")

    if coin.overwintered:
        if tx.version_group_id is None:
            raise DataError("Version group ID must be set.")
        if tx.branch_id is None:
            raise DataError("Branch ID must be set.")
    elif not coin.overwintered:
        if tx.version_group_id is not None:
            raise DataError("Version group ID not enabled on this coin.")
        if tx.branch_id is not None:
            raise DataError("Branch ID not enabled on this coin.")

    return tx


def _sanitize_tx_meta(tx: PrevTx, coin: CoinInfo) -> PrevTx:
    if not coin.extra_data and tx.extra_data_len:
        raise DataError("Extra data not enabled on this coin.")

    if coin.decred or coin.overwintered:
        tx.expiry = tx.expiry if tx.expiry is not None else 0
    elif tx.expiry:
        raise DataError("Expiry not enabled on this coin.")

    if coin.timestamp and not tx.timestamp:
        raise DataError("Timestamp must be set.")
    elif not coin.timestamp and tx.timestamp:
        raise DataError("Timestamp not enabled on this coin.")
    elif not coin.overwintered:
        if tx.version_group_id is not None:
            raise DataError("Version group ID not enabled on this coin.")
        if tx.branch_id is not None:
            raise DataError("Branch ID not enabled on this coin.")

    return tx


def _sanitize_tx_input(txi: MintlayerTxInput) -> MintlayerTxInput:
    from trezor.wire import DataError  # local_cache_global

    if txi.utxo:
        if len(txi.utxo.prev_hash) != TX_HASH_SIZE:
            raise DataError("Provided prev_hash is invalid.")

        if txi.utxo.prev_index < 0:
            raise DataError("Invalid UTXO previous index.")

        if not txi.utxo.address_n:
            raise DataError("Input's address_n must be present for signing.")
    elif txi.account_command:
        cmd = txi.account_command
        no_cmd = (
            cmd.mint is None
            and cmd.unmint is None
            and cmd.freeze_token is None
            and cmd.unfreeze_token is None
            and cmd.lock_token_supply is None
            and cmd.change_token_metadata_uri is None
            and cmd.change_token_authority is None
        )
        if no_cmd:
            raise DataError("No account command present")

        if not txi.account_command.address_n:
            raise DataError("Input's address_n must be present for signing.")
    elif txi.account:
        if not txi.account.address_n:
            raise DataError("Input's address_n must be present for signing.")
    else:
        raise DataError(
            "No input type present either utxo, account_command or account must be present"
        )

    return txi


def _sanitize_tx_output(txo: MintlayerTxOutput) -> MintlayerTxOutput:
    from trezor.wire import DataError  # local_cache_global

    if txo.transfer:
        x = txo.transfer
        if x.value is None:
            raise DataError("Missing amount field.")

        if not x.address:
            raise DataError("Missing address")
    elif txo.lock_then_transfer:
        x = txo.lock_then_transfer
        if x.value is None:
            raise DataError("Missing amount field.")

        if not x.address:
            raise DataError("Missing address")
    else:
        # TODO: senitize other tx outputs
        pass

    return txo


def get_lock(x: MintlayerOutputTimeLock) -> Tuple[int, int]:
    if x.until_height:
        lock_type = 0
        lock_amount = x.until_height
    elif x.until_time:
        lock_type = 1
        lock_amount = x.until_time
    elif x.for_block_count:
        lock_type = 2
        lock_amount = x.for_block_count
    elif x.for_seconds:
        lock_type = 3
        lock_amount = x.for_seconds
    else:
        raise DataError("unhandled mintlayer lock type")
    return (lock_type, lock_amount)
