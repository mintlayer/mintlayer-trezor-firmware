from typing import TYPE_CHECKING, Tuple
from trezor import utils
from trezor.enums import MintlayerRequestType
from trezor.wire import DataError

from ..writers import TX_HASH_SIZE
from . import layout

if TYPE_CHECKING:
    from typing import Any, Awaitable

    from trezor.enums import AmountUnit
    from trezor.messages import (
        PrevInput,
        PrevOutput,
        PrevTx,
        SignTx,
        TxAckPaymentRequest,
        MintlayerTxInput,
        MintlayerTxOutput,
        MintlayerOutputTimeLock,
        TxOutput,
        MintlayerTxRequest,
    )

    from apps.common.coininfo import CoinInfo
    from apps.common.paths import Bip32Path

# Machine instructions
# ===


class UiConfirm:
    def confirm_dialog(self) -> Awaitable[Any]:
        raise NotImplementedError

    __eq__ = utils.obj_eq


class UiConfirmOutput(UiConfirm):
    def __init__(
        self,
        output: TxOutput,
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


class UiConfirmDecredSSTXSubmission(UiConfirm):
    def __init__(self, output: TxOutput, coin: CoinInfo, amount_unit: AmountUnit):
        self.output = output
        self.coin = coin
        self.amount_unit = amount_unit

    def confirm_dialog(self) -> Awaitable[Any]:
        return layout.confirm_decred_sstx_submission(
            self.output, self.coin, self.amount_unit
        )


class UiConfirmPaymentRequest(UiConfirm):
    def __init__(
        self,
        payment_req: TxAckPaymentRequest,
        coin: CoinInfo,
        amount_unit: AmountUnit,
    ):
        self.payment_req = payment_req
        self.amount_unit = amount_unit
        self.coin = coin

    def confirm_dialog(self) -> Awaitable[bool]:
        return layout.should_show_payment_request_details(
            self.payment_req, self.coin, self.amount_unit
        )

    __eq__ = utils.obj_eq


class UiConfirmReplacement(UiConfirm):
    def __init__(self, title: str, txid: bytes):
        self.title = title
        self.txid = txid

    def confirm_dialog(self) -> Awaitable[Any]:
        return layout.confirm_replacement(self.title, self.txid)


class UiConfirmModifyOutput(UiConfirm):
    def __init__(
        self,
        txo: TxOutput,
        orig_txo: TxOutput,
        coin: CoinInfo,
        amount_unit: AmountUnit,
    ):
        self.txo = txo
        self.orig_txo = orig_txo
        self.coin = coin
        self.amount_unit = amount_unit

    def confirm_dialog(self) -> Awaitable[Any]:
        return layout.confirm_modify_output(
            self.txo, self.orig_txo, self.coin, self.amount_unit
        )


class UiConfirmModifyFee(UiConfirm):
    def __init__(
        self,
        title: str,
        user_fee_change: int,
        total_fee_new: int,
        fee_rate: float,
        coin: CoinInfo,
        amount_unit: AmountUnit,
    ):
        self.title = title
        self.user_fee_change = user_fee_change
        self.total_fee_new = total_fee_new
        self.fee_rate = fee_rate
        self.coin = coin
        self.amount_unit = amount_unit

    def confirm_dialog(self) -> Awaitable[Any]:
        return layout.confirm_modify_fee(
            self.title,
            self.user_fee_change,
            self.total_fee_new,
            self.fee_rate,
            self.coin,
            self.amount_unit,
        )


class UiConfirmTotal(UiConfirm):
    def __init__(
        self,
        spending: int,
        fee: int,
        fee_rate: float,
        coin: CoinInfo,
        amount_unit: AmountUnit,
        address_n: Bip32Path | None,
    ):
        self.spending = spending
        self.fee = fee
        self.fee_rate = fee_rate
        self.coin = coin
        self.amount_unit = amount_unit
        self.address_n = address_n

    def confirm_dialog(self) -> Awaitable[Any]:
        return layout.confirm_total(
            self.spending,
            self.fee,
            self.fee_rate,
            self.coin,
            self.amount_unit,
            self.address_n,
        )


class UiConfirmJointTotal(UiConfirm):
    def __init__(
        self, spending: int, total: int, coin: CoinInfo, amount_unit: AmountUnit
    ):
        self.spending = spending
        self.total = total
        self.coin = coin
        self.amount_unit = amount_unit

    def confirm_dialog(self) -> Awaitable[Any]:
        return layout.confirm_joint_total(
            self.spending, self.total, self.coin, self.amount_unit
        )


class UiConfirmFeeOverThreshold(UiConfirm):
    def __init__(self, fee: int, coin: CoinInfo, amount_unit: AmountUnit):
        self.fee = fee
        self.coin = coin
        self.amount_unit = amount_unit

    def confirm_dialog(self) -> Awaitable[Any]:
        return layout.confirm_feeoverthreshold(self.fee, self.coin, self.amount_unit)


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


class UiConfirmNonDefaultLocktime(UiConfirm):
    def __init__(self, lock_time: int, lock_time_disabled: bool):
        self.lock_time = lock_time
        self.lock_time_disabled = lock_time_disabled

    def confirm_dialog(self) -> Awaitable[Any]:
        return layout.confirm_nondefault_locktime(
            self.lock_time, self.lock_time_disabled
        )


class UiConfirmMultipleAccounts(UiConfirm):
    def confirm_dialog(self) -> Awaitable[Any]:
        return layout.confirm_multiple_accounts()


def confirm_output(output: TxOutput, coin: CoinInfo, output_index: int, chunkify: bool) -> Awaitable[None]:  # type: ignore [awaitable-is-generator]
    return (yield UiConfirmOutput(output, coin, output_index, chunkify))


def confirm_decred_sstx_submission(output: TxOutput, coin: CoinInfo, amount_unit: AmountUnit) -> Awaitable[None]:  # type: ignore [awaitable-is-generator]
    return (yield UiConfirmDecredSSTXSubmission(output, coin, amount_unit))


def should_show_payment_request_details(payment_req: TxAckPaymentRequest, coin: CoinInfo, amount_unit: AmountUnit) -> Awaitable[bool]:  # type: ignore [awaitable-is-generator]
    return (yield UiConfirmPaymentRequest(payment_req, coin, amount_unit))


def confirm_replacement(description: str, txid: bytes) -> Awaitable[Any]:  # type: ignore [awaitable-is-generator]
    return (yield UiConfirmReplacement(description, txid))


def confirm_modify_output(txo: TxOutput, orig_txo: TxOutput, coin: CoinInfo, amount_unit: AmountUnit) -> Awaitable[Any]:  # type: ignore [awaitable-is-generator]
    return (yield UiConfirmModifyOutput(txo, orig_txo, coin, amount_unit))


def confirm_modify_fee(title: str, user_fee_change: int, total_fee_new: int, fee_rate: float, coin: CoinInfo, amount_unit: AmountUnit) -> Awaitable[Any]:  # type: ignore [awaitable-is-generator]
    return (
        yield UiConfirmModifyFee(
            title, user_fee_change, total_fee_new, fee_rate, coin, amount_unit
        )
    )


def confirm_total(spending: int, fee: int, fee_rate: float, coin: CoinInfo, amount_unit: AmountUnit, address_n: Bip32Path | None) -> Awaitable[None]:  # type: ignore [awaitable-is-generator]
    return (yield UiConfirmTotal(spending, fee, fee_rate, coin, amount_unit, address_n))


def confirm_joint_total(spending: int, total: int, coin: CoinInfo, amount_unit: AmountUnit) -> Awaitable[Any]:  # type: ignore [awaitable-is-generator]
    return (yield UiConfirmJointTotal(spending, total, coin, amount_unit))


def confirm_feeoverthreshold(fee: int, coin: CoinInfo, amount_unit: AmountUnit) -> Awaitable[Any]:  # type: ignore [awaitable-is-generator]
    return (yield UiConfirmFeeOverThreshold(fee, coin, amount_unit))


def confirm_change_count_over_threshold(change_count: int) -> Awaitable[Any]:  # type: ignore [awaitable-is-generator]
    return (yield UiConfirmChangeCountOverThreshold(change_count))


def confirm_unverified_external_input() -> Awaitable[Any]:  # type: ignore [awaitable-is-generator]
    return (yield UiConfirmUnverifiedExternalInput())


def confirm_foreign_address(address_n: list) -> Awaitable[Any]:  # type: ignore [awaitable-is-generator]
    return (yield UiConfirmForeignAddress(address_n))


def confirm_nondefault_locktime(lock_time: int, lock_time_disabled: bool) -> Awaitable[Any]:  # type: ignore [awaitable-is-generator]
    return (yield UiConfirmNonDefaultLocktime(lock_time, lock_time_disabled))


def confirm_multiple_accounts() -> Awaitable[Any]:  # type: ignore [awaitable-is-generator]
    return (yield UiConfirmMultipleAccounts())


def request_tx_meta(tx_req: TxRequest, coin: CoinInfo, tx_hash: bytes | None = None) -> Awaitable[PrevTx]:  # type: ignore [awaitable-is-generator]
    from trezor.messages import TxAckPrevMeta

    assert tx_req.details is not None
    tx_req.request_type = MintlayerRequestType.TXMETA
    tx_req.details.tx_hash = tx_hash
    ack = yield TxAckPrevMeta, tx_req
    _clear_tx_request(tx_req)
    return _sanitize_tx_meta(ack.tx, coin)


def request_tx_input(tx_req: MintlayerTxRequest, i: int) -> Awaitable[MintlayerTxInput]:  # type: ignore [awaitable-is-generator]
    from trezor.messages import MintlayerTxAckUtxoInput

    assert tx_req.details is not None
    tx_req.request_type = MintlayerRequestType.TXINPUT
    tx_req.details.request_index = i
    ack = yield MintlayerTxAckUtxoInput, tx_req
    _clear_tx_request(tx_req)
    return _sanitize_tx_input(ack.tx.input)


def request_tx_prev_input(tx_req: MintlayerTxRequest, i: int, tx_hash: bytes | None = None) -> Awaitable[PrevInput]:  # type: ignore [awaitable-is-generator]
    from trezor.messages import TxAckPrevInput

    assert tx_req.details is not None
    tx_req.request_type = MintlayerRequestType.TXINPUT
    tx_req.details.request_index = i
    tx_req.details.tx_hash = tx_hash
    ack = yield TxAckPrevInput, tx_req
    _clear_tx_request(tx_req)
    return _sanitize_tx_prev_input(ack.tx.input, coin)


def request_tx_output(tx_req: TxRequest, i: int, tx_hash: bytes | None = None) -> Awaitable[MintlayerTxOutput]:  # type: ignore [awaitable-is-generator]
    from trezor.messages import MintlayerTxAckOutput

    assert tx_req.details is not None
    if tx_hash:
        tx_req.request_type = MintlayerRequestType.TXOUTPUT
        tx_req.details.tx_hash = tx_hash
    else:
        tx_req.request_type = MintlayerRequestType.TXOUTPUT
    tx_req.details.request_index = i
    ack = yield MintlayerTxAckOutput, tx_req
    _clear_tx_request(tx_req)
    return _sanitize_tx_output(ack.tx.output)


def request_tx_prev_output(tx_req: TxRequest, i: int, coin: CoinInfo, tx_hash: bytes | None = None) -> Awaitable[PrevOutput]:  # type: ignore [awaitable-is-generator]
    from trezor.messages import TxAckPrevOutput

    assert tx_req.details is not None
    tx_req.request_type = MintlayerRequestType.TXOUTPUT
    tx_req.details.request_index = i
    tx_req.details.tx_hash = tx_hash
    ack = yield TxAckPrevOutput, tx_req
    _clear_tx_request(tx_req)
    # return sanitize_tx_prev_output(ack.tx, coin)  # no sanitize is required
    return ack.tx.output


def request_tx_finish(tx_req: TxRequest) -> Awaitable[None]:  # type: ignore [awaitable-is-generator]
    tx_req.request_type = MintlayerRequestType.TXFINISHED
    yield None, tx_req
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
    # typechecker thinks serialized_tx is `bytes`, which is immutable
    # we know that it is `bytearray` in reality
    # serialized.serialized_tx[:] = bytes()  # type: ignore ["__setitem__" method not defined on type "bytes"]


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
        no_cmd = (cmd.mint is None
                  and cmd.unmint is None
                  and cmd.freeze_token is None
                  and cmd.unfreeze_token is None
                  and cmd.lock_token_supply is None
                  and cmd.change_token_authority is None)
        if no_cmd:
            raise DataError("No account command present")

        if not txi.account_command.address_n:
            raise DataError("Input's address_n must be present for signing.")
    elif txi.account:
        if not txi.account.address_n:
            raise DataError("Input's address_n must be present for signing.")
    else:
        raise DataError("No input type present either utxo, account_command or account must be present")

    return txi


def _sanitize_tx_prev_input(txi: PrevInput, coin: CoinInfo) -> PrevInput:
    if len(txi.prev_hash) != TX_HASH_SIZE:
        raise DataError("Provided prev_hash is invalid.")

    if not coin.decred and txi.decred_tree is not None:
        raise DataError("Decred details provided but Decred coin not specified.")

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
        raise Exception("unhandled mintlayer lock type")
    return (lock_type, lock_amount)
