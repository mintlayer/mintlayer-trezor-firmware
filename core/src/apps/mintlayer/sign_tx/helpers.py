from micropython import const
from typing import TYPE_CHECKING, Tuple

from trezor import utils
from trezor.crypto.bech32 import bech32_decode, convertbits
from trezor.enums import MintlayerOutputTimeLockType, MintlayerRequestType
from trezor.messages import MintlayerTokenOutputValue
from trezor.wire import DataError

from . import layout

if TYPE_CHECKING:
    from typing import Any, Awaitable

    from trezor.messages import (
        MintlayerOutputTimeLock,
        MintlayerTxInput,
        MintlayerTxOutput,
        MintlayerTxRequest,
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
        output_index: int,
        coininfo: CoinInfo,
        chunkify: bool,
    ) -> None:
        self.output = output
        self.output_index = output_index
        self.chunkify = chunkify
        self.coininfo = coininfo

    def confirm_dialog(self) -> Awaitable[Any]:
        return layout.confirm_output(
            self.output,
            self.output_index,
            self.coininfo,
            self.chunkify,
        )


class UiConfirmTotal(UiConfirm):
    def __init__(
        self,
        spending: int,
        fee: int,
        coininfo: CoinInfo,
        token: MintlayerTokenOutputValue | None,
    ) -> None:
        self.spending = spending
        self.fee = fee
        self.coininfo = coininfo
        self.token = token

    def confirm_dialog(self) -> Awaitable[Any]:
        return layout.confirm_total(self.spending, self.fee, self.coininfo, self.token)


def confirm_output(
    output: MintlayerTxOutput, output_index: int, coininfo: CoinInfo, chunkify: bool
) -> Awaitable[None]:  # type: ignore [awaitable-return-type]
    return (
        yield UiConfirmOutput(  # type: ignore [awaitable-return-type]
            output, output_index, coininfo, chunkify
        )
    )


def confirm_total(
    spending: int, fee: int, coininfo: CoinInfo, token: MintlayerTokenOutputValue | None
) -> Awaitable[None]:  # type: ignore [awaitable-return-type]
    return (yield UiConfirmTotal(spending, fee, coininfo, token))  # type: ignore [awaitable-return-type]


def request_tx_input(tx_req: MintlayerTxRequest, i: int) -> Awaitable[MintlayerTxInput]:  # type: ignore [awaitable-return-type]
    from trezor.messages import MintlayerTxAckUtxoInput

    assert tx_req.details is not None
    tx_req.request_type = MintlayerRequestType.TXINPUT
    tx_req.details.request_index = i
    ack = yield MintlayerTxAckUtxoInput, tx_req  # type: ignore [awaitable-return-type]
    _clear_tx_request(tx_req)
    return _sanitize_tx_input(ack.input)


def request_tx_output(
    tx_req: MintlayerTxRequest, i: int, tx_hash: bytes | None = None
) -> Awaitable[MintlayerTxOutput]:  # type: ignore [awaitable-return-type]
    from trezor.messages import MintlayerTxAckOutput

    assert tx_req.details is not None
    tx_req.request_type = MintlayerRequestType.TXOUTPUT
    if tx_hash:
        tx_req.details.tx_hash = tx_hash

    tx_req.details.request_index = i
    ack = yield MintlayerTxAckOutput, tx_req  # type: ignore [awaitable-return-type]
    _clear_tx_request(tx_req)
    return _sanitize_tx_output(ack.output)


def request_tx_finish(tx_req: MintlayerTxRequest) -> Awaitable[None]:  # type: ignore [awaitable-return-type]
    tx_req.request_type = MintlayerRequestType.TXFINISHED
    yield None, tx_req  # type: ignore [awaitable-return-type]q
    _clear_tx_request(tx_req)


def _clear_tx_request(tx_req: MintlayerTxRequest) -> None:
    details = tx_req.details  # local_cache_attribute

    assert details is not None
    tx_req.request_type = None
    details.request_index = None
    details.tx_hash = None
    tx_req.serialized = None


# Data sanitizers
# ===


def _sanitize_tx_input(txi: MintlayerTxInput) -> MintlayerTxInput:
    from trezor.wire import DataError  # local_cache_global

    if txi.utxo:
        if len(txi.utxo.prev_hash) != TX_HASH_SIZE:
            raise DataError("Provided prev_hash is invalid.")

        if txi.utxo.prev_index < 0:
            raise DataError("Invalid UTXO previous index.")

        if txi.utxo.addresses is None:
            raise DataError("Input's addresses must be present for signing.")
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
            and cmd.conclude_order is None
            and cmd.fill_order is None
        )
        if no_cmd:
            raise DataError("No account command present")

        if txi.account_command.addresses is None:
            raise DataError("Input's addresses must be present for signing.")
    elif txi.account:
        if txi.account.addresses is None:
            raise DataError("Input's addresses must be present for signing.")

        if txi.account.delegation_balance:
            pass
        else:
            raise DataError("No account spending is set")

    else:
        raise DataError(
            "No input type present either utxo, account_command or account must be present"
        )

    return txi


def _sanitize_tx_output(txo: MintlayerTxOutput) -> MintlayerTxOutput:
    from trezor.wire import DataError  # local_cache_global

    if txo.transfer:
        pass
    elif txo.lock_then_transfer:
        pass
    elif txo.burn:
        pass
    elif txo.issue_nft:
        pass
    elif txo.create_stake_pool:
        pass
    elif txo.produce_block_from_stake:
        raise DataError("Cannot create a ProduceBlockFromStake output in a transaction")
    elif txo.create_delegation_id:
        pass
    elif txo.delegate_staking:
        pass
    elif txo.issue_fungible_token:
        pass
    elif txo.issue_nft:
        pass
    elif txo.data_deposit:
        pass
    elif txo.htlc:
        pass
    elif txo.create_order:
        pass
    else:
        raise DataError("Tx Output not set")

    return txo


def get_lock(x: MintlayerOutputTimeLock) -> Tuple[MintlayerOutputTimeLockType, int]:
    if x.until_height:
        lock_type = MintlayerOutputTimeLockType.UNTIL_HEIGHT
        lock_amount = x.until_height
    elif x.until_time:
        lock_type = MintlayerOutputTimeLockType.UNTIL_TIME
        lock_amount = x.until_time
    elif x.for_block_count:
        lock_type = MintlayerOutputTimeLockType.FOR_BLOCK_COUNT
        lock_amount = x.for_block_count
    elif x.for_seconds:
        lock_type = MintlayerOutputTimeLockType.FOR_SECONDS
        lock_amount = x.for_seconds
    else:
        raise DataError("unhandled mintlayer lock type")
    return (lock_type, lock_amount)


def mintlayer_decode(address: str, check_hrp: str | None) -> bytes:
    hrpgot, data, _ = bech32_decode(address)
    if check_hrp is not None and hrpgot != check_hrp:
        raise Exception(f"Invalid address expected HRP {check_hrp} got {hrpgot}")

    decoded = bytes(convertbits(data, 5, 8, False))
    return decoded
