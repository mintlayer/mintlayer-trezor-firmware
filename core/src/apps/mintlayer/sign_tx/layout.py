from micropython import const
from typing import TYPE_CHECKING

from trezor import TR
from trezor.enums import ButtonRequestType
from trezor.strings import format_amount
from trezor.ui import layouts
from trezor.ui.layouts import confirm_metadata

from apps.common.paths import address_n_to_str

from trezor.crypto.bech32 import bech32_encode, bech32_decode, convertbits, reverse_convertbits, decode_address_to_bytes, Encoding

from ...bitcoin import addresses
from ...bitcoin.common import (
    BIP32_WALLET_DEPTH,
    CHANGE_OUTPUT_TO_INPUT_SCRIPT_TYPES,
    format_fee_rate,
)
from ...bitcoin.keychain import address_n_to_name

if TYPE_CHECKING:
    from trezor.enums import AmountUnit
    from trezor.messages import TxAckPaymentRequest, TxOutput, MintlayerTokenOutputValue
    from trezor.ui.layouts import LayoutType

    from apps.common.coininfo import CoinInfo
    from apps.common.paths import Bip32Path

    from trezor.messages import (
        MintlayerTxOutput,
    )

_LOCKTIME_TIMESTAMP_MIN_VALUE = const(500_000_000)


def format_coin_amount(amount: bytes, token: MintlayerTokenOutputValue | None) -> str:
    if token is None:
        decimals = 11
        name = "ML"
    else:
        decimals = token.number_of_decimals
        name = "ML Token: " + token.token_ticker.decode()

    print("amount to display bytes", amount)
    amount_int = 0
    for b in amount:
        amount_int = (amount_int << 8) | b
    decimal_str = str(amount_int)

    if len(decimal_str) <= decimals:
        decimal_str = '0' * (decimals + 1 - len(decimal_str)) + decimal_str  # Add an extra zero to handle leading zero case

    integer_part = decimal_str[:-decimals] or '0'
    decimal_part = decimal_str[-decimals:]
    return f"{integer_part}.{decimal_part} {name}"


def account_label(coin: CoinInfo, address_n: Bip32Path | None) -> str:
    return (
        TR.bitcoin__multiple_accounts
        if address_n is None
        else address_n_to_name(coin, list(address_n) + [0] * BIP32_WALLET_DEPTH)
        or f"Path {address_n_to_str(address_n)}"
    )


async def confirm_output(
    output: MintlayerTxOutput,
    coin: CoinInfo,
    output_index: int,
    chunkify: bool,
) -> None:
    title = TR.bitcoin__title_confirm_details
    if output.transfer:
        x = output.transfer
        assert x.address is not None
        address_short = x.address
        amount = format_coin_amount(x.value.amount, x.value.token)
        address_label = "Transfer"
    elif output.lock_then_transfer:
        x = output.lock_then_transfer
        assert x.address is not None
        address_label = "Lock then Transfer"
        address_short = f"Destination: {x.address}\n"
        if x.lock.until_time:
            address_label = f"Lock until {x.lock.until_time} time"
        elif x.lock.until_height:
            address_label = f"Lock until {x.lock.until_height} height"
        elif x.lock.for_seconds:
            address_label = f"Lock for {x.lock.for_seconds} seconds"
        elif x.lock.for_block_count:
            address_label = f"Lock for {x.lock.for_block_count} blocks"
        else:
            raise Exception("unhandled lock type")
        amount = format_coin_amount(x.value.amount, x.value.token)
    elif output.burn:
        x = output.burn
        address_short = "BURN"
        amount = format_coin_amount(x.value.amount, x.value.token)
        address_label = None
    elif output.create_stake_pool:
        x = output.create_stake_pool
        assert x.staker is not None and x.decommission_key is not None
        address_short = f"staker: {x.staker}, decommission_key: {x.decommission_key}"
        amount = format_coin_amount(x.pledge, None)
        address_label = "Create stake pool"
    elif output.create_delegation_id:
        x = output.create_delegation_id
        assert x.destination is not None
        amount = ""
        data = convertbits(x.pool_id, 8, 5)
        address = bech32_encode("mpool", data, Encoding.BECH32M)
        address_short = f"{x.destination} {address}"
        address_label = f"Create delegation ID"
    elif output.delegate_staking:
        x = output.delegate_staking
        assert x.delegation_id is not None
        data = convertbits(x.delegation_id, 8, 5)
        address = bech32_encode("mdeleg", data, Encoding.BECH32M)
        address_short = address
        amount = format_coin_amount(x.amount, None)
        address_label = "Delegation staking"
    elif output.issue_fungible_token:
        x = output.issue_fungible_token
        address_short = "Issue Fungible Token"
        amount = "amount"
        address_label = "Issue fungible token"
    elif output.issue_nft:
        x = output.issue_nft
        address_short = x.destination
        amount = ""
        address_label = "Issue NFT token"
    else:
        raise Exception("unhandled output type")

    layout = layouts.confirm_output(
        address_short,
        amount,
        title=title,
        address_label=address_label,
        output_index=output_index,
        chunkify=chunkify,
    )

    await layout


async def confirm_decred_sstx_submission(
    output: TxOutput, coin: CoinInfo, amount_unit: AmountUnit
) -> None:
    assert output.address is not None
    address_short = addresses.address_short(coin, output.address)
    amount = format_coin_amount(output.amount, coin, amount_unit)

    await layouts.confirm_value(
        TR.bitcoin__title_purchase_ticket,
        amount,
        TR.bitcoin__ticket_amount,
        "confirm_decred_sstx_submission",
        ButtonRequestType.ConfirmOutput,
        verb=TR.buttons__confirm,
    )

    await layouts.confirm_value(
        TR.bitcoin__title_purchase_ticket,
        address_short,
        TR.bitcoin__voting_rights,
        "confirm_decred_sstx_submission",
        ButtonRequestType.ConfirmOutput,
        verb=TR.buttons__purchase,
    )


async def should_show_payment_request_details(
    msg: TxAckPaymentRequest,
    coin: CoinInfo,
    amount_unit: AmountUnit,
) -> bool:
    from trezor import wire

    memo_texts: list[str] = []
    for m in msg.memos:
        if m.text_memo is not None:
            memo_texts.append(m.text_memo.text)
        elif m.refund_memo is not None:
            pass
        elif m.coin_purchase_memo is not None:
            memo_texts.append(f"{TR.words__buying} {m.coin_purchase_memo.amount}.")
        else:
            raise wire.DataError("Unrecognized memo type in payment request memo.")

    assert msg.amount is not None

    return await layouts.should_show_payment_request_details(
        msg.recipient_name,
        format_coin_amount(msg.amount, coin, amount_unit),
        memo_texts,
    )


async def confirm_replacement(title: str, txid: bytes) -> None:
    from ubinascii import hexlify

    await layouts.confirm_replacement(
        title,
        hexlify(txid).decode(),
    )


async def confirm_modify_output(
    txo: TxOutput,
    orig_txo: TxOutput,
    coin: CoinInfo,
    amount_unit: AmountUnit,
) -> None:
    assert txo.address is not None
    address_short = addresses.address_short(coin, txo.address)
    amount_change = txo.amount - orig_txo.amount
    await layouts.confirm_modify_output(
        address_short,
        amount_change,
        format_coin_amount(abs(amount_change), coin, amount_unit),
        format_coin_amount(txo.amount, coin, amount_unit),
    )


async def confirm_modify_fee(
    title: str,
    user_fee_change: int,
    total_fee_new: int,
    fee_rate: float,
    coin: CoinInfo,
    amount_unit: AmountUnit,
) -> None:
    await layouts.confirm_modify_fee(
        title,
        user_fee_change,
        format_coin_amount(abs(user_fee_change), coin, amount_unit),
        format_coin_amount(total_fee_new, coin, amount_unit),
        fee_rate_amount=format_fee_rate(fee_rate, coin) if fee_rate >= 0 else None,
    )


async def confirm_joint_total(
    spending: int,
    total: int,
    coin: CoinInfo,
    amount_unit: AmountUnit,
) -> None:
    await layouts.confirm_joint_total(
        spending_amount=format_coin_amount(spending, coin, amount_unit),
        total_amount=format_coin_amount(total, coin, amount_unit),
    )


async def confirm_total(
    spending: int,
    fee: int,
    fee_rate: float,
    coin: CoinInfo,
    amount_unit: AmountUnit,
    address_n: Bip32Path | None,
) -> None:

    await layouts.confirm_total(
        format_coin_amount(spending.to_bytes(16, 'big'), None),
        format_coin_amount(fee.to_bytes(16, 'big'), None),
        fee_rate_amount=format_fee_rate(fee_rate, coin) if fee_rate >= 0 else None,
        account_label=account_label(coin, address_n),
    )


async def confirm_feeoverthreshold(
    fee: int, coin: CoinInfo, amount_unit: AmountUnit
) -> None:
    fee_amount = format_coin_amount(fee, coin, amount_unit)
    await layouts.show_warning(
        "fee_over_threshold",
        TR.bitcoin__unusually_high_fee,
        fee_amount,
        br_code=ButtonRequestType.FeeOverThreshold,
    )


async def confirm_change_count_over_threshold(change_count: int) -> None:
    await layouts.show_warning(
        "change_count_over_threshold",
        TR.bitcoin__lot_of_change_outputs,
        f"{str(change_count)} {TR.words__outputs}",
        br_code=ButtonRequestType.SignTx,
    )


async def confirm_unverified_external_input() -> None:
    await layouts.show_warning(
        "unverified_external_input",
        TR.bitcoin__unverified_external_inputs,
        TR.words__continue_anyway,
        button=TR.buttons__continue,
        br_code=ButtonRequestType.SignTx,
    )


async def confirm_multiple_accounts() -> None:
    await layouts.show_warning(
        "sending_from_multiple_accounts",
        TR.send__from_multiple_accounts,
        TR.words__continue_anyway,
        button=TR.buttons__continue,
        br_code=ButtonRequestType.SignTx,
    )


async def confirm_nondefault_locktime(lock_time: int, lock_time_disabled: bool) -> None:
    from trezor.strings import format_timestamp

    if lock_time_disabled:
        await layouts.show_warning(
            "nondefault_locktime",
            TR.bitcoin__locktime_no_effect,
            TR.words__continue_anyway,
            button=TR.buttons__continue,
            br_code=ButtonRequestType.SignTx,
        )
    else:
        if lock_time < _LOCKTIME_TIMESTAMP_MIN_VALUE:
            text = TR.bitcoin__locktime_set_to_blockheight
            value = str(lock_time)
        else:
            text = TR.bitcoin__locktime_set_to
            value = format_timestamp(lock_time)
        await layouts.confirm_value(
            TR.bitcoin__confirm_locktime,
            value,
            text,
            "nondefault_locktime",
            br_code=ButtonRequestType.SignTx,
            verb=TR.buttons__confirm,
        )

