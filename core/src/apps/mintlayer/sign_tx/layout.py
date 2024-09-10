from micropython import const
from typing import TYPE_CHECKING

from trezor import TR
from trezor.enums import ButtonRequestType, MintlayerTokenTotalSupplyType
from trezor.strings import format_amount
from trezor.ui import layouts

from apps.common.paths import address_n_to_str

from trezor.crypto.bech32 import bech32_encode, convertbits, Encoding

from ...bitcoin import addresses
from ...bitcoin.common import (
    BIP32_WALLET_DEPTH,
    format_fee_rate,
)
from ...bitcoin.keychain import address_n_to_name

if TYPE_CHECKING:
    from trezor.enums import AmountUnit
    from trezor.messages import TxAckPaymentRequest, TxOutput, MintlayerTokenOutputValue, MintlayerOutputTimeLock

    from apps.common.coininfo import CoinInfo
    from apps.common.paths import Bip32Path

    from trezor.messages import (
        MintlayerTxOutput,
    )

_LOCKTIME_TIMESTAMP_MIN_VALUE = const(500_000_000)

ML_COIN = "ML"
POOL_HRP = "mpool"
DELEGATION_HRP = "mdeleg"


def format_coin_amount(amount: bytes, token: MintlayerTokenOutputValue | None) -> str:
    if token is None:
        decimals = 11
        name = ML_COIN
    else:
        decimals = token.number_of_decimals
        name = "ML Token: " + token.token_ticker.decode('utf-8')

    amount_int = int.from_bytes(amount, 'big')
    amount_str = format_amount(amount_int, decimals)

    return f"{amount_str} {name}"


def account_label(coin: CoinInfo, address_n: Bip32Path | None) -> str:
    return (
        TR.bitcoin__multiple_accounts
        if address_n is None
        else address_n_to_name(coin, list(address_n) + [0] * BIP32_WALLET_DEPTH)
        or f"Path {address_n_to_str(address_n)}"
    )

def lock_to_string(lock: MintlayerOutputTimeLock) -> str:
    if lock.until_time:
        return f"Lock until {lock.until_time} time"
    elif lock.until_height:
        return f"Lock until {lock.until_height} height"
    elif lock.for_seconds:
        return f"Lock for {lock.for_seconds} seconds"
    elif lock.for_block_count:
        return f"Lock for {lock.for_block_count} blocks"
    else:
        raise Exception("unhandled lock type")

async def confirm_output(
    output: MintlayerTxOutput,
    coin: CoinInfo,
    output_index: int,
    chunkify: bool,
) -> None:
    from ubinascii import hexlify
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
        address_short += lock_to_string(x.lock)
        amount = format_coin_amount(x.value.amount, x.value.token)
    elif output.burn:
        x = output.burn
        address_short = "BURN"
        amount = format_coin_amount(x.value.amount, x.value.token)
        address_label = ""
    elif output.create_stake_pool:
        x = output.create_stake_pool
        assert x.staker is not None and x.decommission_key is not None
        address_short = f"staker: {x.staker}, decommission_key: {x.decommission_key}"
        amount = format_coin_amount(x.pledge, None)
        address_label = "Create stake pool"
    elif output.produce_block_from_stake:
        x = output.produce_block_from_stake
        address_short = f"new decommission_key: {x.destination}"
        amount = ""
        address_label = "Produce block from stake"
    elif output.create_delegation_id:
        x = output.create_delegation_id
        assert x.destination is not None
        amount = ""
        data = convertbits(x.pool_id, 8, 5)
        pool_id_address = bech32_encode(POOL_HRP, data, Encoding.BECH32M)
        address_short = f"Address: {x.destination}\nPoolId: {pool_id_address}"
        address_label = f"Create delegation ID"
    elif output.delegate_staking:
        x = output.delegate_staking
        assert x.delegation_id is not None
        data = convertbits(x.delegation_id, 8, 5)
        address = bech32_encode(DELEGATION_HRP, data, Encoding.BECH32M)
        address_short = address
        amount = format_coin_amount(x.amount, None)
        address_label = "Delegation staking"
    elif output.issue_fungible_token:
        x = output.issue_fungible_token
        ticker = x.token_ticker.decode('utf-8')
        name = x.name.decode('utf-8')
        additional_metadata_uri = x.additional_metadata_uri.decode('utf-8') if x.additional_metadata_uri else None
        metadata_uri = x.metadata_uri.decode('utf-8') if x.metadata_uri else None
        if x.total_supply.type == MintlayerTokenTotalSupplyType.UNLIMITED:
            total_supply = "UNLIMITED"
        elif x.total_supply.type == MintlayerTokenTotalSupplyType.LOCKABLE:
            total_supply = "LOCKABLE"
        elif x.total_supply.type == MintlayerTokenTotalSupplyType.FIXED:
            if not x.total_supply.fixed_amount:
                raise ValueError("Token Fixed supply without amount")
            amount = int.from_bytes(x.total_supply.fixed_amount, 'big')
            formated_amount = format_amount(amount, x.number_of_decimals)
            total_supply = f"FIXED {formated_amount}"
        else:
            raise ValueError("Unhandled Token total supply type")
        is_freezable = "Yes" if x.is_freezable else "No"
        address_short = f"""Ticker: {ticker}
        Authority: {x.authority}
        Metadata URI: {metadata_uri}
        Total token supply: {total_supply}
        Number of Decimals: {x.number_of_decimals}
        Is Freezable: {is_freezable}
        """
        amount = "amount"
        address_label = "Issue fungible token"
    elif output.issue_nft:
        x = output.issue_nft
        ticker = x.ticker.decode('utf-8')
        name = x.name.decode('utf-8')
        icon_uri = x.icon_uri.decode('utf-8') if x.icon_uri else None
        additional_metadata_uri = x.additional_metadata_uri.decode('utf-8') if x.additional_metadata_uri else None
        media_uri = x.media_uri.decode('utf-8') if x.media_uri else None
        address_short = f"""Name: {name}
        Creator: {x.creator}
        ticker: {ticker}
        Address: {x.destination}
        Icon URI: {icon_uri}
        Additional medatada URI: {additional_metadata_uri}
        Media URI: {media_uri}
        """
        amount = ""
        address_label = "Issue NFT token"
    elif output.data_deposit:
        x = output.data_deposit
        address_short = hexlify(x.data).decode()
        amount = ""
        address_label = "Data Deposit"
    elif output.htlc:
        x = output.htlc
        lock = lock_to_string(x.refund_timelock)
        address_short = f"Secret Hash: {x.secret_hash.hex()}, Spend Key: {x.spend_key}, Refund Key: {x.refund_key}, Refund Time Lock: {lock}"
        amount = format_coin_amount(x.value.amount, x.value.token)
        address_label = "HTLC"
    else:
        raise Exception("unhandled output type")

    if amount:
        layout = layouts.confirm_output(
            address_short,
            amount,
            title=title,
            address_label=address_label,
            output_index=output_index,
            chunkify=chunkify,
        )
    else:
        layout = layouts.confirm_text("confirm_address",
            title=title,
            data= address_short,
            description= address_label,
            br_code= ButtonRequestType.ConfirmOutput,
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

