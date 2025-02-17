from typing import TYPE_CHECKING

from trezor import TR
from trezor.enums import ButtonRequestType, MintlayerTokenTotalSupplyType
from trezor.strings import format_amount
from trezor.ui import layouts
from trezor.wire.errors import DataError

if TYPE_CHECKING:
    from trezor.messages import (
        MintlayerOutputTimeLock,
        MintlayerTokenOutputValue,
        MintlayerTxOutput,
    )

    from apps.common.coininfo import CoinInfo


def format_coin_amount(
    amount: bytes, token: MintlayerTokenOutputValue | None, coininfo: CoinInfo
) -> str:
    return format_coin_amount_int(int.from_bytes(amount, "big"), token, coininfo)


def format_coin_amount_int(
    amount_int: int, token: MintlayerTokenOutputValue | None, coininfo: CoinInfo
) -> str:
    if token is None:
        decimals = coininfo.decimals
        name = coininfo.coin_shortcut
    else:
        decimals = token.number_of_decimals
        ticker = token.token_ticker.decode("utf-8")
        name = f"Unknown token with ID: {token.token_id} and ticker {ticker}"

    amount_str = format_amount(amount_int, decimals)

    return f"{amount_str} {name}"


def lock_to_string(lock: MintlayerOutputTimeLock) -> str:
    from trezor.strings import format_timestamp

    if lock.until_time:
        return f"Lock until {format_timestamp(lock.until_time)}"
    elif lock.until_height:
        return f"Lock until block height {lock.until_height}"
    elif lock.for_seconds:
        return f"Lock for {lock.for_seconds} seconds"
    elif lock.for_block_count:
        return f"Lock for {lock.for_block_count} blocks"
    else:
        raise DataError("Unhandled lock type")


async def confirm_output(
    output: MintlayerTxOutput,
    output_index: int,
    coininfo: CoinInfo,
    chunkify: bool,
) -> None:
    from ubinascii import hexlify

    title = TR.bitcoin__title_confirm_details
    if output.transfer:
        x = output.transfer
        assert x.address is not None
        address_short = x.address
        amount = format_coin_amount(x.value.amount, x.value.token, coininfo)
        address_label = "Transfer"
    elif output.lock_then_transfer:
        x = output.lock_then_transfer
        assert x.address is not None
        address_label = "Lock then Transfer"
        address_short = f"Destination: {x.address}\n"
        address_short += lock_to_string(x.lock)
        amount = format_coin_amount(x.value.amount, x.value.token, coininfo)
    elif output.burn:
        x = output.burn
        address_short = "BURN"
        amount = format_coin_amount(x.value.amount, x.value.token, coininfo)
        address_label = ""
    elif output.create_stake_pool:
        x = output.create_stake_pool
        assert x.staker is not None and x.decommission_key is not None
        address_short = f"""Pool ID: {x.pool_id}
Staker: {x.staker}
Decommission key: {x.decommission_key}"
VRF public key: {x.vrf_public_key}
Margin ratio per thousand: {x.margin_ratio_per_thousand}
Cost per block: {int.from_bytes(x.cost_per_block, "big")}
"""
        amount = format_coin_amount(x.pledge, None, coininfo)
        address_label = "Create staking pool"
    elif output.produce_block_from_stake:
        x = output.produce_block_from_stake
        address_short = f"New decommission key: {x.destination}"
        amount = ""
        address_label = "Produce block from stake"
    elif output.create_delegation_id:
        x = output.create_delegation_id
        amount = ""
        address_short = f"Address: {x.destination}\nPoolId: {x.pool_id}"
        address_label = "Create delegation"
    elif output.delegate_staking:
        x = output.delegate_staking
        address_short = x.delegation_id
        amount = format_coin_amount(x.amount, None, coininfo)
        address_label = "Delegate staking"
    elif output.issue_fungible_token:
        x = output.issue_fungible_token
        ticker = x.token_ticker.decode("utf-8")
        metadata_uri = x.metadata_uri.decode("utf-8") if x.metadata_uri else None
        if x.total_supply.type == MintlayerTokenTotalSupplyType.UNLIMITED:
            total_supply = "UNLIMITED"
        elif x.total_supply.type == MintlayerTokenTotalSupplyType.LOCKABLE:
            total_supply = "LOCKABLE"
        elif x.total_supply.type == MintlayerTokenTotalSupplyType.FIXED:
            if not x.total_supply.fixed_amount:
                raise DataError("Token Fixed supply without amount")
            fixed_amount = int.from_bytes(x.total_supply.fixed_amount, "big")
            formatted_amount = format_amount(fixed_amount, x.number_of_decimals)
            total_supply = f"FIXED {formatted_amount}"
        else:
            raise DataError("Unhandled Token total supply type")
        is_freezable = "Yes" if x.is_freezable else "No"
        address_short = f"""Ticker: {ticker}
Authority: {x.authority}
Metadata URI: {metadata_uri}
Total token supply: {total_supply}
Number of decimals: {x.number_of_decimals}
Is freezable: {is_freezable}"""
        amount = ""
        address_label = "Issue fungible token"
    elif output.issue_nft:
        x = output.issue_nft
        ticker = x.ticker.decode("utf-8")
        name = x.name.decode("utf-8")
        icon_uri = x.icon_uri.decode("utf-8") if x.icon_uri else None
        additional_metadata_uri = (
            x.additional_metadata_uri.decode("utf-8")
            if x.additional_metadata_uri
            else None
        )
        media_uri = x.media_uri.decode("utf-8") if x.media_uri else None
        address_short = f"""Name: {name}
Creator: {x.creator}
Ticker: {ticker}
Address: {x.destination}
Icon URI: {icon_uri}
Additional medatada URI: {additional_metadata_uri}
Media URI: {media_uri}"""
        amount = ""
        address_label = "Issue NFT token"
    elif output.data_deposit:
        x = output.data_deposit
        address_short = hexlify(x.data).decode()
        amount = ""
        address_label = "Data deposit"
    elif output.htlc:
        x = output.htlc
        lock = lock_to_string(x.refund_timelock)
        hexified_secret_hash = hexlify(x.secret_hash).decode()
        address_short = f"""Secret hash: {hexified_secret_hash}
Spend key: {x.spend_key}
Refund key: {x.refund_key}
Refund time lock: {lock}"""
        amount = format_coin_amount(x.value.amount, x.value.token, coininfo)
        address_label = "HTLC"
    elif output.create_order:
        x = output.create_order
        ask_amount = format_coin_amount(x.ask.amount, x.ask.token, coininfo)
        give_amount = format_coin_amount(x.give.amount, x.give.token, coininfo)
        address_short = f"""Conclude key: {x.conclude_key}
Ask: {ask_amount}
Give: {give_amount}"""
        amount = ""
        address_label = "Create order"
    else:
        raise DataError("Unhandled output type")

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
        layout = layouts.confirm_text(
            "confirm_address",
            title=title,
            data=address_short,
            description=address_label,
            br_code=ButtonRequestType.ConfirmOutput,
        )

    await layout


async def confirm_total(
    spending: int, fee: int, coininfo: CoinInfo, token: MintlayerTokenOutputValue | None
) -> None:
    await layouts.confirm_total(
        format_coin_amount_int(spending, token, coininfo),
        format_coin_amount_int(fee, token, coininfo),
        fee_rate_amount=None,
    )
