from typing import *
from buffer_types import *


# upymod/modtrezormintlayer/modtrezormintlayer-input-comm.h
def encode_empty_input_commitment() -> bytes:
    """
    Encodes an empty input commitment.
    """


# upymod/modtrezormintlayer/modtrezormintlayer-input-comm.h
def encode_input_commitment_for_utxo(encoded_utxo: AnyBytes) -> bytes:
    """
    Encodes an input commitment for a utxo.
    in v1 it works for any utxo input except ProduceBlockFromStake.
    """


# upymod/modtrezormintlayer/modtrezormintlayer-input-comm.h
def encode_input_commitment_v1_for_produce_block_from_stake_utxo(
  encoded_utxo: AnyBytes, staker_balance_amount: AnyBytes
) -> bytes:
    """
    Encodes an input commitment for a ProduceBlockFromStake utxo (v1 only).
    """


# upymod/modtrezormintlayer/modtrezormintlayer-input-comm.h
def encode_input_commitment_v1_for_fill_order(
    asked_token: AnyBytes, initially_asked_amount: AnyBytes,
    given_token: AnyBytes, initially_given_amount: AnyBytes,
) -> bytes:
    """
    Encodes input commitment for filling an order (v1 only);
    asked_token and given_token can be empty byte arrays, which means that
    the corresponding
    """


# upymod/modtrezormintlayer/modtrezormintlayer-input-comm.h
def encode_input_commitment_v1_for_conclude_order(
    asked_token: AnyBytes,
    initially_asked_amount: AnyBytes,
    ask_balance_amount: AnyBytes,
    given_token: AnyBytes,
    initially_given_amount: AnyBytes,
    give_balance_amount: AnyBytes
) -> bytes:
    """
    Encodes input commitment for concluding an order (v1 only);
    asked_token and given_token can be empty byte arrays, which means that
    the corresponding
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_utxo_input(
    tx_hash: AnyBytes, index: int, utxo_type: int
) -> bytes:
    """
    encodes an utxo input from tx_hash and index
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_account_spending_input(
    nonce: int, delegation_id: AnyBytes, amount: AnyBytes
) -> bytes:
    """
    encodes an utxo account spending from nonce and delegation id
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_token_account_command_input(
    nonce: int, command_type: int, token_id: AnyBytes, data: AnyBytes
) -> bytes:
    """
    encodes an account command from the nonce, command type, token id
    and additional command data
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_conclude_order_account_command_input(
    nonce: int, order_id: AnyBytes
) -> bytes:
    """
    encodes an conclude order account command from the nonce and order id
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_fill_order_account_command_input(
    nonce: int, order_id: AnyBytes, amount: AnyBytes, destination: AnyBytes
) -> bytes:
    """
    encodes a fill order account command from the nonce, order id, output
    amount and destination
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_conclude_order_v1_order_command_input(
    order_id: AnyBytes
) -> bytes:
    """
    encodes a conclude order v1 order command from the order id
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_freeze_order_order_command_input(order_id: AnyBytes) -> bytes:
    """
    encodes a freeze order v1 order command from the order id
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_fill_order_v1_order_command_input(
    order_id: AnyBytes, amount: AnyBytes
) -> bytes:
    """
    encodes a fill order v1 order command from the order id and output
    amount
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_transfer_output(
    amount: AnyBytes, token_id: AnyBytes, address: AnyBytes
) -> bytes:
    """
    encodes a transfer output with given amount and destination address
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_lock_then_transfer_output(
    amount: AnyBytes, token_id: AnyBytes, lock_type: int, lock_amount: int,
    address: AnyBytes
) -> bytes:
    """
    encodes a transfer output with given amount, lock type and amount, and
    destination address
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_burn_output(amount: AnyBytes, token_id: AnyBytes) -> bytes:
    """
    encodes a burn output with given amount
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_create_stake_pool_output(
    pool_id: AnyBytes, pledge_amount: AnyBytes, staker: AnyBytes,
    vrf_public_key: AnyBytes, decommission_key: AnyBytes,
    margin_ratio_per_thousand: int, cost_per_block: AnyBytes
) -> bytes:
    """
    encodes a create stake pool output
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_produce_from_stake_output(
    destination: AnyBytes, pool_id: AnyBytes
) -> bytes:
    """
    encodes a produce from stake output
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_create_delegation_id_output(
    destination: AnyBytes, pool_id: AnyBytes
) -> bytes:
    """
    encodes a create delegation id output
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_delegate_staking_output(
    amount: AnyBytes, delegation_id: AnyBytes
) ->bytes:
    """
    encodes a delegation staking output, given the amount and delegation id
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_issue_fungible_token_output(
    token_ticker: AnyBytes, number_of_decimals: int, metadata_uri: AnyBytes,
    total_supply_type: int, fixed_amount: AnyBytes, authority: AnyBytes,
    is_freezable: bool
) -> bytes:
    """
    encodes a issue fungible token output
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_issue_nft_output(
    token_id: AnyBytes, creator: AnyBytes, name: AnyBytes,
    destination: AnyBytes, ticker: AnyBytes, icon_uri: AnyBytes,
    additional_metadata_uri: AnyBytes, media_uri: AnyBytes,
    media_hash: AnyBytes, destination: AnyBytes
) -> bytes:
    """
    encodes a issue NFT output
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_data_deposit_output(deposit: AnyBytes) -> bytes:
    """
    encodes a data deposit output
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_htlc_output(
    amount: AnyBytes, token_id: AnyBytes, lock_type: int, lock_amount: int,
    refund_key: AnyBytes, spend_key: AnyBytes, secret_hash: AnyBytes
) -> bytes:
    """
    encodes an htlc output with given amount and lock
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_create_order_output(
    destination: AnyBytes, ask_amount: AnyBytes, ask_token_id: AnyBytes,
    give_amount: AnyBytes, give_token_id: AnyBytes
) -> bytes:
    """
    encodes a create order output with given the conclude key, give and
    take amounts
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_compact_length(length: int) -> bytes:
    """
    encodes a compact length to bytes
    """
