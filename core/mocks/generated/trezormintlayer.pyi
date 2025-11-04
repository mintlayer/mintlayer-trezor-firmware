from typing import *


# upymod/modtrezormintlayer/modtrezormintlayer-input-comm.h
def encode_empty_input_commitment() -> bytes:
    """
    Encodes an empty input commitment.
    """


# upymod/modtrezormintlayer/modtrezormintlayer-input-comm.h
def encode_input_commitment_for_utxo(encoded_utxo: bytes) -> bytes:
    """
    Encodes an input commitment for a utxo.
    in v1 it works for any utxo input except ProduceBlockFromStake.
    """


# upymod/modtrezormintlayer/modtrezormintlayer-input-comm.h
def encode_input_commitment_v1_for_produce_block_from_stake_utxo(
  encoded_utxo: bytes, staker_balance_amount: bytes
) -> bytes:
    """
    Encodes an input commitment for a ProduceBlockFromStake utxo (v1 only).
    """


# upymod/modtrezormintlayer/modtrezormintlayer-input-comm.h
def encode_input_commitment_v1_for_fill_order(
    asked_token: bytes, initially_asked_amount: bytes,
    given_token: bytes, initially_given_amount: bytes,
) -> bytes:
    """
    Encodes input commitment for filling an order (v1 only);
    asked_token and given_token can be empty byte arrays, which means that
    the corresponding
    """


# upymod/modtrezormintlayer/modtrezormintlayer-input-comm.h
def encode_input_commitment_v1_for_conclude_order(
    asked_token: bytes, initially_asked_amount: bytes, ask_balance_amount:
    bytes, given_token: bytes, initially_given_amount: bytes,
    give_balance_amount: bytes
) -> bytes:
    """
    Encodes input commitment for concluding an order (v1 only);
    asked_token and given_token can be empty byte arrays, which means that
    the corresponding
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_utxo_input(tx_hash: bytes, index: int, utxo_type: int) -> bytes:
    """
    encodes an utxo input from tx_hash and index
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_account_spending_input(
    nonce: int, delegation_id: bytes, amount: bytes
) -> bytes:
    """
    encodes an utxo account spending from nonce and delegation id
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_token_account_command_input(
    nonce: int, command_type: int, token_id: bytes, data: bytes
) -> bytes:
    """
    encodes an account command from the nonce, command type, token id
    and additional command data
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_conclude_order_account_command_input(
    nonce: int, order_id: bytes
) -> bytes:
    """
    encodes an conclude order account command from the nonce and order id
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_fill_order_account_command_input(
    nonce: int, order_id: bytes, amount: bytes, destination: bytes
) -> bytes:
    """
    encodes a fill order account command from the nonce, order id, output
    amount and destination
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_conclude_order_v1_order_command_input(order_id: bytes) -> bytes:
    """
    encodes a conclude order v1 order command from the order id
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_freeze_order_order_command_input(order_id: bytes) -> bytes:
    """
    encodes a freeze order v1 order command from the order id
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_fill_order_v1_order_command_input(
    order_id: bytes, amount: bytes
) -> bytes:
    """
    encodes a fill order v1 order command from the order id and output
    amount
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_transfer_output(
    amount: bytes, token_id: bytes, address: bytes
) -> bytes:
    """
    encodes a transfer output with given amount and destination address
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_lock_then_transfer_output(
    amount: bytes, token_id: bytes, lock_type: int, lock_amount: int,
    address: bytes
) -> bytes:
    """
    encodes a transfer output with given amount, lock type and amount, and
    destination address
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_burn_output(amount: bytes, token_id: bytes) -> bytes:
    """
    encodes a burn output with given amount
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_create_stake_pool_output(
    pool_id: bytes, pledge_amount: bytes, staker: bytes,
    vrf_public_key: bytes, decommission_key: bytes,
    margin_ratio_per_thousand: int, cost_per_block: bytes
) -> bytes:
    """
    encodes a create stake pool output
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_produce_from_stake_output(
    destination: bytes, pool_id: bytes
) -> bytes:
    """
    encodes a produce from stake output
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_create_delegation_id_output(
    destination: bytes, pool_id: bytes
) -> bytes:
    """
    encodes a create delegation id output
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_delegate_staking_output(
    amount: bytes, delegation_id: bytes
) ->bytes:
    """
    encodes a delegation staking output, given the amount and delegation id
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_issue_fungible_token_output(
    token_ticker: bytes, number_of_decimals: int, metadata_uri: bytes,
    total_supply_type: int, fixed_amount: bytes, authority: bytes,
    is_freezable: bool
) -> bytes:
    """
    encodes a issue fungible token output
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_issue_nft_output(
    token_id: bytes, creator: bytes, name: bytes, destination: bytes,
    ticker: bytes, icon_uri: bytes, additional_metadata_uri: bytes,
    media_uri: bytes, media_hash: bytes, destination: bytes
) -> bytes:
    """
    encodes a issue NFT output
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_data_deposit_output(deposit: bytes) -> bytes:
    """
    encodes a data deposit output
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_htlc_output(
    amount: bytes, token_id: bytes, lock_type: int, lock_amount: int,
    refund_key: bytes, spend_key: bytes, secret_has: bytes
) -> bytes:
    """
    encodes an htlc output with given amount and lock
    """


# upymod/modtrezormintlayer/modtrezormintlayer.h
def encode_create_order_output(
    destination: bytes, ask_amount: bytes, ask_token_id: bytes,
    give_amount: bytes, give_token_id: bytes
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
