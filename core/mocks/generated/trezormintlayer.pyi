from typing import *


# extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_utxo_input(tx_hash: bytes, index: int, utxo_type: int) -> bytes:
    """
    encodes an utxo input from tx_hash and index
    """


# extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_account_spending_input(nonce: int, delegation_id: str, amount:
bytes) -> bytes:
    """
    encodes an utxo input from tx_hash and index
    """


# extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_account_command_input(nonce: int, command: int token_id: str,
data: bytes) -> bytes:
    """
    encodes an utxo input from tx_hash and index
    """


# extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_transfer_output(amount: str, token_id: str, address: str) ->
bytes:
    """
    encodes a transfer output with given amount and destination address
    """


# extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_lock_then_transfer_output(amount: str, token_id: str, lock_type:
int, lock_amount:int, address: str) -> bytes:
    """
    encodes a transfer output with given amount and destination address
    """


# extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_burn_output(amount: str, token_id: str) ->
bytes:
    """
    encodes a transfer output with given amount and destination address
    """


# extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_create_stake_pool_output(pool_id: str, pledge_amount: str,
staker: str, vrf_public_key: str, decommission_key: str,
margin_ratio_per_thousand: int, cost_per_block: str) -> bytes:
    """
    encodes a transfer output with given amount and destination address
    """


# extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_produce_from_stake_output(destination: str, pool_id: str) ->
bytes:
    """
    encodes a transfer output with given amount and destination address
    """


# extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_create_delegation_id_output(destination: str, pool_id: str) ->
bytes:
    """
    encodes a transfer output with given amount and destination address
    """


# extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_delegate_staking_output(amount: str, delegation_id: str) ->
bytes:
    """
    encodes a transfer output with given amount and destination address
    """


# extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_issue_fungible_token_output(token_ticker: str,
number_of_decimals: int, metadata_uri: str, total_supply_type: int,
fixed_amount: str, authority: str, is_freezable: int) -> bytes:
    """
    encodes a transfer output with given amount and destination address
    """


# extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_issue_nft_output(token_id: str,
creator: str, name: str, destination: str,
ticker: str, icon_uri: str, additional_metadata_uri: str, media_uri: str,
media_hash: str, destination: str) -> bytes:
    """
    encodes a transfer output with given amount and destination address
    """


# extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_data_deposit_output(deposit: str) ->
bytes:
    """
    encodes a transfer output with given amount and destination address
    """


# extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_htlc_output(amount: str, token_id: str, lock_type:
int, lock_amount:int, refund_key: str, spend_key: str, secret_has: bytes) ->
bytes:
    """
    encodes an htlc output with given amount and lock
    """


# extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_compact_length(length: int) -> bytes:
    """
    encodes a comapct length to bytes
    """
