from typing import *


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_utxo_input(tx_hash: bytes, index: int, utxo_type: int) -> bytes:
    """
    encodes an utxo input from tx_hash and index
    """


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_account_spending_input(nonce: int, delegation_id: bytes, amount:
bytes) -> bytes:
    """
    encodes an utxo account spendinf from nonce and delegation id
    """


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_token_account_command_input(nonce: int, command: int, token_id:
bytes, data: bytes) -> bytes:
    """
    encodes an account command from the nonce, command, token id and
    additional command data
    """


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_conclude_order_account_command_input(nonce: int, order_id: bytes)
-> bytes:
    """
    encodes an conclude order account command from the nonce and order id
    """


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_fill_order_account_command_input(nonce: int, order_id: bytes,
amount: bytes, token_id: bytes, destination: bytes)
-> bytes:
    """
    encodes an fill order account command from the nonce, order id, output
    value and destination
    """


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_transfer_output(amount: bytes, token_id: bytes, address: bytes)
-> bytes:
    """
    encodes a transfer output with given amount and destination address
    """


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_lock_then_transfer_output(amount: bytes, token_id: bytes,
lock_type: int, lock_amount:int, address: bytes) -> bytes:
    """
    encodes a transfer output with given amount, lock type and amount, and
    destination address
    """


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_burn_output(amount: bytes, token_id: bytes) ->
bytes:
    """
    encodes a burn output with given amount
    """


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_create_stake_pool_output(pool_id: bytes, pledge_amount: bytes,
staker: bytes, vrf_public_key: bytes, decommission_key: bytes,
margin_ratio_per_thousand: int, cost_per_block: bytes) -> bytes:
    """
    encodes a create stake pool output
    """


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_produce_from_stake_output(destination: bytes, pool_id: bytes) ->
bytes:
    """
    encodes a produce from stake output
    """


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_create_delegation_id_output(destination: bytes, pool_id: bytes)
-> bytes:
    """
    encodes a create delegation id output
    """


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_delegate_staking_output(amount: bytes, delegation_id: bytes) ->
bytes:
    """
    encodes a delegation staking output, given the amount and delegation id
    """


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_issue_fungible_token_output(token_ticker: bytes,
number_of_decimals: int, metadata_uri: bytes, total_supply_type: int,
fixed_amount: bytes, authority: bytes, is_freezable: int) -> bytes:
    """
    encodes a issue fungible token output
    """


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_issue_nft_output(token_id: bytes,
creator: bytes, name: bytes, destination: bytes,
ticker: bytes, icon_uri: bytes, additional_metadata_uri: bytes, media_uri:
bytes, media_hash: bytes, destination: bytes) -> bytes:
    """
    encodes a issue NFT output
    """


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_data_deposit_output(deposit: bytes) ->
bytes:
    """
    encodes a data deposit output
    """


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_htlc_output(amount: bytes, token_id: bytes, lock_type:
int, lock_amount:int, refund_key: bytes, spend_key: bytes, secret_has:
bytes) -> bytes:
    """
    encodes an htlc output with given amount and lock
    """


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_anyone_can_take_output(destination: bytes, ask_amount: bytes,
ask_token_id: bytes, give_amount: bytes, give_token_id: bytes) -> bytes:
    """
    encodes an anyone can take output with given the conclude key, give and
    take amounts
    """


# extmod/modtrezormintlayer/modtrezormintlayer.h
def encode_compact_length(length: int) -> bytes:
    """
    encodes a comapct length to bytes
    """
