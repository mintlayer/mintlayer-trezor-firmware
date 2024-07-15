from typing import *


# upymod/extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_utxo_input(tx_hash: bytes, index: int) -> bytes:
    """
    encodes an utxo input from tx_hash and index
    """


# upymod/extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_transfer_output(amount: str, address: str) -> bytes:
    """
    encodes a transfer output with given amount and destination address
    """


# upymod/extmod/modtrezormintlayer/modtrezormintlayer-utils.h
def encode_compact_length(length: int) -> bytes:
    """
    encodes a comapct length to bytes
    """
