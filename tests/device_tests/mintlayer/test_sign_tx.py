# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import itertools
import random
from typing import Optional

import pytest

from trezorlib import messages, mintlayer
from trezorlib.debuglink import TrezorClientDebugLink as Client
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

B = messages.ButtonRequestType


def request_input(n: int) -> messages.MintlayerTxRequest:
    return messages.MintlayerTxRequest(
        input_request=messages.MintlayerTxInputRequest(input_index=n)
    )


def request_output(
    n: int, tx_hash: Optional[bytes] = None
) -> messages.MintlayerTxRequest:
    return messages.MintlayerTxRequest(
        output_request=messages.MintlayerTxOutputRequest(
            output_index=n, tx_hash=tx_hash
        )
    )


def request_finished() -> messages.MintlayerTxRequest:
    return messages.MintlayerTxRequest(
        signing_finished=messages.MintlayerTxSigningResult()
    )


SIGN_TX_VECTORS = [
    (
        1,
        "mmtc1q3plqylyzrj4mdemdfs39v8zy574rnztc5zpse0x",
        "mdelg1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqut3aj8",
        "mmltk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqa3r2pu",
        "mordr1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqacsnmg",
        "mpool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqd2ew4w",
        "mvrfpk1qq7859x9n9zk9d8j3yfefr0l2vjmcsshzdm6ryz765pdmrufxmgsyh6z8a9",
        # sigs ======================
        "0770b640bd217d130e2a654860f6ef0d2c1711871c2bc02f725da6a9c97b84863eac0483bfbb741e53f684d000c6968b628dead5f37c1c0dbb4d926e769bb7ce",
        "0bc5ace472748f2fff8afe60152558fd84f6027081a06a45c0ba621e447b1e7f7481e442849a97a63d077fbc3347badfb03a61cdf5e74120c1e5f69b01e8535a",
    ),
    (
        2,
        "tmtc1qjn5ls4sz90ppcart66jf0vx0n0u8ndjluz8lpsy",
        "tdelg1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnu8zn4",
        "tmltk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqjx44qw",
        "tordr1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj0xv66",
        "tpool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqza035u",
        "tvrfpk1qregu4v895mchautf84u46nsf9xel2507a37ksaf3stmuw44y3m4vffs89t",
        # sigs ======================
        "7ae7291601bd4a6a0069d91f2695b1a37faa4d42485e9cae047f3d080253d1fa827a4c2e38e004a2199adba7b0201a243856a9a3cf1c069ec856964570635ea2",
        "abadf0c5f984c6b1f55a32a05cc7aa37aa5aae6b0b96544bb752c01ad8a29e7d9fe90124776699228f1843b1e033e5f27b081643b0c873e776e1142845aaa56c",
    ),
    (
        3,
        "rmtc1qjn5ls4sz90ppcart66jf0vx0n0u8ndjluu6nzuv",
        "rdelg1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqf9m6ka",
        "rmltk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqglfd9x",
        "rordr1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgk65lj",
        "rpool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcynf35",
        "rvrfpk1qregu4v895mchautf84u46nsf9xel2507a37ksaf3stmuw44y3m4vc2kzme",
        # sigs ======================
        "7ae7291601bd4a6a0069d91f2695b1a37faa4d42485e9cae047f3d080253d1fa827a4c2e38e004a2199adba7b0201a243856a9a3cf1c069ec856964570635ea2",
        "abadf0c5f984c6b1f55a32a05cc7aa37aa5aae6b0b96544bb752c01ad8a29e7d9fe90124776699228f1843b1e033e5f27b081643b0c873e776e1142845aaa56c",
    ),
    (
        4,
        "smtc1qjn5ls4sz90ppcart66jf0vx0n0u8ndjluet3k7h",
        "sdelg1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq4dx7rx",
        "smltk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5h5fsa",
        "sordr1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq578s2f",
        "spool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqyvwdy0",
        "svrfpk1qregu4v895mchautf84u46nsf9xel2507a37ksaf3stmuw44y3m4vt7hh77",
        # sigs ======================
        "7ae7291601bd4a6a0069d91f2695b1a37faa4d42485e9cae047f3d080253d1fa827a4c2e38e004a2199adba7b0201a243856a9a3cf1c069ec856964570635ea2",
        "abadf0c5f984c6b1f55a32a05cc7aa37aa5aae6b0b96544bb752c01ad8a29e7d9fe90124776699228f1843b1e033e5f27b081643b0c873e776e1142845aaa56c",
    ),
]

CHAIN_TYPE_TO_COIN = {1: 19788, 2: 1, 3: 1, 4: 1}


@pytest.mark.altcoin
@pytest.mark.mintlayer
@pytest.mark.setup_client(
    mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)
@pytest.mark.parametrize(
    "chain_type, multisig_addr, delegation_id, token_id, order_id, pool_id, vrf_public_key, sig1, sig2",
    SIGN_TX_VECTORS,
)
def test_mintlayer_sign_tx(
    client: Client,
    chain_type: int,
    multisig_addr: str,
    delegation_id: str,
    token_id: str,
    order_id: str,
    pool_id: str,
    vrf_public_key: str,
    sig1: str,
    sig2: str,
):
    coin = CHAIN_TYPE_TO_COIN[chain_type]
    with client:
        path = parse_path(f"m/44h/{coin}h/0h/0/0")
        address_0 = messages.MintlayerAddressPath(address_n=path)
        wallet_dest0 = mintlayer.get_address(
            client,
            chain_type=chain_type,
            address_n=parse_path(f"m/44h/{coin}h/0h/0/0"),
            show_display=True,
        )
        prev_utxo_index = 1
        prev_utxo_index_token = 2

        path = parse_path(f"m/44h/{coin}h/0h/0/0")
        multisig0 = messages.MintlayerAddressPath(address_n=path, multisig_idx=0)
        path = parse_path(f"m/44h/{coin}h/0h/0/1")
        multisig2 = messages.MintlayerAddressPath(address_n=path, multisig_idx=2)
        prev_multisig_utxo_index = 3

        prev_hash = b"\x00" * 32
        # anyone_can_spend = wallet_dest0
        anyone_can_spend = "mxanyonecanspend1qqx4x7pk"

        token_ticker = "XXXX".encode()
        number_of_decimals = 2
        uri = "http://uri.com".encode()
        amount_10 = (10).to_bytes(16, byteorder="big")
        value_10 = messages.MintlayerOutputValue(amount=amount_10)
        amount_1 = (1).to_bytes(16, byteorder="big")
        value_1 = messages.MintlayerOutputValue(amount=amount_1)
        token_value_1 = messages.MintlayerOutputValue(
            amount=amount_1,
            token=messages.MintlayerTokenOutputValue(
                token_id=token_id,
                token_ticker=token_ticker,
                number_of_decimals=number_of_decimals,
            ),
        )
        amount_0 = (0).to_bytes(16, byteorder="big")
        value_0 = messages.MintlayerOutputValue(amount=amount_0)

        inputs = [
            # UTXO input
            messages.MintlayerTxInput(
                utxo=messages.MintlayerUtxoTxInput(
                    prev_hash=prev_hash,
                    prev_index=prev_utxo_index,
                    addresses=[address_0],
                    type=messages.MintlayerUtxoType.TRANSACTION,
                )
            ),
            # UTXO input wiht tokens
            messages.MintlayerTxInput(
                utxo=messages.MintlayerUtxoTxInput(
                    prev_hash=prev_hash,
                    prev_index=prev_utxo_index_token,
                    addresses=[address_0],
                    type=messages.MintlayerUtxoType.TRANSACTION,
                )
            ),
            # Multisig UTXO
            messages.MintlayerTxInput(
                utxo=messages.MintlayerUtxoTxInput(
                    prev_hash=prev_hash,
                    prev_index=prev_multisig_utxo_index,
                    addresses=[multisig0, multisig2],
                    type=messages.MintlayerUtxoType.TRANSACTION,
                )
            ),
            # Account inpput
            messages.MintlayerTxInput(
                account=messages.MintlayerAccountTxInput(
                    addresses=[address_0],
                    nonce=0,
                    delegation_balance=messages.MintlayerAccountSpendingDelegationBalance(
                        delegation_id=delegation_id,
                        amount=amount_1,
                    ),
                )
            ),
            # Account commands
            messages.MintlayerTxInput(
                account_command=messages.MintlayerAccountCommandTxInput(
                    addresses=[address_0],
                    nonce=0,
                    mint=messages.MintlayerMintTokens(
                        token_id=token_id, amount=amount_1
                    ),
                )
            ),
            messages.MintlayerTxInput(
                account_command=messages.MintlayerAccountCommandTxInput(
                    addresses=[address_0],
                    nonce=0,
                    unmint=messages.MintlayerUnmintTokens(token_id=token_id),
                )
            ),
            messages.MintlayerTxInput(
                account_command=messages.MintlayerAccountCommandTxInput(
                    addresses=[address_0],
                    nonce=0,
                    lock_token_supply=messages.MintlayerLockTokenSupply(
                        token_id=token_id
                    ),
                )
            ),
            messages.MintlayerTxInput(
                account_command=messages.MintlayerAccountCommandTxInput(
                    addresses=[address_0],
                    nonce=0,
                    freeze_token=messages.MintlayerFreezeToken(
                        token_id=token_id, is_token_unfreezable=True
                    ),
                )
            ),
            messages.MintlayerTxInput(
                account_command=messages.MintlayerAccountCommandTxInput(
                    addresses=[address_0],
                    nonce=0,
                    unfreeze_token=messages.MintlayerUnfreezeToken(token_id=token_id),
                )
            ),
            messages.MintlayerTxInput(
                account_command=messages.MintlayerAccountCommandTxInput(
                    addresses=[address_0],
                    nonce=0,
                    change_token_authority=messages.MintlayerChangeTokenAuthority(
                        token_id=token_id, destination=anyone_can_spend
                    ),
                )
            ),
            messages.MintlayerTxInput(
                account_command=messages.MintlayerAccountCommandTxInput(
                    addresses=[address_0],
                    nonce=0,
                    conclude_order=messages.MintlayerConcludeOrder(
                        order_id=order_id,
                        filled_ask_amount=value_0,
                        give_balance=value_1,
                    ),
                )
            ),
            messages.MintlayerTxInput(
                account_command=messages.MintlayerAccountCommandTxInput(
                    addresses=[address_0],
                    nonce=0,
                    fill_order=messages.MintlayerFillOrder(
                        order_id=order_id,
                        amount=amount_1,
                        destination=anyone_can_spend,
                        ask_balance=value_1,
                        give_balance=value_1,
                    ),
                )
            ),
            messages.MintlayerTxInput(
                account_command=messages.MintlayerAccountCommandTxInput(
                    addresses=[address_0],
                    nonce=0,
                    change_token_metadata_uri=messages.MintlayerChangeTokenMetadataUri(
                        token_id=token_id, metadata_uri=uri
                    ),
                )
            ),
        ]

        utxo = messages.MintlayerTransferTxOutput(address=wallet_dest0, value=value_10)
        utxo_out = messages.MintlayerTxOutput(transfer=utxo)
        utxo = messages.MintlayerTransferTxOutput(
            address=wallet_dest0, value=token_value_1
        )
        utxo_out_token = messages.MintlayerTxOutput(transfer=utxo)

        utxo = messages.MintlayerTransferTxOutput(address=multisig_addr, value=value_1)
        multisig_utxo = messages.MintlayerTxOutput(transfer=utxo)
        prev_txs = {
            prev_hash: {
                prev_utxo_index: utxo_out,
                prev_utxo_index_token: utxo_out_token,
                prev_multisig_utxo_index: multisig_utxo,
            }
        }

        value_1 = messages.MintlayerOutputValue(amount=amount_1)
        outputs = [
            messages.MintlayerTxOutput(
                transfer=messages.MintlayerTransferTxOutput(
                    address=anyone_can_spend, value=token_value_1
                )
            ),
            messages.MintlayerTxOutput(
                transfer=messages.MintlayerTransferTxOutput(
                    address=anyone_can_spend, value=value_1
                )
            ),
            messages.MintlayerTxOutput(
                lock_then_transfer=messages.MintlayerLockThenTransferTxOutput(
                    address=anyone_can_spend,
                    value=value_1,
                    lock=messages.MintlayerOutputTimeLock(until_height=10),
                )
            ),
            messages.MintlayerTxOutput(
                lock_then_transfer=messages.MintlayerLockThenTransferTxOutput(
                    address=anyone_can_spend,
                    value=value_1,
                    lock=messages.MintlayerOutputTimeLock(until_time=10),
                )
            ),
            messages.MintlayerTxOutput(
                lock_then_transfer=messages.MintlayerLockThenTransferTxOutput(
                    address=anyone_can_spend,
                    value=value_1,
                    lock=messages.MintlayerOutputTimeLock(for_block_count=10),
                )
            ),
            messages.MintlayerTxOutput(
                lock_then_transfer=messages.MintlayerLockThenTransferTxOutput(
                    address=anyone_can_spend,
                    value=value_1,
                    lock=messages.MintlayerOutputTimeLock(for_seconds=10),
                )
            ),
            messages.MintlayerTxOutput(
                burn=messages.MintlayerBurnTxOutput(
                    value=value_1,
                )
            ),
            messages.MintlayerTxOutput(
                create_stake_pool=messages.MintlayerCreateStakePoolTxOutput(
                    pool_id=pool_id,
                    pledge=amount_1,
                    staker=anyone_can_spend,
                    decommission_key=anyone_can_spend,
                    vrf_public_key=vrf_public_key,
                    margin_ratio_per_thousand=1,
                    cost_per_block=amount_1,
                )
            ),
            messages.MintlayerTxOutput(
                create_delegation_id=messages.MintlayerCreateDelegationIdTxOutput(
                    destination=anyone_can_spend,
                    pool_id=pool_id,
                )
            ),
            messages.MintlayerTxOutput(
                delegate_staking=messages.MintlayerDelegateStakingTxOutput(
                    amount=amount_1,
                    delegation_id=delegation_id,
                )
            ),
            messages.MintlayerTxOutput(
                issue_fungible_token=messages.MintlayerIssueFungibleTokenTxOutput(
                    token_ticker="XXXX".encode(),
                    number_of_decimals=2,
                    metadata_uri=uri,
                    authority=anyone_can_spend,
                    is_freezable=True,
                    total_supply=messages.MintlayerTokenTotalSupply(
                        type=messages.MintlayerTokenTotalSupplyType.UNLIMITED
                    ),
                )
            ),
            messages.MintlayerTxOutput(
                issue_nft=messages.MintlayerIssueNftTxOutput(
                    token_id=token_id,
                    destination=anyone_can_spend,
                    ticker="NFTX".encode(),
                    name="Name".encode(),
                    description="SomeNFT".encode(),
                    media_uri=uri,
                    media_hash="123456".encode(),
                )
            ),
            messages.MintlayerTxOutput(
                data_deposit=messages.MintlayerDataDepositTxOutput(
                    data=bytes([1, 2, 3])
                )
            ),
            messages.MintlayerTxOutput(
                htlc=messages.MintlayerHtlcTxOutput(
                    value=value_1,
                    secret_hash=bytes([1] * 20),
                    spend_key=anyone_can_spend,
                    refund_timelock=messages.MintlayerOutputTimeLock(until_height=10),
                    refund_key=anyone_can_spend,
                )
            ),
            messages.MintlayerTxOutput(
                create_order=messages.MintlayerCreateOrderTxOutput(
                    conclude_key=anyone_can_spend,
                    ask=value_1,
                    give=value_1,
                )
            ),
        ]

        client.set_expected_responses(
            [
                # ===== inputs
                # get First UTXO input
                request_input(0),
                # get First input's UTXO
                request_output(prev_utxo_index),
                # get Second token UTXO input
                request_input(1),
                # get Second token input's UTXO
                request_output(prev_utxo_index_token),
                # get Second UTXO input with multisig address
                request_input(2),
                # get Second input's UTXO
                request_output(prev_multisig_utxo_index),
                # account input
                request_input(3),
                # account command inputs
                request_input(4),
                request_input(5),
                request_input(6),
                request_input(7),
                request_input(8),
                request_input(9),
                request_input(10),
                request_input(11),
                request_input(12),
                # ===== outputs
                # get First Output
                request_output(0),
                messages.ButtonRequest(code=B.ConfirmOutput),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(1),
                messages.ButtonRequest(code=B.ConfirmOutput),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(2),
                messages.ButtonRequest(code=B.ConfirmOutput),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(3),
                messages.ButtonRequest(code=B.ConfirmOutput),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(4),
                messages.ButtonRequest(code=B.ConfirmOutput),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(5),
                messages.ButtonRequest(code=B.ConfirmOutput),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(6),
                messages.ButtonRequest(code=B.ConfirmOutput),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(7),
                messages.ButtonRequest(code=B.ConfirmOutput),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(8),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(9),
                messages.ButtonRequest(code=B.ConfirmOutput),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(10),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(11),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(12),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(13),
                messages.ButtonRequest(code=B.ConfirmOutput),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(14),
                messages.ButtonRequest(code=B.ConfirmOutput),
                # sign tx
                messages.ButtonRequest(code=B.SignTx),
                # sign tx for the tokens total
                messages.ButtonRequest(code=B.SignTx),
                request_finished(),
            ]
        )

        results = mintlayer.sign_tx(client, chain_type, inputs, outputs, prev_txs)

        expected_multi_sigs = {
            0: sig1,
            2: sig2,
        }
        expected_sig = sig1

        assert len(results) == len(inputs)

        for res in results:
            for sig in res.signatures:
                if sig.multisig_idx is not None:
                    assert sig.signature.hex() == expected_multi_sigs[sig.multisig_idx]
                else:
                    assert sig.signature.hex() == expected_sig


@pytest.mark.altcoin
@pytest.mark.mintlayer
@pytest.mark.setup_client(
    mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)
def test_mintlayer_random_sign_tx(client: Client):
    with client:
        num_inputs = random.randint(1, 10)

        prev_txs = {}
        inputs = []
        input_utxos = []
        total_inputs = 0
        for _ in range(num_inputs):
            random_address = random.randint(0, 100)
            random_account = random.randint(0, 100)
            random_purpose = random.choice([0, 1])
            path = parse_path(
                f"m/44h/19788h/{random_account}h/{random_purpose}/{random_address}"
            )

            prev_hash = bytes(random.getrandbits(8) for _ in range(32))

            random_amount = random.randint(1, 10_000)
            total_inputs += random_amount
            address = messages.MintlayerAddressPath(address_n=path)

            prev_utxo_index = random.randint(0, 100)
            inp = messages.MintlayerTxInput(
                utxo=messages.MintlayerUtxoTxInput(
                    prev_hash=prev_hash,
                    prev_index=prev_utxo_index,
                    addresses=[address],
                    type=random.choice(list(messages.MintlayerUtxoType)),
                )
            )

            value = messages.MintlayerOutputValue(
                amount=random_amount.to_bytes(16, byteorder="big")
            )
            utxo = messages.MintlayerTransferTxOutput(
                address="mxanyonecanspend1qqx4x7pk", value=value
            )
            utxo_out = messages.MintlayerTxOutput(transfer=utxo)

            if prev_hash in prev_txs:
                prev_txs[prev_hash][prev_utxo_index] = utxo_out
            else:
                prev_txs[prev_hash] = {prev_utxo_index: utxo_out}
            inputs.append(inp)
            input_utxos.append((prev_hash, prev_utxo_index))

        num_outputs = random.randint(1, 10)
        outputs = []
        for _ in range(num_outputs):
            random_amount = random.randint(0, total_inputs // num_outputs)
            value = messages.MintlayerOutputValue(
                amount=random_amount.to_bytes(16, byteorder="big")
            )
            output = messages.MintlayerTransferTxOutput(
                address="mxanyonecanspend1qqx4x7pk", value=value
            )
            out = messages.MintlayerTxOutput(transfer=output)
            outputs.append(out)

        client.set_expected_responses(
            list(
                itertools.chain.from_iterable(
                    [
                        [
                            # get First input
                            request_input(input_idx),
                            # get First input's UTXO
                            request_output(prev_utxo_index, prev_hash),
                        ]
                        for (
                            input_idx,
                            (prev_hash, prev_utxo_index),
                        ) in enumerate(input_utxos)
                    ]
                    + [
                        [
                            # get First Output
                            request_output(output_idx),
                            # confirm Output
                            messages.ButtonRequest(code=B.ConfirmOutput),
                            # confirm output
                            messages.ButtonRequest(code=B.ConfirmOutput),
                        ]
                        for output_idx in range(num_outputs)
                    ]
                    + [
                        [
                            # sign tx
                            messages.ButtonRequest(code=B.SignTx),
                            request_finished(),
                        ]
                    ]
                )
            )
        )

        result = mintlayer.sign_tx(client, 3, inputs, outputs, prev_txs)

        assert len(result) == num_inputs


CHAIN_TYPES = [1, 2, 3, 4]


@pytest.mark.altcoin
@pytest.mark.mintlayer
@pytest.mark.setup_client(
    mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)
@pytest.mark.parametrize("chain_type", CHAIN_TYPES)
def test_mintlayer_sign_tx_forbidden_path(client: Client, chain_type: int):
    coin = CHAIN_TYPE_TO_COIN[chain_type]

    prev_hash = bytes(random.getrandbits(8) for _ in range(32))
    random_amount = random.randint(1, 10_000)
    prev_utxo_index = random.randint(0, 100)

    value = messages.MintlayerOutputValue(
        amount=random_amount.to_bytes(16, byteorder="big")
    )

    wallet_dest0 = mintlayer.get_address(
        client,
        chain_type=chain_type,
        address_n=parse_path(f"m/44h/{coin}h/0h/0/0"),
        show_display=True,
    )

    utxo = messages.MintlayerTransferTxOutput(address=wallet_dest0, value=value)
    utxo_out = messages.MintlayerTxOutput(transfer=utxo)

    prev_txs = {prev_hash: {prev_utxo_index: utxo_out}}

    with client:
        # invalid coin
        with pytest.raises(TrezorFailure, match="Forbidden key path"):
            path = parse_path(f"m/44h/{coin + 1}h/0h/0/0")
            address = messages.MintlayerAddressPath(address_n=path)

            inp = messages.MintlayerTxInput(
                utxo=messages.MintlayerUtxoTxInput(
                    prev_hash=prev_hash,
                    prev_index=prev_utxo_index,
                    addresses=[address],
                    type=random.choice(list(messages.MintlayerUtxoType)),
                )
            )
            mintlayer.sign_tx(client, chain_type, [inp], [], prev_txs)

        # invalid bip44
        with pytest.raises(TrezorFailure, match="Forbidden key path"):
            path = parse_path(f"m/43h/{coin}h/0h/0/0")
            address = messages.MintlayerAddressPath(address_n=path)

            inp = messages.MintlayerTxInput(
                utxo=messages.MintlayerUtxoTxInput(
                    prev_hash=prev_hash,
                    prev_index=prev_utxo_index,
                    addresses=[address],
                    type=random.choice(list(messages.MintlayerUtxoType)),
                )
            )
            mintlayer.sign_tx(client, chain_type, [inp], [], prev_txs)

        # short path
        with pytest.raises(TrezorFailure, match="Forbidden key path"):
            path = parse_path(f"m/44h/{coin}h")
            address = messages.MintlayerAddressPath(address_n=path)

            inp = messages.MintlayerTxInput(
                utxo=messages.MintlayerUtxoTxInput(
                    prev_hash=prev_hash,
                    prev_index=prev_utxo_index,
                    addresses=[address],
                    type=random.choice(list(messages.MintlayerUtxoType)),
                )
            )
            mintlayer.sign_tx(client, chain_type, [inp], [], prev_txs)

        # short path
        with pytest.raises(TrezorFailure, match="Forbidden key path"):
            path = parse_path("m/44h")
            address = messages.MintlayerAddressPath(address_n=path)

            inp = messages.MintlayerTxInput(
                utxo=messages.MintlayerUtxoTxInput(
                    prev_hash=prev_hash,
                    prev_index=prev_utxo_index,
                    addresses=[address],
                    type=random.choice(list(messages.MintlayerUtxoType)),
                )
            )
            mintlayer.sign_tx(client, chain_type, [inp], [], prev_txs)
