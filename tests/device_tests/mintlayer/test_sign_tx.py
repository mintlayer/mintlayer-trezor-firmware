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
from trezorlib.tools import parse_path

B = messages.ButtonRequestType


def request_input(
    n: int, tx_hash: Optional[bytes] = None
) -> messages.MintlayerTxRequest:
    return messages.MintlayerTxRequest(
        request_type=messages.MintlayerRequestType.TXINPUT,
        details=messages.MintlayerTxRequestDetailsType(
            request_index=n, tx_hash=tx_hash
        ),
    )


def request_output(
    n: int, tx_hash: Optional[bytes] = None
) -> messages.MintlayerTxRequest:
    return messages.MintlayerTxRequest(
        request_type=messages.MintlayerRequestType.TXOUTPUT,
        details=messages.MintlayerTxRequestDetailsType(
            request_index=n, tx_hash=tx_hash
        ),
    )


def request_finished() -> messages.MintlayerTxRequest:
    return messages.MintlayerTxRequest(
        request_type=messages.MintlayerRequestType.TXFINISHED
    )


@pytest.mark.altcoin
@pytest.mark.mintlayer
@pytest.mark.setup_client(
    mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)
def test_mintlayer_sign_tx(client: Client):
    with client:
        path = parse_path("m/44h/1h/0h/0/0")
        address_0 = messages.MintlayerAddressPath(address_n=path)
        wallet_dest0 = "rmt1qx5p4r2en7c99mpmg2tz9hucxfarf4k6dypq388a"
        prev_utxo_index = 1

        path = parse_path("m/44h/1h/0h/0/0")
        multisig0 = messages.MintlayerAddressPath(address_n=path, multisig_idx=0)
        path = parse_path("m/44h/1h/0h/0/1")
        multisig2 = messages.MintlayerAddressPath(address_n=path, multisig_idx=2)
        prev_multisig_utxo_index = 2

        multisig_addr = "rmtc1qjg6f4gxhhtgf5hvavu45ezwaxmtnvawdywlp4t7"

        prev_hash = b"\x00" * 32
        anyone_can_spend = "mxanyonecanspend1qqx4x7pk"
        delegation_id = (
            "rdelg1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqf9m6ka"
        )
        token_id = "rmltk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqglfd9x"
        order_id = "rordr1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgk65lj"
        pool_id = "rpool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcynf35"
        vrf_public_key = (
            "rvrfpk1qqrrkekv3dm65f8kjng88ttjcgdf72ttur75a62nmrjc6htz04p4kt7hrp9"
        )
        uri = "http://uri.com".encode()
        amount_1 = (1).to_bytes(16, byteorder="big")
        value = messages.MintlayerOutputValue(amount=amount_1)

        inputs = [
            # UTXO input
            messages.MintlayerTxInput(
                utxo=messages.MintlayerUtxoTxInput(
                    prev_hash=prev_hash,
                    prev_index=prev_utxo_index,
                    addresses=[address_0],
                    address=wallet_dest0,
                    type=messages.MintlayerUtxoType.TRANSACTION,
                )
            ),
            # Multisig UTXO
            messages.MintlayerTxInput(
                utxo=messages.MintlayerUtxoTxInput(
                    prev_hash=prev_hash,
                    prev_index=prev_multisig_utxo_index,
                    addresses=[multisig0, multisig2],
                    address=multisig_addr,
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
                    address=wallet_dest0,
                    nonce=0,
                    mint=messages.MintlayerMintTokens(
                        token_id=token_id, amount=amount_1
                    ),
                )
            ),
            messages.MintlayerTxInput(
                account_command=messages.MintlayerAccountCommandTxInput(
                    addresses=[address_0],
                    address=wallet_dest0,
                    nonce=0,
                    unmint=messages.MintlayerUnmintTokens(token_id=token_id),
                )
            ),
            messages.MintlayerTxInput(
                account_command=messages.MintlayerAccountCommandTxInput(
                    addresses=[address_0],
                    address=wallet_dest0,
                    nonce=0,
                    lock_token_supply=messages.MintlayerLockTokenSupply(
                        token_id=token_id
                    ),
                )
            ),
            messages.MintlayerTxInput(
                account_command=messages.MintlayerAccountCommandTxInput(
                    addresses=[address_0],
                    address=wallet_dest0,
                    nonce=0,
                    freeze_token=messages.MintlayerFreezeToken(
                        token_id=token_id, is_token_unfreezable=True
                    ),
                )
            ),
            messages.MintlayerTxInput(
                account_command=messages.MintlayerAccountCommandTxInput(
                    addresses=[address_0],
                    address=wallet_dest0,
                    nonce=0,
                    unfreeze_token=messages.MintlayerUnfreezeToken(token_id=token_id),
                )
            ),
            messages.MintlayerTxInput(
                account_command=messages.MintlayerAccountCommandTxInput(
                    addresses=[address_0],
                    address=wallet_dest0,
                    nonce=0,
                    change_token_authority=messages.MintlayerChangeTokenAuthority(
                        token_id=token_id, destination=anyone_can_spend
                    ),
                )
            ),
            messages.MintlayerTxInput(
                account_command=messages.MintlayerAccountCommandTxInput(
                    addresses=[address_0],
                    address=wallet_dest0,
                    nonce=0,
                    conclude_order=messages.MintlayerConcludeOrder(order_id=order_id),
                )
            ),
            messages.MintlayerTxInput(
                account_command=messages.MintlayerAccountCommandTxInput(
                    addresses=[address_0],
                    address=wallet_dest0,
                    nonce=0,
                    fill_order=messages.MintlayerFillOrder(
                        order_id=order_id, amount=amount_1, destination=anyone_can_spend
                    ),
                )
            ),
            messages.MintlayerTxInput(
                account_command=messages.MintlayerAccountCommandTxInput(
                    addresses=[address_0],
                    address=wallet_dest0,
                    nonce=0,
                    change_token_metadata_uri=messages.MintlayerChangeTokenMetadataUri(
                        token_id=token_id, metadata_uri=uri
                    ),
                )
            ),
        ]

        utxo = messages.MintlayerTransferTxOutput(address=wallet_dest0, value=value)
        utxo_out = messages.MintlayerTxOutput(transfer=utxo)

        utxo = messages.MintlayerTransferTxOutput(address=multisig_addr, value=value)
        multisig_utxo = messages.MintlayerTxOutput(transfer=utxo)
        prev_txs = {
            prev_hash: {
                prev_utxo_index: utxo_out,
                prev_multisig_utxo_index: multisig_utxo,
            }
        }

        value = messages.MintlayerOutputValue(amount=amount_1)
        outputs = [
            messages.MintlayerTxOutput(
                transfer=messages.MintlayerTransferTxOutput(
                    address=anyone_can_spend, value=value
                )
            ),
            messages.MintlayerTxOutput(
                lock_then_transfer=messages.MintlayerLockThenTransferTxOutput(
                    address=anyone_can_spend,
                    value=value,
                    lock=messages.MintlayerOutputTimeLock(until_height=10),
                )
            ),
            messages.MintlayerTxOutput(
                lock_then_transfer=messages.MintlayerLockThenTransferTxOutput(
                    address=anyone_can_spend,
                    value=value,
                    lock=messages.MintlayerOutputTimeLock(until_time=10),
                )
            ),
            messages.MintlayerTxOutput(
                lock_then_transfer=messages.MintlayerLockThenTransferTxOutput(
                    address=anyone_can_spend,
                    value=value,
                    lock=messages.MintlayerOutputTimeLock(for_block_count=10),
                )
            ),
            messages.MintlayerTxOutput(
                lock_then_transfer=messages.MintlayerLockThenTransferTxOutput(
                    address=anyone_can_spend,
                    value=value,
                    lock=messages.MintlayerOutputTimeLock(for_seconds=10),
                )
            ),
            messages.MintlayerTxOutput(
                burn=messages.MintlayerBurnTxOutput(
                    value=value,
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
                    value=value,
                    secret_hash=bytes([1] * 20),
                    spend_key=anyone_can_spend,
                    refund_timelock=messages.MintlayerOutputTimeLock(until_height=10),
                    refund_key=anyone_can_spend,
                )
            ),
            messages.MintlayerTxOutput(
                create_order=messages.MintlayerCreateOrderTxOutput(
                    conclude_key=anyone_can_spend,
                    ask=value,
                    give=value,
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
                # get Second UTXO input with multisig address
                request_input(1),
                # get Second input's UTXO
                request_output(prev_multisig_utxo_index),
                # account input
                request_input(2),
                # account command inputs
                request_input(3),
                request_input(4),
                request_input(5),
                request_input(6),
                request_input(7),
                request_input(8),
                request_input(9),
                request_input(10),
                request_input(11),
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
                request_output(8),
                messages.ButtonRequest(code=B.ConfirmOutput),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(9),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(10),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(11),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(12),
                messages.ButtonRequest(code=B.ConfirmOutput),
                messages.ButtonRequest(code=B.ConfirmOutput),
                request_output(13),
                messages.ButtonRequest(code=B.ConfirmOutput),
                # sign tx
                messages.ButtonRequest(code=B.SignTx),
                # sign tx for the tokens total
                messages.ButtonRequest(code=B.SignTx),
                request_finished(),
            ]
        )

        results = mintlayer.sign_tx(client, "Regtest", inputs, outputs, prev_txs)

        expected_multi_sigs = {
            0: "7a99714dc6cc917faa2afded8028159a5048caf6f8382f67e6b61623fbe62c60423f8f7983f88f40c6f42924594f3de492a232e9e703b241c3b17b130f8daa59",
            2: "0a0a17d71bc98fa5c24ea611c856d0d08c6a765ea3c4c8f068668e0bdff710b82b0d2eead83d059386cd3cbdf4308418d4b81e6f52c001a9141ec477a8d24845",
        }
        expected_sig = "7a99714dc6cc917faa2afded8028159a5048caf6f8382f67e6b61623fbe62c60423f8f7983f88f40c6f42924594f3de492a232e9e703b241c3b17b130f8daa59"

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
        for _ in range(num_inputs):
            random_address = random.randint(0, 100)
            random_account = random.randint(0, 100)
            path = parse_path(f"m/44h/19788h/{random_account}h/0/{random_address}")

            prev_hash = bytes(random.getrandbits(8) for _ in range(32))

            random_amount = random.randint(0, 10_000)
            address = messages.MintlayerAddressPath(address_n=path)

            prev_utxo_index = random.randint(0, 100)
            inp = messages.MintlayerTxInput(
                utxo=messages.MintlayerUtxoTxInput(
                    prev_hash=prev_hash,
                    prev_index=prev_utxo_index,
                    addresses=[address],
                    address="mxanyonecanspend1qqx4x7pk",
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
            random_amount = random.randint(0, 10_000)
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

        result = mintlayer.sign_tx(client, "Regtest", inputs, outputs, prev_txs)

        assert len(result) == num_inputs
