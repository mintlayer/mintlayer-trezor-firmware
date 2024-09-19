from micropython import const
from typing import TYPE_CHECKING

from trezor import log, workflow
from trezor.crypto import mintlayer_utils
from trezor.crypto.bech32 import mintlayer_decode_address_to_bytes
from trezor.crypto.curve import bip340
from trezor.crypto.hashlib import blake2b
from trezor.messages import (
    MintlayerSignature,
    MintlayerSignTx,
    MintlayerTxInput,
    MintlayerTxOutput,
    MintlayerTxRequestSerializedType,
)
from trezor.utils import empty_bytearray

from apps.common.coininfo import by_name

from . import helpers
from .progress import progress

if TYPE_CHECKING:
    from typing import Dict, List, Tuple

    from trezor.crypto import bip32
    from trezor.messages import MintlayerOutputValue

    from apps.common.keychain import Keychain


ML_COIN = "ML"
# the number of bytes to preallocate for serialized transaction chunks
_MAX_SERIALIZED_CHUNK_SIZE = const(2048)
_SERIALIZED_TX_BUFFER = empty_bytearray(_MAX_SERIALIZED_CHUNK_SIZE)


class TxUtxoInput:
    def __init__(
        self,
        input: MintlayerTxInput,
        utxo: MintlayerTxOutput | None,
        node: List[Tuple[bip32.HDNode, int | None]],
    ):
        self.input = input
        self.utxo = utxo
        self.node = node


class TxInfo:
    def __init__(
        self,
        tx: MintlayerSignTx,
        inputs: List[TxUtxoInput],
        outputs: List[MintlayerTxOutput],
    ):
        self.tx = tx
        self.inputs = inputs
        self.outputs = outputs

    def add_input(
        self,
        txi: MintlayerTxInput,
        txo: MintlayerTxOutput | None,
        node: List[Tuple[bip32.HDNode, int | None]],
    ):
        self.inputs.append(TxUtxoInput(input=txi, utxo=txo, node=node))

    def add_output(self, txo: MintlayerTxOutput):
        self.outputs.append(txo)


class Mintlayer:
    def init_signing(self) -> None:
        # Next shown progress bar is already signing progress, but it isn't shown until approval from next dialog
        progress.init_signing(
            self.serialize,
            self.tx_info.tx,
        )
        self.signing = True

    async def signer(self) -> None:
        progress.init(self.tx_info.tx)

        # Add inputs to sig_hasher and h_tx_check and compute the sum of input amounts.
        input_totals = await self.step1_process_inputs()

        # Add outputs to sig_hasher and h_tx_check, approve outputs and compute
        # sum of output amounts.
        output_totals = await self.step2_approve_outputs()

        fee = input_totals[ML_COIN] - output_totals[ML_COIN]
        fee_rate = 0
        coin = by_name("Bitcoin")
        await helpers.confirm_total(
            output_totals[ML_COIN],
            fee,
            fee_rate,
            coin,
        )

        # Make sure proper progress is shown, in case dialog was not required
        if not self.signing:
            self.init_signing()
            progress.report_init()
        progress.report()

        # Following steps can take a long time, make sure autolock doesn't kick in.
        # This is set to True again after workflow is finished in start_default().
        workflow.autolock_interrupts_workflow = False

        # Verify the transaction input amounts by requesting each previous transaction
        # and checking its output amount. Verify external inputs which have already
        # been signed or which come with a proof of non-ownership.
        await self.step3_verify_inputs()

        # Check that inputs are unchanged. Serialize inputs and sign the non-segwit ones.
        encoded_inputs, encoded_input_utxos = await self.step4_serialize_inputs()
        if __debug__:
            log.debug(__name__, "encoded inputs: %s", str(encoded_inputs))
            log.debug(__name__, "encoded utxos: %s", str(encoded_input_utxos))

        # Serialize outputs.
        encoded_outputs = await self.step5_serialize_outputs()
        if __debug__:
            log.debug(__name__, "encoded outputs: %s", str(encoded_outputs))

        # Sign segwit inputs and serialize witness data.
        signatures = await self.step6_sign_inputs(
            encoded_inputs, encoded_input_utxos, encoded_outputs
        )

        # Write footer and send remaining data.
        await self.step7_finish(signatures)

    def __init__(
        self,
        tx: MintlayerSignTx,
        keychain: Keychain,
        # approver: approvers.Approver | None,
    ) -> None:
        from trezor.messages import MintlayerTxRequest, MintlayerTxRequestDetailsType

        global _SERIALIZED_TX_BUFFER

        self.tx_info = TxInfo(tx=tx, inputs=[], outputs=[])
        self.keychain = keychain

        # self.approver = approvers.BasicApprover(tx, coin)

        # set of indices of inputs which are external
        self.external: set[int] = set()

        # set of indices of inputs which are presigned
        self.presigned: set[int] = set()

        # indicates whether the transaction is being signed
        self.signing = False

        # transaction and signature serialization
        _SERIALIZED_TX_BUFFER[:] = bytes()
        self.serialized_tx = _SERIALIZED_TX_BUFFER
        self.serialize = tx.serialize
        self.tx_req = MintlayerTxRequest()
        self.tx_req.details = MintlayerTxRequestDetailsType()
        self.tx_req.serialized = []

        # The digest of the presigned external inputs streamed for approval in Step 1. This is
        # used to ensure that the inputs streamed for verification in Step 3 are the same as
        # those in Step 1.
        self.h_presigned_inputs: bytes | None = None

        # The index of the payment request being processed.
        self.payment_req_index: int | None = None

        self.inputs: List[TxUtxoInput] = []
        self.outputs = []

    async def step1_process_inputs(self) -> Dict[str, int]:
        tx_info = self.tx_info  # local_cache_attribute
        # h_presigned_inputs_check = HashWriter(sha256())
        totals = {}

        for i in range(tx_info.tx.inputs_count):
            # STAGE_REQUEST_1_INPUT in legacy
            progress.advance()
            # get the input
            txi = await helpers.request_tx_input(self.tx_req, i)
            if txi.utxo:
                # get the utxo
                txo = await helpers.request_tx_output(
                    self.tx_req, txi.utxo.prev_index, txi.utxo.prev_hash
                )
                node = []
                for address in txi.utxo.address_n:
                    node.append(
                        (self.keychain.derive(address.address_n), address.multisig_idx)
                    )

                update_totals(totals, txo)
                self.tx_info.add_input(txi, txo, node)
            elif txi.account:
                node = []
                for address in txi.account.address_n:
                    node.append(
                        (self.keychain.derive(address.address_n), address.multisig_idx)
                    )
                value = txi.account.value
                amount = int.from_bytes(value.amount, "big")
                token_or_coin = (
                    str(value.token.token_ticker.decode("utf-8"))
                    if value.token
                    else ML_COIN
                )
                if token_or_coin in totals:
                    totals[token_or_coin] += amount
                else:
                    totals[token_or_coin] = amount
                self.tx_info.add_input(txi, None, node)
            elif txi.account_command:
                node = []
                for address in txi.account_command.address_n:
                    node.append(
                        (self.keychain.derive(address.address_n), address.multisig_idx)
                    )
                self.tx_info.add_input(txi, None, node)
            else:
                raise Exception("Unhandled tx input type")

        return totals

    async def step2_approve_outputs(self) -> Dict[str, int]:
        totals = {}

        for i in range(self.tx_info.tx.outputs_count):
            # STAGE_REQUEST_2_OUTPUT in legacy
            progress.advance()
            txo = await helpers.request_tx_output(self.tx_req, i)
            coin = by_name("Bitcoin")
            await helpers.confirm_output(txo, coin, i, False)
            update_totals(totals, txo)
            self.tx_info.add_output(txo)
        return totals

    async def step3_verify_inputs(self) -> None:
        return

    async def step4_serialize_inputs(self) -> Tuple[List[bytes], List[bytes]]:
        encoded_inputs = []
        encoded_input_utxos = []
        for inp in self.tx_info.inputs:
            progress.advance()
            if inp.input.utxo and inp.utxo:
                u = inp.input.utxo
                encoded_inp = mintlayer_utils.encode_utxo_input(
                    u.prev_hash, u.prev_index, int(u.type)
                )
                encoded_inputs.append(encoded_inp)
                data = mintlayer_decode_address_to_bytes(u.address)

                encoded_inp_utxo = self.serialize_output(inp.utxo)
                encoded_input_utxos.append(b"\x01" + encoded_inp_utxo)
            elif inp.input.account:
                a = inp.input.account
                encoded_inp = mintlayer_utils.encode_account_spending_input(
                    a.nonce, a.delegation_id, a.value.amount
                )
                encoded_inputs.append(encoded_inp)
                encoded_input_utxos.append(b"\x00")
            elif inp.input.account_command:
                x = inp.input.account_command
                if x.mint:
                    command = 0
                    token_id = x.mint.token_id
                    data = x.mint.amount
                elif x.unmint:
                    command = 1
                    token_id = x.unmint.token_id
                    data = b""
                elif x.lock_token_supply:
                    command = 2
                    token_id = x.lock_token_supply.token_id
                    data = b""
                elif x.freeze_token:
                    command = 3
                    token_id = x.freeze_token.token_id
                    data = int(x.freeze_token.is_token_unfreezabe).to_bytes(1, "big")
                elif x.unfreeze_token:
                    command = 4
                    token_id = x.unfreeze_token.token_id
                    data = b""
                elif x.change_token_authority:
                    command = 5
                    token_id = x.change_token_authority.token_id
                    data = mintlayer_decode_address_to_bytes(
                        x.change_token_authority.destination
                    )
                elif x.change_token_metadata_uri:
                    command = 8
                    token_id = x.change_token_metadata_uri.token_id
                    data = x.change_token_metadata_uri.metadata_uri
                elif x.conclude_order:
                    ord = x.conclude_order
                    encoded_inp = (
                        mintlayer_utils.encode_conclude_order_account_command_input(
                            x.nonce, ord.order_id
                        )
                    )
                    encoded_inputs.append(encoded_inp)
                    encoded_input_utxos.append(b"\x00")
                    continue
                elif x.fill_order:
                    ord = x.fill_order
                    token_id = b"" if not ord.token_id else ord.token_id
                    destination = mintlayer_decode_address_to_bytes(ord.destination)
                    encoded_inp = (
                        mintlayer_utils.encode_fill_order_account_command_input(
                            x.nonce,
                            ord.order_id,
                            ord.amount,
                            token_id,
                            destination,
                        )
                    )
                    encoded_inputs.append(encoded_inp)
                    encoded_input_utxos.append(b"\x00")
                    continue
                else:
                    raise Exception("unknown account command")

                encoded_inp = mintlayer_utils.encode_token_account_command_input(
                    x.nonce, command, token_id, data
                )
                encoded_inputs.append(encoded_inp)
                encoded_input_utxos.append(b"\x00")

        return encoded_inputs, encoded_input_utxos

    def serialize_output(self, out: MintlayerTxOutput) -> bytes:
        if out.transfer:
            x = out.transfer
            data = mintlayer_decode_address_to_bytes(x.address)
            token_id = b"" if not x.value.token else x.value.token.token_id
            encoded_out = mintlayer_utils.encode_transfer_output(
                x.value.amount, token_id, data
            )
        elif out.lock_then_transfer:
            x = out.lock_then_transfer
            data = mintlayer_decode_address_to_bytes(x.address)
            lock_type, lock_amount = helpers.get_lock(x.lock)
            token_id = b"" if not x.value.token else x.value.token.token_id
            encoded_out = mintlayer_utils.encode_lock_then_transfer_output(
                x.value.amount, token_id, lock_type, lock_amount, data
            )
        elif out.burn:
            x = out.burn
            token_id = b"" if not x.value.token else x.value.token.token_id
            encoded_out = mintlayer_utils.encode_burn_output(x.value.amount, token_id)
        elif out.create_stake_pool:
            x = out.create_stake_pool
            staker = mintlayer_decode_address_to_bytes(x.staker)
            vrf_public_key = mintlayer_decode_address_to_bytes(x.vrf_public_key)
            decommission_key = mintlayer_decode_address_to_bytes(x.decommission_key)
            encoded_out = mintlayer_utils.encode_create_stake_pool_output(
                x.pool_id,
                x.pledge,
                staker,
                vrf_public_key,
                decommission_key,
                x.margin_ratio_per_thousand,
                x.cost_per_block,
            )
        elif out.create_delegation_id:
            x = out.create_delegation_id
            destination = mintlayer_decode_address_to_bytes(x.destination)
            encoded_out = mintlayer_utils.encode_create_delegation_id_output(
                destination, x.pool_id
            )
        elif out.delegate_staking:
            x = out.delegate_staking
            encoded_out = mintlayer_utils.encode_delegate_staking_output(
                x.amount, x.delegation_id
            )
        elif out.produce_block_from_stake:
            x = out.produce_block_from_stake
            destination = mintlayer_decode_address_to_bytes(x.destination)
            encoded_out = mintlayer_utils.encode_produce_from_stake_output(
                destination, x.pool_id
            )
        elif out.issue_fungible_token:
            x = out.issue_fungible_token
            authority = mintlayer_decode_address_to_bytes(x.authority)
            encoded_out = mintlayer_utils.encode_issue_fungible_token_output(
                x.token_ticker,
                x.number_of_decimals,
                x.metadata_uri,
                int(x.total_supply.type),
                x.total_supply.fixed_amount or b"",
                authority,
                int(x.is_freezable),
            )
        elif out.issue_nft:
            x = out.issue_nft
            creator = mintlayer_decode_address_to_bytes(x.creator)
            destination = mintlayer_decode_address_to_bytes(x.destination)
            encoded_out = mintlayer_utils.encode_issue_nft_output(
                x.token_id,
                creator,
                x.name,
                x.description,
                x.ticker,
                x.icon_uri,
                x.additional_metadata_uri,
                x.media_uri,
                x.media_hash,
                destination,
            )
        elif out.data_deposit:
            x = out.data_deposit
            encoded_out = mintlayer_utils.encode_data_deposit_output(x.data)
        elif out.htlc:
            x = out.htlc
            token_id = b"" if not x.value.token else x.value.token.token_id
            spend_key = mintlayer_decode_address_to_bytes(x.spend_key)
            refund_key = mintlayer_decode_address_to_bytes(x.refund_key)
            lock_type, lock_amount = helpers.get_lock(x.refund_timelock)
            encoded_out = mintlayer_utils.encode_htlc_output(
                x.value.amount,
                token_id,
                lock_type,
                lock_amount,
                refund_key,
                spend_key,
                x.secret_hash,
            )
        elif out.anyone_can_take:
            x = out.anyone_can_take
            conclude_key = mintlayer_decode_address_to_bytes(x.conclude_key)
            ask_token_id = b"" if not x.ask.token else x.ask.token.token_id
            give_token_id = b"" if not x.give.token else x.give.token.token_id
            encoded_out = mintlayer_utils.encode_anyone_can_take_output(
                conclude_key, x.ask.amount, ask_token_id, x.give.amount, give_token_id
            )
        else:
            raise Exception("unhandled tx output type")
        return encoded_out

    async def step5_serialize_outputs(self) -> List[bytes]:
        encoded_outputs = []
        for out in self.tx_info.outputs:
            progress.advance()
            encoded_out = self.serialize_output(out)
            encoded_outputs.append(encoded_out)

        return encoded_outputs

    async def step6_sign_inputs(
        self,
        encoded_inputs: List[bytes],
        encoded_input_utxos: List[bytes],
        encoded_outputs: List[bytes],
    ) -> List[List[Tuple[bytes, int | None]]]:
        from trezor.utils import HashWriter

        signatures = []
        for i in range(self.tx_info.tx.inputs_count):
            sigs = []
            for node, multisig_idx in self.tx_info.inputs[i].node:
                writer = HashWriter(blake2b())
                # mode
                writer.extend(b"\x01")

                # version
                writer.extend(b"\x01")
                # flags
                writer.extend(bytes([0] * 16))

                writer.extend(len(encoded_inputs).to_bytes(4, "little"))
                for inp in encoded_inputs:
                    writer.extend(inp)

                writer.extend(len(encoded_input_utxos).to_bytes(4, "little"))
                for utxo in encoded_input_utxos:
                    writer.extend(utxo)

                encoded_len = mintlayer_utils.encode_compact_length(
                    len(encoded_outputs)
                )
                writer.extend(encoded_len)
                for out in encoded_outputs:
                    writer.extend(out)

                hash = writer.get_digest()[:32]
                private_key = node.private_key()
                digest = blake2b(hash).digest()[:32]

                sig = bip340.sign(private_key, digest)
                sigs.append((sig, multisig_idx))
            signatures.append(sigs)

        return signatures

    async def step7_finish(
        self, signatures: List[List[Tuple[bytes, int | None]]]
    ) -> None:
        sigs = [
            MintlayerTxRequestSerializedType(
                signature_index=i,
                signatures=[
                    MintlayerSignature(signature=s[0], multisig_idx=s[1]) for s in sigs
                ],
            )
            for i, sigs in enumerate(signatures)
        ]
        self.tx_req.serialized = sigs
        await helpers.request_tx_finish(self.tx_req)


def update_totals(totals: Dict[str, int], txo: MintlayerTxOutput):
    def update(value: MintlayerOutputValue):
        amount = int.from_bytes(value.amount, "big")
        token_or_coin = (
            str(value.token.token_ticker.decode("utf-8")) if value.token else ML_COIN
        )
        if token_or_coin in totals:
            totals[token_or_coin] += amount
        else:
            totals[token_or_coin] = amount

    if ML_COIN not in totals:
        totals[ML_COIN] = 0

    if txo.transfer:
        update(txo.transfer.value)
    elif txo.lock_then_transfer:
        update(txo.lock_then_transfer.value)
    elif txo.burn:
        update(txo.burn.value)
    elif txo.issue_nft:
        token_or_coin = txo.issue_nft.ticker.decode("utf-8")
        if token_or_coin in totals:
            totals[token_or_coin] += 1
        else:
            totals[token_or_coin] = 1
    elif txo.create_stake_pool:
        amount = int.from_bytes(txo.create_stake_pool.pledge, "big")
        totals[ML_COIN] += amount
    elif txo.delegate_staking:
        amount = int.from_bytes(txo.delegate_staking.amount, "big")
        totals[ML_COIN] += amount
    elif txo.htlc:
        update(txo.htlc.value)
