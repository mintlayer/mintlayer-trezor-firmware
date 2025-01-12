from typing import TYPE_CHECKING

from trezor import log, workflow
from trezor.crypto import mintlayer_utils
from trezor.crypto.curve import bip340
from trezor.crypto.hashlib import blake2b
from trezor.enums import MintlayerAccountCommandType
from trezor.messages import (
    MintlayerSignature,
    MintlayerSignaturesForInput,
    MintlayerSignTx,
    MintlayerTokenOutputValue,
    MintlayerTxInput,
    MintlayerTxOutput,
    MintlayerTxRequestSerializedType,
)
from trezor.wire.errors import DataError

from .. import find_coin_by_chain_type
from . import helpers
from .helpers import mintlayer_decode
from .progress import Progress

if TYPE_CHECKING:
    from typing import Dict, List, Tuple

    from trezor.crypto import bip32
    from trezor.messages import MintlayerOutputValue

    from apps.common.keychain import Keychain


class OutputValueTpl:
    def __init__(
        self, coin_or_token_id: str, ticker: bytes, number_of_decimals: int, amount: int
    ):
        self.coin_or_token_id = coin_or_token_id
        self.ticker = ticker
        self.number_of_decimals = number_of_decimals
        self.amount = amount

    @staticmethod
    def from_token_output_value(
        value: MintlayerTokenOutputValue, amount: int
    ) -> "OutputValueTpl":
        return OutputValueTpl(
            value.token_id,
            value.token_ticker,
            value.number_of_decimals,
            amount,
        )


def decode_nullable_address(address: str | None) -> bytes:
    if address is None:
        return bytes()

    return mintlayer_decode(address, None)


def decode_nullable_token_id(
    token: MintlayerTokenOutputValue | None, token_hrp: str
) -> bytes:
    if token is None:
        return b""
    return mintlayer_decode(token.token_id, token_hrp)


class TxUtxoInput:
    def __init__(
        self,
        input: MintlayerTxInput,
        utxo: MintlayerTxOutput | None,
        nodes: List[Tuple[bip32.HDNode, int | None]],
    ):
        self.input = input
        self.utxo = utxo
        self.nodes = nodes


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
        nodes: List[Tuple[bip32.HDNode, int | None]],
    ):
        self.inputs.append(TxUtxoInput(input=txi, utxo=txo, nodes=nodes))

    def add_output(self, txo: MintlayerTxOutput):
        self.outputs.append(txo)


class Mintlayer:
    def init_signing(self) -> None:
        self.progress.init_signing(self.tx_info.tx)
        self.signing = True

    async def signer(self) -> None:
        self.progress.init(self.tx_info.tx)

        # Fetch and add inputs and compute the sum of input amounts.
        input_totals = await self.step1_process_inputs()

        # Fetch and add outputs, approve outputs and compute sum of output amounts.
        output_totals = await self.step2_approve_outputs()

        if (
            input_totals[self.coininfo.coin_shortcut]
            < output_totals[self.coininfo.coin_shortcut].amount
        ):
            raise DataError("Transaction trying to print money")

        fee = (
            input_totals[self.coininfo.coin_shortcut]
            - output_totals[self.coininfo.coin_shortcut].amount
        )
        await helpers.confirm_total(
            output_totals[self.coininfo.coin_shortcut].amount, fee, self.coininfo, None
        )
        for token, total in output_totals.items():
            if token != self.coininfo.coin_shortcut:
                token2 = MintlayerTokenOutputValue(
                    token_id=total.coin_or_token_id,
                    token_ticker=total.ticker,
                    number_of_decimals=total.number_of_decimals,
                )

                total_inputs = input_totals.get(token, 0)
                if total_inputs < total.amount:
                    raise DataError("Transaction trying to print money")

                fee = total_inputs - total.amount
                await helpers.confirm_total(total.amount, fee, self.coininfo, token2)

        # Make sure proper progress is shown, in case dialog was not required
        if not self.signing:
            self.init_signing()
            self.progress.report_init()
        self.progress.report()

        # Following steps can take a long time, make sure autolock doesn't kick in.
        # This is set to True again after workflow is finished in start_default().
        workflow.autolock_interrupts_workflow = False

        # Serialize the inputs.
        encoded_inputs, encoded_input_utxos = await self.step3_serialize_inputs()
        if __debug__:
            log.debug(__name__, "encoded inputs: %s", str(encoded_inputs))
            log.debug(__name__, "encoded utxos: %s", str(encoded_input_utxos))

        # Serialize the outputs.
        encoded_outputs = await self.step4_serialize_outputs()
        if __debug__:
            log.debug(__name__, "encoded outputs: %s", str(encoded_outputs))

        # Sign the inputs.
        signatures = await self.step5_sign_inputs(
            encoded_inputs, encoded_input_utxos, encoded_outputs
        )

        # write the signatures
        await self.step6_finish(signatures)

    def __init__(
        self,
        tx: MintlayerSignTx,
        keychain: Keychain,
    ) -> None:
        from trezor.messages import MintlayerTxRequest, MintlayerTxRequestDetailsType

        self.progress = Progress()
        self.coininfo = find_coin_by_chain_type(tx.chain_type)
        self.tx_info = TxInfo(tx=tx, inputs=[], outputs=[])
        self.keychain = keychain

        # indicates whether the transaction is being signed
        self.signing = False

        self.serialize = tx.serialize
        self.chunkify = tx.chunkify or False
        self.tx_req = MintlayerTxRequest()
        self.tx_req.details = MintlayerTxRequestDetailsType()
        self.tx_req.serialized = None

    async def step1_process_inputs(
        self,
    ) -> Dict[str, int]:
        tx_info = self.tx_info  # local_cache_attribute
        totals: Dict[str, int] = {self.coininfo.coin_shortcut: 0}

        for i in range(tx_info.tx.inputs_count):
            self.progress.advance()
            # get the input
            txi = await helpers.request_tx_input(self.tx_req, i)
            if txi.utxo:
                # get the utxo
                txo = await helpers.request_tx_output(
                    self.tx_req, txi.utxo.prev_index, txi.utxo.prev_hash
                )
                nodes = []
                for address in txi.utxo.addresses:
                    nodes.append(
                        (
                            self.keychain.derive(address.address_n),
                            address.multisig_idx,
                        )
                    )

                update_input_totals(totals, txo, self.coininfo.coin_shortcut)
                self.tx_info.add_input(txi, txo, nodes)
            elif txi.account:
                nodes = []
                for address in txi.account.addresses:
                    nodes.append(
                        (
                            self.keychain.derive(address.address_n),
                            address.multisig_idx,
                        )
                    )
                if txi.account.delegation_balance:
                    value = txi.account.delegation_balance
                    amount = int.from_bytes(value.amount, "big")
                    totals[self.coininfo.coin_shortcut] += amount
                    self.tx_info.add_input(txi, None, nodes)
                else:
                    raise Exception("Unhandled account spending type")
            elif txi.account_command:
                nodes = []
                for address in txi.account_command.addresses:
                    nodes.append(
                        (
                            self.keychain.derive(address.address_n),
                            address.multisig_idx,
                        )
                    )
                x = txi.account_command
                if x.mint:
                    token_id = x.mint.token_id
                    amount = int.from_bytes(x.mint.amount, "big")
                    if token_id in totals:
                        totals[token_id] += amount
                    else:
                        totals[token_id] = amount
                elif x.unmint:
                    pass
                elif x.lock_token_supply:
                    pass
                elif x.freeze_token:
                    pass
                elif x.unfreeze_token:
                    pass
                elif x.change_token_authority:
                    pass
                elif x.change_token_metadata_uri:
                    pass
                elif x.conclude_order:
                    ask = x.conclude_order.filled_ask_amount
                    amount = int.from_bytes(ask.amount, "big")
                    token_or_coin = (
                        ask.token.token_id if ask.token else self.coininfo.coin_shortcut
                    )

                    if token_or_coin in totals:
                        totals[token_or_coin] += amount
                    elif ask.token:
                        totals[token_or_coin] = amount
                    else:
                        raise Exception("ml_coin not found in totals")

                    give = x.conclude_order.give_balance
                    amount = int.from_bytes(give.amount, "big")
                    token_or_coin = (
                        give.token.token_id
                        if give.token
                        else self.coininfo.coin_shortcut
                    )

                    if token_or_coin in totals:
                        totals[token_or_coin] += amount
                    elif give.token:
                        totals[token_or_coin] = amount
                    else:
                        raise Exception("ml_coin not found in totals")
                elif x.fill_order:
                    give_amount = int.from_bytes(
                        x.fill_order.give_balance.amount, "big"
                    )
                    fill_amount = int.from_bytes(x.fill_order.amount, "big")
                    ask_amount = int.from_bytes(x.fill_order.ask_balance.amount, "big")

                    amount = (give_amount * fill_amount) // ask_amount

                    give = x.fill_order.give_balance
                    token_or_coin = (
                        give.token.token_id
                        if give.token
                        else self.coininfo.coin_shortcut
                    )

                    if token_or_coin in totals:
                        totals[token_or_coin] += amount
                    elif give.token:
                        totals[token_or_coin] = amount
                    else:
                        raise Exception("ml_coin not found in totals")
                else:
                    raise Exception("Unknown account command")
                self.tx_info.add_input(txi, None, nodes)
            else:
                raise Exception("Unhandled tx input type")

        return totals

    async def step2_approve_outputs(
        self,
    ) -> Dict[str, OutputValueTpl]:
        totals: Dict[str, OutputValueTpl] = {
            self.coininfo.coin_shortcut: OutputValueTpl(
                self.coininfo.coin_name,
                self.coininfo.coin_shortcut.encode(),
                self.coininfo.decimals,
                0,
            )
        }

        for i in range(self.tx_info.tx.outputs_count):
            self.progress.advance()
            txo = await helpers.request_tx_output(self.tx_req, i)
            await helpers.confirm_output(txo, i, self.coininfo, self.chunkify)
            update_output_totals(totals, txo, self.coininfo.coin_shortcut)
            self.tx_info.add_output(txo)
        return totals

    async def step3_serialize_inputs(self) -> Tuple[List[bytes], List[bytes]]:
        encoded_inputs = []
        encoded_input_utxos = []
        for inp in self.tx_info.inputs:
            self.progress.advance()
            if inp.input.utxo and inp.utxo:
                u = inp.input.utxo
                encoded_inp = mintlayer_utils.encode_utxo_input(
                    u.prev_hash, u.prev_index, int(u.type)
                )
                encoded_inputs.append(encoded_inp)
                data = decode_nullable_address(u.address)

                encoded_inp_utxo = self.serialize_output(inp.utxo)
                # prepend \x01 for an active Option
                encoded_input_utxos.append(b"\x01" + encoded_inp_utxo)
            elif inp.input.account:
                a = inp.input.account
                nonce = a.nonce
                if a.delegation_balance:
                    deleg_balance = a.delegation_balance
                    delegation_id = mintlayer_decode(
                        deleg_balance.delegation_id, self.coininfo.prefixes.delegation
                    )
                    encoded_inp = mintlayer_utils.encode_account_spending_input(
                        nonce, delegation_id, deleg_balance.amount
                    )
                    encoded_inputs.append(encoded_inp)
                    # just add a \x00 for an empty Option as accounts don't have an UTXO
                    encoded_input_utxos.append(b"\x00")
                else:
                    raise Exception("Unknown account spending")
            elif inp.input.account_command:
                x = inp.input.account_command
                if x.mint:
                    command = MintlayerAccountCommandType.MINT_TOKENS
                    token_id = x.mint.token_id
                    data = x.mint.amount
                elif x.unmint:
                    command = MintlayerAccountCommandType.UNMINT_TOKENS
                    token_id = x.unmint.token_id
                    data = b""
                elif x.lock_token_supply:
                    command = MintlayerAccountCommandType.LOCK_TOKEN_SUPPLY
                    token_id = x.lock_token_supply.token_id
                    data = b""
                elif x.freeze_token:
                    command = MintlayerAccountCommandType.FREEZE_TOKEN
                    token_id = x.freeze_token.token_id
                    data = int(x.freeze_token.is_token_unfreezable).to_bytes(1, "big")
                elif x.unfreeze_token:
                    command = MintlayerAccountCommandType.UNFREEZE_TOKEN
                    token_id = x.unfreeze_token.token_id
                    data = b""
                elif x.change_token_authority:
                    command = MintlayerAccountCommandType.CHANGE_TOKEN_AUTHORITY
                    token_id = x.change_token_authority.token_id
                    data = decode_nullable_address(x.change_token_authority.destination)
                elif x.change_token_metadata_uri:
                    command = MintlayerAccountCommandType.CHANGE_TOKEN_METADATA_URI
                    token_id = x.change_token_metadata_uri.token_id
                    data = x.change_token_metadata_uri.metadata_uri
                elif x.conclude_order:
                    ord = x.conclude_order
                    encoded_inp = (
                        mintlayer_utils.encode_conclude_order_account_command_input(
                            x.nonce,
                            mintlayer_decode(
                                ord.order_id, self.coininfo.prefixes.order
                            ),
                        )
                    )
                    encoded_inputs.append(encoded_inp)
                    # just add a \x00 for an empty Option as account command inputs don't have an UTXO
                    encoded_input_utxos.append(b"\x00")
                    continue
                elif x.fill_order:
                    ord = x.fill_order
                    destination = decode_nullable_address(ord.destination)
                    encoded_inp = (
                        mintlayer_utils.encode_fill_order_account_command_input(
                            x.nonce,
                            mintlayer_decode(
                                ord.order_id, self.coininfo.prefixes.order
                            ),
                            ord.amount,
                            destination,
                        )
                    )
                    encoded_inputs.append(encoded_inp)
                    # just add a \x00 for an empty Option as account command inputs don't have an UTXO
                    encoded_input_utxos.append(b"\x00")
                    continue
                else:
                    raise Exception("Unknown account command")

                encoded_inp = mintlayer_utils.encode_token_account_command_input(
                    x.nonce,
                    int(command),
                    mintlayer_decode(token_id, self.coininfo.prefixes.token),
                    data,
                )
                encoded_inputs.append(encoded_inp)
                # just add a \x00 for an empty Option as account command inputs don't have an UTXO
                encoded_input_utxos.append(b"\x00")

        return encoded_inputs, encoded_input_utxos

    def serialize_output(self, out: MintlayerTxOutput) -> bytes:
        if out.transfer:
            x = out.transfer
            data = decode_nullable_address(x.address)
            token_id = decode_nullable_token_id(
                x.value.token, self.coininfo.prefixes.token
            )
            encoded_out = mintlayer_utils.encode_transfer_output(
                x.value.amount, token_id, data
            )
        elif out.lock_then_transfer:
            x = out.lock_then_transfer
            data = decode_nullable_address(x.address)
            lock_type, lock_amount = helpers.get_lock(x.lock)
            token_id = decode_nullable_token_id(
                x.value.token, self.coininfo.prefixes.token
            )
            encoded_out = mintlayer_utils.encode_lock_then_transfer_output(
                x.value.amount, token_id, int(lock_type), lock_amount, data
            )
        elif out.burn:
            x = out.burn
            token_id = decode_nullable_token_id(
                x.value.token, self.coininfo.prefixes.token
            )
            encoded_out = mintlayer_utils.encode_burn_output(x.value.amount, token_id)
        elif out.create_stake_pool:
            x = out.create_stake_pool
            staker = decode_nullable_address(x.staker)
            vrf_public_key = decode_nullable_address(x.vrf_public_key)
            decommission_key = decode_nullable_address(x.decommission_key)
            encoded_out = mintlayer_utils.encode_create_stake_pool_output(
                mintlayer_decode(x.pool_id, self.coininfo.prefixes.pool),
                x.pledge,
                staker,
                vrf_public_key,
                decommission_key,
                x.margin_ratio_per_thousand,
                x.cost_per_block,
            )
        elif out.create_delegation_id:
            x = out.create_delegation_id
            destination = decode_nullable_address(x.destination)
            encoded_out = mintlayer_utils.encode_create_delegation_id_output(
                destination, mintlayer_decode(x.pool_id, self.coininfo.prefixes.pool)
            )
        elif out.delegate_staking:
            x = out.delegate_staking
            encoded_out = mintlayer_utils.encode_delegate_staking_output(
                x.amount,
                mintlayer_decode(x.delegation_id, self.coininfo.prefixes.delegation),
            )
        elif out.produce_block_from_stake:
            x = out.produce_block_from_stake
            destination = decode_nullable_address(x.destination)
            encoded_out = mintlayer_utils.encode_produce_from_stake_output(
                destination, mintlayer_decode(x.pool_id, self.coininfo.prefixes.pool)
            )
        elif out.issue_fungible_token:
            x = out.issue_fungible_token
            authority = decode_nullable_address(x.authority)
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
            creator = decode_nullable_address(x.creator)
            destination = decode_nullable_address(x.destination)
            encoded_out = mintlayer_utils.encode_issue_nft_output(
                mintlayer_decode(x.token_id, self.coininfo.prefixes.token),
                creator,
                x.name,
                x.description,
                x.ticker,
                x.icon_uri or b"",
                x.additional_metadata_uri or b"",
                x.media_uri or b"",
                x.media_hash,
                destination,
            )
        elif out.data_deposit:
            x = out.data_deposit
            encoded_out = mintlayer_utils.encode_data_deposit_output(x.data)
        elif out.htlc:
            x = out.htlc
            token_id = decode_nullable_token_id(
                x.value.token, self.coininfo.prefixes.token
            )
            spend_key = decode_nullable_address(x.spend_key)
            refund_key = decode_nullable_address(x.refund_key)
            lock_type, lock_amount = helpers.get_lock(x.refund_timelock)
            encoded_out = mintlayer_utils.encode_htlc_output(
                x.value.amount,
                token_id,
                int(lock_type),
                lock_amount,
                refund_key,
                spend_key,
                x.secret_hash,
            )
        elif out.create_order:
            x = out.create_order
            conclude_key = decode_nullable_address(x.conclude_key)
            ask_token_id = decode_nullable_token_id(
                x.ask.token, self.coininfo.prefixes.token
            )
            give_token_id = decode_nullable_token_id(
                x.give.token, self.coininfo.prefixes.token
            )
            encoded_out = mintlayer_utils.encode_create_order_output(
                conclude_key, x.ask.amount, ask_token_id, x.give.amount, give_token_id
            )
        else:
            raise Exception("Unhandled tx output type")
        return encoded_out

    async def step4_serialize_outputs(self) -> List[bytes]:
        encoded_outputs = []
        for out in self.tx_info.outputs:
            self.progress.advance()
            encoded_out = self.serialize_output(out)
            encoded_outputs.append(encoded_out)

        return encoded_outputs

    async def step5_sign_inputs(
        self,
        encoded_inputs: List[bytes],
        encoded_input_utxos: List[bytes],
        encoded_outputs: List[bytes],
    ) -> List[List[Tuple[bytes, int | None]]]:
        from trezor.utils import HashWriter

        signatures = []
        if len(encoded_inputs) != len(encoded_input_utxos):
            raise Exception(
                "number of encoded utxos not the same as the number of inputs"
            )

        for i in range(self.tx_info.tx.inputs_count):
            sigs = []
            for node, multisig_idx in self.tx_info.inputs[i].nodes:
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

    async def step6_finish(
        self, signatures: List[List[Tuple[bytes, int | None]]]
    ) -> None:
        sigs = [
            MintlayerSignaturesForInput(
                input_index=i,
                signatures=[
                    MintlayerSignature(signature=s[0], multisig_idx=s[1]) for s in sigs
                ],
            )
            for i, sigs in enumerate(signatures)
        ]
        self.tx_req.serialized = MintlayerTxRequestSerializedType(signatures=sigs)
        await helpers.request_tx_finish(self.tx_req)


def update_input_totals(
    totals: Dict[str, int],
    txo: MintlayerTxOutput,
    ml_coin,
):
    def update(value: MintlayerOutputValue):
        amount = int.from_bytes(value.amount, "big")
        token_or_coin = value.token.token_id if value.token else ml_coin

        if token_or_coin in totals:
            totals[token_or_coin] += amount
        elif value.token:
            totals[token_or_coin] = amount
        else:
            raise Exception("ml_coin not found in totals")

    if txo.transfer:
        update(txo.transfer.value)
    elif txo.lock_then_transfer:
        update(txo.lock_then_transfer.value)
    elif txo.issue_nft:
        token_or_coin = txo.issue_nft.token_id
        if token_or_coin in totals:
            totals[token_or_coin] += 1
        else:
            totals[token_or_coin] = 1
    elif txo.create_stake_pool:
        amount = int.from_bytes(txo.create_stake_pool.pledge, "big")
        totals[ml_coin] += amount
    elif txo.produce_block_from_stake:
        amount = int.from_bytes(txo.produce_block_from_stake.staker_balance, "big")
        totals[ml_coin] += amount
    elif txo.htlc:
        update(txo.htlc.value)
    else:
        raise Exception("Unhandled TX output type as UTXO")


def update_output_totals(
    totals: Dict[str, OutputValueTpl],
    txo: MintlayerTxOutput,
    ml_coin,
):
    def update(value: MintlayerOutputValue):
        amount = int.from_bytes(value.amount, "big")

        token_or_coin = value.token.token_id if value.token else ml_coin
        if token_or_coin in totals:
            totals[token_or_coin].amount += amount
        elif value.token:
            token = OutputValueTpl.from_token_output_value(value.token, amount)
            totals[token_or_coin] = token
        else:
            raise Exception("ml_coin not found in totals")

    if txo.transfer:
        update(txo.transfer.value)
    elif txo.lock_then_transfer:
        update(txo.lock_then_transfer.value)
    elif txo.burn:
        update(txo.burn.value)
    elif txo.issue_nft:
        pass
    elif txo.create_stake_pool:
        amount = int.from_bytes(txo.create_stake_pool.pledge, "big")
        totals[ml_coin].amount += amount
    elif txo.delegate_staking:
        amount = int.from_bytes(txo.delegate_staking.amount, "big")
        totals[ml_coin].amount += amount
    elif txo.htlc:
        update(txo.htlc.value)
    elif txo.create_order:
        pass
