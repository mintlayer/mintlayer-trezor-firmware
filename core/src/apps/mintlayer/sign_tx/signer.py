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
    MintlayerTxSigningResult,
)
from trezor.wire.errors import DataError

from .. import find_coin_by_chain_type
from . import helpers
from .helpers import mintlayer_decode
from .progress import Progress

if TYPE_CHECKING:
    from typing import Dict, List, Tuple

    from trezor.crypto import bip32
    from trezor.messages import MintlayerAddressPath, MintlayerOutputValue

    from apps.common.keychain import Keychain


class OutputValueTpl:
    def __init__(
        self, coin_or_token_id: str, ticker: bytes, number_of_decimals: int, amount: int
    ) -> None:
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


class TxInput:
    def __init__(
        self,
        input: MintlayerTxInput,
        utxo: MintlayerTxOutput | None,
        nodes: List[Tuple[bip32.HDNode, int | None]],
    ) -> None:
        self.input = input
        self.utxo = utxo
        self.nodes = nodes


class TxInfo:
    def __init__(
        self,
        tx: MintlayerSignTx,
        inputs: List[TxInput],
        outputs: List[MintlayerTxOutput],
    ) -> None:
        self.tx = tx
        self.inputs = inputs
        self.outputs = outputs

    def add_input(
        self,
        txi: MintlayerTxInput,
        txo: MintlayerTxOutput | None,
        nodes: List[Tuple[bip32.HDNode, int | None]],
    ) -> None:
        self.inputs.append(TxInput(input=txi, utxo=txo, nodes=nodes))

    def add_output(self, txo: MintlayerTxOutput) -> None:
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
        coin_total = output_totals.pop(self.coininfo.coin_shortcut)

        if input_totals[self.coininfo.coin_shortcut] < coin_total.amount:
            raise DataError("Transaction trying to print money")

        fee = input_totals[self.coininfo.coin_shortcut] - coin_total.amount
        await helpers.confirm_total(coin_total.amount, fee, self.coininfo, None)
        for token_id, total in output_totals.items():
            token_output_value = MintlayerTokenOutputValue(
                token_id=total.coin_or_token_id,
                token_ticker=total.ticker,
                number_of_decimals=total.number_of_decimals,
            )

            total_inputs = input_totals.get(token_id, 0)
            if total_inputs < total.amount:
                raise DataError("Transaction trying to print money")

            fee = total_inputs - total.amount
            # TODO: new confirm total
            await helpers.confirm_total(
                total.amount, fee, self.coininfo, token_output_value
            )

        # Make sure proper progress is shown, in case dialog was not required
        if not self.signing:
            self.init_signing()
            self.progress.report_init()
        self.progress.report()

        # Following steps can take a long time, make sure autolock doesn't kick in.
        # This is set to True again after workflow is finished in start_default().
        workflow.autolock_interrupts_workflow = False

        # Serialize the inputs.
        encoded_inputs, encoded_input_commitments = await self.step3_serialize_inputs()
        if __debug__:
            log.debug(__name__, "encoded inputs: %s", str(encoded_inputs))
            log.debug(__name__, "encoded utxos: %s", str(encoded_input_commitments))

        # Serialize the outputs.
        encoded_outputs = await self.step4_serialize_outputs()
        if __debug__:
            log.debug(__name__, "encoded outputs: %s", str(encoded_outputs))

        # Sign the inputs.
        signatures = await self.step5_sign_inputs(
            encoded_inputs, encoded_input_commitments, encoded_outputs
        )

        # write the signatures
        await self.step6_finish(signatures)

    def __init__(
        self,
        tx: MintlayerSignTx,
        keychain: Keychain,
    ) -> None:
        from trezor.messages import MintlayerTxRequest

        if tx.version != 1:
            raise DataError("Only transactions of version 1 are supported")

        self.progress = Progress()
        self.coininfo = find_coin_by_chain_type(tx.chain_type)
        self.tx_info = TxInfo(tx=tx, inputs=[], outputs=[])
        self.keychain = keychain

        # indicates whether the transaction is being signed
        self.signing = False

        self.chunkify = tx.chunkify or False
        self.tx_req = MintlayerTxRequest()

    async def step1_process_inputs(
        self,
    ) -> Dict[str, int]:
        tx_info = self.tx_info  # local_cache_attribute
        # Note: the `totals` produced during input and output handling are used to calculate the fee
        # and to check that the tx doesn't try to print money. This leads to some weirdness during
        # `FillOrder` handling, where we add the "filled" amount (which is in the "give" curency)
        # to `totals` instead of the "fill" amount (the one in the "ask" currency), which is
        # actually present in the inputs. But we also show these `totals` to the user, which
        # is confusing. Perhaps we should calculate the actual input amounts (to show them
        # to the user) and the fictional amounts (to satisfy the output amounts) separately.
        # (Note that we already have a TODO related to a custom "confirm_total" dialog, so this
        # can be solved as part of the same task).
        totals: Dict[str, int] = {self.coininfo.coin_shortcut: 0}

        def nodes_for_addresses(
            addresses: list[MintlayerAddressPath],
        ) -> List[Tuple[bip32.HDNode, int | None]]:
            return [
                (
                    self.keychain.derive(address.address_n),
                    address.multisig_idx,
                )
                for address in addresses
            ]

        def update_totals_for_fill_order(
            fill_amount_bytes: bytes,
            ask_balance_bytes: bytes,
            give_balance_bytes: bytes,
            give_token_or_coin: str,
        ) -> None:
            fill_amount = int.from_bytes(fill_amount_bytes, "big")
            ask_balance = int.from_bytes(ask_balance_bytes, "big")
            give_balance = int.from_bytes(give_balance_bytes, "big")

            filled_amount = (give_balance * fill_amount) // ask_balance

            totals[give_token_or_coin] = (
                totals.get(give_token_or_coin, 0) + filled_amount
            )

        def update_totals_for_conclude_order(
            initially_asked_value: MintlayerOutputValue,
            ask_balance_bytes: bytes,
            initially_given_value: MintlayerOutputValue,
            give_balance_bytes: bytes,
        ) -> None:
            ask_token_or_coin = (
                initially_asked_value.token.token_id
                if initially_asked_value.token
                else self.coininfo.coin_shortcut
            )
            initially_asked = int.from_bytes(initially_asked_value.amount, "big")
            ask_balance = int.from_bytes(ask_balance_bytes, "big")
            give_token_or_coin = (
                initially_given_value.token.token_id
                if initially_given_value.token
                else self.coininfo.coin_shortcut
            )
            give_balance = int.from_bytes(give_balance_bytes, "big")

            filled_value = initially_asked - ask_balance

            totals[ask_token_or_coin] = totals.get(ask_token_or_coin, 0) + filled_value
            totals[give_token_or_coin] = (
                totals.get(give_token_or_coin, 0) + give_balance
            )

        for i in range(tx_info.tx.inputs_count):
            self.progress.advance()
            # get the input
            txi = await helpers.request_tx_input(self.tx_req, i)
            if txi.utxo:
                # get the utxo
                txo = await helpers.request_tx_output(
                    self.tx_req, txi.utxo.prev_index, txi.utxo.prev_hash
                )
                nodes = nodes_for_addresses(txi.utxo.addresses)
                update_input_totals(totals, txo, self.coininfo.coin_shortcut)
                self.tx_info.add_input(txi, txo, nodes)
            elif txi.account:
                nodes = nodes_for_addresses(txi.account.addresses)
                if txi.account.delegation_balance:
                    value = txi.account.delegation_balance
                    amount = int.from_bytes(value.amount, "big")
                    totals[self.coininfo.coin_shortcut] += amount
                    self.tx_info.add_input(txi, None, nodes)
                else:
                    raise DataError("Unhandled account spending type")
            elif txi.account_command:
                nodes = nodes_for_addresses(txi.account_command.addresses)
                x = txi.account_command
                if x.mint:
                    token_id = x.mint.token_id
                    amount = int.from_bytes(x.mint.amount, "big")
                    totals[token_id] = totals.get(token_id, 0) + amount
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
                    update_totals_for_conclude_order(
                        x.conclude_order.initially_asked,
                        x.conclude_order.ask_balance,
                        x.conclude_order.initially_given,
                        x.conclude_order.give_balance,
                    )
                elif x.fill_order:
                    given = x.fill_order.initially_given
                    give_token_or_coin = (
                        given.token.token_id
                        if given.token
                        else self.coininfo.coin_shortcut
                    )
                    update_totals_for_fill_order(
                        x.fill_order.amount,
                        x.fill_order.ask_balance,
                        x.fill_order.give_balance,
                        give_token_or_coin,
                    )
                else:
                    raise DataError("Unknown account command")
                self.tx_info.add_input(txi, None, nodes)
            elif txi.order_command:
                x = txi.order_command
                nodes = nodes_for_addresses(x.addresses)
                if x.fill:
                    if len(nodes) > 0:
                        # FillOrder v1 inputs must not be signed.
                        raise DataError("Signature for FillOrder v1 input requested")

                    given = x.fill.initially_given
                    give_token_or_coin = (
                        given.token.token_id
                        if given.token
                        else self.coininfo.coin_shortcut
                    )
                    update_totals_for_fill_order(
                        x.fill.amount,
                        x.fill.initially_asked.amount,
                        x.fill.initially_given.amount,
                        give_token_or_coin,
                    )
                elif x.freeze:
                    pass
                elif x.conclude:
                    update_totals_for_conclude_order(
                        x.conclude.initially_asked,
                        x.conclude.ask_balance,
                        x.conclude.initially_given,
                        x.conclude.give_balance,
                    )
                else:
                    raise DataError("Unknown order command")
                self.tx_info.add_input(txi, None, nodes)
            else:
                raise DataError("Unhandled tx input type")

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
        encoded_input_commitments = []
        for inp in self.tx_info.inputs:
            self.progress.advance()
            if inp.input.utxo and inp.utxo:
                u = inp.input.utxo
                encoded_inp = mintlayer_utils.encode_utxo_input(
                    u.prev_hash, u.prev_index, int(u.type)
                )
                encoded_inputs.append(encoded_inp)

                encoded_input_commitment = self.serialize_input_commitment_for_utxo(
                    inp.utxo
                )
                encoded_input_commitments.append(encoded_input_commitment)
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
                    encoded_input_commitments.append(
                        mintlayer_utils.encode_empty_input_commitment()
                    )
                else:
                    raise DataError("Unknown account spending")
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

                    encoded_input_commitment = (
                        self.serialize_input_commitment_for_conclude_order(
                            ord.initially_asked,
                            ord.ask_balance,
                            ord.initially_given,
                            ord.give_balance,
                        )
                    )
                    encoded_input_commitments.append(encoded_input_commitment)
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

                    encoded_input_commitment = (
                        self.serialize_input_commitment_for_fill_order(
                            ord.initially_asked,
                            ord.initially_given,
                        )
                    )
                    encoded_input_commitments.append(encoded_input_commitment)
                    continue
                else:
                    raise DataError("Unknown account command")

                encoded_inp = mintlayer_utils.encode_token_account_command_input(
                    x.nonce,
                    int(command),
                    mintlayer_decode(token_id, self.coininfo.prefixes.token),
                    data,
                )
                encoded_inputs.append(encoded_inp)
                encoded_input_commitments.append(
                    mintlayer_utils.encode_empty_input_commitment()
                )
            elif inp.input.order_command:
                x = inp.input.order_command

                if x.conclude:
                    ord = x.conclude
                    encoded_inp = (
                        mintlayer_utils.encode_conclude_order_v1_order_command_input(
                            mintlayer_decode(
                                ord.order_id, self.coininfo.prefixes.order
                            ),
                        )
                    )
                    encoded_inputs.append(encoded_inp)

                    encoded_input_commitment = (
                        self.serialize_input_commitment_for_conclude_order(
                            ord.initially_asked,
                            ord.ask_balance,
                            ord.initially_given,
                            ord.give_balance,
                        )
                    )
                    encoded_input_commitments.append(encoded_input_commitment)
                elif x.freeze:
                    ord = x.freeze
                    encoded_inp = (
                        mintlayer_utils.encode_freeze_order_order_command_input(
                            mintlayer_decode(
                                ord.order_id, self.coininfo.prefixes.order
                            ),
                        )
                    )
                    encoded_inputs.append(encoded_inp)
                    encoded_input_commitments.append(
                        mintlayer_utils.encode_empty_input_commitment()
                    )
                elif x.fill:
                    ord = x.fill
                    encoded_inp = (
                        mintlayer_utils.encode_fill_order_v1_order_command_input(
                            mintlayer_decode(
                                ord.order_id, self.coininfo.prefixes.order
                            ),
                            ord.amount,
                        )
                    )
                    encoded_inputs.append(encoded_inp)

                    encoded_input_commitment = (
                        self.serialize_input_commitment_for_fill_order(
                            ord.initially_asked,
                            ord.initially_given,
                        )
                    )
                    encoded_input_commitments.append(encoded_input_commitment)
                else:
                    raise DataError("Unknown account command")
            else:
                raise DataError("Unknown input type")

        return encoded_inputs, encoded_input_commitments

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
                x.is_freezable,
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
            raise DataError("Unhandled tx output type")
        return encoded_out

    def using_v1_input_commitments(self) -> bool:
        ver = self.tx_info.tx.input_commitments_version
        if ver == 0:
            return False
        elif ver == 1:
            return True
        else:
            raise DataError("Unhandled input commitments version")

    def serialize_input_commitment_for_utxo(self, out: MintlayerTxOutput) -> bytes:
        encoded_utxo = self.serialize_output(out)

        if out.produce_block_from_stake and self.using_v1_input_commitments():
            staker_balance = out.produce_block_from_stake.staker_balance
            encoded_comm = mintlayer_utils.encode_input_commitment_v1_for_produce_block_from_stake_utxo(
                encoded_utxo, staker_balance
            )
        else:
            encoded_comm = mintlayer_utils.encode_input_commitment_for_utxo(
                encoded_utxo
            )

        return encoded_comm

    def serialize_input_commitment_for_conclude_order(
        self,
        initially_asked: MintlayerOutputValue,
        ask_balance: bytes,
        initially_given: MintlayerOutputValue,
        give_balance: bytes,
    ) -> bytes:
        if self.using_v1_input_commitments():
            asked_token = decode_nullable_token_id(
                initially_asked.token, self.coininfo.prefixes.token
            )
            given_token = decode_nullable_token_id(
                initially_given.token, self.coininfo.prefixes.token
            )
            encoded_comm = (
                mintlayer_utils.encode_input_commitment_v1_for_conclude_order(
                    asked_token,
                    initially_asked.amount,
                    ask_balance,
                    given_token,
                    initially_given.amount,
                    give_balance,
                )
            )
        else:
            encoded_comm = mintlayer_utils.encode_empty_input_commitment()

        return encoded_comm

    def serialize_input_commitment_for_fill_order(
        self,
        initially_asked: MintlayerOutputValue,
        initially_given: MintlayerOutputValue,
    ) -> bytes:
        if self.using_v1_input_commitments():
            asked_token = decode_nullable_token_id(
                initially_asked.token, self.coininfo.prefixes.token
            )
            given_token = decode_nullable_token_id(
                initially_given.token, self.coininfo.prefixes.token
            )
            encoded_comm = mintlayer_utils.encode_input_commitment_v1_for_fill_order(
                asked_token,
                initially_asked.amount,
                given_token,
                initially_given.amount,
            )
        else:
            encoded_comm = mintlayer_utils.encode_empty_input_commitment()

        return encoded_comm

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
        encoded_input_commitments: List[bytes],
        encoded_outputs: List[bytes],
    ) -> List[List[Tuple[bytes, int | None]]]:
        from trezor.utils import HashWriter

        signatures = []
        if len(encoded_inputs) != len(encoded_input_commitments):
            raise DataError(
                "number of input commitments not the same as the number of inputs"
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

                writer.extend(len(encoded_input_commitments).to_bytes(4, "little"))
                for commitment in encoded_input_commitments:
                    writer.extend(commitment)

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
        self.tx_req.signing_finished = MintlayerTxSigningResult(signatures=sigs)
        await helpers.request_tx_finish(self.tx_req)


def update_input_totals(
    totals: Dict[str, int],
    txo: MintlayerTxOutput,
    ml_coin: str,
) -> None:
    def update(value: MintlayerOutputValue) -> None:
        amount = int.from_bytes(value.amount, "big")
        token_or_coin = value.token.token_id if value.token else ml_coin
        totals[token_or_coin] = totals.get(token_or_coin, 0) + amount

    if txo.transfer:
        update(txo.transfer.value)
    elif txo.lock_then_transfer:
        update(txo.lock_then_transfer.value)
    elif txo.issue_nft:
        token_or_coin = txo.issue_nft.token_id
        totals[token_or_coin] = totals.get(token_or_coin, 0) + 1
    elif txo.create_stake_pool:
        amount = int.from_bytes(txo.create_stake_pool.pledge, "big")
        totals[ml_coin] += amount
    elif txo.produce_block_from_stake:
        amount = int.from_bytes(txo.produce_block_from_stake.staker_balance, "big")
        totals[ml_coin] += amount
    elif txo.htlc:
        update(txo.htlc.value)
    else:
        raise DataError("Unhandled TX output type as UTXO")


def update_output_totals(
    totals: Dict[str, OutputValueTpl],
    txo: MintlayerTxOutput,
    ml_coin: str,
) -> None:
    def update(value: MintlayerOutputValue) -> None:
        amount = int.from_bytes(value.amount, "big")

        token_or_coin = value.token.token_id if value.token else ml_coin
        if token_or_coin in totals:
            totals[token_or_coin].amount += amount
        elif value.token:
            token = OutputValueTpl.from_token_output_value(value.token, amount)
            totals[token_or_coin] = token
        else:
            raise DataError("ml_coin not found in totals")

    if txo.transfer:
        update(txo.transfer.value)
    elif txo.lock_then_transfer:
        update(txo.lock_then_transfer.value)
    elif txo.burn:
        update(txo.burn.value)
    elif txo.create_stake_pool:
        amount = int.from_bytes(txo.create_stake_pool.pledge, "big")
        totals[ml_coin].amount += amount
    elif txo.produce_block_from_stake:
        pass
    elif txo.create_delegation_id:
        pass
    elif txo.delegate_staking:
        amount = int.from_bytes(txo.delegate_staking.amount, "big")
        totals[ml_coin].amount += amount
    elif txo.issue_fungible_token:
        pass
    elif txo.issue_nft:
        pass
    elif txo.data_deposit:
        pass
    elif txo.htlc:
        update(txo.htlc.value)
    elif txo.create_order:
        pass
    else:
        raise DataError("Unhandled TX output type in update_output_totals")
