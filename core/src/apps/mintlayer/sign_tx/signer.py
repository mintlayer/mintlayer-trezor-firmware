from apps.common.coininfo import by_name
from trezor.crypto.bech32 import bech32_encode, bech32_decode, convertbits, reverse_convertbits, Encoding
from trezor.messages import MintlayerSignTx, MintlayerUtxoTxInput, MintlayerTransferTxOutput
from micropython import const
from typing import TYPE_CHECKING

from trezor import workflow
from trezor.crypto.hashlib import blake2b
from trezor.crypto import mintlayer_utils
from trezor.enums import AmountUnit, InputScriptType
from trezor.utils import HashWriter, empty_bytearray
from trezor.wire import DataError, ProcessError
from trezor.crypto.curve import bip340

from apps.common.writers import write_compact_size

from .progress import progress
from . import helpers

if TYPE_CHECKING:
    from typing import Sequence, List, Tuple

    from trezor.crypto import bip32
    from trezor.messages import PrevInput, PrevOutput, PrevTx, TxInput, TxOutput

    from apps.common.keychain import Keychain

    # from ..writers import Writer
    # from . import approvers
    # from .sig_hasher import SigHasher
    # from .tx_info import TxInfo


# the number of bytes to preallocate for serialized transaction chunks
_MAX_SERIALIZED_CHUNK_SIZE = const(2048)
_SERIALIZED_TX_BUFFER = empty_bytearray(_MAX_SERIALIZED_CHUNK_SIZE)

class TxUtxoInput:
    def __init__(self, input: MintlayerUtxoTxInput, utxo: MintlayerTransferTxOutput, node: bip32.HDNode):
        self.input = input
        self.utxo = utxo
        self.node = node


class TxInfo:
    def __init__(self, tx: MintlayerSignTx, inputs: List[TxUtxoInput], outputs: List[MintlayerTransferTxOutput]):
        self.tx = tx
        self.inputs = inputs
        self.outputs = outputs


    def add_input(self, txi: MintlayerUtxoTxInput, txo: MintlayerTransferTxOutput, node: bip32.HDNode):
        self.inputs.append(TxUtxoInput(input= txi, utxo= txo, node= node))

    def add_output(self, txo: MintlayerTransferTxOutput):
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
        await self.step1_process_inputs()

        # Add outputs to sig_hasher and h_tx_check, approve outputs and compute
        # sum of output amounts.
        await self.step2_approve_outputs()

        total = 10
        fee = 1
        fee_rate = 0.1
        coin = by_name('Bitcoin')
        amount_unit = AmountUnit.BITCOIN
        await helpers.confirm_total(
            total,
            fee,
            fee_rate,
            coin,
            amount_unit,
            None,
        )

        # Check fee, approve lock_time and total.
        # FIXME
        # await self.approver.approve_tx(self.tx_info, self.orig_txs, self)

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
        print("encoded inputs", encoded_inputs)
        print("encoded utxos", encoded_input_utxos)

        # Serialize outputs.
        encoded_outputs = await self.step5_serialize_outputs()
        print("encoded outputs", encoded_outputs)

        # Sign segwit inputs and serialize witness data.
        signatures = await self.step6_sign_inputs(encoded_inputs, encoded_input_utxos, encoded_outputs)

        # Write footer and send remaining data.
        await self.step7_finish(signatures)

    def __init__(
        self,
        tx: MintlayerSignTx,
        keychain: Keychain,
        # approver: approvers.Approver | None,
    ) -> None:
        from trezor.messages import (
            MintlayerTxRequest,
            TxRequestDetailsType,
            TxRequestSerializedType,
        )

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
        self.tx_req.details = TxRequestDetailsType()
        self.tx_req.serialized = TxRequestSerializedType()
        self.tx_req.serialized.serialized_tx = self.serialized_tx

        # The digest of the presigned external inputs streamed for approval in Step 1. This is
        # used to ensure that the inputs streamed for verification in Step 3 are the same as
        # those in Step 1.
        self.h_presigned_inputs: bytes | None = None

        # The index of the payment request being processed.
        self.payment_req_index: int | None = None

        self.inputs: List[TxUtxoInput] = []
        self.outputs = []

    async def step1_process_inputs(self) -> None:
        tx_info = self.tx_info  # local_cache_attribute
        # h_presigned_inputs_check = HashWriter(sha256())

        for i in range(tx_info.tx.inputs_count):
            # STAGE_REQUEST_1_INPUT in legacy
            progress.advance()
            # get the input
            txi = await helpers.request_tx_input(self.tx_req, i)
            # get the utxo
            txo = await helpers.request_tx_output(self.tx_req, txi.prev_index, txi.prev_hash)
            node = self.keychain.derive(txo.address_n)

            self.tx_info.add_input(txi, txo, node)

        # tx_info.h_inputs_check = tx_info.get_tx_check_digest()
        # self.h_presigned_inputs = h_presigned_inputs_check.get_digest()

    async def step2_approve_outputs(self) -> None:
        from trezor.messages import TxOutput
        for i in range(self.tx_info.tx.outputs_count):
            # STAGE_REQUEST_2_OUTPUT in legacy
            progress.advance()
            txo = await helpers.request_tx_output(self.tx_req, i)
            coin = by_name('Bitcoin')
            amount_unit = AmountUnit.BITCOIN
            t = TxOutput(amount=txo.amount, address=txo.address)
            await helpers.confirm_output(t, coin, amount_unit, i, False)
            self.tx_info.add_output(txo)

    async def step3_verify_inputs(self) -> None:
        return

    async def step4_serialize_inputs(self) -> Tuple[List[bytes], List[bytes]]:
        encoded_inputs = []
        encoded_input_utxos = []
        for inp in self.tx_info.inputs:
            progress.advance()
            encoded_inp = mintlayer_utils.encode_utxo_input(inp.input.prev_hash, inp.input.prev_index)
            encoded_inputs.append(encoded_inp)

            pk = bytes([0]) + inp.node.public_key()
            hrp = 'mptc'
            hrp = 'mtc'

            pkh = blake2b(pk).digest()[:20]

            data = convertbits(bytes([1])+pkh, 8, 5)
            address = bech32_encode(hrp, data, Encoding.BECH32M)

            _, data = bech32_decode(address)
            data = reverse_convertbits(data, 8, 5)

            encoded_inp_utxo = mintlayer_utils.encode_transfer_output(str(inp.utxo.amount).encode(), bytes(data))
            encoded_input_utxos.append(b'\x01' + encoded_inp_utxo)

        return encoded_inputs, encoded_input_utxos

    async def step5_serialize_outputs(self) -> List[bytes]:
        encoded_outputs = []
        for out in self.tx_info.outputs:
            progress.advance()
            hpr, data = bech32_decode(out.address)
            data = reverse_convertbits(data, 8, 5)
            print('decoded out', hpr, data)

            encoded_out = mintlayer_utils.encode_transfer_output(str(out.amount).encode(), bytes(data))
            encoded_outputs.append(encoded_out)

        return encoded_outputs

    async def step6_sign_inputs(self, encoded_inputs: List[bytes], encoded_input_utxos: Lisst[bytes], encoded_outputs: Lisst[bytes]) -> List[butes]:
        from trezor.utils import HashWriter

        signatures = []
        for i in range(self.tx_info.tx.inputs_count):
            writer = HashWriter(blake2b())
            # mode
            writer.extend(b'\x01')

            # version
            writer.extend(b'\x01')
            # flags
            writer.extend(bytes([0]*16))


            writer.extend(len(encoded_inputs).to_bytes(4, 'little'))
            for inp in encoded_inputs:
                writer.extend(inp)

            writer.extend(len(encoded_input_utxos).to_bytes(4, 'little'))
            print(encoded_input_utxos)
            for utxo in encoded_input_utxos:
                writer.extend(utxo)

            encoded_len = mintlayer_utils.encode_compact_length(len(encoded_outputs))
            print(f'compact len {encoded_len}')
            writer.extend(encoded_len)
            for out in encoded_outputs:
                writer.extend(out)

            hash = writer.get_digest()[:32]
            private_key = self.tx_info.inputs[i].node.private_key()
            digest = blake2b(hash).digest()[:32]
            print(f"hash {list(hash)}, digest {list(digest)}")

            sig = bip340.sign(private_key, digest)
            print("got a signature", sig)
            signatures.append(sig)

        return signatures

    async def step7_finish(self, signatures: List[bytes]) -> None:
        # if self.serialize:
        #     self.write_tx_footer(self.serialized_tx, self.tx_info.tx)
        # if __debug__:
        #     progress.assert_finished()
        await helpers.request_tx_finish(self.tx_req)


    # Tx Helpers
    # ===

    @staticmethod
    def write_tx_output(
        w: Writer,
        txo: TxOutput | PrevOutput,
        script_pubkey: bytes,
    ) -> None:
        writers.write_tx_output(w, txo, script_pubkey)

    def write_tx_footer(self, w: Writer, tx: SignTx | PrevTx) -> None:
        writers.write_uint32(w, tx.lock_time)

    async def write_prev_tx_footer(
        self, w: Writer, tx: PrevTx, prev_hash: bytes
    ) -> None:
        self.write_tx_footer(w, tx)

    def set_serialized_signature(self, index: int, signature: bytes) -> None:
        from trezor.utils import ensure

        serialized = self.tx_req.serialized  # local_cache_attribute

        # Only one signature per TxRequest can be serialized.
        assert serialized is not None
        ensure(serialized.signature is None)

        serialized.signature_index = index
        serialized.signature = signature
