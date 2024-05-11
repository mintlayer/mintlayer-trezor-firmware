from typing import TYPE_CHECKING

from trezor.messages import MintlayerSignTx

if TYPE_CHECKING:
    from trezor.messages import SignTx

    from apps.common.coininfo import CoinInfo

# Checking previous transactions typically requires the following pieces of
# information to be fetched for each input:
# the input, prevtx metadata, prevtx input, prevtx output, prevtx change-output
_PREV_TX_MULTIPLIER = 5


class Progress:
    def __init__(self):
        self.progress = 0
        self.steps = 0
        self.signing = False

        # We don't know how long it will take to fetch the previous transactions,
        # so for each one we reserve _PREV_TX_MULTIPLIER steps in the signing
        # progress. Once we fetch a prev_tx's metadata, we subdivide the reserved
        # space and then prev_tx_step represents the progress of fetching one
        # prev_tx input or output in the overall signing progress.
        self.prev_tx_step = 0

    def init(self, tx: MintlayerSignTx) -> None:
        self.progress = 0
        self.signing = False

        # Step 1 and 2 - load inputs and outputs
        self.steps = tx.inputs_count + tx.outputs_count

        self.report_init()
        self.report()

    def init_signing(
        self,
        serialize: bool,
        tx: MintlayerSignTx,
    ) -> None:
        if __debug__:
            self.assert_finished()

        self.progress = 0
        self.steps = 0
        self.signing = True

        # Step 3 - verify inputs
        self.steps = tx.inputs_count * _PREV_TX_MULTIPLIER

        # Steps 4 and 6 - serialize and sign inputs
        if serialize:
            # Step 4 - serialize all inputs.
            self.steps += tx.inputs_count

        # Step 5 - serialize outputs
        if serialize:
            self.steps += tx.outputs_count

    def init_prev_tx(self, inputs: int, outputs: int) -> None:
        self.prev_tx_step = _PREV_TX_MULTIPLIER / (inputs + outputs)

    def advance(self) -> None:
        self.progress += 1
        self.report()

    def advance_prev_tx(self) -> None:
        self.progress += self.prev_tx_step
        self.report()

    def report_init(self) -> None:
        from trezor import TR, workflow
        from trezor.ui.layouts.progress import bitcoin_progress

        progress_layout = bitcoin_progress
        workflow.close_others()
        text = (
            TR.progress__signing_transaction
            if self.signing
            else TR.progress__loading_transaction
        )
        self.progress_layout = progress_layout(text)

    def report(self) -> None:
        from trezor import utils

        if utils.DISABLE_ANIMATION:
            return
        p = int(1000 * self.progress / self.steps)
        self.progress_layout.report(p)

    if __debug__:

        def assert_finished(self) -> None:
            if abs(self.progress - self.steps) > 0.5:
                from trezor import wire

                operation = "signing" if self.signing else "loading"
                raise wire.FirmwareError(
                    f"Transaction {operation} progress finished at {self.progress}/{self.steps}."
                )


progress = Progress()

