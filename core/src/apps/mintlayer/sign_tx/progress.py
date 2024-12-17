from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trezor.messages import MintlayerSignTx


class Progress:
    def __init__(self):
        self.progress = 0
        self.steps = 0
        self.signing = False

        # We don't know how long it will take to fetch the previous transactions,
        # so for each one we reserve _PREV_TX_MULTIPLIER steps in the signing
        # progress.
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
        tx: MintlayerSignTx,
    ) -> None:
        if __debug__:
            self.assert_finished()

        self.progress = 0
        self.steps = 0
        self.signing = True

        # Step 3 - serialize all inputs.
        self.steps += tx.inputs_count

        # Step 4 - serialize outputs
        self.steps += tx.outputs_count

    def advance(self) -> None:
        self.progress += 1
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
