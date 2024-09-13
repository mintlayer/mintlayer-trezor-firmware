import re
from typing import TYPE_CHECKING

from shamir_mnemonic import shamir  # type: ignore

from trezorlib.debuglink import LayoutType

from .. import buttons
from .. import translations as TR

if TYPE_CHECKING:
    from trezorlib.debuglink import DebugLink


def confirm_new_wallet(debug: "DebugLink") -> None:
    TR.assert_equals(debug.read_layout().title(), "reset__title_create_wallet")
    if debug.layout_type is LayoutType.TT:
        debug.click(buttons.OK, wait=True)
    elif debug.layout_type is LayoutType.Mercury:
        debug.swipe_up(wait=True)
        debug.click(buttons.TAP_TO_CONFIRM, wait=True)
        debug.swipe_up(wait=True)  # Wallet created
    elif debug.layout_type is LayoutType.TR:
        debug.press_right(wait=True)
        debug.press_right(wait=True)


def confirm_read(debug: "DebugLink", middle_r: bool = False) -> None:
    if debug.layout_type is LayoutType.TT:
        debug.click(buttons.OK, wait=True)
    elif debug.layout_type is LayoutType.Mercury:
        debug.swipe_up(wait=True)
    elif debug.layout_type is LayoutType.TR:
        page_count = debug.read_layout().page_count()
        if page_count > 1:
            for _ in range(page_count - 1):
                debug.press_right(wait=True)
        if middle_r:
            debug.press_middle(wait=True)
        else:
            debug.press_right(wait=True)


def cancel_backup(
    debug: "DebugLink", middle_r: bool = False, confirm: bool = False
) -> None:
    if debug.layout_type is LayoutType.TT:
        debug.click(buttons.CANCEL, wait=True)
        debug.click(buttons.CANCEL, wait=True)
    elif debug.layout_type is LayoutType.Mercury:
        debug.click(buttons.CORNER_BUTTON, wait=True)
        debug.click(buttons.VERTICAL_MENU[0], wait=True)
        if confirm:
            debug.swipe_up(wait=True)
            debug.click(buttons.TAP_TO_CONFIRM)
    elif debug.layout_type is LayoutType.TR:
        debug.press_left(wait=True)
        debug.press_left(wait=True)


def set_selection(debug: "DebugLink", button: tuple[int, int], diff: int) -> None:
    if debug.layout_type in (LayoutType.TT, LayoutType.Mercury):
        assert "NumberInputDialog" in debug.read_layout().all_components()
        for _ in range(diff):
            debug.click(button, wait=True)
        if debug.layout_type is LayoutType.TT:
            debug.click(buttons.OK, wait=True)
        else:
            debug.swipe_up(wait=True)
    elif debug.layout_type is LayoutType.TR:
        layout = debug.read_layout()
        if layout.title() in TR.translate(
            "reset__title_number_of_shares"
        ) + TR.translate("words__title_threshold"):
            # Special info screens
            layout = debug.press_right(wait=True)
        assert "NumberInput" in layout.all_components()
        if button == buttons.reset_minus(debug.model.internal_name):
            for _ in range(diff):
                debug.press_left(wait=True)
        else:
            for _ in range(diff):
                debug.press_right(wait=True)
        debug.press_middle(wait=True)


def read_words(debug: "DebugLink", do_htc: bool = True) -> list[str]:
    words: list[str] = []

    if debug.layout_type is LayoutType.TR:
        debug.press_right(wait=True)
    elif debug.layout_type is LayoutType.Mercury:
        debug.swipe_up(wait=True)

    # Swiping through all the pages and loading the words
    layout = debug.read_layout()
    for _ in range(layout.page_count() - 1):
        words.extend(layout.seed_words())
        layout = debug.swipe_up(wait=True)
        assert layout is not None
    if debug.layout_type in (LayoutType.TT, LayoutType.Mercury):
        words.extend(layout.seed_words())

    if debug.layout_type is LayoutType.Mercury:
        debug.swipe_up(wait=True)

    # There is hold-to-confirm button
    if do_htc:
        if debug.layout_type is LayoutType.TT:
            debug.click_hold(buttons.OK, hold_ms=1500)
        elif debug.layout_type is LayoutType.Mercury:
            debug.click_hold(buttons.TAP_TO_CONFIRM, hold_ms=1500)
        elif debug.layout_type is LayoutType.TR:
            debug.press_right_htc(1200)
    else:
        # It would take a very long time to test 16-of-16 with doing 1500 ms HTC after
        # each word set
        debug.press_yes()

    return words


def confirm_words(debug: "DebugLink", words: list[str]) -> None:
    if debug.layout_type is LayoutType.Mercury:
        debug.swipe_up(wait=True)

    layout = debug.wait_layout()
    if debug.layout_type is LayoutType.TT:
        TR.assert_template(layout.text_content(), "reset__select_word_x_of_y_template")
        for _ in range(3):
            # "Select word 3 of 20"
            #              ^
            word_pos_match = re.search(r"\d+", debug.wait_layout().text_content())
            assert word_pos_match is not None
            word_pos = int(word_pos_match.group(0))
            # Unifying both the buttons and words to lowercase
            btn_texts = [
                text.lower() for text in layout.tt_check_seed_button_contents()
            ]
            wanted_word = words[word_pos - 1].lower()
            button_pos = btn_texts.index(wanted_word)
            layout = debug.click(buttons.RESET_WORD_CHECK[button_pos], wait=True)
    elif debug.layout_type is LayoutType.Mercury:
        TR.assert_template(layout.subtitle(), "reset__select_word_x_of_y_template")
        for _ in range(3):
            # "Select word 3 of 20"
            #              ^
            word_pos_match = re.search(r"\d+", debug.wait_layout().subtitle())
            assert word_pos_match is not None
            word_pos = int(word_pos_match.group(0))
            # Unifying both the buttons and words to lowercase
            btn_texts = [
                text.lower() for text in layout.tt_check_seed_button_contents()
            ]
            wanted_word = words[word_pos - 1].lower()
            button_pos = btn_texts.index(wanted_word)
            layout = debug.click(buttons.VERTICAL_MENU[button_pos], wait=True)
    elif debug.layout_type is LayoutType.TR:
        TR.assert_in(layout.text_content(), "reset__select_correct_word")
        layout = debug.press_right(wait=True)
        for _ in range(3):
            # "SELECT 2ND WORD"
            #         ^
            word_pos_match = re.search(r"\d+", layout.title())
            assert word_pos_match is not None
            word_pos = int(word_pos_match.group(0))

            wanted_word = words[word_pos - 1].lower()

            while not layout.get_middle_choice() == wanted_word:
                layout = debug.press_right(wait=True)

            layout = debug.press_middle(wait=True)


def validate_mnemonics(mnemonics: list[str], expected_ems: bytes) -> None:
    # We expect these combinations to recreate the secret properly
    # In case of click tests the mnemonics are always XofX so no need for combinations
    groups = shamir.decode_mnemonics(mnemonics)
    ems = shamir.recover_ems(groups)
    assert expected_ems == ems.ciphertext
