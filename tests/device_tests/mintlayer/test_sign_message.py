import pytest

from trezorlib import messages, mintlayer
from trezorlib.debuglink import TrezorClientDebugLink as Client
from trezorlib.tools import parse_path


@pytest.mark.altcoin
@pytest.mark.mintlayer
@pytest.mark.setup_client(
    mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)
def test_mintlayer_sign_message(client: Client):
    address = "mtc1qyumjs84s5nqgcp6nw9kwde9mn7akph6hgtulsdk"
    result = mintlayer.sign_message(
        client,
        coin_name="mainnet",
        address_type="PUBLIC_KEY_HASH",
        address_n=parse_path("m/44h/19788h/0h/0/0"),
        message="Message to sign".encode(),
    )
    if isinstance(result, messages.MessageSignature):
        assert (
            result.signature.hex()
            == "7d8a743ada09e7ca8e76cf99429385a1651a9738d96a78c6b601c49a7cb20896d076e1c4d4e8a514ad73f4b88fe115cb30b61e1c04fc96d999baeabd32f82fb2"
        )
        assert result.address == address
