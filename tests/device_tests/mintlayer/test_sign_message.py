import pytest
from construct import itertools

from trezorlib import messages, mintlayer
from trezorlib.debuglink import DebugSession as Session
from trezorlib.exceptions import TrezorFailure
from trezorlib.tools import parse_path

from . import pytestmark  # noqa

M_ADDRESS = "mtc1qyumjs84s5nqgcp6nw9kwde9mn7akph6hgtulsdk"
M_PK_ADDRESS = "mptc1qgpm7mud2tddualet6wxe9yglkzf92vup8ljxz2u4lajueqf696x4hs2ryf7j"
M_SIGNATURE = "7d8a743ada09e7ca8e76cf99429385a1651a9738d96a78c6b601c49a7cb20896d076e1c4d4e8a514ad73f4b88fe115cb30b61e1c04fc96d999baeabd32f82fb2"
T_ADDRESS = "tmt1qx5p4r2en7c99mpmg2tz9hucxfarf4k6dyyvsahr"
T_PK_ADDRESS = "tpmt1qgp2w3gnj4e4x60jan0us2wq7a6w3rh3xq7luke0qnd64vc22dwlm4s4hr3um"
T_SIGNATURE = "d85ce2bbad7e86626675b8d95a5f5c87d3a96f9fdf94b1ea0d017a86163998dc54a7e4fec66ee3f196a2275c81434e99a2d7eae669640ac4d05ab708aaa18dc1"
R_ADDRESS = "rmt1qx5p4r2en7c99mpmg2tz9hucxfarf4k6dypq388a"
R_PK_ADDRESS = "rpmt1qgp2w3gnj4e4x60jan0us2wq7a6w3rh3xq7luke0qnd64vc22dwlm4sy595zf"
S_ADDRESS = "smt1qx5p4r2en7c99mpmg2tz9hucxfarf4k6dy5zamcc"
S_PK_ADDRESS = "spmt1qgp2w3gnj4e4x60jan0us2wq7a6w3rh3xq7luke0qnd64vc22dwlm4shqyp8w"

SIGN_TEST_VECTORS = [
    (1, "PUBLIC_KEY_HASH", M_ADDRESS, M_SIGNATURE),
    (1, "PUBLIC_KEY", M_PK_ADDRESS, M_SIGNATURE),
    (2, "PUBLIC_KEY_HASH", T_ADDRESS, T_SIGNATURE),
    (2, "PUBLIC_KEY", T_PK_ADDRESS, T_SIGNATURE),
    (3, "PUBLIC_KEY_HASH", R_ADDRESS, T_SIGNATURE),
    (3, "PUBLIC_KEY", R_PK_ADDRESS, T_SIGNATURE),
    (4, "PUBLIC_KEY_HASH", S_ADDRESS, T_SIGNATURE),
    (4, "PUBLIC_KEY", S_PK_ADDRESS, T_SIGNATURE),
]

CHAIN_TYPE_TO_COIN = {1: 19788, 2: 1, 3: 1, 4: 1}


@pytest.mark.parametrize(
    "chain_type, addr_type, expected_address, expected_signature", SIGN_TEST_VECTORS
)
def test_mintlayer_sign_message(
    session: Session,
    chain_type: int,
    addr_type: str,
    expected_address: str,
    expected_signature: str,
):
    result = mintlayer.sign_message(
        session,
        chain_type=chain_type,
        address_type=addr_type,
        address_n=parse_path(f"m/44h/{CHAIN_TYPE_TO_COIN[chain_type]}h/0h/0/0"),
        message="Message to sign".encode(),
    )
    if isinstance(result, messages.MessageSignature):
        assert result.signature.hex() == expected_signature
        assert result.address == expected_address


INVALID_PATH_TEST_VECTORS = itertools.product(
    [1, 2, 3, 4], ["PUBLIC_KEY", "PUBLIC_KEY_HASH"]
)


@pytest.mark.parametrize("chain_type, addr_type", INVALID_PATH_TEST_VECTORS)
def test_mintlayer_sign_message_error_path(
    session: Session, chain_type: int, addr_type: str
):
    coin = CHAIN_TYPE_TO_COIN[chain_type]
    # invalid coin
    with pytest.raises(TrezorFailure, match="Forbidden key path"):
        mintlayer.sign_message(
            session,
            address_type=addr_type,
            chain_type=chain_type,
            address_n=parse_path(f"m/44h/{coin + 1}h/0h/0/0"),
            message="Message to sign".encode(),
        )

    # invalid bip44
    with pytest.raises(TrezorFailure, match="Forbidden key path"):
        mintlayer.sign_message(
            session,
            address_type=addr_type,
            chain_type=chain_type,
            address_n=parse_path(f"m/43h/{coin}h/0h/0/0"),
            message="Message to sign".encode(),
        )

    # short path
    with pytest.raises(TrezorFailure, match="Forbidden key path"):
        mintlayer.sign_message(
            session,
            address_type=addr_type,
            chain_type=chain_type,
            address_n=parse_path(f"m/44h/{coin}h"),
            message="Message to sign".encode(),
        )

    # short path
    with pytest.raises(TrezorFailure, match="Forbidden key path"):
        mintlayer.sign_message(
            session,
            address_type=addr_type,
            chain_type=chain_type,
            address_n=parse_path("m/44h"),
            message="Message to sign".encode(),
        )
