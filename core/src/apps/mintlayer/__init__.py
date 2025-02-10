from trezor.enums import MintlayerChainType

from apps.common.coininfo import CoinInfo
from apps.common.paths import PATTERN_BIP44, PATTERN_BIP44_PUBKEY

CURVE = "secp256k1"
SLIP44_ID = 19788
PATTERNS = [PATTERN_BIP44, PATTERN_BIP44_PUBKEY]


class Prefixes:
    def __init__(
        self,
        public_key_hash: str,
        public_key: str,
        token: str,
        delegation: str,
        pool: str,
        order: str,
    ) -> None:
        self.public_key_hash = public_key_hash
        self.public_key = public_key
        self.token = token
        self.delegation = delegation
        self.pool = pool
        self.order = order


class MLCoinInfo(CoinInfo):
    def __init__(
        self,
        slip44_id: int,
        coin_name: str,
        coin_shortcut: str,
        decimals: int,
        prefixes: Prefixes,
    ) -> None:
        super().__init__(
            coin_name,
            coin_shortcut,
            decimals,
            0,
            0,
            0,
            "",
            0,
            None,
            None,
            None,
            None,
            None,
            None,
            slip44_id,
            False,
            False,
            None,
            False,
            False,
            False,
            CURVE,
            False,
            False,
            False,
            None,
        )
        self.prefixes = prefixes


TESTNET_COIN = MLCoinInfo(
    slip44_id=1,
    coin_name="testnet",
    coin_shortcut="TML",
    decimals=11,
    prefixes=Prefixes(
        public_key_hash="tmt",
        public_key="tpmt",
        token="tmltk",
        delegation="tdelg",
        pool="tpool",
        order="tordr",
    ),
)

MAINNET_COIN = MLCoinInfo(
    slip44_id=SLIP44_ID,
    coin_name="mainnet",
    coin_shortcut="ML",
    decimals=11,
    prefixes=Prefixes(
        public_key_hash="mtc",
        public_key="mptc",
        token="mmltk",
        delegation="mdelg",
        pool="mpool",
        order="mordr",
    ),
)

REGTEST_COIN = MLCoinInfo(
    slip44_id=1,
    coin_name="regtest",
    coin_shortcut="TML",
    decimals=11,
    prefixes=Prefixes(
        public_key_hash="rmt",
        public_key="rpmt",
        token="rmltk",
        delegation="rdelg",
        pool="rpool",
        order="rordr",
    ),
)

SIGNET_COIN = MLCoinInfo(
    slip44_id=1,
    coin_name="signet",
    coin_shortcut="TML",
    decimals=11,
    prefixes=Prefixes(
        public_key_hash="smt",
        public_key="spmt",
        token="smltk",
        delegation="sdelg",
        pool="spool",
        order="sordr",
    ),
)


def find_coin_by_chain_type(chain_type: MintlayerChainType) -> MLCoinInfo:
    if chain_type == MintlayerChainType.Mainnet:
        return MAINNET_COIN

    if chain_type == MintlayerChainType.Testnet:
        return TESTNET_COIN

    if chain_type == MintlayerChainType.Regtest:
        return REGTEST_COIN

    if chain_type == MintlayerChainType.Signet:
        return SIGNET_COIN

    raise ValueError(f"unknown coin type {chain_type}")
