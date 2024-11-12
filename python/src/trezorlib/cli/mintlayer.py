import base64
import json
from typing import TYPE_CHECKING, TextIO

import click

from .. import messages, mintlayer, protobuf, tools
from . import with_client

if TYPE_CHECKING:
    from ..client import TrezorClient


@click.group(name="mintlayer")
def cli() -> None:
    """Mintalyer coin commands."""


@cli.command()
@click.option("-n", "--address", required=True, help="BIP-32 path")
@click.option("-d", "--show-display", is_flag=True)
@click.option("-C", "--chunkify", is_flag=True)
@with_client
def get_address(
    client: "TrezorClient",
    address: str,
    show_display: bool,
    chunkify: bool,
) -> str:
    """Get address for specified path.

    \b
    $ trezorctl mintlayer get-address -n m/44h/19788h/0h/0/0
    """
    address_n = tools.parse_path(address)

    return mintlayer.get_address(
        client,
        address_n,
        show_display,
        chunkify=chunkify,
    )


@cli.command()
@click.option("-n", "--address", required=True, help="BIP-32 path, e.g. m/44h/0h/0h")
@click.option("-d", "--show-display", is_flag=True)
@with_client
def get_public_key(
    client: "TrezorClient",
    address: str,
    show_display: bool,
) -> dict:
    """Get public key with its chain code of given path.

    \b
    $ trezorctl mintlayer get-public-key -n m/44h/19788h/0h/0/0
    """
    address_n = tools.parse_path(address)
    result = mintlayer.get_public_key(
        client,
        address_n,
        show_display=show_display,
    )
    if isinstance(result, messages.MintlayerPublicKey):
        return {
            "chain_code": result.chain_code.hex(),
            "public_key": result.public_key.hex(),
        }
    else:
        return {"error": result}


@cli.command()
@click.option("-n", "--address_n", required=True, help="BIP-32 path")
@click.option("-a", "--address", required=True, help="bech32 encoded address")
@click.argument("message")
@with_client
def sign_message(
    client: "TrezorClient",
    address_n: str,
    address: str,
    message: str,
) -> dict:
    """Sign message using address of given path."""
    result = mintlayer.sign_message(
        client,
        address_n=tools.parse_path(address_n),
        address=address,
        message=message.encode(),
    )
    if isinstance(result, messages.MessageSignature):
        return {
            "message": message,
            "address": result.address,
            "signature": base64.b64encode(result.signature).decode(),
        }
    else:
        return {"error": result}


@cli.command()
@click.option("-C", "--chunkify", is_flag=True)
@click.argument("json_file", type=click.File())
@with_client
def sign_tx(client: "TrezorClient", json_file: TextIO, chunkify: bool) -> None:
    """Sign transaction.

        Transaction data must be provided in a JSON file. The structure of the JSON matches the shape of the relevant protobuf messages. See
    file [messages-mintlayer.proto] for up-to-date structure
    """
    data = json.load(json_file)
    details = data.get("details", {})
    inputs = [
        protobuf.dict_to_proto(messages.MintlayerTxInput, i)
        for i in data.get("inputs", ())
    ]
    outputs = [
        protobuf.dict_to_proto(messages.MintlayerTxOutput, output)
        for output in data.get("outputs", ())
    ]
    prev_txes = {
        bytes.fromhex(txid): {
            idx: protobuf.dict_to_proto(messages.MintlayerTxOutput, utxo)
            for idx, utxo in tx_utxos.items()
        }
        for txid, tx_utxos in data.get("prev_txes", {}).items()
    }

    results = mintlayer.sign_tx(
        client,
        inputs,
        outputs,
        prev_txs=prev_txes,
        chunkify=chunkify,
        **details,
    )

    click.echo()
    click.echo("Signed signatures:")
    for res in results:
        click.echo(f"signature index: {res.signature_index}")
        click.echo("signature:")
        for sig in res.signatures:
            if sig.multisig_idx is not None:
                click.echo(f"multisig index: {sig.multisig_idx}")
            click.echo(sig.signature.hex())
