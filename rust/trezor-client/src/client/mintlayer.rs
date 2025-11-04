use std::collections::BTreeMap;

use bitcoin::secp256k1;
use protobuf::MessageField;

use super::{handle_interaction, Trezor};
use crate::{
    error::Result,
    protos::{
        self,
        mintlayer_tx_ack::{MintlayerTxInput, MintlayerTxOutput},
        MintlayerChainType, MintlayerTxAck,
    },
    Error,
};

pub mod ml_primitives {
    // Re-export ml_primitives used by the firmware so that mintlayer-core can do its
    // consistency checks without explicitly referencing mintlayer_firmware_deps.
    pub use mintlayer_firmware_deps::ml_primitives::*;
}

/// A chain code
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainCode(pub [u8; 32]);

pub struct XPub {
    pub public_key: secp256k1::PublicKey,
    pub chain_code: ChainCode,
}

#[derive(Debug)]
pub struct MintlayerSignature {
    pub signature: Vec<u8>,
    pub multisig_idx: Option<u32>,
}

impl MintlayerSignature {
    fn new(signature: Vec<u8>, multisig_idx: Option<u32>) -> Self {
        Self { signature, multisig_idx }
    }
}

pub type TransactionId = [u8; 32];

#[derive(Debug, Clone, Copy)]
pub enum SighashInputCommitmentsVersion {
    V0,
    V1,
}

impl SighashInputCommitmentsVersion {
    fn as_msg_param(self) -> u32 {
        match self {
            SighashInputCommitmentsVersion::V0 => 0,
            SighashInputCommitmentsVersion::V1 => 1,
        }
    }
}

pub struct FirmwareInfo {
    pub major_version: u32,
    pub minor_version: u32,
    pub patch_version: u32,
    pub prerelease_id: String,
    pub build_metadata: String,
}

impl Trezor {
    // Mintlayer
    pub fn mintlayer_get_firmware_info(&mut self) -> Result<FirmwareInfo> {
        let msg = self.call::<_, _, protos::MintlayerFirmwareInfo>(
            protos::MintlayerGetFirmwareInfo::new(),
            Box::new(|_, m| {
                Ok(FirmwareInfo {
                    major_version: m.major_version(),
                    minor_version: m.minor_version(),
                    patch_version: m.patch_version(),
                    prerelease_id: m.prerelease_id().to_owned(),
                    build_metadata: m.build_metadata().to_owned(),
                })
            }),
        )?;

        handle_interaction(msg)
    }

    pub fn mintlayer_get_public_key(
        &mut self,
        chain_type: MintlayerChainType,
        path: Vec<u32>,
    ) -> Result<XPub> {
        let mut req = protos::MintlayerGetPublicKey::new();
        req.set_chain_type(chain_type);
        req.address_n = path;
        let msg = self.call::<_, _, protos::MintlayerPublicKey>(
            req,
            Box::new(|_, m| {
                Ok(XPub {
                    public_key: secp256k1::PublicKey::from_slice(m.public_key())?,
                    chain_code: ChainCode(
                        m.chain_code().try_into().map_err(|_| Error::InvalidChaincodeFromDevice)?,
                    ),
                })
            }),
        )?;

        handle_interaction(msg)
    }

    pub fn mintlayer_sign_message(
        &mut self,
        chain_type: MintlayerChainType,
        path: Vec<u32>,
        address_type: protos::MintlayerAddressType,
        message: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let mut req = protos::MintlayerSignMessage::new();
        req.address_n = path;
        req.set_message(message);
        req.set_chain_type(chain_type);
        req.set_address_type(address_type);
        let msg = self.call::<_, _, protos::MessageSignature>(
            req,
            Box::new(|_, m| Ok(m.signature().to_vec())),
        )?;

        handle_interaction(msg)
    }

    pub fn mintlayer_sign_tx(
        &mut self,
        chain_type: MintlayerChainType,
        inputs: Vec<MintlayerTxInput>,
        outputs: Vec<MintlayerTxOutput>,
        utxos: BTreeMap<TransactionId, BTreeMap<u32, MintlayerTxOutput>>,
        input_commitments_version: SighashInputCommitmentsVersion,
    ) -> Result<Vec<Vec<MintlayerSignature>>> {
        let mut req = protos::MintlayerSignTx::new();
        req.set_version(1);
        req.set_chain_type(chain_type);
        req.set_inputs_count(inputs.len() as u32);
        req.set_outputs_count(outputs.len() as u32);
        req.set_input_commitments_version(input_commitments_version.as_msg_param());

        let mut msg = self.call::<_, _, protos::MintlayerTxRequest>(req, Box::new(|_, m| Ok(m)))?;
        loop {
            let response = handle_interaction(msg)?;

            if let Some(inp) = response.input_request.as_ref() {
                let mut req = MintlayerTxAck::new();
                req.input =
                    MessageField::from_option(inputs.get(inp.input_index() as usize).cloned());
                msg = self.call::<_, _, protos::MintlayerTxRequest>(req, Box::new(|_, m| Ok(m)))?;
            } else if let Some(out_req) = response.output_request.as_ref() {
                let mut req = MintlayerTxAck::new();
                if out_req.has_tx_hash() {
                    let tx_id: TransactionId = out_req
                        .tx_hash()
                        .try_into()
                        .map_err(|_| Error::InvalidChaincodeFromDevice)?;
                    let out = utxos.get(&tx_id).and_then(|tx| tx.get(&out_req.output_index()));
                    req.output = MessageField::from_option(out.cloned());
                } else {
                    req.output = MessageField::from_option(
                        outputs.get(out_req.output_index() as usize).cloned(),
                    );
                }
                msg = self.call::<_, _, protos::MintlayerTxRequest>(req, Box::new(|_, m| Ok(m)))?;
            } else if let Some(finish) = response.signing_finished.as_ref() {
                return Ok(finish
                    .signatures
                    .iter()
                    .map(|s| {
                        s.signatures
                            .iter()
                            .map(|s| {
                                MintlayerSignature::new(s.signature().to_vec(), s.multisig_idx)
                            })
                            .collect()
                    })
                    .collect())
            } else {
                return Err(Error::MalformedMintlayerTxRequest(response))
            }
        }
    }
}
