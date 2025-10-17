use ml_common::{Amount, IsTokenFreezable, OutPointSourceId, OutputTimeLock, OutputValue, H256};
use parity_scale_codec::Encode;

use crate::mintlayer::generated_enums::{MintlayerOutputTimeLockType, MintlayerUtxoType};

#[repr(C)]
#[derive(Eq, PartialEq, Clone, Copy)]
pub enum MintlayerErrorCode {
    WrongHashSize = 1,
    InvalidUtxoType = 2,
    InvalidAmount = 3,
    InvalidAccountCommand = 4,
    InvalidDestination = 5,
    InvalidIsTokenUnfreezable = 6,
    InvalidIsTokenFreezable = 7,
    InvalidVrfPublicKey = 8,
    InvalidPublicKey = 9,
    InvalidOutputTimeLock = 10,
    InvalidTokenTotalSupply = 11,
    InvalidEncodedUtxo = 12,
}

#[repr(C)]
pub union LenOrError {
    len: cty::c_uint,
    err: MintlayerErrorCode,
}

#[repr(C)]
pub struct ByteArray {
    data: *const cty::c_uchar,
    len_or_err: LenOrError,
}

impl From<MintlayerErrorCode> for ByteArray {
    fn from(err: MintlayerErrorCode) -> Self {
        Self {
            data: core::ptr::null(),
            len_or_err: LenOrError { err },
        }
    }
}

impl ByteArray {
    pub fn data(&self) -> *const cty::c_uchar {
        self.data
    }
}

pub fn handle_err_or_encode<T: Encode>(x: Result<T, MintlayerErrorCode>) -> ByteArray {
    match x {
        Ok(value) => encode_to_byte_array(&value),
        Err(value) => value.into(),
    }
}

pub fn encode_to_byte_array<T: Encode>(x: &T) -> ByteArray {
    let vec_data = x.encode();
    // Extracting the raw pointer and length from the Vec<u8>
    let ptr_data = vec_data.as_ptr();
    let len = vec_data.len() as cty::c_uint;

    // Prevent Rust from freeing the memory associated with vec_data
    core::mem::forget(vec_data);

    // Construct and return the ByteArray struct
    ByteArray {
        data: ptr_data,
        len_or_err: LenOrError { len },
    }
}

pub fn make_output_time_lock(
    lock_type: MintlayerOutputTimeLockType,
    lock_amount: u64,
) -> OutputTimeLock {
    match lock_type {
        MintlayerOutputTimeLockType::UntilHeight => OutputTimeLock::UntilHeight(lock_amount),
        MintlayerOutputTimeLockType::UntilTime => OutputTimeLock::UntilTime(lock_amount),
        MintlayerOutputTimeLockType::ForBlockCount => OutputTimeLock::ForBlockCount(lock_amount),
        MintlayerOutputTimeLockType::ForSeconds => OutputTimeLock::ForSeconds(lock_amount),
    }
}

pub fn make_is_token_freezable(is_freezable: bool) -> IsTokenFreezable {
    if is_freezable {
        IsTokenFreezable::Yes
    } else {
        IsTokenFreezable::No
    }
}

pub fn make_outpoint_source_id(utxo_type: MintlayerUtxoType, hash: H256) -> OutPointSourceId {
    match utxo_type {
        MintlayerUtxoType::Transaction => OutPointSourceId::Transaction(hash),
        MintlayerUtxoType::Block => OutPointSourceId::BlockReward(hash),
    }
}

pub fn parse_amount(amount_data: &[u8]) -> Result<Amount, MintlayerErrorCode> {
    Amount::from_bytes_be(amount_data).ok_or(MintlayerErrorCode::InvalidAmount)
}

pub fn parse_output_value(
    amount_data: &[u8],
    token_id_data: &[u8],
) -> Result<OutputValue, MintlayerErrorCode> {
    let amount = parse_amount(amount_data)?;

    let value = if !token_id_data.is_empty() {
        let token_id = H256(
            token_id_data
                .try_into()
                .map_err(|_| MintlayerErrorCode::WrongHashSize)?,
        );
        OutputValue::TokenV1(token_id, amount)
    } else {
        OutputValue::Coin(amount)
    };
    Ok(value)
}
