use parity_scale_codec::{DecodeAll as _, Encode};

use mintlayer_firmware_deps::ml_primitives::{
    Amount, BlockHeight, BlockTimestamp, BlocksCount, Destination, GenBlockId, Id,
    IsTokenFreezable, OutPointSourceId, OutputTimeLock, OutputValue, SecondsCount, TransactionId,
    H256,
};

use crate::mintlayer::generated_enums::{
    MintlayerOutputTimeLockType, MintlayerTokenTotalSupplyType, MintlayerUtxoType,
};

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
    PublicKeyDestinationExpected = 9,
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
        MintlayerOutputTimeLockType::UntilHeight => {
            OutputTimeLock::UntilHeight(BlockHeight(lock_amount))
        }
        MintlayerOutputTimeLockType::UntilTime => {
            OutputTimeLock::UntilTime(BlockTimestamp(SecondsCount(lock_amount)))
        }
        MintlayerOutputTimeLockType::ForBlockCount => {
            OutputTimeLock::ForBlockCount(BlocksCount(lock_amount))
        }
        MintlayerOutputTimeLockType::ForSeconds => {
            OutputTimeLock::ForSeconds(SecondsCount(lock_amount))
        }
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
        MintlayerUtxoType::Transaction => OutPointSourceId::Transaction(TransactionId::new(hash)),
        MintlayerUtxoType::Block => OutPointSourceId::BlockReward(GenBlockId::new(hash)),
    }
}

pub fn make_mintlayer_output_timelock_type(
    lock_type: u8,
) -> Result<MintlayerOutputTimeLockType, MintlayerErrorCode> {
    MintlayerOutputTimeLockType::try_from(lock_type as i32)
        .map_err(|_| MintlayerErrorCode::InvalidOutputTimeLock)
}

pub fn make_mintlayer_token_total_supply_type(
    total_supply_type: u8,
) -> Result<MintlayerTokenTotalSupplyType, MintlayerErrorCode> {
    MintlayerTokenTotalSupplyType::try_from(total_supply_type as i32)
        .map_err(|_| MintlayerErrorCode::InvalidTokenTotalSupply)
}

pub fn parse_amount(amount_data: &[u8]) -> Result<Amount, MintlayerErrorCode> {
    amount_data
        .try_into()
        .map_err(|_| MintlayerErrorCode::InvalidAmount)
        .map(|bytes_array| Amount::from_atoms(u128::from_be_bytes(bytes_array)))
}

pub fn parse_hash(hash_data: &[u8]) -> Result<H256, MintlayerErrorCode> {
    Ok(H256(
        hash_data
            .try_into()
            .map_err(|_| MintlayerErrorCode::WrongHashSize)?,
    ))
}

pub fn parse_id<IdTag>(id_data: &[u8]) -> Result<Id<IdTag>, MintlayerErrorCode> {
    let hash = parse_hash(id_data)?;
    Ok(Id::new(hash))
}

pub fn parse_destination(destination_data: &[u8]) -> Result<Destination, MintlayerErrorCode> {
    Destination::decode_all(&mut &*destination_data)
        .map_err(|_| MintlayerErrorCode::InvalidDestination)
}

pub fn parse_output_value(
    amount_data: &[u8],
    token_id_data: &[u8],
) -> Result<OutputValue, MintlayerErrorCode> {
    let amount = parse_amount(amount_data)?;

    let value = if !token_id_data.is_empty() {
        let token_id = Id::new(H256(
            token_id_data
                .try_into()
                .map_err(|_| MintlayerErrorCode::WrongHashSize)?,
        ));
        OutputValue::TokenV1(token_id, amount)
    } else {
        OutputValue::Coin(amount)
    };
    Ok(value)
}
