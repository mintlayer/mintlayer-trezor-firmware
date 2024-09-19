use crate::micropython::ffi;
use core::{
    alloc::{GlobalAlloc, Layout},
    num::ParseIntError,
    ptr::null_mut,
    str::FromStr,
};

use parity_scale_codec::{Decode, DecodeAll, Encode};

const TEN: UnsignedIntType = 10;

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

#[no_mangle]
extern "C" fn mintlayer_encode_utxo_input(
    data: *const u8,
    data_len: u32,
    index: u32,
    utxo_type: u32,
) -> ByteArray {
    let hash = unsafe { core::slice::from_raw_parts(data, data_len as usize) };
    let hash = H256(match hash.try_into() {
        Ok(hash) => hash,
        Err(_) => return MintlayerErrorCode::WrongHashSize.into(),
    });

    let outpoint = match utxo_type {
        0 => OutPointSourceId::Transaction(hash),
        1 => OutPointSourceId::BlockReward(hash),
        _ => return MintlayerErrorCode::InvalidUtxoType.into(),
    };
    let utxo_outpoint = UtxoOutPoint::new(outpoint, index);
    let tx_input = TxInput::Utxo(utxo_outpoint);
    let vec_data = tx_input.encode();
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

#[no_mangle]
extern "C" fn mintlayer_encode_account_spending_input(
    nonce: u64,
    delegation_id_data: *const u8,
    delegation_id_data_len: u32,
    amount_data: *const u8,
    amount_data_len: u32,
) -> ByteArray {
    let delegation_id =
        unsafe { core::slice::from_raw_parts(delegation_id_data, delegation_id_data_len as usize) };
    let delegation_id = H256(match delegation_id.try_into() {
        Ok(hash) => hash,
        Err(_) => return MintlayerErrorCode::WrongHashSize.into(),
    });

    let coin_amount = unsafe { core::slice::from_raw_parts(amount_data, amount_data_len as usize) };
    let amount = match Amount::from_bytes_be(coin_amount.as_ref()) {
        Some(amount) => amount,
        None => return MintlayerErrorCode::InvalidAmount.into(),
    };

    let tx_input = TxInput::Account(AccountOutPoint {
        nonce,
        account: AccountSpending::DelegationBalance(delegation_id, amount),
    });
    let vec_data = tx_input.encode();
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

#[no_mangle]
extern "C" fn mintlayer_encode_token_account_command_input(
    nonce: u64,
    command: u32,
    token_id_data: *const u8,
    token_id_data_len: u32,
    data: *const u8,
    data_len: u32,
) -> ByteArray {
    let token_id =
        unsafe { core::slice::from_raw_parts(token_id_data, token_id_data_len as usize) };
    let token_id = H256(match token_id.try_into() {
        Ok(hash) => hash,
        Err(_) => return MintlayerErrorCode::WrongHashSize.into(),
    });

    let data = unsafe { core::slice::from_raw_parts(data, data_len as usize) };
    let account_command = match command {
        0 => {
            let amount = match Amount::from_bytes_be(data.as_ref()) {
                Some(amount) => amount,
                None => return MintlayerErrorCode::InvalidAmount.into(),
            };
            AccountCommand::MintTokens(token_id, amount)
        }
        1 => AccountCommand::UnmintTokens(token_id),
        2 => AccountCommand::LockTokenSupply(token_id),
        3 => {
            let is_token_unfreezabe = match IsTokenUnfreezable::decode_all(&mut data.as_ref()) {
                Ok(res) => res,
                Err(_) => return MintlayerErrorCode::InvalidIsTokenUnfreezable.into(),
            };
            AccountCommand::FreezeToken(token_id, is_token_unfreezabe)
        }
        4 => AccountCommand::UnfreezeToken(token_id),
        5 => {
            let destination = match Destination::decode_all(&mut data.as_ref()) {
                Ok(destination) => destination,
                Err(_) => return MintlayerErrorCode::InvalidDestination.into(),
            };
            AccountCommand::ChangeTokenAuthority(token_id, destination)
        }
        8 => AccountCommand::ChangeTokenMetadataUri(token_id, data.to_vec()),
        _ => return MintlayerErrorCode::InvalidAccountCommand.into(),
    };

    let tx_input = TxInput::AccountCommand(nonce, account_command);
    let vec_data = tx_input.encode();
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

#[no_mangle]
extern "C" fn mintlayer_encode_conclude_order_account_command_input(
    nonce: u64,
    order_id_data: *const u8,
    order_id_data_len: u32,
) -> ByteArray {
    let order_id =
        unsafe { core::slice::from_raw_parts(order_id_data, order_id_data_len as usize) };
    let order_id = H256(match order_id.try_into() {
        Ok(hash) => hash,
        Err(_) => return MintlayerErrorCode::WrongHashSize.into(),
    });
    let account_command = AccountCommand::ConcludeOrder(order_id);

    let tx_input = TxInput::AccountCommand(nonce, account_command);
    let vec_data = tx_input.encode();
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

#[no_mangle]
extern "C" fn mintlayer_encode_fill_order_account_command_input(
    nonce: u64,
    order_id_data: *const u8,
    order_id_data_len: u32,
    amount_data: *const u8,
    amount_data_len: u32,
    token_id_data: *const u8,
    token_id_data_len: u32,
    destination_data: *const u8,
    destination_data_len: u32,
) -> ByteArray {
    let order_id =
        unsafe { core::slice::from_raw_parts(order_id_data, order_id_data_len as usize) };
    let order_id = H256(match order_id.try_into() {
        Ok(hash) => hash,
        Err(_) => return MintlayerErrorCode::WrongHashSize.into(),
    });
    let value = match parse_output_value(
        amount_data,
        amount_data_len,
        token_id_data_len,
        token_id_data,
    ) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let destination_bytes =
        unsafe { core::slice::from_raw_parts(destination_data, destination_data_len as usize) };
    let destination = match Destination::decode_all(&mut destination_bytes.as_ref()) {
        Ok(destination) => destination,
        Err(_) => return MintlayerErrorCode::InvalidDestination.into(),
    };
    let account_command = AccountCommand::FillOrder(order_id, value, destination);

    let tx_input = TxInput::AccountCommand(nonce, account_command);
    let vec_data = tx_input.encode();
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

fn parse_output_value(
    amount_data: *const u8,
    amount_data_len: u32,
    token_id_data_len: u32,
    token_id_data: *const u8,
) -> Result<OutputValue, ByteArray> {
    let coin_amount = unsafe { core::slice::from_raw_parts(amount_data, amount_data_len as usize) };
    let amount = match Amount::from_bytes_be(coin_amount.as_ref()) {
        Some(amount) => amount,
        None => return Err(MintlayerErrorCode::InvalidAmount.into()),
    };
    let value = if token_id_data_len == 32 {
        let token_id =
            unsafe { core::slice::from_raw_parts(token_id_data, token_id_data_len as usize) };
        let token_id = H256(match token_id.try_into() {
            Ok(hash) => hash,
            Err(_) => return Err(MintlayerErrorCode::WrongHashSize.into()),
        });
        OutputValue::TokenV1(token_id, amount)
    } else {
        OutputValue::Coin(amount)
    };
    Ok(value)
}

#[no_mangle]
extern "C" fn mintlayer_encode_transfer_output(
    amount_data: *const u8,
    amount_data_len: u32,
    token_id_data: *const u8,
    token_id_data_len: u32,
    destination_data: *const u8,
    destination_data_len: u32,
) -> ByteArray {
    let value = match parse_output_value(
        amount_data,
        amount_data_len,
        token_id_data_len,
        token_id_data,
    ) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let destination_bytes =
        unsafe { core::slice::from_raw_parts(destination_data, destination_data_len as usize) };
    let destination = match Destination::decode_all(&mut destination_bytes.as_ref()) {
        Ok(destination) => destination,
        Err(_) => return MintlayerErrorCode::InvalidDestination.into(),
    };

    let txo = TxOutput::Transfer(value, destination);

    let vec_data = txo.encode();
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

#[no_mangle]
extern "C" fn mintlayer_encode_lock_then_transfer_output(
    amount_data: *const u8,
    amount_data_len: u32,
    token_id_data: *const u8,
    token_id_data_len: u32,
    lock_type: u8,
    lock_amount: u64,
    destination_data: *const u8,
    destination_data_len: u32,
) -> ByteArray {
    let value = match parse_output_value(
        amount_data,
        amount_data_len,
        token_id_data_len,
        token_id_data,
    ) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let destination_bytes =
        unsafe { core::slice::from_raw_parts(destination_data, destination_data_len as usize) };
    let destination = match Destination::decode_all(&mut destination_bytes.as_ref()) {
        Ok(destination) => destination,
        Err(_) => return MintlayerErrorCode::InvalidDestination.into(),
    };

    let lock = match lock_type {
        0 => OutputTimeLock::UntilHeight(lock_amount),
        1 => OutputTimeLock::UntilTime(lock_amount),
        2 => OutputTimeLock::ForBlockCount(lock_amount),
        3 => OutputTimeLock::ForSeconds(lock_amount),
        _ => return MintlayerErrorCode::InvalidOutputTimeLock.into(),
    };

    let txo = TxOutput::LockThenTransfer(value, destination, lock);

    let vec_data = txo.encode();
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

#[no_mangle]
extern "C" fn mintlayer_encode_burn_output(
    amount_data: *const u8,
    amount_data_len: u32,
    token_id_data: *const u8,
    token_id_data_len: u32,
) -> ByteArray {
    let value = match parse_output_value(
        amount_data,
        amount_data_len,
        token_id_data_len,
        token_id_data,
    ) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let txo = TxOutput::Burn(value);

    let vec_data = txo.encode();
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

#[no_mangle]
extern "C" fn mintlayer_encode_create_stake_pool_output(
    pool_id_data: *const u8,
    pool_id_data_len: u32,
    pledge_amount_data: *const u8,
    pledge_amount_data_len: u32,
    staker_destination_data: *const u8,
    staker_destination_data_len: u32,
    vrf_public_key_data: *const u8,
    vrf_public_key_data_len: u32,
    decommission_destination_data: *const u8,
    decommission_destination_data_len: u32,
    margin_ratio_per_thousand: u16,
    cost_per_block_amount_data: *const u8,
    cost_per_block_amount_data_len: u32,
) -> ByteArray {
    let pool_id = unsafe { core::slice::from_raw_parts(pool_id_data, pool_id_data_len as usize) };
    let pool_id = H256(match pool_id.try_into() {
        Ok(hash) => hash,
        Err(_) => return MintlayerErrorCode::WrongHashSize.into(),
    });
    let coin_amount =
        unsafe { core::slice::from_raw_parts(pledge_amount_data, pledge_amount_data_len as usize) };
    let pledge = match Amount::from_bytes_be(coin_amount.as_ref()) {
        Some(amount) => amount,
        None => return MintlayerErrorCode::InvalidAmount.into(),
    };

    let destination_bytes = unsafe {
        core::slice::from_raw_parts(
            staker_destination_data,
            staker_destination_data_len as usize,
        )
    };
    let staker = match Destination::decode_all(&mut destination_bytes.as_ref()) {
        Ok(destination) => destination,
        Err(_) => return MintlayerErrorCode::InvalidDestination.into(),
    };

    let vrf_public_key = unsafe {
        core::slice::from_raw_parts(vrf_public_key_data, vrf_public_key_data_len as usize)
    };
    let vrf_public_key = match VRFPublicKeyHolder::decode_all(&mut vrf_public_key.as_ref()) {
        Ok(res) => res,
        Err(_) => return MintlayerErrorCode::InvalidVrfPublicKey.into(),
    };

    let destination_bytes = unsafe {
        core::slice::from_raw_parts(
            decommission_destination_data,
            decommission_destination_data_len as usize,
        )
    };
    let decommission_key = match Destination::decode_all(&mut destination_bytes.as_ref()) {
        Ok(destination) => destination,
        Err(_) => return MintlayerErrorCode::InvalidDestination.into(),
    };
    let coin_amount = unsafe {
        core::slice::from_raw_parts(
            cost_per_block_amount_data,
            cost_per_block_amount_data_len as usize,
        )
    };
    let cost_per_block = match Amount::from_bytes_be(coin_amount.as_ref()) {
        Some(amount) => amount,
        None => return MintlayerErrorCode::InvalidAmount.into(),
    };

    let txo = TxOutput::CreateStakePool(
        pool_id,
        StakePoolData {
            pledge,
            staker,
            decommission_key,
            vrf_public_key,
            margin_ratio_per_thousand,
            cost_per_block,
        },
    );

    let vec_data = txo.encode();
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

#[no_mangle]
extern "C" fn mintlayer_encode_produce_from_stake_output(
    destination_data: *const u8,
    destination_data_len: u32,
    pool_id_data: *const u8,
    pool_id_data_len: u32,
) -> ByteArray {
    let pool_id = unsafe { core::slice::from_raw_parts(pool_id_data, pool_id_data_len as usize) };
    let pool_id = H256(match pool_id.try_into() {
        Ok(hash) => hash,
        Err(_) => return MintlayerErrorCode::WrongHashSize.into(),
    });

    let destination_bytes =
        unsafe { core::slice::from_raw_parts(destination_data, destination_data_len as usize) };
    let destination = match Destination::decode_all(&mut destination_bytes.as_ref()) {
        Ok(destination) => destination,
        Err(_) => return MintlayerErrorCode::InvalidDestination.into(),
    };

    let txo = TxOutput::ProduceBlockFromStake(destination, pool_id);

    let vec_data = txo.encode();
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

#[no_mangle]
extern "C" fn mintlayer_encode_create_delegation_id_output(
    destination_data: *const u8,
    destination_data_len: u32,
    pool_id_data: *const u8,
    pool_id_data_len: u32,
) -> ByteArray {
    let pool_id = unsafe { core::slice::from_raw_parts(pool_id_data, pool_id_data_len as usize) };
    let pool_id = H256(match pool_id.try_into() {
        Ok(hash) => hash,
        Err(_) => return MintlayerErrorCode::WrongHashSize.into(),
    });

    let destination_bytes =
        unsafe { core::slice::from_raw_parts(destination_data, destination_data_len as usize) };
    let destination = match Destination::decode_all(&mut destination_bytes.as_ref()) {
        Ok(destination) => destination,
        Err(_) => return MintlayerErrorCode::InvalidDestination.into(),
    };

    let txo = TxOutput::CreateDelegationId(destination, pool_id);

    let vec_data = txo.encode();
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

#[no_mangle]
extern "C" fn mintlayer_encode_delegate_staking_output(
    amount_data: *const u8,
    amount_data_len: u32,
    delegation_id_data: *const u8,
    delegation_id_data_len: u32,
) -> ByteArray {
    let coin_amount = unsafe { core::slice::from_raw_parts(amount_data, amount_data_len as usize) };
    let amount = match Amount::from_bytes_be(coin_amount.as_ref()) {
        Some(amount) => amount,
        None => return MintlayerErrorCode::InvalidAmount.into(),
    };

    let delegation_id =
        unsafe { core::slice::from_raw_parts(delegation_id_data, delegation_id_data_len as usize) };
    let delegation_id = H256(match delegation_id.try_into() {
        Ok(hash) => hash,
        Err(_) => return MintlayerErrorCode::WrongHashSize.into(),
    });

    let txo = TxOutput::DelegateStaking(amount, delegation_id);

    let vec_data = txo.encode();
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

#[no_mangle]
extern "C" fn mintlayer_encode_issue_fungible_token_output(
    token_ticker_data: *const u8,
    token_ticker_data_len: u32,
    number_of_decimals: u8,
    metadata_uri_data: *const u8,
    metadata_uri_data_len: u32,
    total_supply_type: u32,
    fixed_amount_data: *const u8,
    fixed_amount_data_len: u32,
    authority_data: *const u8,
    authority_data_len: u32,
    is_freezable: u8,
) -> ByteArray {
    let token_ticker =
        unsafe { core::slice::from_raw_parts(token_ticker_data, token_ticker_data_len as usize) };
    let token_ticker = token_ticker.to_vec();

    let metadata_uri =
        unsafe { core::slice::from_raw_parts(metadata_uri_data, metadata_uri_data_len as usize) };
    let metadata_uri = metadata_uri.to_vec();

    let authority_bytes =
        unsafe { core::slice::from_raw_parts(authority_data, authority_data_len as usize) };
    let authority = match Destination::decode_all(&mut authority_bytes.as_ref()) {
        Ok(destination) => destination,
        Err(_) => return MintlayerErrorCode::InvalidDestination.into(),
    };

    let is_freezable = match is_freezable {
        0 => IsTokenFreezable::No,
        1 => IsTokenFreezable::Yes,
        _ => return MintlayerErrorCode::InvalidIsTokenFreezable.into(),
    };

    let total_supply = match total_supply_type {
        0 => {
            let coin_amount = unsafe {
                core::slice::from_raw_parts(fixed_amount_data, fixed_amount_data_len as usize)
            };
            let amount = match Amount::from_bytes_be(coin_amount.as_ref()) {
                Some(amount) => amount,
                None => return MintlayerErrorCode::InvalidAmount.into(),
            };
            TokenTotalSupply::Fixed(amount)
        }
        1 => TokenTotalSupply::Lockable,
        2 => TokenTotalSupply::Unlimited,
        _ => return MintlayerErrorCode::InvalidTokenTotalSupply.into(),
    };

    let issuance = TokenIssuance::V1(TokenIssuanceV1 {
        token_ticker,
        number_of_decimals,
        metadata_uri,
        total_supply,
        authority,
        is_freezable,
    });

    let txo = TxOutput::IssueFungibleToken(issuance);

    let vec_data = txo.encode();
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

#[no_mangle]
extern "C" fn mintlayer_encode_issue_nft_output(
    token_id_data: *const u8,
    token_id_data_len: u32,
    creator_data: *const u8,
    creator_data_len: u32,
    name_data: *const u8,
    name_data_len: u32,
    description_data: *const u8,
    description_data_len: u32,
    ticker_data: *const u8,
    ticker_data_len: u32,
    icon_uri_data: *const u8,
    icon_uri_data_len: u32,
    additional_metadata_uri_data: *const u8,
    additional_metadata_uri_data_len: u32,
    media_uri_data: *const u8,
    media_uri_data_len: u32,
    media_hash_data: *const u8,
    media_hash_data_len: u32,
    destination_data: *const u8,
    destination_data_len: u32,
) -> ByteArray {
    let token_id =
        unsafe { core::slice::from_raw_parts(token_id_data, token_id_data_len as usize) };
    let token_id = H256(match token_id.try_into() {
        Ok(hash) => hash,
        Err(_) => return MintlayerErrorCode::WrongHashSize.into(),
    });

    let creator = unsafe { core::slice::from_raw_parts(creator_data, creator_data_len as usize) };

    let creator = if creator_data_len == 0 {
        None
    } else {
        Some(PublicKeyHolder::Secp256k1Schnorr(PublicKey(
            match creator.try_into() {
                Ok(res) => res,
                Err(_) => return MintlayerErrorCode::InvalidPublicKey.into(),
            },
        )))
    };

    let name = unsafe { core::slice::from_raw_parts(name_data, name_data_len as usize) };
    let name = name.to_vec();

    let description =
        unsafe { core::slice::from_raw_parts(description_data, description_data_len as usize) };
    let description = description.to_vec();

    let ticker = unsafe { core::slice::from_raw_parts(ticker_data, ticker_data_len as usize) };
    let ticker = ticker.to_vec();

    let icon_uri =
        unsafe { core::slice::from_raw_parts(icon_uri_data, icon_uri_data_len as usize) };
    let icon_uri = icon_uri.to_vec();

    let additional_metadata_uri = unsafe {
        core::slice::from_raw_parts(
            additional_metadata_uri_data,
            additional_metadata_uri_data_len as usize,
        )
    };
    let additional_metadata_uri = additional_metadata_uri.to_vec();

    let media_uri =
        unsafe { core::slice::from_raw_parts(media_uri_data, media_uri_data_len as usize) };
    let media_uri = media_uri.to_vec();

    let media_hash =
        unsafe { core::slice::from_raw_parts(media_hash_data, media_hash_data_len as usize) };
    let media_hash = media_hash.to_vec();

    let destination_bytes =
        unsafe { core::slice::from_raw_parts(destination_data, destination_data_len as usize) };
    let destination = match Destination::decode_all(&mut destination_bytes.as_ref()) {
        Ok(destination) => destination,
        Err(_) => return MintlayerErrorCode::InvalidDestination.into(),
    };

    let issuance = NftIssuance::V0(NftIssuanceV0 {
        metadata: Metadata {
            creator,
            name,
            description,
            ticker,
            icon_uri,
            additional_metadata_uri,
            media_uri,
            media_hash,
        },
    });

    let txo = TxOutput::IssueNft(token_id, issuance, destination);

    let vec_data = txo.encode();
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

#[no_mangle]
extern "C" fn mintlayer_encode_data_deposit_output(
    deposit_data: *const u8,
    deposit_data_len: u32,
) -> ByteArray {
    let deposit = unsafe { core::slice::from_raw_parts(deposit_data, deposit_data_len as usize) };
    let deposit = deposit.to_vec();

    let txo = TxOutput::DataDeposit(deposit);

    let vec_data = txo.encode();
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

#[no_mangle]
extern "C" fn mintlayer_encode_htlc_output(
    amount_data: *const u8,
    amount_data_len: u32,
    token_id_data: *const u8,
    token_id_data_len: u32,
    lock_type: u8,
    lock_amount: u64,
    refund_destination_data: *const u8,
    refund_destination_data_len: u32,
    spend_destination_data: *const u8,
    spend_destination_data_len: u32,
    secret_hash_data: *const u8,
    secret_hash_data_len: u32,
) -> ByteArray {
    let value = match parse_output_value(
        amount_data,
        amount_data_len,
        token_id_data_len,
        token_id_data,
    ) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let refund_destination_bytes = unsafe {
        core::slice::from_raw_parts(
            refund_destination_data,
            refund_destination_data_len as usize,
        )
    };
    let refund_key = match Destination::decode_all(&mut refund_destination_bytes.as_ref()) {
        Ok(destination) => destination,
        Err(_) => return MintlayerErrorCode::InvalidDestination.into(),
    };
    let spend_destination_bytes = unsafe {
        core::slice::from_raw_parts(spend_destination_data, spend_destination_data_len as usize)
    };
    let spend_key = match Destination::decode_all(&mut spend_destination_bytes.as_ref()) {
        Ok(destination) => destination,
        Err(_) => return MintlayerErrorCode::InvalidDestination.into(),
    };

    let hash =
        unsafe { core::slice::from_raw_parts(secret_hash_data, secret_hash_data_len as usize) };
    let secret_hash = HtlcSecretHash(match hash.try_into() {
        Ok(hash) => hash,
        Err(_) => return MintlayerErrorCode::WrongHashSize.into(),
    });

    let refund_timelock = match lock_type {
        0 => OutputTimeLock::UntilHeight(lock_amount),
        1 => OutputTimeLock::UntilTime(lock_amount),
        2 => OutputTimeLock::ForBlockCount(lock_amount),
        3 => OutputTimeLock::ForSeconds(lock_amount),
        _ => return MintlayerErrorCode::InvalidOutputTimeLock.into(),
    };

    let txo = TxOutput::Htlc(
        value,
        HashedTimelockContract {
            secret_hash,
            spend_key,
            refund_timelock,
            refund_key,
        },
    );

    let vec_data = txo.encode();
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

#[no_mangle]
extern "C" fn mintlayer_encode_anyone_can_take_output(
    destination_data: *const u8,
    destination_data_len: u32,
    ask_amount_data: *const u8,
    ask_amount_data_len: u32,
    ask_token_id_data: *const u8,
    ask_token_id_data_len: u32,
    give_amount_data: *const u8,
    give_amount_data_len: u32,
    give_token_id_data: *const u8,
    give_token_id_data_len: u32,
) -> ByteArray {
    let ask_value = match parse_output_value(
        ask_amount_data,
        ask_amount_data_len,
        ask_token_id_data_len,
        ask_token_id_data,
    ) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let give_value = match parse_output_value(
        give_amount_data,
        give_amount_data_len,
        give_token_id_data_len,
        give_token_id_data,
    ) {
        Ok(value) => value,
        Err(value) => return value,
    };

    let destination_bytes =
        unsafe { core::slice::from_raw_parts(destination_data, destination_data_len as usize) };
    let destination = match Destination::decode_all(&mut destination_bytes.as_ref()) {
        Ok(destination) => destination,
        Err(_) => return MintlayerErrorCode::InvalidDestination.into(),
    };

    let txo = TxOutput::AnyoneCanTake(OrderData {
        conclude_key: destination,
        ask: ask_value,
        give: give_value,
    });

    let vec_data = txo.encode();
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

#[derive(Encode, Debug, PartialEq, Eq)]
struct CompactLength {
    #[codec(compact)]
    pub value: u32,
}

#[no_mangle]
extern "C" fn mintlayer_encode_compact_length(length: u32) -> ByteArray {
    let vec_data = CompactLength { value: length }.encode();
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

struct CustomAllocator;

unsafe impl GlobalAlloc for CustomAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe {
            let ptr_void = ffi::gc_alloc(layout.size(), 0); // Call ffi::gc_alloc
            if ptr_void.is_null() {
                return null_mut();
            }
            ptr_void as *mut u8 // Cast the pointer to *mut u8
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Implement deallocation logic here if needed
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: CustomAllocator = CustomAllocator;

/// Specifies which parts of the transaction a signature commits to.
///
/// The values of the flags are the same as in Bitcoin.
#[derive(Eq, PartialEq, Clone, Copy, Debug, Ord, PartialOrd, Encode, Decode)]
struct SigHashType(u8);

impl SigHashType {
    pub const ALL: u8 = 0x01;
    pub const NONE: u8 = 0x02;
    pub const SINGLE: u8 = 0x03;
    pub const ANYONECANPAY: u8 = 0x80;

    const MASK_OUT: u8 = 0x7f;
    const MASK_IN: u8 = 0x80;

    // pub fn inputs_mode(&self) -> InputsMode {
    //     match self.0 & Self::MASK_IN {
    //         Self::ANYONECANPAY => InputsMode::AnyoneCanPay,
    //         _ => InputsMode::CommitWhoPays,
    //     }
    // }

    // pub fn outputs_mode(&self) -> OutputsMode {
    //     match self.0 & Self::MASK_OUT {
    //         Self::NONE => OutputsMode::None,
    //         Self::SINGLE => OutputsMode::Single,
    //         _ => OutputsMode::All,
    //     }
    // }

    pub fn get(&self) -> u8 {
        self.0
    }
}

type UnsignedIntType = u128;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
struct Amount {
    #[codec(compact)]
    atoms: UnsignedIntType,
}

impl Amount {
    pub const MAX: Self = Self::from_atoms(UnsignedIntType::MAX);
    pub const ZERO: Self = Self::from_atoms(0);

    pub const fn from_atoms(v: UnsignedIntType) -> Self {
        Amount { atoms: v }
    }

    pub const fn into_atoms(&self) -> UnsignedIntType {
        self.atoms
    }

    pub fn from_bytes_be(bytes: &[u8]) -> Option<Self> {
        bytes
            .try_into()
            .ok()
            .map(|b| Self::from_atoms(UnsignedIntType::from_be_bytes(b)))
    }

    pub fn from_fixedpoint_str(amount_str: &str, decimals: u8) -> Option<Self> {
        amount_str
            .parse::<DecimalAmount>()
            .ok()?
            .to_amount(decimals)
    }
}

#[derive(Clone, Copy, Debug)]
struct DecimalAmount {
    mantissa: UnsignedIntType,
    decimals: u8,
}

impl DecimalAmount {
    pub const ZERO: Self = Self::from_uint_integral(0);

    /// Convert from integer with no decimals
    pub const fn from_uint_integral(number: u128) -> Self {
        Self::from_uint_decimal(number, 0)
    }

    /// Convert from integer, interpreting the last N digits as the fractional
    /// part
    pub const fn from_uint_decimal(mantissa: UnsignedIntType, decimals: u8) -> Self {
        Self { mantissa, decimals }
    }

    /// Convert from amount, keeping all decimal digits
    pub const fn from_amount_full_padding(amount: Amount, decimals: u8) -> Self {
        Self::from_uint_decimal(amount.into_atoms(), decimals)
    }

    /// Convert from amount, keeping as few decimal digits as possible (without
    /// losing precision)
    pub const fn from_amount_no_padding(amount: Amount, decimals: u8) -> Self {
        Self::from_amount_full_padding(amount, decimals).without_padding()
    }

    /// Convert to amount using given number of decimals
    pub fn to_amount(self, decimals: u8) -> Option<Amount> {
        Some(Amount::from_atoms(self.with_decimals(decimals)?.mantissa))
    }

    /// Change the number of decimals. Can only increase decimals, otherwise we
    /// risk losing digits.
    pub fn with_decimals(self, decimals: u8) -> Option<Self> {
        let extra_decimals = decimals.checked_sub(self.decimals)?;
        let mantissa = self
            .mantissa
            .checked_mul(TEN.checked_pow(extra_decimals as u32)?)?;
        Some(Self::from_uint_decimal(mantissa, decimals))
    }

    /// Trim trailing zeroes in the fractional part
    pub const fn without_padding(mut self) -> Self {
        while self.decimals > 0 && self.mantissa % TEN == 0 {
            self.mantissa /= TEN;
            self.decimals -= 1;
        }
        self
    }

    /// Check this is the same number presented with the same precision
    pub fn is_same(&self, other: &Self) -> bool {
        (self.mantissa, self.decimals) == (other.mantissa, other.decimals)
    }
}

fn empty_to_zero(s: &str) -> &str {
    match s {
        "" => "0",
        s => s,
    }
}

#[derive(/* thiserror::Error, */ Debug, PartialEq, Eq)]
enum ParseError {
    // #[error("Resulting number is too big")]
    OutOfRange,

    // #[error("The number string is too long")]
    StringTooLong,

    // #[error("Empty input")]
    EmptyString,

    // #[error("Invalid character used in number")]
    IllegalChar,

    // #[error("Number does not contain any digits")]
    NoDigits,
    // #[error(transparent)]
    IntParse(ParseIntError),
}

impl FromStr for DecimalAmount {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // ensure!(s.len() <= 100, ParseError::StringTooLong);

        let s = s.trim_matches(' ');
        let s = s.replace('_', "");
        // ensure!(!s.is_empty(), ParseError::EmptyString);

        let (int_str, frac_str) = s.split_once('.').unwrap_or((&s, ""));

        // let mut chars = int_str.chars().chain(frac_str.chars());
        // ensure!(chars.all(|c| c.is_ascii_digit()), ParseError::IllegalChar);
        // ensure!(int_str.len() + frac_str.len() > 0, ParseError::NoDigits);

        let int: UnsignedIntType = empty_to_zero(int_str)
            .parse()
            .map_err(ParseError::IntParse)?;
        let frac: UnsignedIntType = empty_to_zero(frac_str)
            .parse()
            .map_err(ParseError::IntParse)?;

        let decimals: u8 = frac_str
            .len()
            .try_into()
            .expect("Checked string length above");

        let mantissa = TEN
            .checked_pow(decimals as u32)
            .and_then(|mul| int.checked_mul(mul))
            .and_then(|shifted| shifted.checked_add(frac))
            .ok_or(ParseError::OutOfRange)?;

        Ok(Self::from_uint_decimal(mantissa, decimals))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
enum OutputValue {
    Coin(Amount),
    TokenV0,
    TokenV1(H256, Amount),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
enum OutputTimeLock {
    #[codec(index = 0)]
    UntilHeight(#[codec(compact)] u64),
    #[codec(index = 1)]
    UntilTime(#[codec(compact)] u64),
    #[codec(index = 2)]
    ForBlockCount(#[codec(compact)] u64),
    #[codec(index = 3)]
    ForSeconds(#[codec(compact)] u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct StakePoolData {
    pledge: Amount,
    staker: Destination,
    vrf_public_key: VRFPublicKeyHolder,
    decommission_key: Destination,
    margin_ratio_per_thousand: u16,
    cost_per_block: Amount,
}

const HASH_SIZE: usize = 20;
const PK_SIZE: usize = 33;
const VRF_PK_SIZE: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
struct PublicKeyHash(pub [u8; HASH_SIZE]);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
struct PublicKey(pub [u8; PK_SIZE]);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
struct VRFPublicKey(pub [u8; VRF_PK_SIZE]);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Decode, Encode)]
enum VRFPublicKeyHolder {
    #[codec(index = 0)]
    Schnorrkel(VRFPublicKey),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Decode, Encode)]
enum PublicKeyHolder {
    #[codec(index = 0)]
    Secp256k1Schnorr(PublicKey),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
enum Destination {
    #[codec(index = 0)]
    AnyoneCanSpend, /* zero verification; used primarily for testing. Never use this for real
                     * money */
    #[codec(index = 1)]
    PublicKeyHash(PublicKeyHash),
    #[codec(index = 2)]
    PublicKey(PublicKeyHolder),
    #[codec(index = 3)]
    ScriptHash(H256),
    #[codec(index = 4)]
    ClassicMultisig(PublicKeyHash),
}

#[derive(Encode)]
enum TokenIssuance {
    #[codec(index = 1)]
    V1(TokenIssuanceV1),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
enum IsTokenFreezable {
    #[codec(index = 0)]
    No,
    #[codec(index = 1)]
    Yes,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
enum TokenTotalSupply {
    #[codec(index = 0)]
    Fixed(Amount), // fixed to a certain amount
    #[codec(index = 1)]
    Lockable, // not known in advance but can be locked once at some point in time
    #[codec(index = 2)]
    Unlimited, // limited only by the Amount data type
}

#[derive(Encode)]
struct TokenIssuanceV1 {
    pub token_ticker: parity_scale_codec::alloc::vec::Vec<u8>,
    pub number_of_decimals: u8,
    pub metadata_uri: parity_scale_codec::alloc::vec::Vec<u8>,
    pub total_supply: TokenTotalSupply,
    pub authority: Destination,
    pub is_freezable: IsTokenFreezable,
}

#[derive(Encode)]
enum NftIssuance {
    #[codec(index = 0)]
    V0(NftIssuanceV0),
}

#[derive(Encode)]
struct NftIssuanceV0 {
    pub metadata: Metadata,
}

#[derive(Encode)]
struct Metadata {
    pub creator: Option<PublicKeyHolder>,
    pub name: parity_scale_codec::alloc::vec::Vec<u8>,
    pub description: parity_scale_codec::alloc::vec::Vec<u8>,
    pub ticker: parity_scale_codec::alloc::vec::Vec<u8>,
    pub icon_uri: parity_scale_codec::alloc::vec::Vec<u8>,
    pub additional_metadata_uri: parity_scale_codec::alloc::vec::Vec<u8>,
    pub media_uri: parity_scale_codec::alloc::vec::Vec<u8>,
    pub media_hash: parity_scale_codec::alloc::vec::Vec<u8>,
}

#[derive(Encode)]
pub struct OrderData {
    /// The key that can authorize conclusion of an order
    conclude_key: Destination,
    /// `Ask` and `give` fields represent amounts of currencies
    /// that an order maker wants to exchange.
    /// E.g. Creator of an order asks for 5 coins and gives 10 tokens in
    /// exchange.
    ask: OutputValue,
    give: OutputValue,
}

#[derive(Encode)]
enum TxOutput {
    /// Transfer an output, giving the provided Destination the authority to
    /// spend it (no conditions)
    #[codec(index = 0)]
    Transfer(OutputValue, Destination),
    /// Same as Transfer, but with the condition that an output can only be
    /// specified after some point in time.
    #[codec(index = 1)]
    LockThenTransfer(OutputValue, Destination, OutputTimeLock),
    /// Burn an amount (whether coin or token)
    #[codec(index = 2)]
    Burn(OutputValue),
    /// Output type that is used to create a stake pool
    #[codec(index = 3)]
    CreateStakePool(H256, StakePoolData),
    /// Output type that represents spending of a stake pool output in a block
    /// reward in order to produce a block
    #[codec(index = 4)]
    ProduceBlockFromStake(Destination, H256),
    /// Create a delegation; takes the owner destination (address authorized to
    /// withdraw from the delegation) and a pool id
    #[codec(index = 5)]
    CreateDelegationId(Destination, H256),
    /// Transfer an amount to a delegation that was previously created for
    /// staking
    #[codec(index = 6)]
    DelegateStaking(Amount, H256),
    #[codec(index = 7)]
    IssueFungibleToken(TokenIssuance),
    #[codec(index = 8)]
    IssueNft(H256, NftIssuance, Destination),
    #[codec(index = 9)]
    DataDeposit(parity_scale_codec::alloc::vec::Vec<u8>),
    #[codec(index = 10)]
    Htlc(OutputValue, HashedTimelockContract),
    #[codec(index = 11)]
    AnyoneCanTake(OrderData),
}

#[derive(Encode)]
pub struct HashedTimelockContract {
    // can be spent either by a specific address that knows the secret
    secret_hash: HtlcSecretHash,
    spend_key: Destination,

    // or by a multisig after timelock expires making it possible to refund
    refund_timelock: OutputTimeLock,
    refund_key: Destination,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Encode, Decode)]
struct H256(pub [u8; 32]);

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Encode, Decode)]
struct HtlcSecretHash(pub [u8; 20]);

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Ord, PartialOrd)]
enum OutPointSourceId {
    #[codec(index = 0)]
    Transaction(H256),
    #[codec(index = 1)]
    BlockReward(H256),
}

impl OutPointSourceId {
    pub fn get_tx_id(&self) -> Option<&H256> {
        match self {
            OutPointSourceId::Transaction(id) => Some(id),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Ord, PartialOrd)]
struct UtxoOutPoint {
    id: OutPointSourceId,
    index: u32,
}

impl UtxoOutPoint {
    pub fn new(outpoint_source_id: OutPointSourceId, output_index: u32) -> Self {
        UtxoOutPoint {
            id: outpoint_source_id,
            index: output_index,
        }
    }

    pub fn source_id(&self) -> OutPointSourceId {
        self.id.clone()
    }

    pub fn output_index(&self) -> u32 {
        self.index
    }
}

#[derive(Encode)]
enum AccountSpending {
    #[codec(index = 0)]
    DelegationBalance(H256, Amount),
}

#[derive(Encode)]
struct AccountOutPoint {
    #[codec(compact)]
    nonce: u64,
    account: AccountSpending,
}

#[derive(Encode, Decode)]
enum IsTokenUnfreezable {
    #[codec(index = 0)]
    No,
    #[codec(index = 1)]
    Yes,
}

type OrderId = H256;
type TokenId = H256;

#[derive(Encode)]
enum AccountCommand {
    // Create certain amount of tokens and add them to circulating supply
    #[codec(index = 0)]
    MintTokens(TokenId, Amount),
    // Take tokens out of circulation. Not the same as Burn because unminting means that certain
    // amount of tokens is no longer supported by underlying fiat currency, which can only be
    // done by the authority.
    #[codec(index = 1)]
    UnmintTokens(TokenId),
    // After supply is locked tokens cannot be minted or unminted ever again.
    // Works only for Lockable tokens supply.
    #[codec(index = 2)]
    LockTokenSupply(TokenId),
    // Freezing token forbids any operation with all the tokens (except for optional unfreeze)
    #[codec(index = 3)]
    FreezeToken(TokenId, IsTokenUnfreezable),
    // By unfreezing token all operations are available for the tokens again
    #[codec(index = 4)]
    UnfreezeToken(TokenId),
    // Change the authority who can authorize operations for a token
    #[codec(index = 5)]
    ChangeTokenAuthority(TokenId, Destination),
    #[codec(index = 6)]
    ConcludeOrder(OrderId),
    #[codec(index = 7)]
    FillOrder(OrderId, OutputValue, Destination),
    // Change token metadata uri
    #[codec(index = 8)]
    ChangeTokenMetadataUri(TokenId, parity_scale_codec::alloc::vec::Vec<u8>),
}

#[derive(Encode)]
enum TxInput {
    #[codec(index = 0)]
    Utxo(UtxoOutPoint),
    #[codec(index = 1)]
    Account(AccountOutPoint),
    #[codec(index = 2)]
    AccountCommand(#[codec(compact)] u64, AccountCommand),
}

// fn signature_hash(
//     mode: SigHashType,
//     tx: &Transaction,
//     inputs_utxos: &[Option<&TxOutput>],
//     input_num: usize,
// ) -> Result<H256, DestinationSigError> {
//     let mut stream = DefaultHashAlgoStream::new();

//     stream_signature_hash(tx, inputs_utxos, &mut stream, mode, input_num)?;

//     let result = stream.finalize().into();
//     Ok(result)
// }
