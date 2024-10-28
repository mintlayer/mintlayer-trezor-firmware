use crate::micropython::ffi;
use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::null_mut,
};

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use parity_scale_codec::{Decode, DecodeAll, Encode};

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
    let res = mintlayer_encode_utxo_input_impl(hash, utxo_type, index);
    handle_err_or_encode(res)
}

fn mintlayer_encode_utxo_input_impl(
    hash: &[u8],
    utxo_type: u32,
    index: u32,
) -> Result<TxInput, MintlayerErrorCode> {
    let hash = H256(
        hash.try_into()
            .map_err(|_| MintlayerErrorCode::WrongHashSize)?,
    );
    let outpoint = match OutPointSourceIdIndex::from_u32(utxo_type)
        .ok_or(MintlayerErrorCode::InvalidUtxoType)?
    {
        OutPointSourceIdIndex::Transaction => OutPointSourceId::Transaction(hash),
        OutPointSourceIdIndex::BlockReward => OutPointSourceId::BlockReward(hash),
    };
    let utxo_outpoint = UtxoOutPoint::new(outpoint, index);
    let tx_input = TxInput::Utxo(utxo_outpoint);
    Ok(tx_input)
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
    let coin_amount = unsafe { core::slice::from_raw_parts(amount_data, amount_data_len as usize) };

    let res = mintlayer_encode_account_spending_input_impl(delegation_id, coin_amount, nonce);
    handle_err_or_encode(res)
}

fn mintlayer_encode_account_spending_input_impl(
    delegation_id: &[u8],
    coin_amount: &[u8],
    nonce: u64,
) -> Result<TxInput, MintlayerErrorCode> {
    let delegation_id = H256(
        delegation_id
            .try_into()
            .map_err(|_| MintlayerErrorCode::WrongHashSize)?,
    );
    let amount =
        Amount::from_bytes_be(coin_amount.as_ref()).ok_or(MintlayerErrorCode::InvalidAmount)?;
    let tx_input = TxInput::Account(AccountOutPoint {
        nonce,
        account: AccountSpending::DelegationBalance(delegation_id, amount),
    });
    Ok(tx_input)
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
    let data = unsafe { core::slice::from_raw_parts(data, data_len as usize) };

    let res = mintlayer_encode_token_account_command_input_impl(token_id, command, data, nonce);
    handle_err_or_encode(res)
}

fn mintlayer_encode_token_account_command_input_impl(
    token_id: &[u8],
    command: u32,
    data: &[u8],
    nonce: u64,
) -> Result<TxInput, MintlayerErrorCode> {
    let token_id = H256(match token_id.try_into() {
        Ok(hash) => hash,
        Err(_) => return Err(MintlayerErrorCode::WrongHashSize),
    });
    let account_command = match AccountCommandIndex::from_u32(command)
        .ok_or(MintlayerErrorCode::InvalidAccountCommand)?
    {
        AccountCommandIndex::MintTokens => {
            let amount =
                Amount::from_bytes_be(data.as_ref()).ok_or(MintlayerErrorCode::InvalidAmount)?;
            AccountCommand::MintTokens(token_id, amount)
        }
        AccountCommandIndex::UnmintTokens => AccountCommand::UnmintTokens(token_id),
        AccountCommandIndex::LockTokenSupply => AccountCommand::LockTokenSupply(token_id),
        AccountCommandIndex::FreezeToken => {
            let is_token_unfreezabe = IsTokenUnfreezable::decode_all(&mut data.as_ref())
                .map_err(|_| MintlayerErrorCode::InvalidIsTokenUnfreezable)?;
            AccountCommand::FreezeToken(token_id, is_token_unfreezabe)
        }
        AccountCommandIndex::UnfreezeToken => AccountCommand::UnfreezeToken(token_id),
        AccountCommandIndex::ChangeTokenAuthority => {
            let destination = Destination::decode_all(&mut data.as_ref())
                .map_err(|_| MintlayerErrorCode::InvalidDestination)?;
            AccountCommand::ChangeTokenAuthority(token_id, destination)
        }
        AccountCommandIndex::ChangeTokenMetadataUri => {
            AccountCommand::ChangeTokenMetadataUri(token_id, data.to_vec())
        }
        _ => return Err(MintlayerErrorCode::InvalidAccountCommand),
    };
    let tx_input = TxInput::AccountCommand(nonce, account_command);
    Ok(tx_input)
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

    encode_to_byte_array(&tx_input)
}

#[no_mangle]
extern "C" fn mintlayer_encode_fill_order_account_command_input(
    nonce: u64,
    order_id_data: *const u8,
    order_id_data_len: u32,
    amount_data: *const u8,
    amount_data_len: u32,
    destination_data: *const u8,
    destination_data_len: u32,
) -> ByteArray {
    let order_id =
        unsafe { core::slice::from_raw_parts(order_id_data, order_id_data_len as usize) };
    let coin_amount = unsafe { core::slice::from_raw_parts(amount_data, amount_data_len as usize) };
    let destination_bytes =
        unsafe { core::slice::from_raw_parts(destination_data, destination_data_len as usize) };

    let res = mintlayer_encode_fill_order_account_command_input_impl(
        order_id,
        coin_amount,
        destination_bytes,
        nonce,
    );

    handle_err_or_encode(res)
}

fn mintlayer_encode_fill_order_account_command_input_impl(
    order_id: &[u8],
    coin_amount: &[u8],
    destination_bytes: &[u8],
    nonce: u64,
) -> Result<TxInput, MintlayerErrorCode> {
    let order_id = H256(
        order_id
            .try_into()
            .map_err(|_| MintlayerErrorCode::WrongHashSize)?,
    );
    let amount =
        Amount::from_bytes_be(coin_amount.as_ref()).ok_or(MintlayerErrorCode::InvalidAmount)?;

    let destination = Destination::decode_all(&mut destination_bytes.as_ref())
        .map_err(|_| MintlayerErrorCode::InvalidDestination)?;
    let account_command = AccountCommand::FillOrder(order_id, amount, destination);
    let tx_input = TxInput::AccountCommand(nonce, account_command);
    Ok(tx_input)
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

    encode_to_byte_array(&txo)
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

    let lock = match OutputTimeLockIndex::from_u8(lock_type) {
        Some(OutputTimeLockIndex::UntilHeight) => OutputTimeLock::UntilHeight(lock_amount),
        Some(OutputTimeLockIndex::UntilTime) => OutputTimeLock::UntilTime(lock_amount),
        Some(OutputTimeLockIndex::ForBlockCount) => OutputTimeLock::ForBlockCount(lock_amount),
        Some(OutputTimeLockIndex::ForSeconds) => OutputTimeLock::ForSeconds(lock_amount),
        None => return MintlayerErrorCode::InvalidOutputTimeLock.into(),
    };

    let txo = TxOutput::LockThenTransfer(value, destination, lock);

    encode_to_byte_array(&txo)
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

    encode_to_byte_array(&txo)
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
    let pledge_coin_amount =
        unsafe { core::slice::from_raw_parts(pledge_amount_data, pledge_amount_data_len as usize) };
    let staker_destination_bytes = unsafe {
        core::slice::from_raw_parts(
            staker_destination_data,
            staker_destination_data_len as usize,
        )
    };
    let vrf_public_key = unsafe {
        core::slice::from_raw_parts(vrf_public_key_data, vrf_public_key_data_len as usize)
    };
    let decommission_destination_bytes = unsafe {
        core::slice::from_raw_parts(
            decommission_destination_data,
            decommission_destination_data_len as usize,
        )
    };
    let cost_per_block_coin_amount = unsafe {
        core::slice::from_raw_parts(
            cost_per_block_amount_data,
            cost_per_block_amount_data_len as usize,
        )
    };

    let res = mintlayer_encode_create_stake_pool_output_impl(
        pool_id,
        pledge_coin_amount,
        staker_destination_bytes,
        vrf_public_key,
        decommission_destination_bytes,
        cost_per_block_coin_amount,
        margin_ratio_per_thousand,
    );

    handle_err_or_encode(res)
}

fn mintlayer_encode_create_stake_pool_output_impl(
    pool_id: &[u8],
    pledge_coin_amount: &[u8],
    staker_destination_bytes: &[u8],
    vrf_public_key: &[u8],
    decommission_destination_bytes: &[u8],
    cost_per_block_coin_amount: &[u8],
    margin_ratio_per_thousand: u16,
) -> Result<TxOutput, MintlayerErrorCode> {
    let pool_id = H256(
        pool_id
            .try_into()
            .map_err(|_| MintlayerErrorCode::WrongHashSize)?,
    );
    let pledge = Amount::from_bytes_be(pledge_coin_amount.as_ref())
        .ok_or(MintlayerErrorCode::InvalidAmount)?;
    let staker = Destination::decode_all(&mut staker_destination_bytes.as_ref())
        .map_err(|_| MintlayerErrorCode::InvalidDestination)?;
    let vrf_public_key = VRFPublicKeyHolder::decode_all(&mut vrf_public_key.as_ref())
        .map_err(|_| MintlayerErrorCode::InvalidVrfPublicKey)?;
    let decommission_key = Destination::decode_all(&mut decommission_destination_bytes.as_ref())
        .map_err(|_| MintlayerErrorCode::InvalidDestination)?;
    let cost_per_block = Amount::from_bytes_be(cost_per_block_coin_amount.as_ref())
        .ok_or(MintlayerErrorCode::InvalidAmount)?;
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
    Ok(txo)
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

    encode_to_byte_array(&txo)
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

    encode_to_byte_array(&txo)
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

    encode_to_byte_array(&txo)
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
    let metadata_uri =
        unsafe { core::slice::from_raw_parts(metadata_uri_data, metadata_uri_data_len as usize) };
    let authority_bytes =
        unsafe { core::slice::from_raw_parts(authority_data, authority_data_len as usize) };
    let coin_amount =
        unsafe { core::slice::from_raw_parts(fixed_amount_data, fixed_amount_data_len as usize) };

    let res = mintlayer_encode_issue_fungible_token_output_impl(
        token_ticker,
        metadata_uri,
        authority_bytes,
        is_freezable,
        total_supply_type,
        coin_amount,
        number_of_decimals,
    );

    handle_err_or_encode(res)
}

fn mintlayer_encode_issue_fungible_token_output_impl(
    token_ticker: &[u8],
    metadata_uri: &[u8],
    authority_bytes: &[u8],
    is_freezable: u8,
    total_supply_type: u32,
    coin_amount: &[u8],
    number_of_decimals: u8,
) -> Result<TxOutput, MintlayerErrorCode> {
    let token_ticker = token_ticker.to_vec();
    let metadata_uri = metadata_uri.to_vec();
    let authority = Destination::decode_all(&mut authority_bytes.as_ref())
        .map_err(|_| MintlayerErrorCode::InvalidDestination)?;
    let is_freezable = IsTokenFreezable::from_u8(is_freezable)
        .ok_or(MintlayerErrorCode::InvalidIsTokenFreezable)?;
    let total_supply = match TokenTotalSupplyIndex::from_u32(total_supply_type)
        .ok_or(MintlayerErrorCode::InvalidTokenTotalSupply)?
    {
        TokenTotalSupplyIndex::Fixed => {
            let amount = Amount::from_bytes_be(coin_amount.as_ref())
                .ok_or(MintlayerErrorCode::InvalidAmount)?;
            TokenTotalSupply::Fixed(amount)
        }
        TokenTotalSupplyIndex::Lockable => TokenTotalSupply::Lockable,
        TokenTotalSupplyIndex::Unlimited => TokenTotalSupply::Unlimited,
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
    Ok(txo)
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
    let creator = unsafe { core::slice::from_raw_parts(creator_data, creator_data_len as usize) };
    let name = unsafe { core::slice::from_raw_parts(name_data, name_data_len as usize) };
    let description =
        unsafe { core::slice::from_raw_parts(description_data, description_data_len as usize) };
    let ticker = unsafe { core::slice::from_raw_parts(ticker_data, ticker_data_len as usize) };
    let icon_uri =
        unsafe { core::slice::from_raw_parts(icon_uri_data, icon_uri_data_len as usize) };
    let additional_metadata_uri = unsafe {
        core::slice::from_raw_parts(
            additional_metadata_uri_data,
            additional_metadata_uri_data_len as usize,
        )
    };
    let media_uri =
        unsafe { core::slice::from_raw_parts(media_uri_data, media_uri_data_len as usize) };
    let media_hash =
        unsafe { core::slice::from_raw_parts(media_hash_data, media_hash_data_len as usize) };
    let destination_bytes =
        unsafe { core::slice::from_raw_parts(destination_data, destination_data_len as usize) };

    let res = mintlayer_encode_issue_nft_output_impl(
        token_id,
        creator_data_len,
        creator,
        name,
        description,
        ticker,
        icon_uri,
        additional_metadata_uri,
        media_uri,
        media_hash,
        destination_bytes,
    );

    handle_err_or_encode(res)
}

fn mintlayer_encode_issue_nft_output_impl(
    token_id: &[u8],
    creator_data_len: u32,
    creator: &[u8],
    name: &[u8],
    description: &[u8],
    ticker: &[u8],
    icon_uri: &[u8],
    additional_metadata_uri: &[u8],
    media_uri: &[u8],
    media_hash: &[u8],
    destination_bytes: &[u8],
) -> Result<TxOutput, MintlayerErrorCode> {
    let token_id = H256(
        token_id
            .try_into()
            .map_err(|_| MintlayerErrorCode::WrongHashSize)?,
    );
    let creator = if creator_data_len == 0 {
        None
    } else {
        Some(PublicKeyHolder::Secp256k1Schnorr(PublicKey(
            creator
                .try_into()
                .map_err(|_| MintlayerErrorCode::InvalidPublicKey)?,
        )))
    };
    let name = name.to_vec();
    let description = description.to_vec();
    let ticker = ticker.to_vec();
    let icon_uri = icon_uri.to_vec();
    let additional_metadata_uri = additional_metadata_uri.to_vec();
    let media_uri = media_uri.to_vec();
    let media_hash = media_hash.to_vec();
    let destination = Destination::decode_all(&mut destination_bytes.as_ref())
        .map_err(|_| MintlayerErrorCode::InvalidDestination)?;
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
    Ok(txo)
}

#[no_mangle]
extern "C" fn mintlayer_encode_data_deposit_output(
    deposit_data: *const u8,
    deposit_data_len: u32,
) -> ByteArray {
    let deposit = unsafe { core::slice::from_raw_parts(deposit_data, deposit_data_len as usize) };
    let deposit = deposit.to_vec();

    let txo = TxOutput::DataDeposit(deposit);

    encode_to_byte_array(&txo)
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
    let spend_destination_bytes = unsafe {
        core::slice::from_raw_parts(spend_destination_data, spend_destination_data_len as usize)
    };
    let hash =
        unsafe { core::slice::from_raw_parts(secret_hash_data, secret_hash_data_len as usize) };

    let res = mintlayer_encode_htlc_output_impl(
        refund_destination_bytes,
        spend_destination_bytes,
        hash,
        lock_type,
        lock_amount,
        value,
    );

    handle_err_or_encode(res)
}

fn mintlayer_encode_htlc_output_impl(
    refund_destination_bytes: &[u8],
    spend_destination_bytes: &[u8],
    hash: &[u8],
    lock_type: u8,
    lock_amount: u64,
    value: OutputValue,
) -> Result<TxOutput, MintlayerErrorCode> {
    let refund_key = Destination::decode_all(&mut refund_destination_bytes.as_ref())
        .map_err(|_| MintlayerErrorCode::InvalidDestination)?;
    let spend_key = Destination::decode_all(&mut spend_destination_bytes.as_ref())
        .map_err(|_| MintlayerErrorCode::InvalidDestination)?;
    let secret_hash = HtlcSecretHash(
        hash.try_into()
            .map_err(|_| MintlayerErrorCode::WrongHashSize)?,
    );
    let refund_timelock = match OutputTimeLockIndex::from_u8(lock_type)
        .ok_or(MintlayerErrorCode::InvalidOutputTimeLock)?
    {
        OutputTimeLockIndex::UntilHeight => OutputTimeLock::UntilHeight(lock_amount),
        OutputTimeLockIndex::UntilTime => OutputTimeLock::UntilTime(lock_amount),
        OutputTimeLockIndex::ForBlockCount => OutputTimeLock::ForBlockCount(lock_amount),
        OutputTimeLockIndex::ForSeconds => OutputTimeLock::ForSeconds(lock_amount),
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
    Ok(txo)
}

#[no_mangle]
extern "C" fn mintlayer_encode_create_order_output(
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

    let txo = TxOutput::CreateOrder(OrderData {
        conclude_key: destination,
        ask: ask_value,
        give: give_value,
    });

    encode_to_byte_array(&txo)
}

#[derive(Encode, Debug, PartialEq, Eq)]
struct CompactLength {
    #[codec(compact)]
    pub value: u32,
}

#[no_mangle]
extern "C" fn mintlayer_encode_compact_length(length: u32) -> ByteArray {
    let len = CompactLength { value: length };
    encode_to_byte_array(&len)
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

#[derive(FromPrimitive)]
enum OutputTimeLockIndex {
    UntilHeight = 0,
    UntilTime = 1,
    ForBlockCount = 2,
    ForSeconds = 3,
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

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, FromPrimitive)]
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

#[derive(FromPrimitive)]
enum TokenTotalSupplyIndex {
    Fixed = 0,
    Lockable = 1,
    Unlimited = 2,
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
    CreateOrder(OrderData),
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

#[derive(FromPrimitive)]
enum OutPointSourceIdIndex {
    Transaction = 0,
    BlockReward = 1,
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
    FillOrder(OrderId, Amount, Destination),
    // Change token metadata uri
    #[codec(index = 8)]
    ChangeTokenMetadataUri(TokenId, parity_scale_codec::alloc::vec::Vec<u8>),
}

#[derive(FromPrimitive)]
enum AccountCommandIndex {
    MintTokens = 0,
    UnmintTokens = 1,
    LockTokenSupply = 2,
    FreezeToken = 3,
    UnfreezeToken = 4,
    ChangeTokenAuthority = 5,
    ConcludeOrder = 6,
    FillOrder = 7,
    ChangeTokenMetadataUri = 8,
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

fn handle_err_or_encode<T: Encode>(x: Result<T, MintlayerErrorCode>) -> ByteArray {
    match x {
        Ok(value) => encode_to_byte_array(&value),
        Err(value) => value.into(),
    }
}

fn encode_to_byte_array<T: Encode>(x: &T) -> ByteArray {
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
