use parity_scale_codec::{DecodeAll, Encode};

use mintlayer_firmware_deps::ml_primitives::{
    AccountCommand, AccountNonce, AccountOutPoint, AccountSpending, Destination,
    HashedTimelockContract, HtlcSecretHash, IsTokenUnfreezable, NftIssuance, NftIssuanceV0,
    OrderAccountCommand, OrderData, PerThousand, StakePoolData, TokenIssuance, TokenIssuanceV1,
    TokenTotalSupply, TxInput, TxOutput, UtxoOutPoint, VrfPublicKey,
};

use crate::mintlayer::{
    generated_enums::{
        MintlayerAccountCommandType, MintlayerTokenTotalSupplyType, MintlayerUtxoType,
    },
    utils::{
        encode_to_byte_array, handle_err_or_encode, make_is_token_freezable,
        make_mintlayer_output_timelock_type, make_mintlayer_token_total_supply_type,
        make_outpoint_source_id, make_output_time_lock, parse_amount, parse_destination,
        parse_hash, parse_id, parse_output_value, ByteArray, MintlayerErrorCode,
    },
};

mod generated_enums;
mod input_commitments;
mod utils;

#[no_mangle]
extern "C" fn mintlayer_encode_utxo_input(
    data: *const u8,
    data_len: u32,
    index: u32,
    utxo_type: u8,
) -> ByteArray {
    let hash = unsafe { core::slice::from_raw_parts(data, data_len as usize) };
    let res = mintlayer_encode_utxo_input_impl(hash, utxo_type, index);
    handle_err_or_encode(res)
}

fn mintlayer_encode_utxo_input_impl(
    hash: &[u8],
    utxo_type: u8,
    index: u32,
) -> Result<TxInput, MintlayerErrorCode> {
    let hash = parse_hash(hash)?;
    let utxo_type = MintlayerUtxoType::try_from(utxo_type as i32)
        .map_err(|_| MintlayerErrorCode::InvalidUtxoType)?;
    let outpoint = make_outpoint_source_id(utxo_type, hash);
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
    let delegation_id = parse_id(delegation_id)?;
    let amount = parse_amount(coin_amount)?;
    let tx_input = TxInput::Account(AccountOutPoint {
        nonce: AccountNonce(nonce),
        spending: AccountSpending::DelegationBalance(delegation_id, amount),
    });
    Ok(tx_input)
}

#[no_mangle]
extern "C" fn mintlayer_encode_token_account_command_input(
    nonce: u64,
    command_type: u8,
    token_id_data: *const u8,
    token_id_data_len: u32,
    data: *const u8,
    data_len: u32,
) -> ByteArray {
    let token_id =
        unsafe { core::slice::from_raw_parts(token_id_data, token_id_data_len as usize) };
    let data = unsafe { core::slice::from_raw_parts(data, data_len as usize) };

    let res =
        mintlayer_encode_token_account_command_input_impl(token_id, command_type, data, nonce);
    handle_err_or_encode(res)
}

fn mintlayer_encode_token_account_command_input_impl(
    token_id: &[u8],
    command_type: u8,
    data: &[u8],
    nonce: u64,
) -> Result<TxInput, MintlayerErrorCode> {
    let token_id = parse_id(token_id)?;
    let command_type = MintlayerAccountCommandType::try_from(command_type as i32)
        .map_err(|_| MintlayerErrorCode::InvalidAccountCommand)?;
    let account_command = match command_type {
        MintlayerAccountCommandType::MintTokens => {
            let amount = parse_amount(data)?;
            AccountCommand::MintTokens(token_id, amount)
        }
        MintlayerAccountCommandType::UnmintTokens => AccountCommand::UnmintTokens(token_id),
        MintlayerAccountCommandType::LockTokenSupply => AccountCommand::LockTokenSupply(token_id),
        MintlayerAccountCommandType::FreezeToken => {
            let is_token_unfreezabe = IsTokenUnfreezable::decode_all(&mut &*data)
                .map_err(|_| MintlayerErrorCode::InvalidIsTokenUnfreezable)?;
            AccountCommand::FreezeToken(token_id, is_token_unfreezabe)
        }
        MintlayerAccountCommandType::UnfreezeToken => AccountCommand::UnfreezeToken(token_id),
        MintlayerAccountCommandType::ChangeTokenAuthority => {
            let destination = parse_destination(data)?;
            AccountCommand::ChangeTokenAuthority(token_id, destination)
        }
        MintlayerAccountCommandType::ChangeTokenMetadataUri => {
            AccountCommand::ChangeTokenMetadataUri(token_id, data.to_vec())
        }
        MintlayerAccountCommandType::ConcludeOrder | MintlayerAccountCommandType::FillOrder => {
            return Err(MintlayerErrorCode::InvalidAccountCommand)
        }
    };
    let tx_input = TxInput::AccountCommand(AccountNonce(nonce), account_command);
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

    let res = mintlayer_encode_conclude_order_account_command_input_impl(nonce, order_id);
    handle_err_or_encode(res)
}

fn mintlayer_encode_conclude_order_account_command_input_impl(
    nonce: u64,
    order_id: &[u8],
) -> Result<TxInput, MintlayerErrorCode> {
    let order_id = parse_id(order_id)?;

    Ok(TxInput::AccountCommand(
        AccountNonce(nonce),
        AccountCommand::ConcludeOrder(order_id),
    ))
}

#[no_mangle]
extern "C" fn mintlayer_encode_conclude_order_v1_order_command_input(
    order_id_data: *const u8,
    order_id_data_len: u32,
) -> ByteArray {
    let order_id =
        unsafe { core::slice::from_raw_parts(order_id_data, order_id_data_len as usize) };

    let res = mintlayer_encode_conclude_order_v1_order_command_input_impl(order_id);
    handle_err_or_encode(res)
}

fn mintlayer_encode_conclude_order_v1_order_command_input_impl(
    order_id: &[u8],
) -> Result<TxInput, MintlayerErrorCode> {
    let order_id = parse_id(order_id)?;

    Ok(TxInput::OrderAccountCommand(
        OrderAccountCommand::ConcludeOrder(order_id),
    ))
}

#[no_mangle]
extern "C" fn mintlayer_encode_freeze_order_order_command_input(
    order_id_data: *const u8,
    order_id_data_len: u32,
) -> ByteArray {
    let order_id =
        unsafe { core::slice::from_raw_parts(order_id_data, order_id_data_len as usize) };

    let res = mintlayer_encode_freeze_order_order_command_input_impl(order_id);
    handle_err_or_encode(res)
}

fn mintlayer_encode_freeze_order_order_command_input_impl(
    order_id: &[u8],
) -> Result<TxInput, MintlayerErrorCode> {
    let order_id = parse_id(order_id)?;

    Ok(TxInput::OrderAccountCommand(
        OrderAccountCommand::FreezeOrder(order_id),
    ))
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
    let destination =
        unsafe { core::slice::from_raw_parts(destination_data, destination_data_len as usize) };

    let res = mintlayer_encode_fill_order_account_command_input_impl(
        order_id,
        coin_amount,
        destination,
        nonce,
    );

    handle_err_or_encode(res)
}

fn mintlayer_encode_fill_order_account_command_input_impl(
    order_id: &[u8],
    coin_amount: &[u8],
    destination: &[u8],
    nonce: u64,
) -> Result<TxInput, MintlayerErrorCode> {
    let order_id = parse_id(order_id)?;
    let amount = parse_amount(coin_amount)?;

    let destination = parse_destination(destination)?;
    let account_command = AccountCommand::FillOrder(order_id, amount, destination);
    let tx_input = TxInput::AccountCommand(AccountNonce(nonce), account_command);
    Ok(tx_input)
}

#[no_mangle]
extern "C" fn mintlayer_encode_fill_order_v1_order_command_input(
    order_id_data: *const u8,
    order_id_data_len: u32,
    amount_data: *const u8,
    amount_data_len: u32,
) -> ByteArray {
    let order_id =
        unsafe { core::slice::from_raw_parts(order_id_data, order_id_data_len as usize) };
    let coin_amount = unsafe { core::slice::from_raw_parts(amount_data, amount_data_len as usize) };

    let res = mintlayer_encode_fill_order_v1_order_command_input_impl(order_id, coin_amount);

    handle_err_or_encode(res)
}

fn mintlayer_encode_fill_order_v1_order_command_input_impl(
    order_id: &[u8],
    coin_amount: &[u8],
) -> Result<TxInput, MintlayerErrorCode> {
    let order_id = parse_id(order_id)?;
    let amount = parse_amount(coin_amount)?;

    let order_command = OrderAccountCommand::FillOrder(order_id, amount);
    let tx_input = TxInput::OrderAccountCommand(order_command);
    Ok(tx_input)
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
    let amount = unsafe { core::slice::from_raw_parts(amount_data, amount_data_len as usize) };
    let token_id =
        unsafe { core::slice::from_raw_parts(token_id_data, token_id_data_len as usize) };
    let destination =
        unsafe { core::slice::from_raw_parts(destination_data, destination_data_len as usize) };

    let res = mintlayer_encode_transfer_output_impl(amount, token_id, destination);

    handle_err_or_encode(res)
}

fn mintlayer_encode_transfer_output_impl(
    amount: &[u8],
    token_id: &[u8],
    destination: &[u8],
) -> Result<TxOutput, MintlayerErrorCode> {
    let value = parse_output_value(amount, token_id)?;
    let destination = parse_destination(destination)?;

    Ok(TxOutput::Transfer(value, destination))
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
    let amount = unsafe { core::slice::from_raw_parts(amount_data, amount_data_len as usize) };
    let token_id =
        unsafe { core::slice::from_raw_parts(token_id_data, token_id_data_len as usize) };
    let destination =
        unsafe { core::slice::from_raw_parts(destination_data, destination_data_len as usize) };

    let res = mintlayer_encode_lock_then_transfer_output_impl(
        amount,
        token_id,
        lock_type,
        lock_amount,
        destination,
    );

    handle_err_or_encode(res)
}

fn mintlayer_encode_lock_then_transfer_output_impl(
    amount: &[u8],
    token_id: &[u8],
    lock_type: u8,
    lock_amount: u64,
    destination: &[u8],
) -> Result<TxOutput, MintlayerErrorCode> {
    let value = parse_output_value(amount, token_id)?;
    let destination = parse_destination(destination)?;
    let lock_type = make_mintlayer_output_timelock_type(lock_type)?;
    let lock = make_output_time_lock(lock_type, lock_amount);

    Ok(TxOutput::LockThenTransfer(value, destination, lock))
}

#[no_mangle]
extern "C" fn mintlayer_encode_burn_output(
    amount_data: *const u8,
    amount_data_len: u32,
    token_id_data: *const u8,
    token_id_data_len: u32,
) -> ByteArray {
    let amount = unsafe { core::slice::from_raw_parts(amount_data, amount_data_len as usize) };
    let token_id =
        unsafe { core::slice::from_raw_parts(token_id_data, token_id_data_len as usize) };

    let res = mintlayer_encode_burn_output_impl(amount, token_id);
    handle_err_or_encode(res)
}

fn mintlayer_encode_burn_output_impl(
    amount: &[u8],
    token_id: &[u8],
) -> Result<TxOutput, MintlayerErrorCode> {
    let value = parse_output_value(amount, token_id)?;
    Ok(TxOutput::Burn(value))
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
    let staker_destination = unsafe {
        core::slice::from_raw_parts(
            staker_destination_data,
            staker_destination_data_len as usize,
        )
    };
    let vrf_public_key = unsafe {
        core::slice::from_raw_parts(vrf_public_key_data, vrf_public_key_data_len as usize)
    };
    let decommission_destination = unsafe {
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
        staker_destination,
        vrf_public_key,
        decommission_destination,
        cost_per_block_coin_amount,
        margin_ratio_per_thousand,
    );

    handle_err_or_encode(res)
}

fn mintlayer_encode_create_stake_pool_output_impl(
    pool_id: &[u8],
    pledge_coin_amount: &[u8],
    staker_destination: &[u8],
    vrf_public_key: &[u8],
    decommission_destination: &[u8],
    cost_per_block_coin_amount: &[u8],
    margin_ratio_per_thousand: u16,
) -> Result<TxOutput, MintlayerErrorCode> {
    let pool_id = parse_id(pool_id)?;
    let pledge = parse_amount(pledge_coin_amount)?;
    let staker = parse_destination(staker_destination)?;
    let vrf_public_key = VrfPublicKey::decode_all(&mut &*vrf_public_key)
        .map_err(|_| MintlayerErrorCode::InvalidVrfPublicKey)?;
    let decommission_key = parse_destination(decommission_destination)?;
    let cost_per_block = parse_amount(cost_per_block_coin_amount)?;
    let txo = TxOutput::CreateStakePool(
        pool_id,
        StakePoolData {
            pledge,
            staker,
            decommission_key,
            vrf_public_key,
            margin_ratio_per_thousand: PerThousand(margin_ratio_per_thousand),
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
    let destination =
        unsafe { core::slice::from_raw_parts(destination_data, destination_data_len as usize) };
    let pool_id = unsafe { core::slice::from_raw_parts(pool_id_data, pool_id_data_len as usize) };

    let res = mintlayer_encode_produce_from_stake_output_impl(destination, pool_id);

    handle_err_or_encode(res)
}

fn mintlayer_encode_produce_from_stake_output_impl(
    destination: &[u8],
    pool_id: &[u8],
) -> Result<TxOutput, MintlayerErrorCode> {
    let destination = parse_destination(destination)?;
    let pool_id = parse_id(pool_id)?;

    Ok(TxOutput::ProduceBlockFromStake(destination, pool_id))
}

#[no_mangle]
extern "C" fn mintlayer_encode_create_delegation_id_output(
    destination_data: *const u8,
    destination_data_len: u32,
    pool_id_data: *const u8,
    pool_id_data_len: u32,
) -> ByteArray {
    let destination =
        unsafe { core::slice::from_raw_parts(destination_data, destination_data_len as usize) };
    let pool_id = unsafe { core::slice::from_raw_parts(pool_id_data, pool_id_data_len as usize) };

    let res = mintlayer_encode_create_delegation_id_output_impl(destination, pool_id);

    handle_err_or_encode(res)
}

fn mintlayer_encode_create_delegation_id_output_impl(
    destination: &[u8],
    pool_id: &[u8],
) -> Result<TxOutput, MintlayerErrorCode> {
    let destination = parse_destination(destination)?;
    let pool_id = parse_id(pool_id)?;

    Ok(TxOutput::CreateDelegationId(destination, pool_id))
}

#[no_mangle]
extern "C" fn mintlayer_encode_delegate_staking_output(
    amount_data: *const u8,
    amount_data_len: u32,
    delegation_id_data: *const u8,
    delegation_id_data_len: u32,
) -> ByteArray {
    let amount = unsafe { core::slice::from_raw_parts(amount_data, amount_data_len as usize) };
    let delegation_id =
        unsafe { core::slice::from_raw_parts(delegation_id_data, delegation_id_data_len as usize) };

    let res = mintlayer_encode_delegate_staking_output_impl(amount, delegation_id);

    handle_err_or_encode(res)
}

fn mintlayer_encode_delegate_staking_output_impl(
    amount: &[u8],
    delegation_id: &[u8],
) -> Result<TxOutput, MintlayerErrorCode> {
    let amount = parse_amount(amount)?;
    let delegation_id = parse_id(delegation_id)?;

    Ok(TxOutput::DelegateStaking(amount, delegation_id))
}

#[no_mangle]
extern "C" fn mintlayer_encode_issue_fungible_token_output(
    token_ticker_data: *const u8,
    token_ticker_data_len: u32,
    number_of_decimals: u8,
    metadata_uri_data: *const u8,
    metadata_uri_data_len: u32,
    total_supply_type: u8,
    fixed_amount_data: *const u8,
    fixed_amount_data_len: u32,
    authority_data: *const u8,
    authority_data_len: u32,
    is_freezable: bool,
) -> ByteArray {
    let token_ticker =
        unsafe { core::slice::from_raw_parts(token_ticker_data, token_ticker_data_len as usize) };
    let metadata_uri =
        unsafe { core::slice::from_raw_parts(metadata_uri_data, metadata_uri_data_len as usize) };
    let authority =
        unsafe { core::slice::from_raw_parts(authority_data, authority_data_len as usize) };
    let coin_amount =
        unsafe { core::slice::from_raw_parts(fixed_amount_data, fixed_amount_data_len as usize) };

    let res = mintlayer_encode_issue_fungible_token_output_impl(
        token_ticker,
        metadata_uri,
        authority,
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
    authority: &[u8],
    is_freezable: bool,
    total_supply_type: u8,
    coin_amount: &[u8],
    number_of_decimals: u8,
) -> Result<TxOutput, MintlayerErrorCode> {
    let token_ticker = token_ticker.to_vec();
    let metadata_uri = metadata_uri.to_vec();
    let authority = parse_destination(authority)?;
    let is_freezable = make_is_token_freezable(is_freezable);
    let total_supply_type = make_mintlayer_token_total_supply_type(total_supply_type)?;
    let total_supply = match total_supply_type {
        MintlayerTokenTotalSupplyType::Fixed => {
            let amount = parse_amount(coin_amount)?;
            TokenTotalSupply::Fixed(amount)
        }
        MintlayerTokenTotalSupplyType::Lockable => TokenTotalSupply::Lockable,
        MintlayerTokenTotalSupplyType::Unlimited => TokenTotalSupply::Unlimited,
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
    let destination =
        unsafe { core::slice::from_raw_parts(destination_data, destination_data_len as usize) };

    let res = mintlayer_encode_issue_nft_output_impl(
        token_id,
        creator,
        name,
        description,
        ticker,
        icon_uri,
        additional_metadata_uri,
        media_uri,
        media_hash,
        destination,
    );

    handle_err_or_encode(res)
}

#[allow(clippy::too_many_arguments)]
fn mintlayer_encode_issue_nft_output_impl(
    token_id: &[u8],
    creator: &[u8],
    name: &[u8],
    description: &[u8],
    ticker: &[u8],
    icon_uri: &[u8],
    additional_metadata_uri: &[u8],
    media_uri: &[u8],
    media_hash: &[u8],
    destination: &[u8],
) -> Result<TxOutput, MintlayerErrorCode> {
    let token_id = parse_id(token_id)?;
    let creator = if creator.is_empty() {
        None
    } else {
        match parse_destination(creator)? {
            Destination::PublicKey(public_key) => Some(public_key),

            Destination::AnyoneCanSpend
            | Destination::PublicKeyHash(_)
            | Destination::ScriptHash(_)
            | Destination::ClassicMultisig(_) => {
                return Err(MintlayerErrorCode::PublicKeyDestinationExpected);
            }
        }
    };
    let name = name.to_vec();
    let description = description.to_vec();
    let ticker = ticker.to_vec();
    let icon_uri = icon_uri.to_vec();
    let additional_metadata_uri = additional_metadata_uri.to_vec();
    let media_uri = media_uri.to_vec();
    let media_hash = media_hash.to_vec();
    let destination = parse_destination(destination)?;
    let issuance = NftIssuance::V0(NftIssuanceV0 {
        creator,
        name,
        description,
        ticker,
        icon_uri,
        additional_metadata_uri,
        media_uri,
        media_hash,
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
    let amount = unsafe { core::slice::from_raw_parts(amount_data, amount_data_len as usize) };
    let token_id =
        unsafe { core::slice::from_raw_parts(token_id_data, token_id_data_len as usize) };
    let refund_destination = unsafe {
        core::slice::from_raw_parts(
            refund_destination_data,
            refund_destination_data_len as usize,
        )
    };
    let spend_destination = unsafe {
        core::slice::from_raw_parts(spend_destination_data, spend_destination_data_len as usize)
    };
    let hash =
        unsafe { core::slice::from_raw_parts(secret_hash_data, secret_hash_data_len as usize) };

    let res = mintlayer_encode_htlc_output_impl(
        amount,
        token_id,
        refund_destination,
        spend_destination,
        hash,
        lock_type,
        lock_amount,
    );

    handle_err_or_encode(res)
}

fn mintlayer_encode_htlc_output_impl(
    amount: &[u8],
    token_id: &[u8],
    refund_destination: &[u8],
    spend_destination: &[u8],
    hash: &[u8],
    lock_type: u8,
    lock_amount: u64,
) -> Result<TxOutput, MintlayerErrorCode> {
    let value = parse_output_value(amount, token_id)?;
    let refund_key = parse_destination(refund_destination)?;
    let spend_key = parse_destination(spend_destination)?;
    let secret_hash = HtlcSecretHash(
        hash.try_into()
            .map_err(|_| MintlayerErrorCode::WrongHashSize)?,
    );
    let lock_type = make_mintlayer_output_timelock_type(lock_type)?;
    let refund_timelock = make_output_time_lock(lock_type, lock_amount);
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
    let destination =
        unsafe { core::slice::from_raw_parts(destination_data, destination_data_len as usize) };
    let ask_amount =
        unsafe { core::slice::from_raw_parts(ask_amount_data, ask_amount_data_len as usize) };
    let ask_token_id =
        unsafe { core::slice::from_raw_parts(ask_token_id_data, ask_token_id_data_len as usize) };
    let give_amount =
        unsafe { core::slice::from_raw_parts(give_amount_data, give_amount_data_len as usize) };
    let give_token_id =
        unsafe { core::slice::from_raw_parts(give_token_id_data, give_token_id_data_len as usize) };

    let res = mintlayer_encode_create_order_output_impl(
        destination,
        ask_amount,
        ask_token_id,
        give_amount,
        give_token_id,
    );

    handle_err_or_encode(res)
}

fn mintlayer_encode_create_order_output_impl(
    destination: &[u8],
    ask_amount: &[u8],
    ask_token_id: &[u8],
    give_amount: &[u8],
    give_token_id: &[u8],
) -> Result<TxOutput, MintlayerErrorCode> {
    let destination = parse_destination(destination)?;
    let ask_value = parse_output_value(ask_amount, ask_token_id)?;
    let give_value = parse_output_value(give_amount, give_token_id)?;

    Ok(TxOutput::CreateOrder(OrderData {
        conclude_key: destination,
        ask: ask_value,
        give: give_value,
    }))
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

// Note: can't use this allocator globally in tests, because allocations start
// to happen too early (before main).
#[cfg(not(test))]
mod global_alloc {
    use core::alloc::{GlobalAlloc, Layout};

    use crate::micropython::ffi::{gc_alloc, gc_free};

    struct CustomAllocator;

    unsafe impl GlobalAlloc for CustomAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { gc_alloc(layout.size(), 0).cast() }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            unsafe {
                gc_free(ptr.cast());
            }
        }
    }

    #[global_allocator]
    static GLOBAL_ALLOCATOR: CustomAllocator = CustomAllocator;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let hash: [u8; 32] = [0; 32];
        let result = mintlayer_encode_utxo_input(hash.as_ptr(), 32, 123, 1);
        assert!(result.data() != core::ptr::null());

        let result = mintlayer_encode_utxo_input(hash.as_ptr(), 31, 123, 1);
        assert!(result.data() == core::ptr::null());
    }
}
