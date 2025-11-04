use parity_scale_codec::DecodeAll as _;

use mintlayer_firmware_deps::ml_primitives::{SighashInputCommitment, TxOutput};

use crate::mintlayer::{
    encode_to_byte_array, handle_err_or_encode,
    utils::{parse_amount, parse_output_value},
    ByteArray, MintlayerErrorCode,
};

#[no_mangle]
extern "C" fn mintlayer_encode_empty_input_commitment() -> ByteArray {
    encode_to_byte_array(&SighashInputCommitment::None)
}

#[no_mangle]
extern "C" fn mintlayer_encode_input_commitment_for_utxo(
    encoded_utxo_data: *const u8,
    encoded_utxo_data_len: u32,
) -> ByteArray {
    let encoded_utxo =
        unsafe { core::slice::from_raw_parts(encoded_utxo_data, encoded_utxo_data_len as usize) };
    let res = mintlayer_encode_input_commitment_for_utxo_impl(encoded_utxo);
    handle_err_or_encode(res)
}

fn mintlayer_encode_input_commitment_for_utxo_impl(
    encoded_utxo: &[u8],
) -> Result<SighashInputCommitment, MintlayerErrorCode> {
    let utxo = TxOutput::decode_all(&mut &encoded_utxo[..])
        .map_err(|_| MintlayerErrorCode::InvalidEncodedUtxo)?;

    Ok(SighashInputCommitment::Utxo(utxo))
}

#[no_mangle]
extern "C" fn mintlayer_encode_input_commitment_v1_for_produce_block_from_stake_utxo(
    encoded_utxo_data: *const u8,
    encoded_utxo_data_len: u32,
    staker_balance_amount_data: *const u8,
    staker_balance_amount_data_len: u32,
) -> ByteArray {
    let encoded_utxo =
        unsafe { core::slice::from_raw_parts(encoded_utxo_data, encoded_utxo_data_len as usize) };
    let staker_balance_amount = unsafe {
        core::slice::from_raw_parts(
            staker_balance_amount_data,
            staker_balance_amount_data_len as usize,
        )
    };
    let res = mintlayer_encode_input_commitment_v1_for_produce_block_from_stake_utxo_impl(
        encoded_utxo,
        staker_balance_amount,
    );
    handle_err_or_encode(res)
}

fn mintlayer_encode_input_commitment_v1_for_produce_block_from_stake_utxo_impl(
    encoded_utxo: &[u8],
    staker_balance_amount: &[u8],
) -> Result<SighashInputCommitment, MintlayerErrorCode> {
    let utxo = TxOutput::decode_all(&mut &encoded_utxo[..])
        .map_err(|_| MintlayerErrorCode::InvalidEncodedUtxo)?;
    let staker_balance = parse_amount(staker_balance_amount)?;

    Ok(SighashInputCommitment::ProduceBlockFromStakeUtxo {
        utxo,
        staker_balance,
    })
}

#[no_mangle]
extern "C" fn mintlayer_encode_input_commitment_v1_for_fill_order(
    asked_token_data: *const u8,
    asked_token_data_len: u32,
    initially_asked_amount_data: *const u8,
    initially_asked_amount_data_len: u32,
    given_token_data: *const u8,
    given_token_data_len: u32,
    initially_given_amount_data: *const u8,
    initially_given_amount_data_len: u32,
) -> ByteArray {
    let asked_token =
        unsafe { core::slice::from_raw_parts(asked_token_data, asked_token_data_len as usize) };
    let initially_asked_amount = unsafe {
        core::slice::from_raw_parts(
            initially_asked_amount_data,
            initially_asked_amount_data_len as usize,
        )
    };
    let given_token =
        unsafe { core::slice::from_raw_parts(given_token_data, given_token_data_len as usize) };
    let initially_given_amount = unsafe {
        core::slice::from_raw_parts(
            initially_given_amount_data,
            initially_given_amount_data_len as usize,
        )
    };

    let res = mintlayer_encode_input_commitment_v1_for_fill_order_impl(
        asked_token,
        initially_asked_amount,
        given_token,
        initially_given_amount,
    );
    handle_err_or_encode(res)
}

fn mintlayer_encode_input_commitment_v1_for_fill_order_impl(
    asked_token: &[u8],
    initially_asked_amount: &[u8],
    given_token: &[u8],
    initially_given_amount: &[u8],
) -> Result<SighashInputCommitment, MintlayerErrorCode> {
    let initially_asked = parse_output_value(initially_asked_amount, asked_token)?;
    let initially_given = parse_output_value(initially_given_amount, given_token)?;

    Ok(SighashInputCommitment::FillOrderAccountCommand {
        initially_asked,
        initially_given,
    })
}

#[no_mangle]
extern "C" fn mintlayer_encode_input_commitment_v1_for_conclude_order(
    asked_token_data: *const u8,
    asked_token_data_len: u32,
    initially_asked_amount_data: *const u8,
    initially_asked_amount_data_len: u32,
    ask_balance_amount_data: *const u8,
    ask_balance_amount_data_len: u32,
    given_token_data: *const u8,
    given_token_data_len: u32,
    initially_given_amount_data: *const u8,
    initially_given_amount_data_len: u32,
    give_balance_amount_data: *const u8,
    give_balance_amount_data_len: u32,
) -> ByteArray {
    let asked_token =
        unsafe { core::slice::from_raw_parts(asked_token_data, asked_token_data_len as usize) };
    let initially_asked_amount = unsafe {
        core::slice::from_raw_parts(
            initially_asked_amount_data,
            initially_asked_amount_data_len as usize,
        )
    };
    let ask_balance_amount = unsafe {
        core::slice::from_raw_parts(
            ask_balance_amount_data,
            ask_balance_amount_data_len as usize,
        )
    };
    let given_token =
        unsafe { core::slice::from_raw_parts(given_token_data, given_token_data_len as usize) };
    let initially_given_amount = unsafe {
        core::slice::from_raw_parts(
            initially_given_amount_data,
            initially_given_amount_data_len as usize,
        )
    };
    let give_balance_amount = unsafe {
        core::slice::from_raw_parts(
            give_balance_amount_data,
            give_balance_amount_data_len as usize,
        )
    };

    let res = mintlayer_encode_input_commitment_v1_for_conclude_order_impl(
        asked_token,
        initially_asked_amount,
        ask_balance_amount,
        given_token,
        initially_given_amount,
        give_balance_amount,
    );
    handle_err_or_encode(res)
}

fn mintlayer_encode_input_commitment_v1_for_conclude_order_impl(
    asked_token: &[u8],
    initially_asked_amount: &[u8],
    ask_balance_amount: &[u8],
    given_token: &[u8],
    initially_given_amount: &[u8],
    give_balance_amount: &[u8],
) -> Result<SighashInputCommitment, MintlayerErrorCode> {
    let initially_asked = parse_output_value(initially_asked_amount, asked_token)?;
    let initially_given = parse_output_value(initially_given_amount, given_token)?;
    let ask_balance = parse_amount(ask_balance_amount)?;
    let give_balance = parse_amount(give_balance_amount)?;

    Ok(SighashInputCommitment::ConcludeOrderAccountCommand {
        initially_asked,
        initially_given,
        ask_balance,
        give_balance,
    })
}
