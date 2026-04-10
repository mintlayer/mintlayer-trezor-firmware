#include <stdio.h>
#include "py/objstr.h"

#include "embed/upymod/trezorobj.h"

#include "embed/rust/mintlayer.h"

#include "bip32.h"
#include "bip39.h"
#include "curves.h"
#include "memzero.h"

#include "utils.h"

/// def encode_empty_input_commitment() -> bytes:
///     """
///     Encodes an empty input commitment.
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_empty_input_commitment() {
  ByteArray arr = mintlayer_encode_empty_input_commitment();
  handle_err(&arr);

  return mp_obj_new_bytes(arr.data, arr.len_or_err.len);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_0(
    mod_trezormintlayer_utils_mintlayer_encode_empty_input_commitment_obj,
    mod_trezormintlayer_utils_mintlayer_encode_empty_input_commitment);

/// def encode_input_commitment_for_utxo(encoded_utxo: AnyBytes) -> bytes:
///     """
///     Encodes an input commitment for a utxo.
//      Note: in input commitments v0 this works for any utxo input;
///     in v1 it works for any utxo input except ProduceBlockFromStake.
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_input_commitment_for_utxo(
    mp_obj_t encoded_utxo_obj) {
  mp_buffer_info_t encoded_utxo = {0};
  mp_get_buffer_raise(encoded_utxo_obj, &encoded_utxo, MP_BUFFER_READ);
  ByteArray arr = mintlayer_encode_input_commitment_for_utxo(encoded_utxo.buf,
                                                             encoded_utxo.len);
  handle_err(&arr);

  return mp_obj_new_bytes(arr.data, arr.len_or_err.len);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(
    mod_trezormintlayer_utils_mintlayer_encode_input_commitment_for_utxo_obj,
    mod_trezormintlayer_utils_mintlayer_encode_input_commitment_for_utxo);

/// def encode_input_commitment_v1_for_produce_block_from_stake_utxo(
///   encoded_utxo: AnyBytes, staker_balance_amount: AnyBytes
/// ) -> bytes:
///     """
///     Encodes an input commitment for a ProduceBlockFromStake utxo (v1 only).
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_input_commitment_v1_for_produce_block_from_stake_utxo(
    mp_obj_t encoded_utxo_obj, mp_obj_t staker_balance_amount_obj) {
  mp_buffer_info_t encoded_utxo = {0};
  mp_get_buffer_raise(encoded_utxo_obj, &encoded_utxo, MP_BUFFER_READ);
  mp_buffer_info_t staker_balance_amount = {0};
  mp_get_buffer_raise(staker_balance_amount_obj, &staker_balance_amount,
                      MP_BUFFER_READ);
  ByteArray arr =
      mintlayer_encode_input_commitment_v1_for_produce_block_from_stake_utxo(
          encoded_utxo.buf, encoded_utxo.len, staker_balance_amount.buf,
          staker_balance_amount.len);
  handle_err(&arr);

  return mp_obj_new_bytes(arr.data, arr.len_or_err.len);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(
    mod_trezormintlayer_utils_mintlayer_encode_input_commitment_v1_for_produce_block_from_stake_utxo_obj,
    mod_trezormintlayer_utils_mintlayer_encode_input_commitment_v1_for_produce_block_from_stake_utxo);

/// def encode_input_commitment_v1_for_fill_order(
///     asked_token: AnyBytes, initially_asked_amount: AnyBytes,
///     given_token: AnyBytes, initially_given_amount: AnyBytes,
/// ) -> bytes:
///     """
///     Encodes input commitment for filling an order (v1 only);
///     asked_token and given_token can be empty byte arrays, which means that
///     the corresponding
//      amounts are in coins.
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_input_commitment_v1_for_fill_order(
    size_t n_args, const mp_obj_t *args) {
  mp_buffer_info_t asked_token = {0};
  mp_get_buffer_raise(args[0], &asked_token, MP_BUFFER_READ);
  mp_buffer_info_t initially_asked_amount = {0};
  mp_get_buffer_raise(args[1], &initially_asked_amount, MP_BUFFER_READ);

  mp_buffer_info_t given_token = {0};
  mp_get_buffer_raise(args[2], &given_token, MP_BUFFER_READ);
  mp_buffer_info_t initially_given_amount = {0};
  mp_get_buffer_raise(args[3], &initially_given_amount, MP_BUFFER_READ);

  ByteArray arr = mintlayer_encode_input_commitment_v1_for_fill_order(
      asked_token.buf, asked_token.len, initially_asked_amount.buf,
      initially_asked_amount.len, given_token.buf, given_token.len,
      initially_given_amount.buf, initially_given_amount.len);
  handle_err(&arr);

  return mp_obj_new_bytes(arr.data, arr.len_or_err.len);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezormintlayer_utils_mintlayer_encode_input_commitment_v1_for_fill_order_obj,
    4, 4,
    mod_trezormintlayer_utils_mintlayer_encode_input_commitment_v1_for_fill_order);

/// def encode_input_commitment_v1_for_conclude_order(
///     asked_token: AnyBytes,
///     initially_asked_amount: AnyBytes,
///     ask_balance_amount: AnyBytes,
///     given_token: AnyBytes,
///     initially_given_amount: AnyBytes,
///     give_balance_amount: AnyBytes
/// ) -> bytes:
///     """
///     Encodes input commitment for concluding an order (v1 only);
///     asked_token and given_token can be empty byte arrays, which means that
///     the corresponding
//      amounts are in coins.
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_input_commitment_v1_for_conclude_order(
    size_t n_args, const mp_obj_t *args) {
  mp_buffer_info_t asked_token = {0};
  mp_get_buffer_raise(args[0], &asked_token, MP_BUFFER_READ);
  mp_buffer_info_t initially_asked_amount = {0};
  mp_get_buffer_raise(args[1], &initially_asked_amount, MP_BUFFER_READ);
  mp_buffer_info_t ask_balance_amount = {0};
  mp_get_buffer_raise(args[2], &ask_balance_amount, MP_BUFFER_READ);

  mp_buffer_info_t given_token = {0};
  mp_get_buffer_raise(args[3], &given_token, MP_BUFFER_READ);
  mp_buffer_info_t initially_given_amount = {0};
  mp_get_buffer_raise(args[4], &initially_given_amount, MP_BUFFER_READ);
  mp_buffer_info_t give_balance_amount = {0};
  mp_get_buffer_raise(args[5], &give_balance_amount, MP_BUFFER_READ);

  ByteArray arr = mintlayer_encode_input_commitment_v1_for_conclude_order(
      asked_token.buf, asked_token.len, initially_asked_amount.buf,
      initially_asked_amount.len, ask_balance_amount.buf,
      ask_balance_amount.len, given_token.buf, given_token.len,
      initially_given_amount.buf, initially_given_amount.len,
      give_balance_amount.buf, give_balance_amount.len);
  handle_err(&arr);

  return mp_obj_new_bytes(arr.data, arr.len_or_err.len);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezormintlayer_utils_mintlayer_encode_input_commitment_v1_for_conclude_order_obj,
    6, 6,
    mod_trezormintlayer_utils_mintlayer_encode_input_commitment_v1_for_conclude_order);
