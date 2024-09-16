#include <stdio.h>
#include "py/objstr.h"

#include "embed/extmod/trezorobj.h"

#include "embed/rust/mintlayer.h"

#include "bip32.h"
#include "bip39.h"
#include "curves.h"
#include "memzero.h"

void handle_err(ByteArray *res) {
  if (res->data != NULL) {
    return;
  }

  switch (res->len_or_err.err) {
    case WrongHashSize:
      mp_raise_ValueError("Invalid hash size");
      break;
    case InvalidUtxoType:
      mp_raise_ValueError("Invalid UTXO type");
      break;
    case InvalidAmount:
      mp_raise_ValueError("Invalid amount");
      break;
    case InvalidAccountCommand:
      mp_raise_ValueError("Invalid account command");
      break;
    case InvalidDestination:
      mp_raise_ValueError("Invalid destination");
      break;
    case InvalidIsTokenUnfreezable:
      mp_raise_ValueError("Invalid token unfreezable flag");
      break;
    case InvalidIsTokenFreezable:
      mp_raise_ValueError("Invalid token freezable flag");
      break;
    case InvalidVrfPublicKey:
      mp_raise_ValueError("Invalid VRF public key");
      break;
    case InvalidPublicKey:
      mp_raise_ValueError("Invalid public key");
      break;
    case InvalidOutputTimeLock:
      mp_raise_ValueError("Invalid output time lock");
      break;
    case InvalidTokenTotalSupply:
      mp_raise_ValueError("Invalid token total supply");
      break;
    default:
      mp_raise_ValueError("Unknown error");
      break;
  }
}

/// def encode_utxo_input(tx_hash: bytes, index: int, utxo_type: int) -> bytes:
///     """
///     encodes an utxo input from tx_hash and index
///     """
STATIC mp_obj_t mod_trezormintlayer_utils_mintlayer_encode_utxo_input(
    mp_obj_t tx_hash, mp_obj_t index, mp_obj_t utxo_type_obj) {
  mp_buffer_info_t hash = {0};
  mp_get_buffer_raise(tx_hash, &hash, MP_BUFFER_READ);
  if (hash.len != 32) {
    printf("invalid hash len: %ld", (long int)hash.len);
    mp_raise_ValueError("Invalid hash");
  }
  uint32_t idx = trezor_obj_get_uint(index);
  uint32_t utxo_type = trezor_obj_get_uint(utxo_type_obj);
  ByteArray arr =
      mintlayer_encode_utxo_input(hash.buf, hash.len, idx, utxo_type);
  handle_err(&arr);

  vstr_t pkh = {0};
  vstr_init_len(&pkh, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)pkh.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &pkh);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_3(
    mod_trezormintlayer_utils_mintlayer_encode_utxo_input_obj,
    mod_trezormintlayer_utils_mintlayer_encode_utxo_input);

/// def encode_account_spending_input(nonce: int, delegation_id: bytes, amount:
/// bytes) -> bytes:
///     """
///     encodes an utxo account spendinf from nonce and delegation id
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_account_spending_input(
    mp_obj_t nonce_obj, mp_obj_t delegation_id, mp_obj_t amount_obj) {
  uint64_t nonce = trezor_obj_get_uint64(nonce_obj);

  mp_buffer_info_t hash = {0};
  mp_get_buffer_raise(delegation_id, &hash, MP_BUFFER_READ);
  if (hash.len != 32) {
    printf("invalid hash len: %ld", (long int)hash.len);
    mp_raise_ValueError("Invalid hash");
  }

  mp_buffer_info_t amount = {0};
  mp_get_buffer_raise(amount_obj, &amount, MP_BUFFER_READ);

  ByteArray arr = mintlayer_encode_account_spending_input(
      nonce, hash.buf, hash.len, amount.buf, amount.len);
  handle_err(&arr);

  vstr_t pkh = {0};
  vstr_init_len(&pkh, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)pkh.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &pkh);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_3(
    mod_trezormintlayer_utils_mintlayer_encode_account_spending_input_obj,
    mod_trezormintlayer_utils_mintlayer_encode_account_spending_input);

/// def encode_token_account_command_input(nonce: int, command: int, token_id:
/// bytes, data: bytes) -> bytes:
///     """
///     encodes an account command from the nonce, command, token id and
///     additional command data
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_token_account_command_input(
    size_t n_args, const mp_obj_t *args) {
  uint64_t nonce = trezor_obj_get_uint64(args[0]);
  uint32_t command = trezor_obj_get_uint(args[1]);

  mp_buffer_info_t hash = {0};
  mp_get_buffer_raise(args[2], &hash, MP_BUFFER_READ);
  if (hash.len != 32) {
    printf("invalid hash len: %ld", (long int)hash.len);
    mp_raise_ValueError("Invalid hash");
  }

  mp_buffer_info_t data = {0};
  mp_get_buffer_raise(args[3], &data, MP_BUFFER_READ);

  ByteArray arr = mintlayer_encode_token_account_command_input(
      nonce, command, hash.buf, hash.len, data.buf, data.len);
  handle_err(&arr);

  vstr_t pkh = {0};
  vstr_init_len(&pkh, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)pkh.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &pkh);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezormintlayer_utils_mintlayer_encode_token_account_command_input_obj,
    4, 4,
    mod_trezormintlayer_utils_mintlayer_encode_token_account_command_input);

/// def encode_conclude_order_account_command_input(nonce: int, order_id: bytes)
/// -> bytes:
///     """
///     encodes an conclude order account command from the nonce and order id
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_conclude_order_account_command_input(
    mp_obj_t nonce_obj, mp_obj_t order_id_obj) {
  uint64_t nonce = trezor_obj_get_uint64(nonce_obj);
  mp_buffer_info_t order_id = {0};
  mp_get_buffer_raise(order_id_obj, &order_id, MP_BUFFER_READ);

  ByteArray arr = mintlayer_encode_conclude_order_account_command_input(
      nonce, order_id.buf, order_id.len);
  handle_err(&arr);

  vstr_t pkh = {0};
  vstr_init_len(&pkh, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)pkh.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &pkh);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(
    mod_trezormintlayer_utils_mintlayer_encode_conclude_order_account_command_input_obj,
    mod_trezormintlayer_utils_mintlayer_encode_conclude_order_account_command_input);

/// def encode_fill_order_account_command_input(nonce: int, order_id: bytes,
/// amount: bytes, token_id: bytes, destination: bytes)
/// -> bytes:
///     """
///     encodes an fill order account command from the nonce, order id, output
///     value and destination
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_fill_order_account_command_input(
    size_t n_args, const mp_obj_t *args) {
  uint64_t nonce = trezor_obj_get_uint64(args[0]);
  mp_buffer_info_t order_id = {0};
  mp_get_buffer_raise(args[1], &order_id, MP_BUFFER_READ);
  mp_buffer_info_t amount = {0};
  mp_get_buffer_raise(args[2], &amount, MP_BUFFER_READ);
  mp_buffer_info_t token_id = {0};
  mp_get_buffer_raise(args[3], &token_id, MP_BUFFER_READ);
  mp_buffer_info_t destination = {0};
  mp_get_buffer_raise(args[4], &destination, MP_BUFFER_READ);

  ByteArray arr = mintlayer_encode_fill_order_account_command_input(
      nonce, order_id.buf, order_id.len, amount.buf, amount.len, token_id.buf,
      token_id.len, destination.buf, destination.len);
  handle_err(&arr);

  vstr_t pkh = {0};
  vstr_init_len(&pkh, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)pkh.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &pkh);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezormintlayer_utils_mintlayer_encode_fill_order_account_command_input_obj,
    5, 5,
    mod_trezormintlayer_utils_mintlayer_encode_fill_order_account_command_input);

/// def encode_transfer_output(amount: bytes, token_id: bytes, address: bytes)
/// -> bytes:
///     """
///     encodes a transfer output with given amount and destination address
///     """
STATIC mp_obj_t mod_trezormintlayer_utils_mintlayer_encode_transfer_output(
    mp_obj_t amount_obj, mp_obj_t token_id_obj, mp_obj_t address_obj) {
  mp_buffer_info_t amount = {0};
  mp_get_buffer_raise(amount_obj, &amount, MP_BUFFER_READ);
  mp_buffer_info_t token_id = {0};
  mp_get_buffer_raise(token_id_obj, &token_id, MP_BUFFER_READ);
  mp_buffer_info_t address = {0};
  mp_get_buffer_raise(address_obj, &address, MP_BUFFER_READ);
  ByteArray arr =
      mintlayer_encode_transfer_output(amount.buf, amount.len, token_id.buf,
                                       token_id.len, address.buf, address.len);
  handle_err(&arr);

  vstr_t encoding = {0};
  vstr_init_len(&encoding, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)encoding.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &encoding);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_3(
    mod_trezormintlayer_utils_mintlayer_encode_transfer_output_obj,
    mod_trezormintlayer_utils_mintlayer_encode_transfer_output);

/// def encode_lock_then_transfer_output(amount: bytes, token_id: bytes,
/// lock_type: int, lock_amount:int, address: bytes) -> bytes:
///     """
///     encodes a transfer output with given amount, lock type and amount, and
///     destination address
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_lock_then_transfer_output(
    size_t n_args, const mp_obj_t *args) {
  mp_buffer_info_t amount = {0};
  mp_get_buffer_raise(args[0], &amount, MP_BUFFER_READ);
  mp_buffer_info_t token_id = {0};
  mp_get_buffer_raise(args[1], &token_id, MP_BUFFER_READ);
  uint8_t lock_type = trezor_obj_get_uint8(args[2]);
  uint64_t lock_amount = trezor_obj_get_uint64(args[3]);
  mp_buffer_info_t address = {0};
  mp_get_buffer_raise(args[4], &address, MP_BUFFER_READ);
  ByteArray arr = mintlayer_encode_lock_then_transfer_output(
      amount.buf, amount.len, token_id.buf, token_id.len, lock_type,
      lock_amount, address.buf, address.len);
  handle_err(&arr);

  vstr_t encoding = {0};
  vstr_init_len(&encoding, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)encoding.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &encoding);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezormintlayer_utils_mintlayer_encode_lock_then_transfer_output_obj, 5,
    5, mod_trezormintlayer_utils_mintlayer_encode_lock_then_transfer_output);

/// def encode_burn_output(amount: bytes, token_id: bytes) ->
/// bytes:
///     """
///     encodes a burn output with given amount
///     """
STATIC mp_obj_t mod_trezormintlayer_utils_mintlayer_encode_burn_output(
    mp_obj_t amount_obj, mp_obj_t token_id_obj) {
  mp_buffer_info_t amount = {0};
  mp_get_buffer_raise(amount_obj, &amount, MP_BUFFER_READ);
  mp_buffer_info_t token_id = {0};
  mp_get_buffer_raise(token_id_obj, &token_id, MP_BUFFER_READ);
  ByteArray arr = mintlayer_encode_burn_output(amount.buf, amount.len,
                                               token_id.buf, token_id.len);
  handle_err(&arr);

  vstr_t encoding = {0};
  vstr_init_len(&encoding, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)encoding.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &encoding);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(
    mod_trezormintlayer_utils_mintlayer_encode_burn_output_obj,
    mod_trezormintlayer_utils_mintlayer_encode_burn_output);

/// def encode_create_stake_pool_output(pool_id: bytes, pledge_amount: bytes,
/// staker: bytes, vrf_public_key: bytes, decommission_key: bytes,
/// margin_ratio_per_thousand: int, cost_per_block: bytes) -> bytes:
///     """
///     encodes a create stake pool output
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_create_stake_pool_output(
    size_t n_args, const mp_obj_t *args) {
  mp_buffer_info_t pool_id = {0};
  mp_get_buffer_raise(args[0], &pool_id, MP_BUFFER_READ);
  mp_buffer_info_t pledge_amount = {0};
  mp_get_buffer_raise(args[1], &pledge_amount, MP_BUFFER_READ);
  mp_buffer_info_t staker = {0};
  mp_get_buffer_raise(args[2], &staker, MP_BUFFER_READ);
  mp_buffer_info_t vrf_public_key = {0};
  mp_get_buffer_raise(args[3], &vrf_public_key, MP_BUFFER_READ);
  mp_buffer_info_t decommission_key = {0};
  mp_get_buffer_raise(args[4], &decommission_key, MP_BUFFER_READ);
  uint16_t margin_ratio_per_thousand = (uint16_t)trezor_obj_get_uint64(args[5]);
  mp_buffer_info_t cost_per_block = {0};
  mp_get_buffer_raise(args[6], &cost_per_block, MP_BUFFER_READ);

  ByteArray arr = mintlayer_encode_create_stake_pool_output(
      pool_id.buf, pool_id.len, pledge_amount.buf, pledge_amount.len,
      staker.buf, staker.len, vrf_public_key.buf, vrf_public_key.len,
      decommission_key.buf, decommission_key.len, margin_ratio_per_thousand,
      cost_per_block.buf, cost_per_block.len);
  handle_err(&arr);

  vstr_t encoding = {0};
  vstr_init_len(&encoding, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)encoding.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &encoding);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezormintlayer_utils_mintlayer_encode_create_stake_pool_output_obj, 7,
    7, mod_trezormintlayer_utils_mintlayer_encode_create_stake_pool_output);

/// def encode_produce_from_stake_output(destination: bytes, pool_id: bytes) ->
/// bytes:
///     """
///     encodes a produce from stake output
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_produce_from_stake_output(
    mp_obj_t destination_obj, mp_obj_t pool_id_obj) {
  mp_buffer_info_t destination = {0};
  mp_get_buffer_raise(destination_obj, &destination, MP_BUFFER_READ);
  mp_buffer_info_t pool_id = {0};
  mp_get_buffer_raise(pool_id_obj, &pool_id, MP_BUFFER_READ);
  ByteArray arr = mintlayer_encode_produce_from_stake_output(
      destination.buf, destination.len, pool_id.buf, pool_id.len);
  handle_err(&arr);

  vstr_t encoding = {0};
  vstr_init_len(&encoding, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)encoding.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &encoding);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(
    mod_trezormintlayer_utils_mintlayer_encode_produce_from_stake_output_obj,
    mod_trezormintlayer_utils_mintlayer_encode_produce_from_stake_output);

/// def encode_create_delegation_id_output(destination: bytes, pool_id: bytes)
/// -> bytes:
///     """
///     encodes a create delegation id output
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_create_delegation_id_output(
    mp_obj_t destination_obj, mp_obj_t pool_id_obj) {
  mp_buffer_info_t destination = {0};
  mp_get_buffer_raise(destination_obj, &destination, MP_BUFFER_READ);
  mp_buffer_info_t pool_id = {0};
  mp_get_buffer_raise(pool_id_obj, &pool_id, MP_BUFFER_READ);
  ByteArray arr = mintlayer_encode_create_delegation_id_output(
      destination.buf, destination.len, pool_id.buf, pool_id.len);
  handle_err(&arr);

  vstr_t encoding = {0};
  vstr_init_len(&encoding, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)encoding.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &encoding);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(
    mod_trezormintlayer_utils_mintlayer_encode_create_delegation_id_output_obj,
    mod_trezormintlayer_utils_mintlayer_encode_create_delegation_id_output);

/// def encode_delegate_staking_output(amount: bytes, delegation_id: bytes) ->
/// bytes:
///     """
///     encodes a delegation staking output, given the amount and delegation id
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_delegate_staking_output(
    mp_obj_t destination_obj, mp_obj_t delegation_id_obj) {
  mp_buffer_info_t amount = {0};
  mp_get_buffer_raise(destination_obj, &amount, MP_BUFFER_READ);
  mp_buffer_info_t delegation_id = {0};
  mp_get_buffer_raise(delegation_id_obj, &delegation_id, MP_BUFFER_READ);
  ByteArray arr = mintlayer_encode_delegate_staking_output(
      amount.buf, amount.len, delegation_id.buf, delegation_id.len);
  handle_err(&arr);

  vstr_t encoding = {0};
  vstr_init_len(&encoding, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)encoding.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &encoding);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(
    mod_trezormintlayer_utils_mintlayer_encode_delegate_staking_output_obj,
    mod_trezormintlayer_utils_mintlayer_encode_delegate_staking_output);

/// def encode_issue_fungible_token_output(token_ticker: bytes,
/// number_of_decimals: int, metadata_uri: bytes, total_supply_type: int,
/// fixed_amount: bytes, authority: bytes, is_freezable: int) -> bytes:
///     """
///     encodes a issue fungible token output
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_issue_fungible_token_output(
    size_t n_args, const mp_obj_t *args) {
  mp_buffer_info_t token_ticker = {0};
  mp_get_buffer_raise(args[0], &token_ticker, MP_BUFFER_READ);
  uint8_t number_of_decimals = trezor_obj_get_uint8(args[1]);
  mp_buffer_info_t metadata_uri = {0};
  mp_get_buffer_raise(args[2], &metadata_uri, MP_BUFFER_READ);
  uint32_t total_supply_type = (uint32_t)trezor_obj_get_uint64(args[3]);
  mp_buffer_info_t fixed_amount = {0};
  mp_get_buffer_raise(args[4], &fixed_amount, MP_BUFFER_READ);
  mp_buffer_info_t authority = {0};
  mp_get_buffer_raise(args[5], &authority, MP_BUFFER_READ);
  uint8_t is_freezable = trezor_obj_get_uint8(args[6]);

  ByteArray arr = mintlayer_encode_issue_fungible_token_output(
      token_ticker.buf, token_ticker.len, number_of_decimals, metadata_uri.buf,
      metadata_uri.len, total_supply_type, fixed_amount.buf, fixed_amount.len,
      authority.buf, authority.len, is_freezable);
  handle_err(&arr);

  vstr_t encoding = {0};
  vstr_init_len(&encoding, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)encoding.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &encoding);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezormintlayer_utils_mintlayer_encode_issue_fungible_token_output_obj,
    7, 7,
    mod_trezormintlayer_utils_mintlayer_encode_issue_fungible_token_output);

/// def encode_issue_nft_output(token_id: bytes,
/// creator: bytes, name: bytes, destination: bytes,
/// ticker: bytes, icon_uri: bytes, additional_metadata_uri: bytes, media_uri:
/// bytes, media_hash: bytes, destination: bytes) -> bytes:
///     """
///     encodes a issue NFT output
///     """
STATIC mp_obj_t mod_trezormintlayer_utils_mintlayer_encode_issue_nft_output(
    size_t n_args, const mp_obj_t *args) {
  mp_buffer_info_t token_id = {0};
  mp_get_buffer_raise(args[0], &token_id, MP_BUFFER_READ);
  mp_buffer_info_t creator = {0};
  mp_get_buffer_raise(args[1], &creator, MP_BUFFER_READ);
  mp_buffer_info_t name = {0};
  mp_get_buffer_raise(args[2], &name, MP_BUFFER_READ);
  mp_buffer_info_t description = {0};
  mp_get_buffer_raise(args[3], &description, MP_BUFFER_READ);
  mp_buffer_info_t ticker = {0};
  mp_get_buffer_raise(args[4], &ticker, MP_BUFFER_READ);
  mp_buffer_info_t icon_uri = {0};
  mp_get_buffer_raise(args[5], &icon_uri, MP_BUFFER_READ);
  mp_buffer_info_t additional_metadata_uri = {0};
  mp_get_buffer_raise(args[6], &additional_metadata_uri, MP_BUFFER_READ);
  mp_buffer_info_t media_uri = {0};
  mp_get_buffer_raise(args[7], &media_uri, MP_BUFFER_READ);
  mp_buffer_info_t media_hash = {0};
  mp_get_buffer_raise(args[8], &media_hash, MP_BUFFER_READ);
  mp_buffer_info_t destination = {0};
  mp_get_buffer_raise(args[9], &destination, MP_BUFFER_READ);

  ByteArray arr = mintlayer_encode_issue_nft_output(
      token_id.buf, token_id.len, creator.buf, creator.len, name.buf, name.len,
      description.buf, description.len, ticker.buf, ticker.len, icon_uri.buf,
      icon_uri.len, additional_metadata_uri.buf, additional_metadata_uri.len,
      media_uri.buf, media_uri.len, media_hash.buf, media_hash.len,
      destination.buf, destination.len);
  handle_err(&arr);

  vstr_t encoding = {0};
  vstr_init_len(&encoding, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)encoding.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &encoding);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezormintlayer_utils_mintlayer_encode_issue_nft_output_obj, 10, 10,
    mod_trezormintlayer_utils_mintlayer_encode_issue_nft_output);

/// def encode_data_deposit_output(deposit: bytes) ->
/// bytes:
///     """
///     encodes a data deposit output
///     """
STATIC mp_obj_t mod_trezormintlayer_utils_mintlayer_encode_data_deposit_output(
    mp_obj_t deposit_obj) {
  mp_buffer_info_t deposit = {0};
  mp_get_buffer_raise(deposit_obj, &deposit, MP_BUFFER_READ);
  ByteArray arr =
      mintlayer_encode_data_deposit_output(deposit.buf, deposit.len);
  handle_err(&arr);

  vstr_t encoding = {0};
  vstr_init_len(&encoding, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)encoding.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &encoding);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(
    mod_trezormintlayer_utils_mintlayer_encode_data_deposit_output_obj,
    mod_trezormintlayer_utils_mintlayer_encode_data_deposit_output);

/// def encode_htlc_output(amount: bytes, token_id: bytes, lock_type:
/// int, lock_amount:int, refund_key: bytes, spend_key: bytes, secret_has:
/// bytes) -> bytes:
///     """
///     encodes an htlc output with given amount and lock
///     """
STATIC mp_obj_t mod_trezormintlayer_utils_mintlayer_encode_htlc_output(
    size_t n_args, const mp_obj_t *args) {
  mp_buffer_info_t amount = {0};
  mp_get_buffer_raise(args[0], &amount, MP_BUFFER_READ);
  mp_buffer_info_t token_id = {0};
  mp_get_buffer_raise(args[1], &token_id, MP_BUFFER_READ);
  uint8_t lock_type = trezor_obj_get_uint8(args[2]);
  uint64_t lock_amount = trezor_obj_get_uint64(args[3]);
  mp_buffer_info_t refund_key = {0};
  mp_get_buffer_raise(args[4], &refund_key, MP_BUFFER_READ);
  mp_buffer_info_t spend_key = {0};
  mp_get_buffer_raise(args[5], &spend_key, MP_BUFFER_READ);
  mp_buffer_info_t secret_hash = {0};
  mp_get_buffer_raise(args[6], &secret_hash, MP_BUFFER_READ);
  ByteArray arr = mintlayer_encode_htlc_output(
      amount.buf, amount.len, token_id.buf, token_id.len, lock_type,
      lock_amount, refund_key.buf, refund_key.len, spend_key.buf, spend_key.len,
      secret_hash.buf, secret_hash.len);
  handle_err(&arr);

  vstr_t encoding = {0};
  vstr_init_len(&encoding, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)encoding.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &encoding);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezormintlayer_utils_mintlayer_encode_htlc_output_obj, 5, 5,
    mod_trezormintlayer_utils_mintlayer_encode_htlc_output);

/// def encode_anyone_can_take_output(destination: bytes, ask_amount: bytes,
/// ask_token_id: bytes, give_amount: bytes, give_token_id: bytes) -> bytes:
///     """
///     encodes an anyone can take output with given the conclude key, give and
///     take amounts
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_anyone_can_take_output(
    size_t n_args, const mp_obj_t *args) {
  mp_buffer_info_t conclude_key = {0};
  mp_get_buffer_raise(args[0], &conclude_key, MP_BUFFER_READ);
  mp_buffer_info_t ask_amount = {0};
  mp_get_buffer_raise(args[1], &ask_amount, MP_BUFFER_READ);
  mp_buffer_info_t ask_token_id = {0};
  mp_get_buffer_raise(args[2], &ask_token_id, MP_BUFFER_READ);
  mp_buffer_info_t give_amount = {0};
  mp_get_buffer_raise(args[3], &give_amount, MP_BUFFER_READ);
  mp_buffer_info_t give_token_id = {0};
  mp_get_buffer_raise(args[4], &give_token_id, MP_BUFFER_READ);

  ByteArray arr = mintlayer_encode_anyone_can_take_output(
      conclude_key.buf, conclude_key.len, ask_amount.buf, ask_amount.len,
      ask_token_id.buf, ask_token_id.len, give_amount.buf, give_amount.len,
      give_token_id.buf, give_token_id.len);
  handle_err(&arr);

  vstr_t encoding = {0};
  vstr_init_len(&encoding, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)encoding.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &encoding);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(
    mod_trezormintlayer_utils_mintlayer_encode_anyone_can_take_output_obj, 5, 5,
    mod_trezormintlayer_utils_mintlayer_encode_anyone_can_take_output);

/// def encode_compact_length(length: int) -> bytes:
///     """
///     encodes a comapct length to bytes
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_comact_length(mp_obj_t length) {
  uint32_t len = trezor_obj_get_uint(length);
  ByteArray arr = mintlayer_encode_compact_length(len);
  handle_err(&arr);

  vstr_t encoding = {0};
  vstr_init_len(&encoding, arr.len_or_err.len);
  int i = 0;
  for (; i < arr.len_or_err.len; i++) {
    ((uint8_t *)encoding.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &encoding);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(
    mod_trezormintlayer_utils_mintlayer_encode_comact_length_obj,
    mod_trezormintlayer_utils_mintlayer_encode_comact_length);
