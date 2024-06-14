#include <stdio.h>
#include "py/objstr.h"

#include "embed/extmod/trezorobj.h"

// FIXME
#include "embed/rust/rust_ui_common.h"

#include "bip32.h"
#include "bip39.h"
#include "curves.h"
#include "memzero.h"

/// def encode_utxo_input(tx_hash: bytes, index: int) -> bytes:
///     """
///     encodes an utxo input from tx_hash and index
///     """
STATIC mp_obj_t mod_trezormintlayer_utils_mintlayer_encode_utxo_input(
    mp_obj_t tx_hash, mp_obj_t index) {
  mp_buffer_info_t hash = {0};
  mp_get_buffer_raise(tx_hash, &hash, MP_BUFFER_READ);
  if (hash.len != 32) {
    printf("invalid hash len: %ld", (long int)hash.len);
    mp_raise_ValueError("Invalid hash");
  }
  uint32_t idx = trezor_obj_get_uint(index);
  ByteArray arr = mintlayer_encode_utxo_input(hash.buf, hash.len, idx);

  vstr_t pkh = {0};
  vstr_init_len(&pkh, arr.len);
  int i = 0;
  for (; i < arr.len; i++) {
    ((uint8_t *)pkh.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &pkh);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(
    mod_trezormintlayer_utils_mintlayer_encode_utxo_input_obj,
    mod_trezormintlayer_utils_mintlayer_encode_utxo_input);

/// def encode_transfer_output(amount: str, address: str) -> bytes:
///     """
///     encodes a transfer output with given amount and destination address
///     """
STATIC mp_obj_t mod_trezormintlayer_utils_mintlayer_encode_transfer_output(
    mp_obj_t amount_obj, mp_obj_t address_obj) {
  mp_buffer_info_t amount = {0};
  mp_get_buffer_raise(amount_obj, &amount, MP_BUFFER_READ);
  mp_buffer_info_t address = {0};
  mp_get_buffer_raise(address_obj, &address, MP_BUFFER_READ);
  ByteArray arr = mintlayer_encode_transfer_output(amount.buf, amount.len,
                                                   address.buf, address.len);

  vstr_t encoding = {0};
  vstr_init_len(&encoding, arr.len);
  int i = 0;
  for (; i < arr.len; i++) {
    ((uint8_t *)encoding.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &encoding);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(
    mod_trezormintlayer_utils_mintlayer_encode_transfer_output_obj,
    mod_trezormintlayer_utils_mintlayer_encode_transfer_output);

/// def encode_compact_length(length: int) -> bytes:
///     """
///     encodes a comapct length to bytes
///     """
STATIC mp_obj_t
mod_trezormintlayer_utils_mintlayer_encode_comact_length(mp_obj_t length) {
  uint32_t len = trezor_obj_get_uint(length);
  ByteArray arr = mintlayer_encode_compact_length(len);

  vstr_t encoding = {0};
  vstr_init_len(&encoding, arr.len);
  int i = 0;
  for (; i < arr.len; i++) {
    ((uint8_t *)encoding.buf)[i] = (uint8_t)arr.data[i];
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &encoding);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_1(
    mod_trezormintlayer_utils_mintlayer_encode_comact_length_obj,
    mod_trezormintlayer_utils_mintlayer_encode_comact_length);

STATIC const mp_rom_map_elem_t mod_trezormintlayer_utils_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_bip32)},
    {MP_ROM_QSTR(MP_QSTR_encode_utxo_input),
     MP_ROM_PTR(&mod_trezormintlayer_utils_mintlayer_encode_utxo_input_obj)},
    {MP_ROM_QSTR(MP_QSTR_encode_transfer_output),
     MP_ROM_PTR(
         &mod_trezormintlayer_utils_mintlayer_encode_transfer_output_obj)},
    {MP_ROM_QSTR(MP_QSTR_encode_compact_length),
     MP_ROM_PTR(&mod_trezormintlayer_utils_mintlayer_encode_comact_length_obj)},
};
STATIC MP_DEFINE_CONST_DICT(mod_trezormintlayer_utils_globals,
                            mod_trezormintlayer_utils_globals_table);

STATIC const mp_obj_module_t mod_trezormintlayer_utils_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mod_trezormintlayer_utils_globals,
};
